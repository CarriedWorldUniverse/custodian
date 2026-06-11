package custodian

import (
	"context"
	"testing"

	cwbv1 "github.com/CarriedWorldUniverse/cwb-proto/gen/go/cwb/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

// mdCtx builds an incoming-metadata context as interchange would inject it.
func mdCtx(org, sub, scopes string) context.Context {
	md := metadata.New(map[string]string{
		"cwb-org":     org,
		"cwb-subject": sub,
		"cwb-scopes":  scopes,
	})
	return metadata.NewIncomingContext(context.Background(), md)
}

func codeOf(err error) codes.Code { return status.Code(err) }

func TestGRPCMissingIdentity(t *testing.T) {
	srv := NewCredentialServer(newTestService(t))
	if _, err := srv.Fetch(context.Background(), &cwbv1.FetchRequest{Kind: "git", Name: "github.com"}); codeOf(err) != codes.Unauthenticated {
		t.Fatalf("Fetch w/o identity: want Unauthenticated, got %v", err)
	}
	if _, err := srv.SetCredential(context.Background(), &cwbv1.SetCredentialRequest{Kind: "git", Name: "github.com"}); codeOf(err) != codes.Unauthenticated {
		t.Fatalf("Set w/o identity: want Unauthenticated, got %v", err)
	}
}

// TestScopeMatrix — Fetch requires cred:read, SetCredential requires cred:write.
func TestScopeMatrix(t *testing.T) {
	svc := newTestService(t)
	srv := NewCredentialServer(svc)

	setReq := &cwbv1.SetCredentialRequest{
		Kind: "git", Name: "github.com",
		Bundle: &cwbv1.SetCredentialRequest_GitBundle{GitBundle: &cwbv1.GitBundle{
			Username: "nexus-cw", Password: "ghp_secret", Host: "github.com",
		}},
	}

	// Set without cred:write → PermissionDenied + audited.
	if _, err := srv.SetCredential(mdCtx("orgA", "shadow", "cred:read"), setReq); codeOf(err) != codes.PermissionDenied {
		t.Fatalf("Set with only cred:read: want PermissionDenied, got %v", err)
	}
	if n := auditCount(t, svc, "orgA", "denied"); n != 1 {
		t.Fatalf("denied Set should be audited: got %d", n)
	}

	// Set with cred:write → ok.
	if _, err := srv.SetCredential(mdCtx("orgA", "shadow", "cred:write"), setReq); err != nil {
		t.Fatalf("Set with cred:write: %v", err)
	}

	// Fetch without cred:read → PermissionDenied + audited.
	if _, err := srv.Fetch(mdCtx("orgA", "shadow", "cred:write"), &cwbv1.FetchRequest{Kind: "git", Name: "github.com"}); codeOf(err) != codes.PermissionDenied {
		t.Fatalf("Fetch with only cred:write: want PermissionDenied, got %v", err)
	}
	if n := auditCount(t, svc, "orgA", "denied"); n != 2 {
		t.Fatalf("denied Fetch should be audited: got %d", n)
	}

	// Fetch with cred:read → ok and returns the bundle.
	resp, err := srv.Fetch(mdCtx("orgA", "shadow", "cred:read"), &cwbv1.FetchRequest{Kind: "git", Name: "github.com"})
	if err != nil {
		t.Fatalf("Fetch with cred:read: %v", err)
	}
	if gb := resp.GetGitBundle(); gb == nil || gb.GetPassword() != "ghp_secret" {
		t.Fatalf("Fetch returned wrong bundle: %+v", resp)
	}
}

// TestAdminWriteSuperset — admin:write satisfies both cred lanes.
func TestAdminWriteSuperset(t *testing.T) {
	srv := NewCredentialServer(newTestService(t))
	setReq := &cwbv1.SetCredentialRequest{
		Kind: "git", Name: "github.com",
		Bundle: &cwbv1.SetCredentialRequest_GitBundle{GitBundle: &cwbv1.GitBundle{Username: "u", Password: "p", Host: "github.com"}},
	}
	if _, err := srv.SetCredential(mdCtx("orgA", "admin", "admin:write"), setReq); err != nil {
		t.Fatalf("Set with admin:write: %v", err)
	}
	if _, err := srv.Fetch(mdCtx("orgA", "admin", "admin:write"), &cwbv1.FetchRequest{Kind: "git", Name: "github.com"}); err != nil {
		t.Fatalf("Fetch with admin:write: %v", err)
	}
}

// TestGRPCOrgIsolation — orgB (cred:read) cannot read orgA's credential.
func TestGRPCOrgIsolation(t *testing.T) {
	srv := NewCredentialServer(newTestService(t))
	setReq := &cwbv1.SetCredentialRequest{
		Kind: "git", Name: "github.com",
		Bundle: &cwbv1.SetCredentialRequest_GitBundle{GitBundle: &cwbv1.GitBundle{Username: "u", Password: "p", Host: "github.com"}},
	}
	if _, err := srv.SetCredential(mdCtx("orgA", "shadow", "cred:write"), setReq); err != nil {
		t.Fatal(err)
	}
	if _, err := srv.Fetch(mdCtx("orgB", "intruder", "cred:read"), &cwbv1.FetchRequest{Kind: "git", Name: "github.com"}); codeOf(err) != codes.NotFound {
		t.Fatalf("orgB fetch of orgA cred: want NotFound, got %v", err)
	}
}

// TestListScopeGate — List requires cred:read.
func TestListScopeGate(t *testing.T) {
	srv := NewCredentialServer(newTestService(t))
	if _, err := srv.ListCredentials(mdCtx("orgA", "x", "cred:write"), &cwbv1.ListCredentialsRequest{}); codeOf(err) != codes.PermissionDenied {
		t.Fatalf("List without cred:read: want PermissionDenied, got %v", err)
	}
}
