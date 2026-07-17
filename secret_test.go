package custodian

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/CarriedWorldUniverse/cwb-proto/authz"
	cwbv1 "github.com/CarriedWorldUniverse/cwb-proto/gen/go/cwb/v1"
	"google.golang.org/grpc/codes"
)

// TestSecretSetFetchRoundTrip — Set then Fetch returns the same SecretBundle
// (value + hints preserved).
func TestSecretSetFetchRoundTrip(t *testing.T) {
	svc := newTestService(t)
	ctx := authCtx("orgA", "shadow")

	in := SecretBundle{Value: "sk-abc123", Host: "api.anthropic.com", Username: "x-api-key"}
	if _, err := svc.SetSecretCredential(ctx, "secret", "anthropic-key", in); err != nil {
		t.Fatalf("SetSecretCredential: %v", err)
	}
	got, meta, err := svc.FetchSecret(ctx, "secret", "anthropic-key")
	if err != nil {
		t.Fatalf("FetchSecret: %v", err)
	}
	if got != in {
		t.Fatalf("bundle mismatch: got %+v want %+v", got, in)
	}
	if meta.Kind != "secret" || meta.Name != "anthropic-key" || meta.Writer != "shadow" {
		t.Fatalf("meta mismatch: %+v", meta)
	}
}

// TestSecretAtRestSealedNotPlaintext — value must not appear in the
// sealed_bundle_b64 stored in the DB (ciphertext-only at rest).
func TestSecretAtRestSealedNotPlaintext(t *testing.T) {
	svc := newTestService(t)
	ctx := authCtx("orgA", "shadow")
	if _, err := svc.SetSecretCredential(ctx, "secret", "my-key",
		SecretBundle{Value: "SECRET_PLAINTEXT_VALUE", Host: "example.com"}); err != nil {
		t.Fatalf("SetSecretCredential: %v", err)
	}
	var sealedB64 string
	if err := svc.db.QueryRowContext(ctx,
		`SELECT sealed_bundle_b64 FROM credentials WHERE org='orgA' AND kind='secret' AND name='my-key'`).
		Scan(&sealedB64); err != nil {
		t.Fatalf("read sealed: %v", err)
	}
	if strings.Contains(sealedB64, "SECRET_PLAINTEXT_VALUE") {
		t.Fatal("at-rest sealed value must not contain plaintext secret value")
	}
}

// TestSecretValidationMissingValue — Set with empty value fails.
func TestSecretValidationMissingValue(t *testing.T) {
	svc := newTestService(t)
	ctx := authCtx("orgA", "shadow")
	_, err := svc.SetSecretCredential(ctx, "secret", "svc", SecretBundle{Host: "example.com"})
	if !errors.Is(err, ErrInvalid) {
		t.Fatalf("missing value: want ErrInvalid, got %v", err)
	}
}

// TestSecretOrgIsolation — orgB cannot fetch orgA's secret credential.
func TestSecretOrgIsolation(t *testing.T) {
	svc := newTestService(t)
	if _, err := svc.SetSecretCredential(authCtx("orgA", "shadow"), "secret", "svc",
		SecretBundle{Value: "v"}); err != nil {
		t.Fatalf("SetSecretCredential orgA: %v", err)
	}
	if _, _, err := svc.FetchSecret(authCtx("orgB", "intruder"), "secret", "svc"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("orgB fetch of orgA secret cred: want ErrNotFound, got %v", err)
	}
}

// TestSecretListIncludesSecretKind — ListCredentials returns secret entries in
// metadata (never secret material).
func TestSecretListIncludesSecretKind(t *testing.T) {
	svc := newTestService(t)
	ctx := authCtx("orgA", "shadow")
	if _, err := svc.SetSecretCredential(ctx, "secret", "anthropic-key", SecretBundle{Value: "v"}); err != nil {
		t.Fatalf("SetSecretCredential: %v", err)
	}
	if _, err := svc.SetCredential(ctx, "git", "github.com",
		GitBundle{Username: "u", Password: "p", Host: "github.com"}); err != nil {
		t.Fatalf("SetCredential git: %v", err)
	}
	metas, err := svc.ListCredentials(ctx, "")
	if err != nil {
		t.Fatal(err)
	}
	if len(metas) != 2 {
		t.Fatalf("want 2 metas, got %d", len(metas))
	}
	kinds := make(map[string]bool)
	for _, m := range metas {
		kinds[m.Kind] = true
	}
	if !kinds["secret"] || !kinds["git"] {
		t.Fatalf("expected both git and secret kinds, got %v", kinds)
	}
}

// =============================================================================
// gRPC handler tests for secret + DeleteCredential
// =============================================================================

// TestGRPCSecretSetFetch — gRPC Fetch returns the secret bundle for kind=secret.
func TestGRPCSecretSetFetch(t *testing.T) {
	svc := newTestService(t)
	srv := NewCredentialServer(svc, authz.Config{Mode: "metadata"})

	setReq := &cwbv1.SetCredentialRequest{
		Kind: "secret",
		Name: "anthropic-key",
		Bundle: &cwbv1.SetCredentialRequest_SecretBundle{SecretBundle: &cwbv1.SecretBundle{
			Value:    "sk-abc123",
			Host:     "api.anthropic.com",
			Username: "x-api-key",
		}},
	}
	if _, err := srv.SetCredential(mdCtx("orgA", "shadow", "cred:write"), setReq); err != nil {
		t.Fatalf("SetCredential secret: %v", err)
	}

	resp, err := srv.Fetch(mdCtx("orgA", "shadow", "cred:read"), &cwbv1.FetchRequest{
		Kind: "secret",
		Name: "anthropic-key",
	})
	if err != nil {
		t.Fatalf("Fetch secret: %v", err)
	}
	sb := resp.GetSecretBundle()
	if sb == nil {
		t.Fatalf("expected secret_bundle in response, got nil (bundle=%T)", resp.Bundle)
	}
	if sb.GetValue() != "sk-abc123" {
		t.Fatalf("value mismatch: got %q", sb.GetValue())
	}
	if sb.GetHost() != "api.anthropic.com" || sb.GetUsername() != "x-api-key" {
		t.Fatalf("hint mismatch: %+v", sb)
	}
}

// TestGRPCSecretMissingBundle — SetCredential with kind=secret but no
// secret_bundle → InvalidArgument.
func TestGRPCSecretMissingBundle(t *testing.T) {
	srv := NewCredentialServer(newTestService(t), authz.Config{Mode: "metadata"})
	req := &cwbv1.SetCredentialRequest{Kind: "secret", Name: "svc"}
	if _, err := srv.SetCredential(mdCtx("orgA", "shadow", "cred:write"), req); codeOf(err) != codes.InvalidArgument {
		t.Fatalf("Set secret with no bundle: want InvalidArgument, got %v", err)
	}
}

// TestGRPCSecretKindGitBundleMismatch — kind=secret with a git_bundle arm
// (instead of secret_bundle) is rejected as InvalidArgument, not silently
// accepted or misrouted.
func TestGRPCSecretKindGitBundleMismatch(t *testing.T) {
	srv := NewCredentialServer(newTestService(t), authz.Config{Mode: "metadata"})
	req := &cwbv1.SetCredentialRequest{
		Kind: "secret", Name: "svc",
		Bundle: &cwbv1.SetCredentialRequest_GitBundle{GitBundle: &cwbv1.GitBundle{
			Username: "u", Password: "p", Host: "example.com",
		}},
	}
	if _, err := srv.SetCredential(mdCtx("orgA", "shadow", "cred:write"), req); codeOf(err) != codes.InvalidArgument {
		t.Fatalf("Set secret with git_bundle arm: want InvalidArgument, got %v", err)
	}
}

// TestGRPCGitKindSecretBundleMismatch — the reverse: kind=git with a
// secret_bundle arm (instead of git_bundle) is rejected as InvalidArgument.
// Symmetric to TestGRPCSecretKindGitBundleMismatch.
func TestGRPCGitKindSecretBundleMismatch(t *testing.T) {
	srv := NewCredentialServer(newTestService(t), authz.Config{Mode: "metadata"})
	req := &cwbv1.SetCredentialRequest{
		Kind: "git", Name: "github.com",
		Bundle: &cwbv1.SetCredentialRequest_SecretBundle{SecretBundle: &cwbv1.SecretBundle{
			Value: "v",
		}},
	}
	if _, err := srv.SetCredential(mdCtx("orgA", "shadow", "cred:write"), req); codeOf(err) != codes.InvalidArgument {
		t.Fatalf("Set git with secret_bundle arm: want InvalidArgument, got %v", err)
	}
}

// TestGRPCSecretValidationPropagated — validation failures surface as InvalidArgument.
func TestGRPCSecretValidationPropagated(t *testing.T) {
	srv := NewCredentialServer(newTestService(t), authz.Config{Mode: "metadata"})
	req := &cwbv1.SetCredentialRequest{
		Kind: "secret", Name: "svc",
		Bundle: &cwbv1.SetCredentialRequest_SecretBundle{SecretBundle: &cwbv1.SecretBundle{
			// value missing
			Host: "example.com",
		}},
	}
	if _, err := srv.SetCredential(mdCtx("orgA", "shadow", "cred:write"), req); codeOf(err) != codes.InvalidArgument {
		t.Fatalf("Set secret missing value: want InvalidArgument, got %v", err)
	}
}

// TestDeleteCredentialExisting — deleting an existing credential returns
// deleted=true and a subsequent Fetch is NotFound. Also verifies the audit
// row: action="delete", reason="" (hit).
func TestDeleteCredentialExisting(t *testing.T) {
	svc := newTestService(t)
	srv := NewCredentialServer(svc, authz.Config{Mode: "metadata"})

	setReq := &cwbv1.SetCredentialRequest{
		Kind: "secret", Name: "svc",
		Bundle: &cwbv1.SetCredentialRequest_SecretBundle{SecretBundle: &cwbv1.SecretBundle{Value: "v"}},
	}
	if _, err := srv.SetCredential(mdCtx("orgA", "shadow", "cred:write"), setReq); err != nil {
		t.Fatalf("SetCredential: %v", err)
	}

	resp, err := srv.DeleteCredential(mdCtx("orgA", "shadow", "cred:write"), &cwbv1.DeleteCredentialRequest{
		Kind: "secret", Name: "svc",
	})
	if err != nil {
		t.Fatalf("DeleteCredential: %v", err)
	}
	if !resp.GetDeleted() {
		t.Fatal("want deleted=true for existing row")
	}

	if _, err := srv.Fetch(mdCtx("orgA", "shadow", "cred:read"), &cwbv1.FetchRequest{Kind: "secret", Name: "svc"}); codeOf(err) != codes.NotFound {
		t.Fatalf("Fetch after delete: want NotFound, got %v", err)
	}
	if n := auditCount(t, svc, "orgA", "delete"); n != 1 {
		t.Fatalf("want 1 delete audit row, got %d", n)
	}
	if got := auditReason(t, svc, "orgA", "delete"); got != "" {
		t.Fatalf("hit delete: want reason=\"\", got %q", got)
	}
}

// TestDeleteCredentialMissing — deleting a missing row returns deleted=false,
// no error, and the audit row is distinguishable from a hit: action="delete",
// reason="not-found" (mirrors the Fetch-miss convention).
func TestDeleteCredentialMissing(t *testing.T) {
	svc := newTestService(t)
	srv := NewCredentialServer(svc, authz.Config{Mode: "metadata"})

	resp, err := srv.DeleteCredential(mdCtx("orgA", "shadow", "cred:write"), &cwbv1.DeleteCredentialRequest{
		Kind: "secret", Name: "nope",
	})
	if err != nil {
		t.Fatalf("DeleteCredential missing row: want no error, got %v", err)
	}
	if resp.GetDeleted() {
		t.Fatal("want deleted=false for missing row")
	}
	if n := auditCount(t, svc, "orgA", "delete"); n != 1 {
		t.Fatalf("want 1 delete audit row, got %d", n)
	}
	if got := auditReason(t, svc, "orgA", "delete"); got != "not-found" {
		t.Fatalf("miss delete: want reason=\"not-found\", got %q", got)
	}
}

// TestDeleteCredentialRequiresWriteScope — DeleteCredential without
// cred:write is denied.
func TestDeleteCredentialRequiresWriteScope(t *testing.T) {
	svc := newTestService(t)
	srv := NewCredentialServer(svc, authz.Config{Mode: "metadata"})

	if _, err := srv.DeleteCredential(mdCtx("orgA", "shadow", "cred:read"), &cwbv1.DeleteCredentialRequest{
		Kind: "secret", Name: "svc",
	}); codeOf(err) != codes.PermissionDenied {
		t.Fatalf("Delete without cred:write: want PermissionDenied, got %v", err)
	}
}

// TestDeleteCredentialMissingIdentity — DeleteCredential without identity is
// Unauthenticated.
func TestDeleteCredentialMissingIdentity(t *testing.T) {
	srv := NewCredentialServer(newTestService(t), authz.Config{Mode: "metadata"})
	if _, err := srv.DeleteCredential(context.Background(), &cwbv1.DeleteCredentialRequest{
		Kind: "secret", Name: "svc",
	}); codeOf(err) != codes.Unauthenticated {
		t.Fatalf("Delete w/o identity: want Unauthenticated, got %v", err)
	}
}
