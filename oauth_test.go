package custodian

import (
	"errors"
	"strings"
	"testing"

	cwbv1 "github.com/CarriedWorldUniverse/cwb-proto/gen/go/cwb/v1"
	"google.golang.org/grpc/codes"
)

// TestOAuthSetFetchRoundTrip — Set then Fetch returns the same OAuthBundle.
func TestOAuthSetFetchRoundTrip(t *testing.T) {
	svc := newTestService(t)
	ctx := authCtx("orgA", "shadow")

	in := OAuthBundle{
		ClientID:     "client-123",
		ClientSecret: "secret-abc",
		RefreshToken: "refresh-xyz",
		TokenURI:     "https://oauth2.googleapis.com/token",
		Scope:        "openid email",
	}
	if _, err := svc.SetOAuthCredential(ctx, "oauth", "google-workspace", in); err != nil {
		t.Fatalf("SetOAuthCredential: %v", err)
	}
	got, meta, err := svc.FetchOAuth(ctx, "oauth", "google-workspace")
	if err != nil {
		t.Fatalf("FetchOAuth: %v", err)
	}
	if got != in {
		t.Fatalf("bundle mismatch: got %+v want %+v", got, in)
	}
	if meta.Kind != "oauth" || meta.Name != "google-workspace" || meta.Writer != "shadow" {
		t.Fatalf("meta mismatch: %+v", meta)
	}
}

// TestOAuthAtRestSealedNotPlaintext — refresh_token must not appear in the
// sealed_bundle_b64 stored in the DB (ciphertext-only at rest).
func TestOAuthAtRestSealedNotPlaintext(t *testing.T) {
	svc := newTestService(t)
	ctx := authCtx("orgA", "shadow")
	if _, err := svc.SetOAuthCredential(ctx, "oauth", "my-service",
		OAuthBundle{
			ClientID:     "client-id",
			ClientSecret: "SECRET_CLIENT",
			RefreshToken: "REFRESH_PLAINTEXT",
			TokenURI:     "https://example.com/token",
		}); err != nil {
		t.Fatalf("SetOAuthCredential: %v", err)
	}
	var sealedB64 string
	if err := svc.db.QueryRowContext(ctx,
		`SELECT sealed_bundle_b64 FROM credentials WHERE org='orgA' AND kind='oauth' AND name='my-service'`).
		Scan(&sealedB64); err != nil {
		t.Fatalf("read sealed: %v", err)
	}
	if strings.Contains(sealedB64, "REFRESH_PLAINTEXT") || strings.Contains(sealedB64, "SECRET_CLIENT") {
		t.Fatal("at-rest sealed value must not contain plaintext refresh_token or client_secret")
	}
}

// TestOAuthValidationMissingClientID — Set with missing client_id fails.
func TestOAuthValidationMissingClientID(t *testing.T) {
	svc := newTestService(t)
	ctx := authCtx("orgA", "shadow")
	_, err := svc.SetOAuthCredential(ctx, "oauth", "svc",
		OAuthBundle{ClientSecret: "s", RefreshToken: "r", TokenURI: "https://t.example.com/token"})
	if !errors.Is(err, ErrInvalid) {
		t.Fatalf("missing client_id: want ErrInvalid, got %v", err)
	}
}

// TestOAuthValidationMissingRefreshToken — Set with missing refresh_token fails.
func TestOAuthValidationMissingRefreshToken(t *testing.T) {
	svc := newTestService(t)
	ctx := authCtx("orgA", "shadow")
	_, err := svc.SetOAuthCredential(ctx, "oauth", "svc",
		OAuthBundle{ClientID: "c", ClientSecret: "s", TokenURI: "https://t.example.com/token"})
	if !errors.Is(err, ErrInvalid) {
		t.Fatalf("missing refresh_token: want ErrInvalid, got %v", err)
	}
}

// TestOAuthValidationMissingTokenURI — Set with missing token_uri fails.
func TestOAuthValidationMissingTokenURI(t *testing.T) {
	svc := newTestService(t)
	ctx := authCtx("orgA", "shadow")
	_, err := svc.SetOAuthCredential(ctx, "oauth", "svc",
		OAuthBundle{ClientID: "c", RefreshToken: "r"})
	if !errors.Is(err, ErrInvalid) {
		t.Fatalf("missing token_uri: want ErrInvalid, got %v", err)
	}
}

// TestOAuthOrgIsolation — orgB cannot fetch orgA's oauth credential.
func TestOAuthOrgIsolation(t *testing.T) {
	svc := newTestService(t)
	if _, err := svc.SetOAuthCredential(authCtx("orgA", "shadow"), "oauth", "svc",
		OAuthBundle{ClientID: "c", ClientSecret: "s", RefreshToken: "r", TokenURI: "https://t.example.com/token"}); err != nil {
		t.Fatalf("SetOAuthCredential orgA: %v", err)
	}
	if _, _, err := svc.FetchOAuth(authCtx("orgB", "intruder"), "oauth", "svc"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("orgB fetch of orgA oauth cred: want ErrNotFound, got %v", err)
	}
}

// TestGitUnaffectedByOAuth — existing git credentials are unaffected by the
// addition of kind=oauth.
func TestGitUnaffectedByOAuth(t *testing.T) {
	svc := newTestService(t)
	ctx := authCtx("orgA", "shadow")

	gitIn := GitBundle{Username: "nexus-cw", Password: "ghp_secret", Host: "github.com"}
	if _, err := svc.SetCredential(ctx, "git", "github.com", gitIn); err != nil {
		t.Fatalf("SetCredential git: %v", err)
	}
	got, meta, err := svc.Fetch(ctx, "git", "github.com")
	if err != nil {
		t.Fatalf("Fetch git: %v", err)
	}
	if got != gitIn {
		t.Fatalf("git bundle mismatch: got %+v want %+v", got, gitIn)
	}
	if meta.Kind != "git" {
		t.Fatalf("unexpected kind: %q", meta.Kind)
	}
}

// TestOAuthUnsupportedKindStillRejected — non-oauth/git kinds still rejected.
func TestOAuthUnsupportedKindStillRejected(t *testing.T) {
	svc := newTestService(t)
	ctx := authCtx("orgA", "shadow")
	if _, err := svc.SetCredential(ctx, "provider", "anthropic", GitBundle{}); !errors.Is(err, ErrKindUnsup) {
		t.Fatalf("want ErrKindUnsup, got %v", err)
	}
}

// TestOAuthListIncludesOAuthKind — ListCredentials returns oauth entries in
// metadata (never secret material).
func TestOAuthListIncludesOAuthKind(t *testing.T) {
	svc := newTestService(t)
	ctx := authCtx("orgA", "shadow")
	if _, err := svc.SetOAuthCredential(ctx, "oauth", "google",
		OAuthBundle{ClientID: "c", RefreshToken: "r", TokenURI: "https://t.example.com/token"}); err != nil {
		t.Fatalf("SetOAuthCredential: %v", err)
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
	if !kinds["oauth"] || !kinds["git"] {
		t.Fatalf("expected both git and oauth kinds, got %v", kinds)
	}
}

// =============================================================================
// gRPC handler tests for oauth
// =============================================================================

// TestGRPCOAuthSetFetch — gRPC Fetch returns the oauth bundle for kind=oauth.
func TestGRPCOAuthSetFetch(t *testing.T) {
	svc := newTestService(t)
	srv := NewCredentialServer(svc)

	setReq := &cwbv1.SetCredentialRequest{
		Kind: "oauth",
		Name: "google-workspace",
		Bundle: &cwbv1.SetCredentialRequest_OauthBundle{OauthBundle: &cwbv1.OAuthBundle{
			ClientId:     "client-123",
			ClientSecret: "secret-abc",
			RefreshToken: "refresh-xyz",
			TokenUri:     "https://oauth2.googleapis.com/token",
			Scope:        "openid email",
		}},
	}
	if _, err := srv.SetCredential(mdCtx("orgA", "shadow", "cred:write"), setReq); err != nil {
		t.Fatalf("SetCredential oauth: %v", err)
	}

	resp, err := srv.Fetch(mdCtx("orgA", "shadow", "cred:read"), &cwbv1.FetchRequest{
		Kind: "oauth",
		Name: "google-workspace",
	})
	if err != nil {
		t.Fatalf("Fetch oauth: %v", err)
	}
	ob := resp.GetOauthBundle()
	if ob == nil {
		t.Fatalf("expected oauth_bundle in response, got nil (bundle=%T)", resp.Bundle)
	}
	if ob.GetRefreshToken() != "refresh-xyz" {
		t.Fatalf("refresh_token mismatch: got %q", ob.GetRefreshToken())
	}
	if ob.GetClientId() != "client-123" {
		t.Fatalf("client_id mismatch: got %q", ob.GetClientId())
	}
}

// TestGRPCOAuthMissingBundle — SetCredential with kind=oauth but no oauth_bundle → InvalidArgument.
func TestGRPCOAuthMissingBundle(t *testing.T) {
	srv := NewCredentialServer(newTestService(t))
	req := &cwbv1.SetCredentialRequest{Kind: "oauth", Name: "svc"}
	if _, err := srv.SetCredential(mdCtx("orgA", "shadow", "cred:write"), req); codeOf(err) != codes.InvalidArgument {
		t.Fatalf("Set oauth with no bundle: want InvalidArgument, got %v", err)
	}
}

// TestGRPCOAuthValidationPropagated — validation failures surface as InvalidArgument.
func TestGRPCOAuthValidationPropagated(t *testing.T) {
	srv := NewCredentialServer(newTestService(t))
	req := &cwbv1.SetCredentialRequest{
		Kind: "oauth", Name: "svc",
		Bundle: &cwbv1.SetCredentialRequest_OauthBundle{OauthBundle: &cwbv1.OAuthBundle{
			// client_id missing
			RefreshToken: "r",
			TokenUri:     "https://t.example.com/token",
		}},
	}
	if _, err := srv.SetCredential(mdCtx("orgA", "shadow", "cred:write"), req); codeOf(err) != codes.InvalidArgument {
		t.Fatalf("Set oauth missing client_id: want InvalidArgument, got %v", err)
	}
}
