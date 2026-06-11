package custodian

import (
	"context"
	"errors"
	"path/filepath"
	"strings"
	"testing"
)

// newTestService builds a Service on a temp DB with a fixed (non-ephemeral)
// seed so sealed values are stable across the test.
func newTestService(t *testing.T) *Service {
	t.Helper()
	dir := t.TempDir()
	svc, err := New(context.Background(), Config{
		DBPath:     filepath.Join(dir, "custodian.db"),
		SeedSource: &EnvSeedSource{seed: testSeed(t)},
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(func() { _ = svc.Close() })
	return svc
}

func authCtx(org, sub string) context.Context {
	return ContextWithAuth(context.Background(), &AuthClaims{Org: org, Sub: sub})
}

// TestSetFetchRoundTrip — Set then Fetch returns the same git bundle.
func TestSetFetchRoundTrip(t *testing.T) {
	svc := newTestService(t)
	ctx := authCtx("orgA", "shadow")

	in := GitBundle{Username: "nexus-cw", Password: "ghp_secret", Host: "github.com"}
	if _, err := svc.SetCredential(ctx, "git", "github.com", in); err != nil {
		t.Fatalf("SetCredential: %v", err)
	}
	got, meta, err := svc.Fetch(ctx, "git", "github.com")
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	if got != in {
		t.Fatalf("bundle mismatch: got %+v want %+v", got, in)
	}
	if meta.Kind != "git" || meta.Name != "github.com" || meta.Writer != "shadow" {
		t.Fatalf("meta mismatch: %+v", meta)
	}
}

// TestAtRestSealedNotPlaintext — the stored sealed_bundle_b64 must NOT contain
// the plaintext password (ciphertext-only at rest).
func TestAtRestSealedNotPlaintext(t *testing.T) {
	svc := newTestService(t)
	ctx := authCtx("orgA", "shadow")
	if _, err := svc.SetCredential(ctx, "git", "github.com",
		GitBundle{Username: "nexus-cw", Password: "ghp_PLAINTEXT", Host: "github.com"}); err != nil {
		t.Fatalf("SetCredential: %v", err)
	}
	var sealedB64 string
	if err := svc.db.QueryRowContext(ctx,
		`SELECT sealed_bundle_b64 FROM credentials WHERE org='orgA' AND kind='git' AND name='github.com'`).
		Scan(&sealedB64); err != nil {
		t.Fatalf("read sealed: %v", err)
	}
	if strings.Contains(sealedB64, "ghp_PLAINTEXT") || strings.Contains(sealedB64, "nexus-cw") {
		t.Fatal("at-rest sealed value must not contain plaintext secret/username")
	}
}

// TestOrgIsolation — orgB cannot Fetch orgA's credential (org-scoped query +
// crypto). orgB sees a not-found.
func TestOrgIsolation(t *testing.T) {
	svc := newTestService(t)
	if _, err := svc.SetCredential(authCtx("orgA", "shadow"), "git", "github.com",
		GitBundle{Username: "a", Password: "secretA", Host: "github.com"}); err != nil {
		t.Fatalf("SetCredential orgA: %v", err)
	}
	if _, _, err := svc.Fetch(authCtx("orgB", "intruder"), "git", "github.com"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("orgB fetch of orgA cred: want ErrNotFound, got %v", err)
	}
}

// TestSetUpdatePreservesCreatedAt — re-Set updates the bundle but keeps
// created_at.
func TestSetUpdatePreservesCreatedAt(t *testing.T) {
	svc := newTestService(t)
	ctx := authCtx("orgA", "shadow")
	m1, err := svc.SetCredential(ctx, "git", "github.com", GitBundle{Username: "u", Password: "p1", Host: "github.com"})
	if err != nil {
		t.Fatal(err)
	}
	m2, err := svc.SetCredential(ctx, "git", "github.com", GitBundle{Username: "u", Password: "p2", Host: "github.com"})
	if err != nil {
		t.Fatal(err)
	}
	if m1.CreatedAt != m2.CreatedAt {
		t.Fatalf("created_at should be preserved on update: %q vs %q", m1.CreatedAt, m2.CreatedAt)
	}
	got, _, err := svc.Fetch(ctx, "git", "github.com")
	if err != nil {
		t.Fatal(err)
	}
	if got.Password != "p2" {
		t.Fatalf("update did not take: got password %q", got.Password)
	}
}

// TestFetchNotFoundAudited — a missing credential fetch writes a denied audit
// row (attempted access is visible).
func TestFetchNotFoundAudited(t *testing.T) {
	svc := newTestService(t)
	ctx := authCtx("orgA", "shadow")
	if _, _, err := svc.Fetch(ctx, "git", "nope.com"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("want ErrNotFound, got %v", err)
	}
	if n := auditCount(t, svc, "orgA", "denied"); n != 1 {
		t.Fatalf("want 1 denied audit row, got %d", n)
	}
}

// TestFetchAndSetAudited — successful set + fetch each write an audit row.
func TestFetchAndSetAudited(t *testing.T) {
	svc := newTestService(t)
	ctx := authCtx("orgA", "shadow")
	if _, err := svc.SetCredential(ctx, "git", "github.com",
		GitBundle{Username: "u", Password: "p", Host: "github.com"}); err != nil {
		t.Fatal(err)
	}
	if _, _, err := svc.Fetch(ctx, "git", "github.com"); err != nil {
		t.Fatal(err)
	}
	if n := auditCount(t, svc, "orgA", "set"); n != 1 {
		t.Fatalf("want 1 set audit row, got %d", n)
	}
	if n := auditCount(t, svc, "orgA", "fetch"); n != 1 {
		t.Fatalf("want 1 fetch audit row, got %d", n)
	}
}

// TestUnsupportedKind — M1 rejects non-git kinds.
func TestUnsupportedKind(t *testing.T) {
	svc := newTestService(t)
	ctx := authCtx("orgA", "shadow")
	if _, err := svc.SetCredential(ctx, "provider", "anthropic",
		GitBundle{}); !errors.Is(err, ErrKindUnsup) {
		t.Fatalf("want ErrKindUnsup, got %v", err)
	}
}

// TestListMetadataOnly — List returns metadata, never password material.
func TestListMetadataOnly(t *testing.T) {
	svc := newTestService(t)
	ctx := authCtx("orgA", "shadow")
	if _, err := svc.SetCredential(ctx, "git", "github.com",
		GitBundle{Username: "u", Password: "p", Host: "github.com"}); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.SetCredential(ctx, "git", "gitlab.com",
		GitBundle{Username: "u2", Password: "p2", Host: "gitlab.com"}); err != nil {
		t.Fatal(err)
	}
	metas, err := svc.ListCredentials(ctx, "")
	if err != nil {
		t.Fatal(err)
	}
	if len(metas) != 2 {
		t.Fatalf("want 2 metas, got %d", len(metas))
	}
	// CredentialMeta has no password field — structurally metadata-only. Verify
	// org isolation on List too.
	if other, err := svc.ListCredentials(authCtx("orgB", "x"), ""); err != nil || len(other) != 0 {
		t.Fatalf("orgB list should be empty: %d %v", len(other), err)
	}
}

func auditCount(t *testing.T, svc *Service, org, action string) int {
	t.Helper()
	var n int
	if err := svc.db.QueryRow(
		`SELECT COUNT(*) FROM credential_audit WHERE org = ? AND action = ?`, org, action).Scan(&n); err != nil {
		t.Fatalf("audit count: %v", err)
	}
	return n
}
