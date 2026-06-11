package custodian

import (
	"bytes"
	"testing"
)

func testSeed(t *testing.T) []byte {
	t.Helper()
	s := make([]byte, 32)
	for i := range s {
		s[i] = byte(i + 1)
	}
	return s
}

// TestSealOpenRoundTrip — a credential sealed for (org, kind, name) opens back
// to the same plaintext under the same coordinates.
func TestSealOpenRoundTrip(t *testing.T) {
	seed := testSeed(t)
	pt := []byte(`{"username":"nexus-cw","password":"ghp_secret","host":"github.com"}`)

	env, _, err := sealCredential(seed, "orgA", "git", "github.com", pt)
	if err != nil {
		t.Fatalf("seal: %v", err)
	}
	if bytes.Contains(env, []byte("ghp_secret")) {
		t.Fatal("sealed envelope must not contain plaintext password")
	}
	got, err := openCredential(seed, "orgA", "git", "github.com", env)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if !bytes.Equal(got, pt) {
		t.Fatalf("round-trip mismatch: got %q want %q", got, pt)
	}
}

// TestOpenWrongOrgFails — the per-org DEK + org AAD mean another org cannot
// open the envelope (crypto-enforced isolation, security design §4).
func TestOpenWrongOrgFails(t *testing.T) {
	seed := testSeed(t)
	env, _, err := sealCredential(seed, "orgA", "git", "github.com", []byte("secret"))
	if err != nil {
		t.Fatalf("seal: %v", err)
	}
	if _, err := openCredential(seed, "orgB", "git", "github.com", env); err == nil {
		t.Fatal("expected open under wrong org to FAIL")
	}
}

// TestOpenWrongPathFails — entry-swap protection: a credential sealed at one
// (kind,name) does not open at another.
func TestOpenWrongPathFails(t *testing.T) {
	seed := testSeed(t)
	env, _, err := sealCredential(seed, "orgA", "git", "github.com", []byte("secret"))
	if err != nil {
		t.Fatalf("seal: %v", err)
	}
	if _, err := openCredential(seed, "orgA", "git", "gitlab.com", env); err == nil {
		t.Fatal("expected open under wrong name to FAIL")
	}
}

// TestPerOrgDEKDistinct — different orgs derive different DEKs.
func TestPerOrgDEKDistinct(t *testing.T) {
	seed := testSeed(t)
	a, err := deriveOrgDEK(seed, "orgA")
	if err != nil {
		t.Fatal(err)
	}
	b, err := deriveOrgDEK(seed, "orgB")
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(a, b) {
		t.Fatal("per-org DEKs must differ across orgs")
	}
}

// TestDeriveOrgDEKEmptyInputs — empty seed/org are rejected.
func TestDeriveOrgDEKEmptyInputs(t *testing.T) {
	if _, err := deriveOrgDEK(nil, "orgA"); err == nil {
		t.Fatal("empty seed must error")
	}
	if _, err := deriveOrgDEK(testSeed(t), ""); err == nil {
		t.Fatal("empty org must error")
	}
}
