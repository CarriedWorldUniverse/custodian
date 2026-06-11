package custodian

import (
	"context"
	"encoding/base64"
	"testing"
)

// TestSeedFailClosed — without CUSTODIAN_ORG_SEED and without the dev opt-in,
// NewEnvSeedSource MUST error (custodian never boots with a default seed).
func TestSeedFailClosed(t *testing.T) {
	t.Setenv("CUSTODIAN_ORG_SEED", "")
	t.Setenv("CUSTODIAN_DEV_INSECURE", "")
	if _, err := NewEnvSeedSource(); err == nil {
		t.Fatal("missing seed without dev opt-in must FAIL closed")
	}
}

// TestSeedInvalidBase64FailClosed — a malformed seed is fatal, not a usable key.
func TestSeedInvalidBase64FailClosed(t *testing.T) {
	t.Setenv("CUSTODIAN_ORG_SEED", "!!!not-base64!!!")
	t.Setenv("CUSTODIAN_DEV_INSECURE", "")
	if _, err := NewEnvSeedSource(); err == nil {
		t.Fatal("invalid base64 seed without dev opt-in must FAIL closed")
	}
}

// TestSeedDevInsecureEphemeral — with the dev opt-in and no seed, an ephemeral
// seed is minted (dev only).
func TestSeedDevInsecureEphemeral(t *testing.T) {
	t.Setenv("CUSTODIAN_ORG_SEED", "")
	t.Setenv("CUSTODIAN_DEV_INSECURE", "1")
	s, err := NewEnvSeedSource()
	if err != nil {
		t.Fatalf("dev-insecure should mint ephemeral seed: %v", err)
	}
	seed, err := s.OrgSeed(context.Background(), "orgA")
	if err != nil || len(seed) == 0 {
		t.Fatalf("ephemeral seed unusable: %v", err)
	}
}

// TestSeedValid — a valid base64 seed is used as-is.
func TestSeedValid(t *testing.T) {
	want := testSeed(t)
	t.Setenv("CUSTODIAN_ORG_SEED", base64.StdEncoding.EncodeToString(want))
	t.Setenv("CUSTODIAN_DEV_INSECURE", "")
	s, err := NewEnvSeedSource()
	if err != nil {
		t.Fatalf("valid seed should load: %v", err)
	}
	got, err := s.OrgSeed(context.Background(), "any")
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(want) {
		t.Fatal("seed mismatch")
	}
}
