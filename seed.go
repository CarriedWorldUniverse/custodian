package custodian

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"log"
	"os"
)

// SeedSource resolves an org's base seed — the root from which the per-org DEK
// is derived (see crypto.go). The seed is sensitive key material; a SeedSource
// implementation is responsible for its custody.
//
// M1 ships two implementations:
//
//   - EnvSeedSource — a single configured seed from CUSTODIAN_ORG_SEED, for the
//     single-org dev/deploy case.
//   - DBSeedSource  — per-org seeds persisted in the org_seeds table, seeded
//     via an admin/bootstrap path.
//
// The "correct" path is herald-backed: derive the per-org key off the herald
// org base seed (the same single escrowed-root derivation tree the security
// design §3 mandates). That is the documented TODO — wired when the herald RPC
// is available. The SeedSource interface is the seam it will slot into without
// touching the crypto or handlers.
type SeedSource interface {
	// OrgSeed returns the base seed for org. It must return a non-empty seed
	// or an error; callers never proceed with an empty seed.
	OrgSeed(ctx context.Context, org string) ([]byte, error)
}

// EnvSeedSource serves a single seed (from CUSTODIAN_ORG_SEED, base64) for
// every org. Suitable for the single-org dev/deploy case only. Production must
// set CUSTODIAN_ORG_SEED (and should prefer DBSeedSource or the herald path).
type EnvSeedSource struct {
	seed []byte
}

// NewEnvSeedSource reads CUSTODIAN_ORG_SEED (base64) and builds a fail-closed
// env seed source.
//
// Behaviour (the FAIL-CLOSED seed discipline — security design §2/§8):
//
//   - A valid, non-empty seed → use it.
//   - No / empty / invalid seed, WITHOUT the explicit dev opt-in
//     (CUSTODIAN_DEV_INSECURE=1, the same gate cmd/custodian uses for mTLS) →
//     ERROR. A production boot never derives DEKs from a default; an absent or
//     malformed seed is fatal, never a usable key. Custodian holds irreplaceable
//     customer credentials — it must never seal under a guessable key.
//   - No / empty seed WITH CUSTODIAN_DEV_INSECURE=1 → a freshly-generated random
//     ephemeral dev seed, logged loudly. The seed lives only for this process,
//     so credentials sealed under it are not portable — exactly the property we
//     want for a clearly-non-production run.
func NewEnvSeedSource() (*EnvSeedSource, error) {
	if v := os.Getenv("CUSTODIAN_ORG_SEED"); v != "" {
		b, err := base64.StdEncoding.DecodeString(v)
		if err != nil {
			if devInsecure() {
				return newEphemeralDevSeed()
			}
			return nil, fmt.Errorf("custodian: CUSTODIAN_ORG_SEED is not valid base64: %w (set a valid seed, or CUSTODIAN_DEV_INSECURE=1 for local dev)", err)
		}
		if len(b) == 0 {
			if devInsecure() {
				return newEphemeralDevSeed()
			}
			return nil, fmt.Errorf("custodian: CUSTODIAN_ORG_SEED decodes to an empty seed (set a valid seed, or CUSTODIAN_DEV_INSECURE=1 for local dev)")
		}
		return &EnvSeedSource{seed: b}, nil
	}

	// No seed configured.
	if devInsecure() {
		return newEphemeralDevSeed()
	}
	return nil, fmt.Errorf("custodian: CUSTODIAN_ORG_SEED is required (set it, or CUSTODIAN_DEV_INSECURE=1 for local dev)")
}

// devInsecure reports whether the explicit local-dev opt-in is set. It mirrors
// the gate cmd/custodian/main.go uses to allow running without mTLS.
func devInsecure() bool { return os.Getenv("CUSTODIAN_DEV_INSECURE") == "1" }

// newEphemeralDevSeed mints a random, process-lifetime-only dev seed and logs
// loudly. Only reachable under CUSTODIAN_DEV_INSECURE=1.
func newEphemeralDevSeed() (*EnvSeedSource, error) {
	seed := make([]byte, 32)
	if _, err := rand.Read(seed); err != nil {
		return nil, fmt.Errorf("custodian: generate ephemeral dev seed: %w", err)
	}
	log.Printf("custodian: CUSTODIAN_DEV_INSECURE=1 and no CUSTODIAN_ORG_SEED — using a RANDOM EPHEMERAL dev seed (credentials are NOT recoverable across restarts; dev only)")
	return &EnvSeedSource{seed: seed}, nil
}

// OrgSeed returns the configured seed for any org.
func (e *EnvSeedSource) OrgSeed(_ context.Context, _ string) ([]byte, error) {
	if len(e.seed) == 0 {
		return nil, fmt.Errorf("custodian: env seed is empty")
	}
	return e.seed, nil
}

// DBSeedSource resolves per-org seeds from the org_seeds table. Seeds are
// provisioned via Service.SetOrgSeed (an admin/bootstrap path).
type DBSeedSource struct {
	svc *Service
}

// NewDBSeedSource builds a SeedSource backed by svc's org_seeds table.
func NewDBSeedSource(svc *Service) *DBSeedSource {
	return &DBSeedSource{svc: svc}
}

// OrgSeed loads the seed for org from org_seeds.
func (d *DBSeedSource) OrgSeed(ctx context.Context, org string) ([]byte, error) {
	var b64 string
	err := d.svc.db.QueryRowContext(ctx,
		`SELECT seed_b64 FROM org_seeds WHERE org = ?`, org).Scan(&b64)
	if err != nil {
		return nil, fmt.Errorf("custodian: no seed for org %q: %w", org, err)
	}
	seed, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		return nil, fmt.Errorf("custodian: decode seed for org %q: %w", org, err)
	}
	if len(seed) == 0 {
		return nil, fmt.Errorf("custodian: empty seed for org %q", org)
	}
	return seed, nil
}

// SetOrgSeed provisions (or replaces) the base seed for org. This is the
// admin/bootstrap on-ramp for DBSeedSource; in production the herald-backed
// derive path supersedes it.
func (s *Service) SetOrgSeed(ctx context.Context, org string, seed []byte) error {
	if org == "" {
		return fmt.Errorf("custodian: SetOrgSeed: org required")
	}
	if len(seed) == 0 {
		return fmt.Errorf("custodian: SetOrgSeed: seed required")
	}
	now := nowRFC3339()
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO org_seeds (org, seed_b64, created_at) VALUES (?, ?, ?)
		 ON CONFLICT(org) DO UPDATE SET seed_b64 = excluded.seed_b64`,
		org, base64.StdEncoding.EncodeToString(seed), now)
	if err != nil {
		return fmt.Errorf("custodian: SetOrgSeed: %w", err)
	}
	return nil
}
