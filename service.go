// Package custodian is the external-credential vault pillar: it holds a
// consumer org's credentials (git tokens, API keys, DB connections, …) and
// brokers their *use* to that org's herald-verified identities without ever
// handing out raw secrets — the scoped-handle pattern herald uses for identity,
// applied to secrets.
//
// Credentials are casket-sealed at rest under a per-org DEK derived
// (HKDF, domain-separated) from the org base seed (crypto.go); plaintext exists
// only transiently in memory on a Fetch. Org isolation is enforced on every
// store call AND cryptographically by the per-org DEK — a caller only ever sees
// its own org's credentials, and an org's runtime never possesses another org's
// key.
//
// It runs behind interchange over mTLS; identity (org/subject/scopes) comes
// from the cwb-* gRPC metadata the gateway injects (see mdident.go).
package custodian

import (
	"context"
	"database/sql"
	"fmt"

	_ "github.com/ncruces/go-sqlite3/driver"
)

// Config carries the service's runtime configuration.
type Config struct {
	// DBPath is the on-disk location of custodian.db.
	DBPath string
	// SeedSource resolves an org's base seed (used to derive the per-org DEK).
	// When nil, New installs an EnvSeedSource backed by CUSTODIAN_ORG_SEED (the
	// single-org dev case) and fails closed if that seed is missing/invalid
	// without the CUSTODIAN_DEV_INSECURE=1 opt-in. See crypto.go / seed.go for
	// the herald-backed TODO.
	SeedSource SeedSource
}

// Service is the in-process credential vault.
type Service struct {
	cfg   Config
	db    *sql.DB
	seeds SeedSource
}

// New opens (or creates) custodian.db, applies the embedded schema, and returns
// a ready Service. schema.sql is idempotent, so applySchema runs on every call.
func New(ctx context.Context, cfg Config) (*Service, error) {
	if cfg.DBPath == "" {
		return nil, fmt.Errorf("custodian.New: DBPath required")
	}

	dsn := "file:" + cfg.DBPath + "?_journal_mode=WAL&_busy_timeout=5000&_foreign_keys=on"
	db, err := sql.Open("sqlite3", dsn)
	if err != nil {
		return nil, fmt.Errorf("custodian.New: open %s: %w", cfg.DBPath, err)
	}
	if err := db.PingContext(ctx); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("custodian.New: ping: %w", err)
	}
	if err := applySchema(ctx, db); err != nil {
		_ = db.Close()
		return nil, err
	}

	seeds := cfg.SeedSource
	if seeds == nil {
		// Fail-closed: with no explicit SeedSource, derive one from the
		// environment. A missing/invalid CUSTODIAN_ORG_SEED without the dev
		// opt-in is fatal here — custodian never boots with a default seed.
		envSeeds, err := NewEnvSeedSource()
		if err != nil {
			_ = db.Close()
			return nil, err
		}
		seeds = envSeeds
	}

	return &Service{
		cfg:   cfg,
		db:    db,
		seeds: seeds,
	}, nil
}

// Close releases the DB handle.
func (s *Service) Close() error {
	if s.db != nil {
		return s.db.Close()
	}
	return nil
}
