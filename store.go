package custodian

import (
	"context"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
)

// Error sentinels mapped to gRPC codes by toStatus (grpcserver.go).
var (
	ErrNotFound  = errors.New("custodian: not found")
	ErrInvalid   = errors.New("custodian: invalid argument")
	ErrNoSeed    = errors.New("custodian: org seed unavailable")
	ErrKindUnsup = errors.New("custodian: unsupported kind")
)

// KindGit is the only credential kind M1 supports. name is the git host.
const KindGit = "git"

// GitBundle is a git push/fetch credential. password is a PAT or token and is
// never returned by List/metadata paths or logged — only by Fetch over mTLS.
type GitBundle struct {
	Username string `json:"username"`
	Password string `json:"password"`
	Host     string `json:"host"`
}

// CredentialMeta describes a stored credential without its secret material.
type CredentialMeta struct {
	Kind      string
	Name      string
	CreatedAt string
	UpdatedAt string
	Writer    string
}

// writeTxOpts forces read-modify-write transactions to begin as IMMEDIATE
// (write-locking) transactions — mirrors almanac's serialization discipline so
// concurrent writers serialize on the write lock instead of failing on upgrade.
var writeTxOpts = &sql.TxOptions{Isolation: sql.LevelSerializable}

func nowRFC3339() string { return time.Now().UTC().Format(time.RFC3339) }

// normalize trims and validates a kind/name pair. Empty values are rejected,
// and M1 only accepts kind="git".
func normalize(kind, name string) (string, string, error) {
	k := strings.TrimSpace(kind)
	n := strings.TrimSpace(name)
	if k == "" || n == "" {
		return "", "", fmt.Errorf("%w: kind and name are required", ErrInvalid)
	}
	if k != KindGit {
		return "", "", fmt.Errorf("%w: %q (M1 supports only %q)", ErrKindUnsup, k, KindGit)
	}
	return k, n, nil
}

// SetCredential seals a git bundle and stores it for (org, kind, name). Org
// comes from the auth context — never a request field. Every set is audited.
func (s *Service) SetCredential(ctx context.Context, kind, name string, bundle GitBundle) (*CredentialMeta, error) {
	claims := AuthFromContext(ctx)
	if claims == nil {
		return nil, fmt.Errorf("custodian: SetCredential: no auth in context")
	}
	k, n, err := normalize(kind, name)
	if err != nil {
		return nil, err
	}

	plaintext, err := json.Marshal(bundle)
	if err != nil {
		return nil, fmt.Errorf("custodian: SetCredential: marshal bundle: %w", err)
	}

	seed, err := s.seeds.OrgSeed(ctx, claims.Org)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrNoSeed, err)
	}
	env, keyRef, err := sealCredential(seed, claims.Org, k, n, plaintext)
	if err != nil {
		return nil, err
	}
	now := nowRFC3339()
	sealedB64 := base64.StdEncoding.EncodeToString(env)
	keyRefB64 := base64.StdEncoding.EncodeToString(keyRef[:])

	tx, err := s.db.BeginTx(ctx, writeTxOpts)
	if err != nil {
		return nil, err
	}
	defer func() { _ = tx.Rollback() }()

	var createdAt string
	err = tx.QueryRowContext(ctx,
		`SELECT created_at FROM credentials WHERE org = ? AND kind = ? AND name = ?`,
		claims.Org, k, n).Scan(&createdAt)
	switch {
	case err == sql.ErrNoRows:
		createdAt = now
		if _, err := tx.ExecContext(ctx,
			`INSERT INTO credentials (org, kind, name, sealed_bundle_b64, keyref_b64, created_at, updated_at, writer)
			 VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
			claims.Org, k, n, sealedB64, keyRefB64, createdAt, now, claims.Sub); err != nil {
			return nil, err
		}
	case err != nil:
		return nil, err
	default:
		if _, err := tx.ExecContext(ctx,
			`UPDATE credentials SET sealed_bundle_b64 = ?, keyref_b64 = ?, updated_at = ?, writer = ?
			 WHERE org = ? AND kind = ? AND name = ?`,
			sealedB64, keyRefB64, now, claims.Sub, claims.Org, k, n); err != nil {
			return nil, err
		}
	}
	s.auditTx(ctx, tx, claims, k, n, "set", "")
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return &CredentialMeta{
		Kind: k, Name: n, CreatedAt: createdAt, UpdatedAt: now, Writer: claims.Sub,
	}, nil
}

// Fetch loads, decrypts, and returns the git bundle for (org, kind, name).
// Every fetch is audited (the caller is expected to audit denials separately —
// see grpcserver.go's scope gate). Org comes from the auth context.
func (s *Service) Fetch(ctx context.Context, kind, name string) (GitBundle, *CredentialMeta, error) {
	claims := AuthFromContext(ctx)
	if claims == nil {
		return GitBundle{}, nil, fmt.Errorf("custodian: Fetch: no auth in context")
	}
	k, n, err := normalize(kind, name)
	if err != nil {
		return GitBundle{}, nil, err
	}

	var sealedB64 string
	meta := &CredentialMeta{Kind: k, Name: n}
	err = s.db.QueryRowContext(ctx,
		`SELECT sealed_bundle_b64, created_at, updated_at, writer FROM credentials
		 WHERE org = ? AND kind = ? AND name = ?`, claims.Org, k, n).
		Scan(&sealedB64, &meta.CreatedAt, &meta.UpdatedAt, &meta.Writer)
	if err == sql.ErrNoRows {
		// Audit the denied/miss so the audit feed shows attempted access.
		s.audit(ctx, claims, k, n, "denied", "not-found")
		return GitBundle{}, nil, ErrNotFound
	}
	if err != nil {
		return GitBundle{}, nil, err
	}
	sealedBytes, err := base64.StdEncoding.DecodeString(sealedB64)
	if err != nil {
		return GitBundle{}, nil, fmt.Errorf("custodian: Fetch: decode envelope: %w", err)
	}
	seed, err := s.seeds.OrgSeed(ctx, claims.Org)
	if err != nil {
		return GitBundle{}, nil, fmt.Errorf("%w: %v", ErrNoSeed, err)
	}
	plaintext, err := openCredential(seed, claims.Org, k, n, sealedBytes)
	if err != nil {
		return GitBundle{}, nil, err
	}
	var gb GitBundle
	if err := json.Unmarshal(plaintext, &gb); err != nil {
		return GitBundle{}, nil, fmt.Errorf("custodian: Fetch: unmarshal bundle: %w", err)
	}
	s.audit(ctx, claims, k, n, "fetch", "")
	return gb, meta, nil
}

// ListCredentials returns metadata (never secret material) for the caller's
// org, optionally narrowed to a single kind.
func (s *Service) ListCredentials(ctx context.Context, kind string) ([]CredentialMeta, error) {
	claims := AuthFromContext(ctx)
	if claims == nil {
		return nil, fmt.Errorf("custodian: ListCredentials: no auth in context")
	}
	var (
		rows *sql.Rows
		err  error
	)
	if strings.TrimSpace(kind) == "" {
		rows, err = s.db.QueryContext(ctx,
			`SELECT kind, name, created_at, updated_at, writer FROM credentials
			 WHERE org = ? ORDER BY kind, name`, claims.Org)
	} else {
		rows, err = s.db.QueryContext(ctx,
			`SELECT kind, name, created_at, updated_at, writer FROM credentials
			 WHERE org = ? AND kind = ? ORDER BY name`, claims.Org, strings.TrimSpace(kind))
	}
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []CredentialMeta
	for rows.Next() {
		var m CredentialMeta
		if err := rows.Scan(&m.Kind, &m.Name, &m.CreatedAt, &m.UpdatedAt, &m.Writer); err != nil {
			return nil, err
		}
		out = append(out, m)
	}
	return out, rows.Err()
}

// --- audit ---

// audit writes a credential_audit row. Best-effort — a failure must not block
// the legitimate operation.
func (s *Service) audit(ctx context.Context, c *AuthClaims, kind, name, action, reason string) {
	_, _ = s.db.ExecContext(ctx,
		`INSERT INTO credential_audit (org, identity, kind, name, action, reason, at)
		 VALUES (?, ?, ?, ?, ?, ?, ?)`,
		c.Org, c.Sub, kind, name, action, reason, nowRFC3339())
}

func (s *Service) auditTx(ctx context.Context, tx *sql.Tx, c *AuthClaims, kind, name, action, reason string) {
	_, _ = tx.ExecContext(ctx,
		`INSERT INTO credential_audit (org, identity, kind, name, action, reason, at)
		 VALUES (?, ?, ?, ?, ?, ?, ?)`,
		c.Org, c.Sub, kind, name, action, reason, nowRFC3339())
}

// AuditDenied writes a denied-action audit row. Exposed so the gRPC handler can
// record scope/identity denials before the request ever reaches the store.
func (s *Service) AuditDenied(ctx context.Context, c *AuthClaims, kind, name, reason string) {
	if c == nil {
		return
	}
	s.audit(ctx, c, kind, name, "denied", reason)
}
