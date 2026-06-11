-- custodian schema — the external-credential vault pillar (M1).
--
-- Org isolation is structural AND cryptographic: every table is keyed by
-- (org, ...) and every query filters WHERE org = ?, while the sealed bundle is
-- encrypted under the per-org DEK (crypto.go). There is no cross-org path.
--
-- The schema is applied idempotently on every boot (see schema.go), so all
-- CREATEs use IF NOT EXISTS and migrations are ALTER TABLE ADD COLUMN.

-- credentials — current sealed bundle for each (org, kind, name). The plaintext
-- is NEVER stored; sealed_bundle_b64 is the base64 casket envelope, keyref_b64
-- the base64 of the opaque 16-byte casket KeyRef. PRIMARY KEY(org, kind, name)
-- gives one live row per credential coordinate. For M1, kind='git' and name is
-- the git host (e.g. 'github.com').
CREATE TABLE IF NOT EXISTS credentials (
    org               TEXT NOT NULL,
    kind              TEXT NOT NULL,
    name              TEXT NOT NULL,
    sealed_bundle_b64 TEXT NOT NULL,
    keyref_b64        TEXT NOT NULL,
    created_at        TEXT NOT NULL,
    updated_at        TEXT NOT NULL,
    writer            TEXT NOT NULL DEFAULT '',
    PRIMARY KEY (org, kind, name)
);

CREATE INDEX IF NOT EXISTS idx_credentials_org ON credentials (org);

-- credential_audit — append-only audit of every brokered credential use. Each
-- Fetch (success AND denial) and every Set writes a row; the brokered-use audit
-- trail is custodian's whole point. action is one of: fetch | set | denied.
CREATE TABLE IF NOT EXISTS credential_audit (
    id       INTEGER PRIMARY KEY AUTOINCREMENT,
    org      TEXT NOT NULL,
    identity TEXT NOT NULL,
    kind     TEXT NOT NULL,
    name     TEXT NOT NULL,
    action   TEXT NOT NULL, -- fetch | set | denied
    reason   TEXT NOT NULL DEFAULT '',
    at       TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_credential_audit_org ON credential_audit (org, at);

-- org_seeds — per-org base seed used to derive the per-org DEK. For M1 this is
-- a configured seed (admin/bootstrap-provisioned or deploy-provided via
-- CUSTODIAN_ORG_SEED); the herald-backed derive path is the documented TODO
-- (see crypto.go / seed.go and the security design §3).
CREATE TABLE IF NOT EXISTS org_seeds (
    org        TEXT NOT NULL PRIMARY KEY,
    seed_b64   TEXT NOT NULL,
    created_at TEXT NOT NULL
);
