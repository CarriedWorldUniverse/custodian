# custodian

CWB external-credential vault — **Spec A Sub-plan 2**. Custodian holds an org's external credentials (API keys, git tokens, DB connections) and brokers their *use* to that org's herald-verified identities **without handing out raw secrets**. Per-org cryptographic isolation; encrypted at rest under keys derived from a single escrowed root.

> **Status: M1 (connected MVP) built.** custodian is a gRPC pillar (architecturally almanac with a credential data-model) serving `kind="git"` credentials over mTLS behind interchange. The broker routes its `git` credential fetches here (the cw git-credential-helper → broker → custodian path). Later milestones add multi-org herald-seed derivation, satchel ingest, OTP/unlock-prompting, and additional kinds (provider/jira/imap/db).

## M1 service

`CredentialService` (proto: `CarriedWorldUniverse/cwb-proto` `cwb/v1/custodian.proto`):

- `Fetch(kind, name) → bundle` — decrypted credential over mTLS. Requires `cred:read`. Audited (success + denial).
- `SetCredential(kind, name, git_bundle)` — seals + stores. Requires `cred:write`. Returns metadata only.
- `ListCredentials(kind?) → []meta` — metadata only, never secret material. Requires `cred:read`.

### Crypto / key custody

- **Per-org DEK** = `HKDF-SHA256(orgSeed, info="custodian-org-dek-v1:"+org)` — org-id is the first domain-separation level, so org A cannot derive org B's key (security design §4).
- **Per-credential seal** = `casket.Seal` under the DEK, path-bound AAD `RepoIdentity=org`, `ObjectPath=kind/name` — entry-swap protection. Ciphertext-only at rest (`sealed_bundle_b64`); plaintext only in memory on `Fetch`.
- **Fail-closed seed** — no public fallback. A missing/invalid `CUSTODIAN_ORG_SEED` is fatal unless `CUSTODIAN_DEV_INSECURE=1` (which mints an ephemeral dev seed, logged loudly). `orgSeed` is resolved via `SeedSource`; M1 = env (`CUSTODIAN_ORG_SEED`); the **herald-derived per-org seed off the escrowed root is the documented TODO** (security design §3 — the single derivation tree).

### Org isolation

The org is taken **only** from the herald-verified `cwb-org` gRPC metadata (injected by interchange), never a request body; every query is org-scoped; and the per-org DEK makes isolation cryptographic, not just access-control.

### Run

`cmd/custodian` listens on `:8085` (mTLS via `CUSTODIAN_TLS_CERT/_KEY/_CA`, or `CUSTODIAN_DEV_INSECURE=1` for local dev). DB at `CUSTODIAN_DB` (default `/var/lib/cwb/custodian.db`).

## Design

- [Security, Key-Management & DR Design](docs/2026-06-07-custodian-security-design.md) — the crypto/DR contract custodian must satisfy: escrowed root → per-org derived keys, crypto-enforced no-cross-sharing, encrypted-DB at rest, derive-don't-store, and the invariant that *nothing uses the root directly — only derived keys*.
- [Satchel — Operator Credential On-Ramp](docs/2026-06-10-satchel-credential-onramp-design.md) — the human edge that feeds custodian: a pass-patterned, casket-encrypted, git-on-cairn file-per-secret store; `cw cred` CLI + thin capture clients (browser, Raycast, QR-for-TOTP); move-semantics ingest into the vault.
