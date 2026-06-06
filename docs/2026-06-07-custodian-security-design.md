# Custodian — Security, Key-Management & DR Design

> **Status:** reference design (not yet built). Captures the architecture agreed in the 2026-06-06/07 design discussion, ahead of custodian being specced/built as **Spec A Sub-plan 2** (CWB Multi-Consumer Identity & Credential Authority). Today custodian exists only as a seam in nexus (`nexus/broker/custodian.go`, the casket-assertion→herald flow). This document is the contract those builds must satisfy.

## 1. Purpose

Custodian is the **external-credential vault** of the CWB platform: it holds credentials (API keys, git tokens, DB connections, etc.) that belong to a consumer org, and brokers their *use* to that org's identities **without ever handing out raw secrets** — the same scoped-handle pattern herald uses for identity. It is keyed by herald identity: an identity proves who it is to herald, and custodian serves only the credentials that identity's org is entitled to.

Because it holds **customer (tenant) credentials**, custodian's contents are *irreplaceable customer data* — the one class of data in the platform that cannot be rebuilt from a repo or re-minted from genesis. Its security and disaster-recovery model is therefore the most consequential in the system, and is the subject of this document.

## 2. First principle — re-mintable vs. irreplaceable

The platform's disaster-recovery story rests on sorting everything into three buckets:

| Bucket | Examples | Recovery |
|---|---|---|
| **Rebuildable** | the cloud itself, all service config | rebuild from `carriedworld-cloud` (`REBUILD.md`) |
| **Re-mintable / re-creatable** | nexus authorities, aspect keyfiles, the nexus credential store, external API keys, herald identities (while no real tenants) | re-derive from genesis / re-obtain from providers |
| **Irreplaceable** | the **escrowed base root**, and **custodian's customer-credential vault** | must be preserved (escrow the root; back up the vault) |

Nexus is **disposable**: its work lives in repos, its keys re-mint, its brokered API keys re-obtain. Custodian's vault is **not** — it is the thing the whole backup + escrow design exists to protect.

## 3. Key hierarchy — derive everything from one escrowed root

**Going forward, anything encrypted derives its key — via domain-separated KDF (HKDF, distinct `info` strings) — from a single escrowed base root.** Nothing else is stored or backed up; it is all re-derivable.

```
escrowed root  (the ONLY escrowed secret)
  └─ derive(root, "org/<org-id>")              ← per-org key
       ├─ derive(orgKey, "cred-dek")           ← that org's credential vault DEK
       ├─ derive(orgKey, "repo/<id>")          ← that org's cairn repo keys
       └─ derive(orgKey, "identity/<slug>")    ← that org's identity keys
```

**Invariant — nothing uses the root directly; only derived keys.** The root is a *derivation-only seed*: its sole use is as KDF input to mint derived keys. No data is ever encrypted or decrypted with the root itself, and no service operates with it. This confines the root's plaintext exposure to the single moment of derivation; everything downstream — custodian, the DBs, the backups — handles only derived keys. Wherever possible, derivation happens *at the root-holding boundary* and only the derived key is emitted, so the root never travels to the consumer at all.

This generalises the herald-rooted bootstrap (`DeriveAgentKey(owner_seed, slug)`) from identities to **all** data-encryption keys. Consequences:

- **Escrow shrinks to the root.** The root is the only secret ever backed up.
- **Recovery is deterministic:** fetch the root → re-derive every key → decrypt everything.
- **Domain separation is the safety discipline** — distinct `info` strings (`org/<id>`, `cred-dek`, `repo/<id>`, `backup/dek`, …) so derivations never collide and stay scoped.

> Re-root note: today nexus's credential store derives its data key via `HKDF(nexus_identity.session_signing_secret)` — a nexus-*local* secret, not the escrowed root. Under this principle that re-roots to the escrowed base. Custodian must derive from the escrowed root from day one, never mint a local secret.

## 4. Per-org crypto isolation — no cross-sharing

The **org-id is the first domain-separation level**, so **every org's data is encrypted under its own derived key**. Org A literally cannot decrypt org B's data: the keys are different, and A never holds B's key.

This is **stronger than logical / access-control isolation** — an authorization bug cannot leak cross-org data, because the keys are physically separate and an org's runtime never possesses another org's key.

**Enforcement point — custodian + herald:** custodian derives the per-org key from the root and serves it **only to herald-verified identities in that org**. The herald `identity → org` binding *is* the cryptographic boundary (the crypto backing under herald's multi-tenant IAM and its `ResolveBinding` org-isolation).

**Recoverability nuance:** derived-from-root means the root-holder *can* derive any org's key — which is what keeps the platform recoverable and keeps orgs isolated *from each other*. Isolating orgs *from the platform too* (platform-blind) would require an org-held key component mixed into the derivation — a stronger, more complex model, noted as a future option, not adopted now.

## 5. At-rest encryption — an encrypted-DB platform primitive

Custodian does **not** hand-roll envelope crypto. Instead, **"encrypted database" is a *type* offered by the platform data-layer primitive**, provisioned on demand and **opened with the key** — the per-org root-derived key *is* the access credential ("provisioned/opened by presenting the key", same brokered-handle pattern as the other primitives).

Concretely on this stack: the data layer is **libSQL (sqld), which has native encryption-at-rest** — open the database with an encryption key and the engine decrypts pages into memory on read. Therefore:

- Custodian's vault = an **encrypted libSQL DB opened with the per-org derived key**.
- The disk holds **only ciphertext**; plaintext lives **only in memory, transiently**, on a herald-verified read.
- **"Decrypt into memory" is the DB engine's job, not custodian code** — don't roll your own; supply the key, the engine does the crypto.
- This **generalises**: encrypted-at-rest becomes a *platform capability* (a third data-layer variant alongside plain sqld and brokered Postgres), available to any service that asks for an encrypted DB keyed by its derived key.

**Custodian operates on derived keys, never the root** (§3 invariant). Preferred shape: the root never enters custodian at all — a derivation step *at the root-holding boundary* mints the per-org key and hands custodian only that. Custodian then holds only the per-org derived key(s) in active use, zeroed after. If derivation must happen inside custodian, the root is touched solely at derivation time and immediately zeroed; it is never used to encrypt/decrypt anything directly.

## 6. Root escrow — AWS Secrets Manager

The escrowed root is the **only** secret that is backed up. It lives in **AWS Secrets Manager** (account present; region `ap-southeast-2`, Sydney).

Why AWS Secrets Manager for the root specifically:
- **Tiny + ultra-critical + IAM-access-controlled** — purpose-built for a handful of root secrets.
- **Dodges the bootstrap chicken-and-egg:** you cannot encrypt the backup *of your own keys* (you'd need a key to read it). Secrets Manager is IAM-rooted, so the recovery bootstrap is *an AWS credential* — the one thing carried out-of-band → fetch the root → re-derive/decrypt everything.
- **Not real lock-in:** a few portable keys, not trapped compute — an acceptable exception to the otherwise no-hyperscaler stance. Movable later to Vault / 1Password / a KMS / a hardware token.

**Gating:** escrow activates when there is something irreplaceable to protect — i.e. **when custodian is built and holds real tenant credentials**. Until then the AWS account is intentionally empty; nexus and herald (with no real tenants) are re-mintable / re-genesis-able, so nothing is escrowed prematurely.

## 7. Disaster recovery — full procedure

Because the vault is ciphertext at rest, **its backup *is* that ciphertext** — no separate encryption step. The live DB and its off-site backup are the same sealed artifact, inert without the root. Backups follow the tiered plan (frequent → local dock, daily → off-site R2).

Full recovery, in order:
1. **Rebuild** the cloud from `carriedworld-cloud` (`REBUILD.md`).
2. **Fetch the base root** from AWS Secrets Manager.
3. **Re-mint** nexus authorities + re-derive all keys from the root.
4. **Restore** custodian's ciphertext vault (from dock/R2) and **open it with the re-derived per-org keys**.

## 8. Custodian build contract (summary)

When custodian is specced and built, it must satisfy:

1. **Identity-keyed access** — serve credentials only to herald-verified identities; the `identity → org` binding is the boundary.
2. **Derive-from-escrowed-root** — all keys derive (domain-separated KDF) from the escrowed base root; never mint a local secret. **Never use the root directly — operate only on derived keys** (ideally custodian receives the per-org derived key and never sees the root).
3. **Per-org key separation** — every org's data under its own derived key; no-cross-sharing is crypto-enforced.
4. **Encrypted-DB at rest** — provision a platform encrypted-DB (encrypted libSQL) and supply the per-org derived key; ciphertext-only on disk, plaintext only in memory on read.
5. **Minimise root residency** — hold the root in memory only as needed; derive lazily; zero after use.
6. **No raw secrets out** — broker *use* of credentials (scoped handles), never hand back raw secrets — the same model as herald identity and git-cred brokering.

## 9. Open questions / dependencies

- **Owner-seed custody / the base root** — the escrowed root is the management-org genesis material; the herald-rooted bootstrap (`DeriveAgentKey(owner_seed, slug)`) that produces the derivation tree is still a target, not built. Custodian depends on it.
- **Platform-blind isolation** (§4) — whether to mix an org-held key component so the platform itself cannot derive an org's key. Future option.
- **Where the derivation boundary lives** — since nothing uses the root directly and custodian ideally never holds it, *something* still derives the per-org keys from the root. Open: is that a small derivation service / KMS-style boundary that holds the root and emits only derived keys (preferred — the root never travels), or does custodian derive in-process at boot (root touched briefly, then zeroed)? The former keeps the root's plaintext to one tightly-scoped place.

## 10. Relationships

- **herald** — the identity authority; the `identity → org` binding custodian enforces against. ([[Spec A]])
- **data layer** — provides the encrypted-DB primitive (encrypted libSQL / sqld).
- **casket** — the platform crypto substrate; the KDF + envelope primitives.
- **hosting platform** (`carriedworld-cloud`) — provisions/brokers the encrypted-DB and the standing config.
- **backup/DR plan** — the tiered backup (dock + R2) of the ciphertext vault; the AWS root escrow.

---
*Derived from the 2026-06-06/07 design discussion. Reference only — supersede with a proper spec when custodian enters its brainstorm → spec → plan cycle.*
