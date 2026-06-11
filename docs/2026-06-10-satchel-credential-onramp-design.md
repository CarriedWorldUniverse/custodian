# Satchel — Operator Credential On-Ramp (pass-patterned, casket-encrypted)

> **Status:** **approved** (operator, 2026-06-11) — build begins at M1. Companion to the [custodian security design](2026-06-07-custodian-security-design.md): custodian is the vault and broker; **satchel is the human edge** — how credentials get *into* the platform, and where the operator's personal-tier secrets live. Working name `satchel` (a small bag one carries — sibling to porter, *one who carries*).

## 1. Purpose

Getting an external credential into the platform today is the worst UX seam we have: sign up for a service in a browser, then hand-paste secrets into keyfiles / `kubectl create secret`. 2FA enrollment is worse still (TOTP QR codes have no capture path at all). Satchel fixes the human edge:

- a **casket-encrypted, git-backed, file-per-secret store** the operator captures credentials into — from the CLI, the browser, or launcher tooling;
- an **ingest contract** by which custodian (or, interim, the custodian seam in nexus) imports entries destined for the platform — after which custodian brokers their *use* as usual;
- the **operator-personal credential tier** (things that are the operator's, not any org's), which otherwise has no home in the platform.

Satchel is **edge, not vault**: it holds onboarding-grade and personal secrets in transit/at the boundary. Custodian remains the only place org credentials live long-term, and the only thing that brokers their use.

## 2. Design source — what we take from `pass`, and what we don't

[`pass`](https://www.passwordstore.org/) (and its Go reimplementation `gopass`) proved a shape worth stealing: **one encrypted file per secret, in a plain directory tree, versioned by git, driven by a CLI**. The format is so simple that an unofficial client ecosystem grew around it (browser extensions, phone apps, Raycast) — every client is thin because the store *is* the interface. That is our no-GUI principle realized: CLI/file-format as substrate, GUIs as optional layers.

| From pass | Adopt? | Notes |
|---|---|---|
| file-per-secret directory tree | ✅ | the store *is* the API |
| git as sync/versioning/change-audit | ✅ | hosted on cairn |
| body format: line 1 = secret, then `key: value` metadata | ✅ | wholesale, incl. `otpauth://` lines (pass-otp convention) |
| per-subtree recipient lists (`.gpg-id`) | ✅ | as `.recipients`, casket identities |
| GPG as the crypto | ❌ | casket instead — see §3 |
| third-party clients as-is | ❌/partial | GPG-bound; we keep the *protocols* where possible (§6) |

Precedent for swapping the crypto out from under the pass layout: `passage` (pass-on-age). We do the same with casket.

## 3. Why casket, not GPG

1. **One crypto root.** The platform principle is a single derivation tree ([security design §3](2026-06-07-custodian-security-design.md)): keys derive from seeds via `DeriveAgentKey` / domain-separated KDF. GPG imports a second, foreign key hierarchy that can never join that tree.
2. **No gpg-agent/pinentry custody.** GPG's key custody runs through OS keyrings and pinentry — exactly the class of pain that forced maren's always-on pod. Casket keys are files/derived seeds under our own custody model.
3. **Recipients are platform identities.** A `.recipients` entry is a casket/herald identity (operator device, custodian-ingest), not an email-keyed GPG identity. Custodian can be a *native recipient* — ingest needs no cross-crypto re-encryption boundary.
4. **Path-bound ciphertexts.** casket-go's `Seal`/`Open` bind AAD to `(repoIdentity, objectPath)`. An entry decrypts only at its own path in the right store — which closes pass's known entry-swap weakness (moving `bank.gpg` over `forum.gpg` to trick autofill) *for free*.

**Cost:** we forfeit the ready-made GPG client ecosystem and own thin clients ourselves (§6). That is the explicit trade the operator chose; the mitigation is keeping clients thin by reusing the ecosystem's *protocols* (browserpass native-messaging) rather than its crypto.

### 3.1 Key custody model (operator decision, 2026-06-11)

The custody question is settled — keys form one herald-rooted tree, and the human's protection is *time*, not carried material:

1. **Org base key** — custodian mints it at org creation, **derived from the org's herald base key**. One derivation tree; no second root.
2. **Per-user keys** — each member's key is either **derived from the org key** or **the user's own enrolled key**; which mode applies is an **org-admin policy option**.
3. **Session-based activation** — a human's personal key never sits open: it activates a **session** (TTL is an **org-admin knob, default 2 minutes**) — enough to use a credential — then auto-locks. Ephemeral capability, no long-held decryption state. Agent use stays on the brokered, use-audited custodian path; sessions gate *human* activation.
4. **OTP in-session** — sessions support OTP: TOTP codes are minted at use-time inside the window (the brokered-2FA goal); seeds are never exposed raw.
5. **Unlock prompting** — when a brokered use needs human activation, custodian doesn't fail: it **prompts the operator** (riding the existing broker escalation/notify seam → agora/panel/push) with *who* needs *what* credential for *what* use. Approval = session activation → the use proceeds. Pending requests carry their own timeout; approval is scoped to the requesting use (the session exists to serve it, not as an open window anything can ride); every prompt and decision is a ledger event.

This also resolves the herald-bootstrap custody question: agent identities derive from the **org root** (platform-side), with human sessions gating sensitive operations — no human-carried seed.

## 4. Store format

```
satchel/                          ← git repo, hosted on cairn (private)
  .satchel.toml                   ← store id (= casket repoIdentity), format version
  .recipients                     ← root recipient set: operator device identities
  personal/
    github.com/jacinta.casket
    …
  ingest/                         ← inbox for the platform
    .recipients                   ← operator devices + custodian-ingest identity
    <org>/<service>/<account>.casket
```

- **Entry** = one casket envelope (`.casket`), AAD-bound to `(store-id, path)`. Body is pass-convention plaintext:

  ```
  <the secret>
  login: maren@carriedworld.com
  url: https://app.meshy.ai
  kind: api-key | password | oauth-client | totp-seed | db-conn
  otpauth://totp/…            ← TOTP seed, pass-otp-compatible URI
  ```

- **Multi-recipient envelope** — the one casket capability to add: per-entry DEK, AEAD-sealed body under the DEK, DEK wrapped to each recipient's ECDH public key (age-style). casket-go already has the parts (ECDH shared-key derivation, `Seal`/`Open` AEAD); satchel needs them composed into a recipient-set envelope, in casket (shared primitive), not in satchel.
- **`.recipients`** applies to its subtree, nearest-ancestor wins (pass `.gpg-id` semantics). Changing a recipient set re-seals the subtree (`cw cred recipients` does this), exactly as `pass init -p` re-encrypts.
- **Operator keys are per-device** (little-blue, dMon, phone-later), so a device is revocable by re-sealing without rotating the operator's whole identity. Device keys follow the custody model (§3.1): derived from the org key or enrolled raw, per org-admin policy.

## 5. CLI — `cw cred`

Lives in the cw suite (the proven nexus↔CWB client lib). Agent-first: everything below is the complete interface; every other client is a wrapper over it.

```
cw cred ls [subtree]            cw cred insert <path> [--multiline]
cw cred show [--clip] <path>    cw cred generate <path> [length]
cw cred otp <path>              cw cred edit <path>
cw cred mv|rm <path>            cw cred recipients add|rm <identity> [subtree]
cw cred sync                    ← git pull --rebase + push
cw cred qr <image|--screen>     ← decode a TOTP QR (zbar) → otpauth entry
```

`show`/`otp` decrypt with the local device key under the §3.1 session model — activation opens the org-TTL window (default 2 min) rather than holding the key open; `sync` is plain git against cairn. No daemon, no server — the lazy-connection principle holds.

## 6. Clients (thin layers, in build order)

1. **CLI** (§5) — the substrate; M1.
2. **Raycast extension** (little-blue) — TypeScript shim that shells to `cw cred`; search/copy/OTP. Days, not weeks.
3. **Browser capture** — reimplement the **browserpass native-messaging host** backed by the satchel store: the stock browserpass extension (Chrome/Firefox) speaks a documented JSON protocol to a native host binary; we ship a casket-backed host, keep their extension. Fallback if protocol drift bites: a minimal fork of the extension.
4. **Phone — deferred.** Android Password Store / Pass-for-iOS are GPG-bound; a casket phone client is a real build. Not needed for the killer flows: TOTP QR codes appear on the *desktop* screen during enrollment, so `cw cred qr --screen` covers 2FA capture without a phone. Revisit as a tailnet PWA after the post-MVP human web layer exists.

## 7. Ingest — the satchel → custodian contract

`ingest/<org>/<service>/<account>` entries are sealed to the **custodian-ingest identity** (plus operator devices). Flow:

1. Operator captures the credential (browser save, `insert`, or `qr`) under `ingest/…`; `cw cred sync` pushes to cairn.
2. Custodian — interim: the custodian seam in nexus, as a `cw`-driven or scheduled pull — fetches the repo, unwraps entries addressed to it, and imports each into the vault under the org's root-derived key (per the [security design](2026-06-07-custodian-security-design.md): encrypted libSQL, per-org DEK).
3. **Move semantics:** after a verified import, custodian commits the entry's removal with a tombstone message (`ingested <path> → custodian <ref>`). The inbox stays empty in steady state; satchel never accumulates org credentials.
4. The import is recorded (ledger event); from here on, **use** is custodian-brokered and use-audited as normal. Satchel's git log is the *change* audit of the edge; it is never a *use* audit.

TOTP seeds ingest like any secret; custodian minting codes at use-time is what makes brokered 2FA possible (the agy/Atlassian/GitHub enrollment class).

## 8. Security analysis

- **Tier policy (hard rule):** satchel holds operator-personal and onboarding-grade secrets only. Never: the escrowed root, owner seeds, herald genesis material, or any custodian-vault export. The blast radius of a fully-compromised satchel must be "rotate some app passwords."
- **Git history is forever:** cairn retains old ciphertext, so a compromised recipient key decrypts *historical* entries it was a recipient of. Consequences: (a) revoking a device protects the future, not the past — **rotate the credentials a lost device could read**, not just the key; (b) move-semantics ingest keeps org credentials' residency in history short, but not zero — treat anything that transited `ingest/` as rotatable-on-compromise.
- **Path-bound AAD** (§3.4) prevents within-store entry swaps and cross-store replay.
- **Metadata leaks by design:** like pass, the *tree is plaintext* — entry names/paths reveal which services exist. Accepted at this tier (same posture as pass); don't put secrets in filenames.
- **Custodian-ingest key** is held by custodian (interim: nexus seam) under its normal key handling; it can read `ingest/` only — never `personal/` (it is simply not a recipient there; crypto-enforced, same spirit as per-org isolation).

## 9. Build plan

- **M1 — format + CLI:** multi-recipient envelope in casket-go; store layout + `.recipients` semantics; `cw cred` (ls/show/insert/generate/edit/rm/mv/otp/recipients/sync); satchel repo on cairn; little-blue + dMon device keys. *Usable as the operator's password manager from M1.*
- **M2 — ingest:** custodian-ingest identity; pull-import-tombstone loop at the nexus custodian seam; ledger event per import. *Closes the paste-into-keyfiles seam.*
- **M3 — capture UX:** `cw cred qr` (zbar); Raycast extension; browserpass-protocol native host.
- **M4 — deferred:** phone client (tailnet PWA, post-MVP web layer); automation (cairn push-webhook → ingest instead of poll); custodian-proper takeover of M2 when Sub-plan 2 builds.

## 10. Open questions

- **Name** — `satchel`, confirmed (2026-06-11).
- **Multi-recipient envelope home** — casket-go first, then ports to casket-ts/-dotnet as needed; wire format must be cross-language like the channel format.
- **Operator device-key derivation** — resolved by §3.1 (org-derived or enrolled, org-admin policy); raw enrolled keys remain the day-one M1 path.
- **Non-tailnet git access** — cairn is reachable on the tailnet; a future phone client either joins the tailnet or needs an interchange-edge route. Deferred with M4.

## 11. Relationships

- **custodian** — the vault satchel feeds; owns brokered use + use-audit. ([security design](2026-06-07-custodian-security-design.md))
- **casket** — crypto substrate; gains the multi-recipient envelope.
- **cairn** — hosts the store repo; git is the sync + change-audit layer.
- **cw** — `cw cred` lives in the cw suite.
- **herald** — recipient identities; device-key derivation root (eventually).
- **porter** — sibling precedent for casket-encrypted stores (per-object AEAD).

---
*Derived from the 2026-06-10 design discussion (pass-ecosystem evaluation → casket pivot). Reference only — supersede with a proper spec when satchel enters its brainstorm → spec → plan cycle.*
