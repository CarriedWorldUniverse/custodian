# custodian

CWB external-credential vault — **Spec A Sub-plan 2**. Custodian holds an org's external credentials (API keys, git tokens, DB connections) and brokers their *use* to that org's herald-verified identities **without handing out raw secrets**. Per-org cryptographic isolation; encrypted at rest under keys derived from a single escrowed root.

> **Status: not yet built.** This repo currently holds the reference design only. Custodian exists today as a seam in nexus (`nexus/broker/custodian.go`); it graduates to its own service when Sub-plan 2 is specced and built.

## Design

- [Security, Key-Management & DR Design](docs/2026-06-07-custodian-security-design.md) — the crypto/DR contract custodian must satisfy: escrowed root → per-org derived keys, crypto-enforced no-cross-sharing, encrypted-DB at rest, derive-don't-store, and the invariant that *nothing uses the root directly — only derived keys*.
