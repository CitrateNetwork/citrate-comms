# citrate-comms

> An **end-to-end-encrypted, agentic team workspace** for the Citrate federation —
> Comms + CRM + Project Management in one self-hostable binary. Secure login through a
> cryptographic handshake on `citrate-identity`, messages routed by a **server-blind relay**
> that can never read them, and AI agents that participate as **cryptographic members** of a
> conversation rather than server-side wiretaps. Runs on-prem and airgapped alongside `nist-agent`.

**Status:** accepted into the federation (2026-06-14). **COMMS-S0 (Foundations) prototype is complete** —
the cryptographic + transport spine works end to end (22 tests green). This is the first internal tool our
own team will run; if it works for us it productizes for any team on the network. Next: COMMS-S1
(WebSocket transport + RocksDB persistence + full channels/forums/DMs).

## Read first
The complete design lives in [`PLANSET/`](PLANSET/):
- [`00_OVERVIEW.md`](PLANSET/00_OVERVIEW.md) — vision, the locked decisions, architecture at a glance, reuse map
- [`01_SCOPE_OF_WORK.md`](PLANSET/01_SCOPE_OF_WORK.md) — phases, deliverables, in/out of scope, risk register (R1–R10)
- [`02_ARCHITECTURE.md`](PLANSET/02_ARCHITECTURE.md) — crate layout, auth handshake, MLS mapping, RBAC, CRM/PM model, storage, audit
- [`03_TLA_SPECS.md`](PLANSET/03_TLA_SPECS.md) — formal invariants (Commit-ordering, audit-chain contiguity)
- [`04_FEATURES_BDD.md`](PLANSET/04_FEATURES_BDD.md) — Gherkin features for every v1 capability
- [`05_SPRINTS_AND_WPS.md`](PLANSET/05_SPRINTS_AND_WPS.md) — sprint plan & work packages (COMMS-S0…)
- [`06_AGENT_INTEGRATION_SPEC.md`](PLANSET/06_AGENT_INTEGRATION_SPEC.md) — agents-as-members, IPC bridge, key custody, compliance story
- [`07_IMPLEMENTATION_AND_HARDENING_PLAN.md`](PLANSET/07_IMPLEMENTATION_AND_HARDENING_PLAN.md) — airgap build, reproducibility, threat model, Tier-1 audit feed

## The core invariant
> **The relay is trusted for *liveness and ordering*, never for *confidentiality*.** It stores and
> forwards ciphertext + routing metadata only. All plaintext, all group secrets, and all CRM/PM
> records live exclusively on member clients. An agent reading a channel is cryptographically
> identical to a human reading it — there is no shadow key and no plaintext escrow.

## Architecture at a glance
```
  citrate-identity (SIWE/OIDC)        AI agents (nist-agent / agent-runtime)
   wallet_address = identity            join as MLS members, keys in keyring
            │                                   │
            ▼                                   ▼
   ┌──────────────────────┐         ┌──────────────────────────┐
   │  comms-client (Slint) │        │  comms-agent-bridge       │
   │  MLS client + local   │        │  MLS client for an agent  │
   │  encrypted store      │        │  Unix-socket JSON IPC     │
   └──────────┬───────────┘         └───────────┬──────────────┘
              │  opaque MLS ciphertext envelopes │
              ▼                                  ▼
   ┌──────────────────────────────────────────────────────────┐
   │  comms-relay  (server-blind delivery service)             │
   │  WS transport · per-group total order · KeyPackage dir    │
   │  ciphertext store (RocksDB+AES-256-GCM) · BLAKE3 audit log│
   │  reads ZERO plaintext · loopback admin + bearer token     │
   └──────────────────────────────────────────────────────────┘
```

## Crypto grade (matches the chain)
MLS (RFC 9420) via OpenMLS, ciphersuite `MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519`
(X25519 KEM · AES-128-GCM · Ed25519 signatures — the strongest standard MLS suite over the chain's
X25519/Ed25519 curves; the AES-256-GCM "chain grade" is delivered at the at-rest layer, see below).
At-rest: RocksDB column families encrypted
with AES-256-GCM, keys wrapped by the chain's PQ-hybrid `HybridKEM` (Kyber-768 + X25519, SHA3-512 combine).
Audit: BLAKE3 hash-chained append-only log, optionally anchored to chain 40204 for tamper-evidence.

## Workspace
COMMS-S0 built the crypto + transport spine (✅ implemented & tested); the rest fills in per `PLANSET/05`.
```
crates/
├─ comms-proto         # ✅ wire types (Envelope, GroupId, Commit/Welcome/AppMsg, RoleAssertion, AuditRecord)
├─ comms-core          # ✅ mls (OpenMLS) · identity (SIWE+attestation) · audit (BLAKE3 chain); rbac/domain/store next
├─ comms-relay         # ✅ server-blind DeliveryService (total order, KeyPackage dir, audit); WS+RocksDB in S1
├─ comms-agent-bridge  # ⏳ Unix-socket IPC to nist-agent / citrate-agent-runtime; an agent's MLS client (S3)
└─ comms-client        # ⏳ native Slint app (@citrate-ui-kit); houses the S0 e2e test; UI from design package (S2)
```
**Server-blind, enforced by the build graph:** `comms-relay` links `comms-core` with
`default-features = false`, so the `mls` module (the only place group secrets live) is not compiled into
the relay — referencing `comms_core::mls` from the relay fails to compile.

## Build
```bash
cargo build --workspace --release --locked
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
```

## Agentile
This repo follows the [Agentile methodology](../AGENTILE.md). Entry point: [`.agentile/AGENT_ENTRY.md`](.agentile/AGENT_ENTRY.md).
Active sprint: `COMMS-S0` (Foundations) — see `citrate-federation/repos/citrate-comms/sprints/`.

---
© 2026 Citrate Inc.. Licensed under Apache-2.0.
