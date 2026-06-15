//! `comms-core` — the citrate-comms domain library (no network sockets bound here).
//!
//! Planned modules (built per `PLANSET/05_SPRINTS_AND_WPS.md`):
//! - `mls`      — OpenMLS wrapper; group lifecycle, KeyPackage management, the
//!                `MLS_256_DHKEMX25519_AES256GCM_SHA512_Ed25519` ciphersuite.
//! - `identity` — SIWE-bound MLS credential; reuses the `citrate-studio/src/auth.rs`
//!                OIDC/PKCE/keyring model. Identity == `wallet_address`.
//! - `rbac`     — roles → capabilities; signed `RoleAssertion`; binding to MLS membership.
//! - `domain`   — CRM + PM entities as E2E-encrypted, event-sourced records (CRDT only
//!                for ordered/collaborative fields).
//! - `store`    — client-side RocksDB with AES-256-GCM column families; CF keys wrapped
//!                by the chain's PQ-hybrid `HybridKEM`. Persists OpenMLS group state.
//! - `audit`    — BLAKE3 hash-chained append-only metadata log; mirrors
//!                `citrate-agent-runtime` `AuditChain`.
//!
//! Secret MLS state in `mls` is `pub(crate)` to the module: the relay links this crate
//! for `store`/`audit` only and is statically prevented from touching group keys
//! (the server-blind invariant — see `PLANSET/02_ARCHITECTURE.md`).

#![forbid(unsafe_code)]
