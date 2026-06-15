//! `comms-core` — the citrate-comms domain library (no network sockets bound here).
//!
//! Modules (built per `PLANSET/05_SPRINTS_AND_WPS.md`):
//! - [`audit`]    — BLAKE3 hash-chained append-only metadata log.
//! - [`identity`] — SIWE handshake (secp256k1) + nonce store + wallet binding attestation.
//! - [`mls`]      — OpenMLS group engine (feature `mls`; the relay does NOT enable it).
//!
//! The server-blind invariant is enforced at the dependency graph: `comms-relay`
//! depends on this crate with `default-features = false`, so the [`mls`] module —
//! which is the only place group secrets live — is not even compiled into the relay.

#![forbid(unsafe_code)]

pub mod audit;
pub mod domain;
pub mod identity;
pub mod rbac;

#[cfg(feature = "store")]
pub mod store;

#[cfg(feature = "mls")]
pub mod mls;
