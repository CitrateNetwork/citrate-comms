//! `comms-relay` — the server-blind delivery service (deployed as a daemon).
//!
//! Responsibilities (MLS deliberately under-specifies the Delivery Service; the relay
//! must provide these — see `PLANSET/02_ARCHITECTURE.md` §"Delivery-service duties"):
//! 1. Per-group **total ordering** of Commits (first-writer-wins per epoch, fail-closed).
//!    This is the load-bearing correctness property — formalized in `PLANSET/03_TLA_SPECS.md`.
//! 2. Fan-out of Welcome / Commit / application envelopes to current members.
//! 3. A **KeyPackage directory** keyed by `wallet_address`, one-time-use enforced.
//! 4. A ciphertext envelope store (RocksDB + AES-256-GCM) and a BLAKE3 audit log.
//!
//! It reads ZERO plaintext and holds NO group secrets. Admin surface follows
//! `citrate-node-agent` supervision: loopback-bind + per-instance bearer token, fail-closed.
//!
//! The runnable daemon (`main.rs` / bin target) lands in COMMS-S0/S1.

#![forbid(unsafe_code)]
