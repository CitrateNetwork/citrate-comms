//! `comms-wire` — the client half of the server-blind relay protocol.
//!
//! The wire frames, the [`RelayClient`] connector, and the endpoint-security guard
//! that decides whether a dial is allowed at all. Everything here was **moved
//! verbatim** out of `comms-relay` (COMMS-S1 WP-1.6 / S4 WP-4.6); nothing about the
//! bytes on the wire changed.
//!
//! ## Why the split exists
//!
//! `comms-relay` is a server: it links RocksDB (the ciphertext store), axum (the
//! loopback admin surface) and the platform OS keyring (the at-rest master key). A
//! program that only wants to *talk* to a relay had to link all of it, because
//! `RelayClient` lived in the same crate. citrate-quorum's Rooms surface is exactly
//! that program — a Tauri desktop app that must not carry a storage engine and an
//! HTTP server to open a WebSocket.
//!
//! The dependency direction also re-states the server-blind invariant in the crate
//! graph, the way `comms-core`'s `mls`/`store` features already do: **this crate
//! cannot decrypt anything.** It has no `mls` dependency and no access to group
//! secrets — it moves opaque ciphertext and routing metadata, which is precisely
//! what the relay is trusted with (`PLANSET/02` §1).
//!
//! `comms-relay` depends on this crate and re-exports these types from its `ws`
//! module, so every existing `comms_relay::ws::{RelayClient, ClientFrame, …}` path
//! keeps resolving.

#![forbid(unsafe_code)]

pub mod client;
pub mod endpoint;
pub mod frames;

pub use client::{NotifyPush, RelayClient, WsError};
pub use endpoint::{classify_endpoint, enforce_endpoint_policy, EndpointClass, EndpointError};
pub use frames::{ClientFrame, ServerFrame};
