//! `comms-agent-bridge` — bridges an AI agent into citrate-comms as a first-class
//! cryptographic MLS member.
//!
//! The bridge IS the MLS client for the agent: it holds the agent's MLS group state
//! and its own signature key (OS keyring), decrypts inbound application messages, and
//! hands them to `nist-agent` / `citrate-agent-runtime` over a Unix-domain socket using
//! the JSON-per-line framing from `nist-agent-daemon/src/ipc.rs`. Agent actions come
//! back as JSON lines, are MLS-encrypted, and handed to the relay.
//!
//! Compliance posture: the agent decrypts using its OWN leaf secret, obtained via an MLS
//! Add that every member can see. "An agent is in this channel" is cryptographically
//! visible and consented-to — a participant, not a wiretap. See `PLANSET/06_AGENT_INTEGRATION_SPEC.md`.
//!
//! Control surface: loopback-bind + per-instance bearer token, fail-closed
//! (mirrors `citrate-node-agent/crates/supervision/src/server.rs`).

#![forbid(unsafe_code)]
