//! `comms-proto` — the wire vocabulary of citrate-comms.
//!
//! Pure data types only: no cryptography, no sockets, no storage. Shared by
//! `comms-relay`, `comms-core`, and `comms-client` so every party agrees on the
//! exact byte layout of what crosses the network.
//!
//! Planned types (built in COMMS-S0, see `PLANSET/05_SPRINTS_AND_WPS.md`):
//! `Envelope`, `GroupId`, `EpochId`, `CommitMsg`, `WelcomeMsg`, `AppMsg`,
//! `KeyPackageRef`, `RoleAssertion`, `AuditRecord`.
//!
//! Invariant: an `Envelope` carries an opaque `ciphertext_blob` plus routing
//! metadata (`group_id`, `epoch`, `recipients`) ONLY. No field here is ever
//! plaintext content — see `PLANSET/02_ARCHITECTURE.md`.

#![forbid(unsafe_code)]
