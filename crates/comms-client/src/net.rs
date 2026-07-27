//! Networked session — MOVED to the `comms-session` crate.
//!
//! `NetSession` was extracted so that an application without a UI toolkit can hold a
//! member session (citrate-quorum's Rooms surface is a Tauri app; depending on this
//! crate would have pulled Slint into it). The logic and its tests went with it.
//!
//! One API change came out of that move: `login` takes a `SiweSigner` rather than an
//! `EthWallet`, so a caller whose private key lives behind a human-approval ceremony
//! can hold a session without ever materialising the key. `EthWallet` implements
//! `SiweSigner`, which is why nothing in this crate behaves differently — see
//! `netdrive.rs`, which boxes the wallet at the one call site.
#[allow(unused_imports)] // the re-export IS the point: downstream paths keep working
pub use comms_session::{Inbound, NetError, NetSession, SignerError, SiweSigner};
