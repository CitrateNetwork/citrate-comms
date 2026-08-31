//! The relay wire frames — the CBOR-framed request/response protocol spoken
//! between a client and the server-blind relay.
//!
//! **Moved verbatim** out of `comms-relay/src/ws.rs` (COMMS-S1 WP-1.6) when the
//! client half was extracted into this crate. The definitions are the same bytes
//! on the wire; the only change is where they live, so that a CLIENT does not
//! have to link the relay server (and therefore RocksDB, axum and the OS keyring)
//! to speak to it.

use comms_core::identity::SiweMessage;
use comms_proto::{
    ClaimSubmission, Envelope, EnvelopeKind, GroupId, KeyPackagePublication, RoleAssertion,
    WalletAddress,
};
use serde::{Deserialize, Serialize};

/// A request from a client to the relay.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum ClientFrame {
    /// Request a fresh single-use nonce (e.g. for a KeyPackage binding attestation).
    Challenge,
    Authenticate {
        message: SiweMessage,
        signature: Vec<u8>,
    },
    PublishKeyPackage(KeyPackagePublication),
    TakeKeyPackage {
        wallet: WalletAddress,
    },
    RegisterGroup {
        group_id: GroupId,
    },
    Onboard {
        group_id: GroupId,
        joiner: WalletAddress,
        /// `None` if the caller IS the workspace owner; otherwise an owner-signed
        /// grant whose role carries `AddMember` (FWA-C11-03).
        admin_assertion: Option<RoleAssertion>,
        welcome: Envelope,
        ratchet_tree: Vec<u8>,
    },
    Submit(Envelope),
    RatchetTree {
        group_id: GroupId,
    },
    /// Query a group's current member roster (addresses) — a joiner needs it to address messages.
    GroupMembers {
        group_id: GroupId,
    },
    Offboard {
        group_id: GroupId,
        removed: WalletAddress,
        admin_assertion: Option<RoleAssertion>,
        remove_commit: Envelope,
        ratchet_tree: Vec<u8>,
    },
    /// CONNECT-S1 — submit a claim to the server-blind claims-inbox (pre-membership; SIWE only).
    SubmitClaim(ClaimSubmission),
    /// CONNECT-S1 — poll the claims-inbox for an invite by its `token_hash` (owner-side).
    PollClaims {
        token_hash: [u8; 32],
    },
}

/// A response or server-push to a client.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum ServerFrame {
    Challenge {
        nonce: String,
    },
    Authenticated {
        address: WalletAddress,
    },
    KeyPackage(Option<KeyPackagePublication>),
    RatchetTree(Option<Vec<u8>>),
    Members(Option<Vec<WalletAddress>>),
    Ack {
        seq: Option<u64>,
    },
    Deliver(Envelope),
    /// **E-5 WP-3 — advisory notification ping.** Pushed to each *connected* recipient
    /// (never the sender) when a Submit is accepted, so a native client can raise an OS
    /// notification without waiting to decrypt the envelope. Carries routing-level
    /// metadata ONLY — group id, envelope kind, and the relay-assigned `group_seq`.
    /// **No ciphertext, no body, no content — ever** (server-blind invariant; schema
    /// test `notify_frame_is_metadata_only` below).
    ///
    /// Notify is **advisory and never ordering-relevant**: the per-group total order is
    /// carried exclusively by `group_seq` on delivered [`Envelope`]s (formalized in
    /// `formal/RelayCommitOrder.tla` — that spec is unchanged by this frame). A client
    /// MUST NOT sequence, apply, or reject anything based on a Notify; dropping every
    /// Notify frame loses no correctness, only latency.
    Notify {
        group_id: GroupId,
        kind: EnvelopeKind,
        group_seq: u64,
    },
    /// CONNECT-S1 — the claims sealed under a polled `token_hash` (opaque ciphertexts; server-blind).
    Claims(Vec<ClaimSubmission>),
    Error {
        message: String,
    },
}
