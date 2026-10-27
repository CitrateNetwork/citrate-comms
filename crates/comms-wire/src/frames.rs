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
    /// A member's current grant generation in a group (`None` if not a member). An owner
    /// signs a delegated grant for this generation (`rbac::sign_group_grant`); offboarding
    /// advances it, which ends every grant issued before. Answered only to a member.
    GrantGeneration {
        group_id: GroupId,
        member: WalletAddress,
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
    /// INVITE-S2 — the owner mints a single-use, group-bound, owner-TTL'd invite. The
    /// relay stores `token_hash -> group_info` (the PUBLIC MLS group state a token-holder
    /// needs to self-admit by external commit) and NOTHING secret. `group_info` is opaque
    /// to the relay. The relay binds the inviter to the authenticated session.
    PublishInvite {
        group_id: GroupId,
        /// BLAKE3 of the raw invite token — the store key. The relay never sees the token.
        token_hash: [u8; 32],
        /// The owner's exported `GroupInfo` blob (public group state; opaque to the relay).
        group_info: Vec<u8>,
        /// Unix milliseconds after which the invite is dead (owner-set TTL).
        expires_at: u64,
    },
    /// INVITE-S2 — the minter revokes a previously-published invite (tombstone; the
    /// relay then fails every redeem of it closed).
    RevokeInvite {
        token_hash: [u8; 32],
        /// When set, revoking an invite that was already redeemed is refused with
        /// [`INVITE_ALREADY_USED`] instead of acknowledged, so the minter can tell a closed
        /// unused invite from a spent one. Omitted from the encoding when unset (the frame is
        /// byte-identical to the original); a relay that predates the field ignores it and
        /// acknowledges as before.
        #[serde(default, skip_serializing_if = "is_false")]
        report_used: bool,
    },
    /// INVITE-S2 — a token-holder self-admits: presents the RAW token (the relay hashes
    /// it to find the invite) plus its own fresh KeyPackage. On success the relay
    /// consumes the invite (single-use), adds the redeemer to the routing roster, records
    /// the referral, and returns the stored `GroupInfo` in [`ServerFrame::RedeemInvite`].
    RedeemInvite {
        group_id: GroupId,
        /// The raw invite token (bearer secret). The relay stores only its hash.
        token: Vec<u8>,
        /// The redeemer's TLS-serialized MLS KeyPackage (structurally bounded by the relay;
        /// its cryptographic validity is enforced by the existing members when they merge
        /// the resulting external commit — the relay is server-blind and never parses MLS).
        key_package: Vec<u8>,
    },
}

/// The relay's error message when [`ClientFrame::RevokeInvite`] with `report_used` names an
/// invite that was already redeemed. Stable: the member daemon and the app match on it.
pub const INVITE_ALREADY_USED: &str = "invite already used";

fn is_false(b: &bool) -> bool {
    !*b
}

/// INVITE-S2 — the fail-closed reason a [`ClientFrame::RedeemInvite`] was refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum RedeemError {
    /// The invite's TTL has passed.
    Expired,
    /// The invite was already redeemed (single-use).
    Consumed,
    /// The minter revoked the invite.
    Revoked,
    /// No invite exists for this token (unknown / wrong token / wrong group).
    UnknownToken,
    /// The presented KeyPackage failed the relay's structural bound (empty / oversized).
    InvalidKeyPackage,
}

impl RedeemError {
    /// The stable wire string for this reason (matches the INVITE-S2 vocabulary).
    pub fn as_str(&self) -> &'static str {
        match self {
            RedeemError::Expired => "expired",
            RedeemError::Consumed => "consumed",
            RedeemError::Revoked => "revoked",
            RedeemError::UnknownToken => "unknown_token",
            RedeemError::InvalidKeyPackage => "invalid_key_package",
        }
    }
}

/// INVITE-S2 — the outcome of a [`ClientFrame::RedeemInvite`]. Success carries the
/// public `GroupInfo` the redeemer feeds to `external_commit_join`, plus the group's
/// routing epoch at mint time; failure carries a typed, fail-closed reason.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum RedeemInviteResult {
    Ok {
        /// The stored public `GroupInfo` (opaque to the relay).
        group_info: Vec<u8>,
        /// The group's routing epoch when the invite was minted (informational; the
        /// redeemer takes its authoritative epoch from the external-commit result).
        epoch: u64,
    },
    Err(RedeemError),
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
    GrantGeneration(Option<u64>),
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
    /// INVITE-S2 — the result of a [`ClientFrame::RedeemInvite`].
    RedeemInvite(RedeemInviteResult),
    Error {
        message: String,
    },
}

#[cfg(test)]
mod revoke_compat_tests {
    //! `RevokeInvite` gained an optional `report_used` field. Old and new peers must keep
    //! understanding each other in both directions.
    use super::ClientFrame;
    use comms_proto::canonical;
    use serde::{Deserialize, Serialize};

    /// The frame as peers that predate `report_used` define it.
    #[derive(Debug, Serialize, Deserialize, PartialEq)]
    enum OldClientFrame {
        RevokeInvite { token_hash: [u8; 32] },
    }

    #[test]
    fn a_revoke_without_report_used_encodes_exactly_as_before() {
        let new = canonical::to_vec(&ClientFrame::RevokeInvite {
            token_hash: [7; 32],
            report_used: false,
        })
        .expect("encode");
        let old = canonical::to_vec(&OldClientFrame::RevokeInvite {
            token_hash: [7; 32],
        })
        .expect("encode");
        assert_eq!(new, old);
    }

    #[test]
    fn an_old_peer_decodes_a_revoke_that_reports_use() {
        let bytes = canonical::to_vec(&ClientFrame::RevokeInvite {
            token_hash: [8; 32],
            report_used: true,
        })
        .expect("encode");
        let old: OldClientFrame = canonical::from_slice(&bytes).expect("old relay decodes it");
        assert_eq!(
            old,
            OldClientFrame::RevokeInvite {
                token_hash: [8; 32]
            }
        );
    }

    #[test]
    fn a_new_relay_reads_an_old_revoke_as_not_reporting_use() {
        let bytes = canonical::to_vec(&OldClientFrame::RevokeInvite {
            token_hash: [9; 32],
        })
        .expect("encode");
        match canonical::from_slice::<ClientFrame>(&bytes).expect("decode") {
            ClientFrame::RevokeInvite {
                token_hash,
                report_used,
            } => {
                assert_eq!(token_hash, [9; 32]);
                assert!(!report_used);
            }
            other => panic!("decoded as {other:?}"),
        }
    }
}
