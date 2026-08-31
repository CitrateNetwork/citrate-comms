//! `comms-proto` — the wire vocabulary of citrate-comms.
//!
//! Pure data types only: no cryptography, no sockets, no storage. Shared by
//! `comms-relay`, `comms-core`, and `comms-client` so every party agrees on the
//! exact byte layout of what crosses the network.
//!
//! Invariant: an [`Envelope`] carries an opaque `ciphertext` blob plus routing
//! metadata (`group_id`, `epoch`, `kind`, `sender`, `recipients`) ONLY. No field
//! here is ever plaintext message content — see `PLANSET/02_ARCHITECTURE.md`.

#![forbid(unsafe_code)]

use serde::{Deserialize, Serialize};
use std::fmt;

pub mod canonical;

/// The Citrate chain id every SIWE login binds to (anti-cross-chain-replay).
pub const CITRATE_CHAIN_ID: u64 = 40204;

/// A 20-byte Ethereum-style wallet address — the durable member identity
/// (`sub` / `wallet_address` from `citrate-identity`).
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub struct WalletAddress(pub [u8; 20]);

impl WalletAddress {
    pub fn from_hex(s: &str) -> Result<Self, ProtoError> {
        let s = s.strip_prefix("0x").unwrap_or(s);
        let bytes = hex::decode(s).map_err(|_| ProtoError::BadHex)?;
        let arr: [u8; 20] = bytes.try_into().map_err(|_| ProtoError::BadLength)?;
        Ok(Self(arr))
    }
    pub fn to_hex(&self) -> String {
        format!("0x{}", hex::encode(self.0))
    }
}

impl fmt::Debug for WalletAddress {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "WalletAddress({})", self.to_hex())
    }
}

/// 32-byte content-addressed identifier of an MLS group (channel / DM / forum).
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Default, Serialize, Deserialize)]
pub struct GroupId(pub [u8; 32]);

impl fmt::Debug for GroupId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "GroupId({})", hex::encode(self.0))
    }
}

/// MLS epoch counter for a group. Increases by exactly 1 per applied Commit
/// (the `MonotoneEpoch` invariant in `PLANSET/03_TLA_SPECS.md`).
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug, Serialize, Deserialize)]
pub struct EpochId(pub u64);

/// Opaque MLS KeyPackage reference (a hash the directory keys on).
#[derive(Clone, PartialEq, Eq, Hash, Debug, Serialize, Deserialize)]
pub struct KeyPackageRef(pub Vec<u8>);

/// What an [`Envelope`] carries. The relay routes by kind + metadata; it never
/// inspects `ciphertext`.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub enum EnvelopeKind {
    /// MLS Welcome — onboards new member(s); routed to the named joiner(s).
    Welcome,
    /// MLS Commit — a membership/epoch change; fanned out to current members.
    Commit,
    /// MLS Proposal — staged change; fanned out to current members.
    Proposal,
    /// MLS application message — fanned out to current members.
    Application,
}

/// The unit the relay stores and forwards. `ciphertext` is opaque MLS bytes.
/// `group_seq` is assigned by the relay (its per-group total order) and is
/// `None` on submission, `Some` once accepted.
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct Envelope {
    pub group_id: GroupId,
    pub epoch: EpochId,
    pub kind: EnvelopeKind,
    pub sender: WalletAddress,
    /// Routing targets (the relay's unavoidable metadata exposure — R4).
    pub recipients: Vec<WalletAddress>,
    /// Opaque MLS ciphertext. NEVER plaintext.
    pub ciphertext: Vec<u8>,
    /// Relay-assigned monotonic per-group sequence; `None` until accepted.
    pub group_seq: Option<u64>,
}

/// A client publishing its MLS KeyPackage to the relay's directory, with the
/// wallet-signed binding attestation that proves the KeyPackage belongs to the
/// wallet (defeats KeyPackage spoofing — R3, `PLANSET/02` §2 step 6).
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct KeyPackagePublication {
    pub wallet: WalletAddress,
    /// TLS-serialized MLS KeyPackage.
    pub key_package: Vec<u8>,
    /// The MLS Ed25519 signature public key inside the credential.
    pub mls_sig_pubkey: Vec<u8>,
    /// secp256k1 signature by `wallet` over
    /// `BLAKE3(wallet ‖ mls_sig_pubkey ‖ relay_domain ‖ nonce)`; 65 bytes (r‖s‖v).
    pub binding_attestation: Vec<u8>,
    /// The relay nonce the attestation was bound to (single-use).
    pub nonce: String,
    pub relay_domain: String,
}

/// CONNECT-S1 — a pre-membership claim submitted to the relay's **server-blind** claims-inbox, so an
/// invitee's request reaches the group owner without a manual DM/clipboard round-trip. The relay keys
/// it by `token_hash` (BLAKE3 of the invite token — the token itself never reaches the relay) and
/// stores `ciphertext` OPAQUELY (sealed to the invite link's ephemeral pubkey; the owner alone opens it).
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct ClaimSubmission {
    /// BLAKE3 of the invite token — the inbox key. The relay never sees the token, only its hash.
    pub token_hash: [u8; 32],
    /// The claim sealed to the invite link's ephemeral pubkey. Opaque to the relay — never decrypted.
    pub ciphertext: Vec<u8>,
}

/// RBAC roles (capabilities defined in `comms-core::rbac`, `PLANSET/02` §4).
#[derive(Clone, Copy, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub enum Role {
    Owner,
    Admin,
    Member,
    Partner,
    Guest,
    Agent,
}

/// A signed grant of a role to a subject within a scope. Issued by an owner/admin
/// wallet; distributed as an MLS application message so it inherits E2E + ordering.
/// Offboarding supersedes it in the same Commit as the MLS Remove (atomic — `PLANSET/02` §4.3).
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct RoleAssertion {
    pub subject: WalletAddress,
    pub role: Role,
    /// `None` == workspace-wide; `Some(group)` == channel-scoped.
    pub scope: Option<GroupId>,
    /// Unix milliseconds; `None` == no expiry.
    pub not_after: Option<u64>,
    pub issuer: WalletAddress,
    /// secp256k1 signature by `issuer` over the canonical encoding of the fields above.
    pub signature: Vec<u8>,
}

/// A tamper-evident audit event. Records metadata ONLY — never plaintext content
/// (`PLANSET/02` §7). The hash chain over these lives in `comms-core::audit`.
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub enum AuditEvent {
    Genesis,
    GroupCreated {
        group_id: GroupId,
        creator: WalletAddress,
    },
    MemberAdded {
        group_id: GroupId,
        member: WalletAddress,
        epoch: EpochId,
    },
    MemberRemoved {
        group_id: GroupId,
        member: WalletAddress,
        epoch: EpochId,
    },
    AgentAdded {
        group_id: GroupId,
        agent: WalletAddress,
        epoch: EpochId,
    },
    AgentRemoved {
        group_id: GroupId,
        agent: WalletAddress,
        epoch: EpochId,
    },
    KeyPackagePublished {
        wallet: WalletAddress,
        key_package_ref: KeyPackageRef,
    },
    EnvelopeReceipt {
        group_id: GroupId,
        group_seq: u64,
        epoch: EpochId,
        sender: WalletAddress,
        kind: EnvelopeKind,
        /// BLAKE3 of the ciphertext (proves receipt without revealing content).
        ciphertext_hash: [u8; 32],
        size: u64,
    },
    RoleAsserted {
        subject: WalletAddress,
        role: Role,
        scope: Option<GroupId>,
    },
    RoleRevoked {
        subject: WalletAddress,
        scope: Option<GroupId>,
    },
}

/// One link in the BLAKE3 audit chain. `record_hash` and `previous_hash` are
/// computed/checked in `comms-core::audit`; this is the serializable wire form.
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct AuditRecord {
    pub sequence: u64,
    /// Unix milliseconds (supplied by the caller; the chain does not read a clock).
    pub timestamp_ms: u64,
    pub previous_hash: [u8; 32],
    pub event: AuditEvent,
    pub record_hash: [u8; 32],
}

#[derive(Debug, thiserror::Error)]
pub enum ProtoError {
    #[error("invalid hex")]
    BadHex,
    #[error("invalid byte length")]
    BadLength,
    #[error("canonical encode failed: {0}")]
    Encode(String),
}
