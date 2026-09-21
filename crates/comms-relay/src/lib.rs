//! `comms-relay` — the server-blind delivery service.
//!
//! This is the in-process core of the relay daemon: the WebSocket transport is a
//! thin wrapper landing in COMMS-S1 (`PLANSET/05`). Everything here operates on
//! opaque [`Envelope`] ciphertext + routing metadata. The relay:
//!
//! - authenticates a session with the SIWE handshake (`comms-core::identity`),
//! - runs a one-time-use **KeyPackage directory**, verifying each wallet binding
//!   attestation as a *courtesy pre-filter* (R3). This check is NOT the security
//!   boundary for KeyPackage spoofing: the relay is the in-scope attacker for a
//!   server-blind asset (RFC 9420 §3), so a hostile relay simply skips it. The
//!   authoritative check runs client-side in `comms_core::mls::verify_incoming_key_package`
//!   before any member is admitted (finding CM2-B-A001),
//! - assigns a **per-group total order** (`group_seq`) and enforces
//!   **first-writer-wins per epoch** for Commits (R1, formalized in `PLANSET/03`),
//! - stores ciphertext envelopes and fans them out to recipient mailboxes,
//! - maintains a BLAKE3 hash-chained **audit log** of metadata events.
//!
//! It never holds a group secret and never reads plaintext. The build graph makes
//! this checkable: `comms-core` is linked WITHOUT the `mls` feature, so the module
//! that holds group secrets is not even compiled here.

#![forbid(unsafe_code)]

pub mod admin;
pub mod keyvault;
pub mod ws;

/// The endpoint-security guard MOVED to `comms-wire` — it governs a *client's* dial,
/// so it belongs on the client side of the split. Re-exported unchanged so every
/// `comms_relay::endpoint::…` path keeps resolving.
pub mod endpoint {
    pub use comms_wire::endpoint::*;
}

use std::collections::{BTreeSet, HashMap, VecDeque};
use std::path::Path;

use comms_core::audit::{AuditChain, AuditError};
use comms_core::identity::{self, InMemoryNonceStore, NonceStore, SiweMessage};
use comms_core::rbac::{self, Capability, RbacError};
use comms_core::store::{self, EncryptedStore, StoreError};
use comms_proto::{
    canonical, AuditEvent, AuditRecord, ClaimSubmission, Envelope, EnvelopeKind, EpochId, GroupId,
    KeyPackagePublication, KeyPackageRef, RoleAssertion, WalletAddress,
};
use comms_wire::frames::RedeemError;
use serde::{Deserialize, Serialize};

/// Per-group routing + ordering state. Holds NO secrets — only ciphertext, the
/// public ratchet tree, the member roster, and the order log.
#[derive(Default)]
struct GroupState {
    members: BTreeSet<WalletAddress>,
    current_epoch: u64,
    next_seq: u64,
    /// First-writer-wins record: epoch → BLAKE3(ciphertext) of the accepted Commit.
    accepted_commit: HashMap<u64, [u8; 32]>,
    /// The latest public ratchet tree (handed to joiners alongside their Welcome).
    ratchet_tree: Vec<u8>,
    /// The ordered ciphertext log (the durable, replayable relay state).
    log: Vec<Envelope>,
    /// The wallet that created this group (`register_group`) — the per-group admin,
    /// authorized for THIS group's membership ops (onboard/offboard) without an
    /// owner-signed assertion. `None` for groups persisted before this field existed
    /// (and any group whose creation predates the audit trail): those fall back to
    /// global-owner-only authorization, never an auth bypass.
    creator: Option<WalletAddress>,
}

/// The serializable, on-disk projection of a group's metadata (everything but the
/// envelope log, which is persisted separately keyed by `group_id ‖ seq`).
#[derive(Serialize, Deserialize)]
struct GroupSnapshot {
    members: Vec<WalletAddress>,
    current_epoch: u64,
    next_seq: u64,
    accepted_commit: Vec<(u64, [u8; 32])>,
    ratchet_tree: Vec<u8>,
    /// `#[serde(default)]` → already-persisted snapshots (written before this field)
    /// deserialize to `None`, i.e. the global-owner-only fallback.
    #[serde(default)]
    creator: Option<WalletAddress>,
}

impl GroupState {
    fn snapshot(&self) -> GroupSnapshot {
        GroupSnapshot {
            members: self.members.iter().copied().collect(),
            current_epoch: self.current_epoch,
            next_seq: self.next_seq,
            accepted_commit: self.accepted_commit.iter().map(|(k, v)| (*k, *v)).collect(),
            ratchet_tree: self.ratchet_tree.clone(),
            creator: self.creator,
        }
    }
    fn from_snapshot(s: GroupSnapshot) -> Self {
        Self {
            members: s.members.into_iter().collect(),
            current_epoch: s.current_epoch,
            next_seq: s.next_seq,
            accepted_commit: s.accepted_commit.into_iter().collect(),
            ratchet_tree: s.ratchet_tree,
            log: Vec::new(), // rebuilt from the envelopes CF
            creator: s.creator,
        }
    }
}

/// INVITE-S2 — a single-use, group-bound, owner-TTL'd invite the relay stores against a
/// token hash. It holds the PUBLIC MLS `GroupInfo` (public group state a token-holder
/// self-admits with by external commit) and NO group secret — the server-blind invariant
/// is unchanged. `consumed`/`revoked` are the fail-closed tombstones.
#[derive(Clone, Serialize, Deserialize)]
struct InviteRecord {
    group_id: GroupId,
    /// The owner's exported `GroupInfo` (opaque to the relay).
    group_info: Vec<u8>,
    /// The wallet that minted the invite (the referral attributes joins to this address).
    inviter: WalletAddress,
    /// Unix milliseconds after which the invite is dead.
    expires_at: u64,
    /// Set once redeemed (single-use).
    consumed: bool,
    /// Set if the minter revoked it.
    revoked: bool,
}

/// INVITE-S2 — one append-only referral row: who admitted whom, into which group, under
/// which invite, and when. The airdrop/attribution scorer reads these; scoring itself is
/// out of scope for the relay.
#[derive(Clone, Serialize, Deserialize)]
struct ReferralRecord {
    inviter: WalletAddress,
    joiner: WalletAddress,
    group_id: GroupId,
    token_hash: [u8; 32],
    ts: u64,
}

/// Parameters for [`DeliveryService::offboard`]. Bundled so the call site reads as
/// one intent ("offboard this member with this Remove commit").
pub struct OffboardRequest<'a> {
    pub group_id: GroupId,
    pub admin: WalletAddress,
    /// `None` if the admin IS the workspace owner; otherwise an owner-signed grant.
    pub admin_assertion: Option<&'a RoleAssertion>,
    pub removed: WalletAddress,
    /// The MLS Remove commit (`EnvelopeKind::Commit`) at the new epoch.
    pub remove_commit: Envelope,
    /// The public ratchet tree at the post-removal epoch.
    pub ratchet_tree: Vec<u8>,
}

/// The server-blind relay.
pub struct DeliveryService {
    domain: String,
    /// The workspace owner — the trust anchor for RBAC `RoleAssertion`s the relay
    /// verifies before admitting a membership-mutating op.
    owner: WalletAddress,
    nonces: InMemoryNonceStore,
    /// One-time-use KeyPackage directory, keyed by wallet.
    key_packages: HashMap<WalletAddress, VecDeque<KeyPackagePublication>>,
    /// CONNECT-S1 — the server-blind claims-inbox, keyed by invite `token_hash`. Ciphertext ONLY
    /// (opaque). In-memory + ephemeral by design (a dropped connect-request is just re-submitted).
    claims: HashMap<[u8; 32], Vec<ClaimSubmission>>,
    /// INVITE-S2 — single-use, group-bound invites keyed by BLAKE3(token). Public
    /// `GroupInfo` only (never a group secret). Durable in `CF_INVITES`.
    invites: HashMap<[u8; 32], InviteRecord>,
    /// INVITE-S2 — append-only referral ledger (who admitted whom). Durable in
    /// `CF_REFERRALS`; the row index is the vector position (never deleted).
    referrals: Vec<ReferralRecord>,
    groups: HashMap<GroupId, GroupState>,
    /// Per-wallet delivery mailboxes (the fan-out target).
    mailboxes: HashMap<WalletAddress, Vec<Envelope>>,
    /// Authenticated sessions (wallet proved control via SIWE).
    sessions: BTreeSet<WalletAddress>,
    audit: AuditChain,
    /// Durable, encrypted backing store. `None` = in-memory only (tests).
    store: Option<EncryptedStore>,
}

impl DeliveryService {
    /// In-memory relay (no persistence) — used by tests and ephemeral deployments.
    pub fn new(
        domain: impl Into<String>,
        owner: WalletAddress,
        genesis_ts_ms: u64,
    ) -> Result<Self, RelayError> {
        Ok(Self {
            domain: domain.into(),
            owner,
            nonces: InMemoryNonceStore::new(),
            key_packages: HashMap::new(),
            claims: HashMap::new(),
            invites: HashMap::new(),
            referrals: Vec::new(),
            groups: HashMap::new(),
            mailboxes: HashMap::new(),
            sessions: BTreeSet::new(),
            audit: AuditChain::new(genesis_ts_ms)?,
            store: None,
        })
    }

    /// Durable relay backed by an encrypted RocksDB store at `path`. On a fresh store
    /// it starts a new audit chain; on an existing one it **replays** the persisted
    /// groups, envelope logs, KeyPackage directory, and audit chain (verifying chain
    /// integrity) so the relay survives restart (R10). Sessions are not persisted —
    /// clients re-authenticate on reconnect.
    pub fn open(
        path: impl AsRef<Path>,
        domain: impl Into<String>,
        owner: WalletAddress,
        master_key: [u8; 32],
        genesis_ts_ms: u64,
    ) -> Result<Self, RelayError> {
        let store = EncryptedStore::open(path, master_key)?;

        // Audit chain: rebuild from disk, or start + persist a genesis.
        let mut audit_records: Vec<AuditRecord> = Vec::new();
        for (_k, v) in store.scan(store::CF_AUDIT)? {
            audit_records.push(canonical::from_slice(&v).map_err(RelayError::Decode)?);
        }
        // Creator backfill map: each group's creator from the EARLIEST GroupCreated audit
        // event (records scan in sequence order, so `or_insert` keeps the first). Lets
        // groups persisted before `GroupSnapshot.creator` existed still authorize their
        // creator; groups with no GroupCreated on record stay `None` (owner-only).
        let mut creator_by_group: HashMap<GroupId, WalletAddress> = HashMap::new();
        for r in &audit_records {
            if let AuditEvent::GroupCreated { group_id, creator } = &r.event {
                creator_by_group.entry(*group_id).or_insert(*creator);
            }
        }
        let audit = if audit_records.is_empty() {
            let chain = AuditChain::new(genesis_ts_ms)?;
            for r in chain.records() {
                store.put(
                    store::CF_AUDIT,
                    &r.sequence.to_be_bytes(),
                    &canonical::to_vec(r).map_err(RelayError::Decode)?,
                )?;
            }
            chain
        } else {
            AuditChain::from_records(audit_records)?
        };

        // Groups: metadata snapshots, then the envelope logs.
        let mut groups: HashMap<GroupId, GroupState> = HashMap::new();
        for (k, v) in store.scan(store::CF_MEMBERSHIP)? {
            let gid = GroupId(
                k.as_slice()
                    .try_into()
                    .map_err(|_| RelayError::CorruptKey)?,
            );
            let snap: GroupSnapshot = canonical::from_slice(&v).map_err(RelayError::Decode)?;
            groups.insert(gid, GroupState::from_snapshot(snap));
        }
        // Apply the creator backfill to any group whose persisted snapshot predates the
        // `creator` field (creator == None); groups without a GroupCreated audit record
        // remain None → global-owner-only authorization (no auth bypass).
        for (gid, g) in groups.iter_mut() {
            if g.creator.is_none() {
                g.creator = creator_by_group.get(gid).copied();
            }
        }
        for (k, v) in store.scan(store::CF_ENVELOPES)? {
            if k.len() < 32 {
                return Err(RelayError::CorruptKey);
            }
            let gid = GroupId(k[..32].try_into().map_err(|_| RelayError::CorruptKey)?);
            let env: Envelope = canonical::from_slice(&v).map_err(RelayError::Decode)?;
            if let Some(g) = groups.get_mut(&gid) {
                g.log.push(env);
            }
        }

        // KeyPackage directory (each value is the wallet's whole queue).
        let mut key_packages: HashMap<WalletAddress, VecDeque<KeyPackagePublication>> =
            HashMap::new();
        for (k, v) in store.scan(store::CF_KEYPACKAGES)? {
            let wallet = WalletAddress(
                k.as_slice()
                    .try_into()
                    .map_err(|_| RelayError::CorruptKey)?,
            );
            let queue: Vec<KeyPackagePublication> =
                canonical::from_slice(&v).map_err(RelayError::Decode)?;
            key_packages.insert(wallet, queue.into());
        }

        // INVITE-S2 — replay the invite store (public GroupInfo + tombstones) and the
        // append-only referral ledger so self-admit + attribution survive a restart (R10).
        let mut invites: HashMap<[u8; 32], InviteRecord> = HashMap::new();
        for (k, v) in store.scan(store::CF_INVITES)? {
            let token_hash: [u8; 32] = k
                .as_slice()
                .try_into()
                .map_err(|_| RelayError::CorruptKey)?;
            let rec: InviteRecord = canonical::from_slice(&v).map_err(RelayError::Decode)?;
            invites.insert(token_hash, rec);
        }
        let mut referral_rows: Vec<(u64, ReferralRecord)> = Vec::new();
        for (k, v) in store.scan(store::CF_REFERRALS)? {
            let seq = u64::from_be_bytes(
                k.as_slice()
                    .try_into()
                    .map_err(|_| RelayError::CorruptKey)?,
            );
            let rec: ReferralRecord = canonical::from_slice(&v).map_err(RelayError::Decode)?;
            referral_rows.push((seq, rec));
        }
        referral_rows.sort_by_key(|(seq, _)| *seq);
        let referrals: Vec<ReferralRecord> = referral_rows.into_iter().map(|(_, r)| r).collect();

        Ok(Self {
            domain: domain.into(),
            owner,
            nonces: InMemoryNonceStore::new(),
            key_packages,
            claims: HashMap::new(),
            invites,
            referrals,
            groups,
            mailboxes: HashMap::new(),
            sessions: BTreeSet::new(),
            audit,
            store: Some(store),
        })
    }

    pub fn domain(&self) -> &str {
        &self.domain
    }

    pub fn owner(&self) -> WalletAddress {
        self.owner
    }

    // ─────────────────── persistence helpers (no-op when in-memory) ───────────────────

    /// Append an audit event AND persist the new record (kept atomic with the chain).
    fn audit_append(&mut self, event: AuditEvent, now_ms: u64) -> Result<(), RelayError> {
        let rec = self.audit.append(event, now_ms)?.clone();
        if let Some(s) = &self.store {
            s.put(
                store::CF_AUDIT,
                &rec.sequence.to_be_bytes(),
                &canonical::to_vec(&rec).map_err(RelayError::Decode)?,
            )?;
        }
        Ok(())
    }

    fn persist_group(&self, gid: &GroupId) -> Result<(), RelayError> {
        if let (Some(s), Some(g)) = (&self.store, self.groups.get(gid)) {
            s.put(
                store::CF_MEMBERSHIP,
                &gid.0,
                &canonical::to_vec(&g.snapshot()).map_err(RelayError::Decode)?,
            )?;
        }
        Ok(())
    }

    fn persist_envelope(&self, gid: &GroupId, seq: u64, env: &Envelope) -> Result<(), RelayError> {
        if let Some(s) = &self.store {
            s.put(
                store::CF_ENVELOPES,
                &store::seq_key(&gid.0, seq),
                &canonical::to_vec(env).map_err(RelayError::Decode)?,
            )?;
        }
        Ok(())
    }

    /// Persist a wallet's whole KeyPackage queue (so one-time-use consumption is
    /// reflected on disk — consumed packages do not reappear after restart).
    fn persist_keypackages(&self, wallet: &WalletAddress) -> Result<(), RelayError> {
        if let Some(s) = &self.store {
            let queue: Vec<&KeyPackagePublication> = self
                .key_packages
                .get(wallet)
                .map(|q| q.iter().collect())
                .unwrap_or_default();
            s.put(
                store::CF_KEYPACKAGES,
                &wallet.0,
                &canonical::to_vec(&queue).map_err(RelayError::Decode)?,
            )?;
        }
        Ok(())
    }

    /// Persist one invite record (the consumed/revoked tombstone lives here too, so a
    /// consumed invite does not resurrect after restart — no replay of a single-use link).
    fn persist_invite(&self, token_hash: &[u8; 32]) -> Result<(), RelayError> {
        if let (Some(s), Some(inv)) = (&self.store, self.invites.get(token_hash)) {
            s.put(
                store::CF_INVITES,
                token_hash,
                &canonical::to_vec(inv).map_err(RelayError::Decode)?,
            )?;
        }
        Ok(())
    }

    /// Persist one append-only referral row at its sequence index.
    fn persist_referral(&self, seq: u64, referral: &ReferralRecord) -> Result<(), RelayError> {
        if let Some(s) = &self.store {
            s.put(
                store::CF_REFERRALS,
                &seq.to_be_bytes(),
                &canonical::to_vec(referral).map_err(RelayError::Decode)?,
            )?;
        }
        Ok(())
    }

    // ─────────────────────────── handshake ───────────────────────────

    /// Issue a single-use challenge nonce for a SIWE login or a KeyPackage binding.
    pub fn issue_challenge(&mut self, now_ms: u64) -> String {
        self.nonces.fresh(now_ms)
    }

    /// Verify a SIWE login; on success the wallet has an authenticated session.
    pub fn authenticate(
        &mut self,
        message: &SiweMessage,
        signature: &[u8; 65],
        now_ms: u64,
    ) -> Result<WalletAddress, RelayError> {
        let domain = self.domain.clone();
        let verified =
            identity::verify_siwe_login(message, signature, &domain, now_ms, &mut self.nonces)
                .map_err(RelayError::Siwe)?;
        self.sessions.insert(verified.address);
        Ok(verified.address)
    }

    fn require_session(&self, wallet: &WalletAddress) -> Result<(), RelayError> {
        if self.sessions.contains(wallet) {
            Ok(())
        } else {
            Err(RelayError::NotAuthenticated)
        }
    }

    /// Drop an authenticated session (revocation). The session set was previously
    /// insert-only — a SIWE login was permanent for the process lifetime, it grew
    /// without bound, and an offboarded member kept passing `require_session`. The WS
    /// teardown calls this on disconnect and `offboard` calls it on removal, so a
    /// session no longer outlives its purpose (CM2-B-A011 / CM2-B-B019).
    pub fn end_session(&mut self, wallet: &WalletAddress) {
        self.sessions.remove(wallet);
    }

    /// Whether a wallet currently holds an authenticated session (test/introspection).
    pub fn has_session(&self, wallet: &WalletAddress) -> bool {
        self.sessions.contains(wallet)
    }

    // ─────────────────────── KeyPackage directory ───────────────────────

    /// Admit a KeyPackage to the directory after verifying its wallet binding
    /// attestation (R3, a courtesy pre-filter) and consuming the bound nonce
    /// (single-use). The client that later admits the member re-verifies the
    /// attestation itself (`comms_core::mls::verify_incoming_key_package`) — that
    /// client-side check, not this one, is the security boundary against a hostile
    /// relay substituting a KeyPackage (CM2-B-A001).
    pub fn publish_key_package(
        &mut self,
        publication: KeyPackagePublication,
        now_ms: u64,
    ) -> Result<KeyPackageRef, RelayError> {
        self.require_session(&publication.wallet)?;
        if publication.relay_domain != self.domain {
            return Err(RelayError::DomainMismatch);
        }
        // The attestation is bound to a single-use nonce; consume it.
        if !self.nonces.consume(&publication.nonce) {
            return Err(RelayError::NonceRejected);
        }
        identity::verify_binding_attestation(&publication).map_err(RelayError::Binding)?;

        // CIT-COMMS-005: cap the one-time-KeyPackage queue per wallet. Publishing is
        // session-gated + nonce-consuming, but a wallet could still grow its directory
        // without bound; a legitimate client keeps only a small pool of spare packages.
        let wallet = publication.wallet;
        if self.key_package_count(&wallet) >= Self::MAX_KEYPACKAGES_PER_WALLET {
            return Err(RelayError::KeyPackageQuotaExceeded {
                max: Self::MAX_KEYPACKAGES_PER_WALLET,
            });
        }

        let kp_ref = KeyPackageRef(blake3::hash(&publication.key_package).as_bytes().to_vec());
        self.key_packages
            .entry(wallet)
            .or_default()
            .push_back(publication);
        self.persist_keypackages(&wallet)?;
        self.audit_append(
            AuditEvent::KeyPackagePublished {
                wallet,
                key_package_ref: kp_ref.clone(),
            },
            now_ms,
        )?;
        Ok(kp_ref)
    }

    /// Consume a KeyPackage for `wallet` (one-time-use) — called by an admin who is
    /// about to add that wallet to a group. The on-disk queue is updated so a consumed
    /// package does not reappear after restart.
    pub fn take_key_package(&mut self, wallet: &WalletAddress) -> Option<KeyPackagePublication> {
        let popped = self
            .key_packages
            .get_mut(wallet)
            .and_then(|q| q.pop_front());
        if popped.is_some() {
            let _ = self.persist_keypackages(wallet);
        }
        popped
    }

    pub fn key_package_count(&self, wallet: &WalletAddress) -> usize {
        self.key_packages.get(wallet).map(|q| q.len()).unwrap_or(0)
    }

    // ─────────────────── CONNECT-S1 claims-inbox (server-blind) ───────────────────

    const MAX_CLAIMS_PER_TOKEN: usize = 16;

    /// Ceiling on the one-time KeyPackage queue per wallet (CIT-COMMS-005). A client
    /// keeps only a few spare packages; this bounds the directory a single wallet can
    /// grow while still leaving generous headroom for legitimate re-publication.
    const MAX_KEYPACKAGES_PER_WALLET: usize = 64;

    /// A submit's `recipients` may name at most this many wallets. A hard backstop
    /// on top of the `recipients ⊆ roster` rule (finding CM2-B-A005): a group larger
    /// than this cannot exist, so a legitimate fan-out never approaches it, while an
    /// abusive one is refused before any per-recipient work.
    const MAX_RECIPIENTS: usize = 4096;

    /// Ceiling on a single envelope's ciphertext (finding CM2-B-A005). Generous
    /// versus real MLS chat/commit/welcome payloads, but bounds one submit so a
    /// member cannot drive the single-droplet relay to OOM with an oversized blob.
    const MAX_CIPHERTEXT_BYTES: usize = 4 * 1024 * 1024;

    /// Submit a claim to the server-blind claims-inbox (CONNECT-S1). The `submitter` must be
    /// SIWE-authenticated but is NOT required to be a member (the pre-membership connect path). The
    /// relay stores the `ciphertext` opaquely — NO attestation verify, NEVER decrypted. Fails closed
    /// without a session. Idempotent per identical ciphertext; capped per token to bound growth.
    pub fn submit_claim(
        &mut self,
        submitter: &WalletAddress,
        submission: ClaimSubmission,
    ) -> Result<(), RelayError> {
        self.require_session(submitter)?;
        let q = self.claims.entry(submission.token_hash).or_default();
        if !q.iter().any(|c| c.ciphertext == submission.ciphertext) {
            // A007: newest-DROP when the inbox is full, not oldest-evict. The genuine
            // connect-request is by construction the earliest claim; oldest-first
            // eviction let a squatter who learns the invite token (it travels in the
            // shared link) submit MAX distinct junk claims and silently delete it.
            // Refusing new claims once full preserves any already-delivered genuine one.
            if q.len() < Self::MAX_CLAIMS_PER_TOKEN {
                q.push(submission);
            }
        }
        Ok(())
    }

    /// Poll the claims-inbox for an invite `token_hash` (owner-side). Non-destructive; the ciphertexts
    /// are opaque and useless without the invite's ephemeral private key. Requires a session.
    pub fn poll_claims(
        &self,
        poller: &WalletAddress,
        token_hash: &[u8; 32],
    ) -> Result<Vec<ClaimSubmission>, RelayError> {
        self.require_session(poller)?;
        Ok(self.claims.get(token_hash).cloned().unwrap_or_default())
    }

    /// Clear the inbox for a `token_hash` once the owner has consumed the (one-time) invite.
    pub fn clear_claims(&mut self, token_hash: &[u8; 32]) {
        self.claims.remove(token_hash);
    }

    // ─────────────────── INVITE-S2 token-authorized self-admit ───────────────────

    /// Ceiling on live invites the relay stores, so a member cannot grow `CF_INVITES`
    /// without bound. Generous versus any real workspace's outstanding invites.
    const MAX_INVITES: usize = 4096;

    /// **INVITE-S2 (owner mints).** Store a single-use, group-bound invite: `token_hash ->
    /// {group_info, inviter, expires_at}`. `group_info` is the owner's exported PUBLIC MLS
    /// group state (opaque to the relay — the server-blind invariant is unchanged: the
    /// relay stores/serves it but holds no group secret). Only a current member of the
    /// group may mint an invite into it, and the `inviter` is bound to the authenticated
    /// session by the WS layer (it cannot be spoofed). Idempotent per `token_hash`
    /// (re-publishing the same token overwrites its record rather than growing the store).
    pub fn publish_invite(
        &mut self,
        inviter: WalletAddress,
        group_id: GroupId,
        token_hash: [u8; 32],
        group_info: Vec<u8>,
        expires_at: u64,
    ) -> Result<(), RelayError> {
        self.require_session(&inviter)?;
        {
            let state = self.groups.get(&group_id).ok_or(RelayError::GroupUnknown)?;
            if !state.members.contains(&inviter) {
                return Err(RelayError::NotAMember);
            }
        }
        // Bound the stored blob (A005-style DoS cap) — an empty GroupInfo is meaningless.
        if group_info.is_empty() || group_info.len() > Self::MAX_CIPHERTEXT_BYTES {
            return Err(RelayError::CiphertextTooLarge {
                size: group_info.len() as u64,
                max: Self::MAX_CIPHERTEXT_BYTES as u64,
            });
        }
        // Cap the number of live invites (only new tokens count toward the ceiling).
        if !self.invites.contains_key(&token_hash) && self.invites.len() >= Self::MAX_INVITES {
            return Err(RelayError::InviteQuotaExceeded {
                max: Self::MAX_INVITES,
            });
        }
        self.invites.insert(
            token_hash,
            InviteRecord {
                group_id,
                group_info,
                inviter,
                expires_at,
                consumed: false,
                revoked: false,
            },
        );
        self.persist_invite(&token_hash)?;
        Ok(())
    }

    /// **INVITE-S2 (owner revokes).** Tombstone a previously-minted invite so every later
    /// redeem of it fails closed. Only the wallet that minted it may revoke it (bound to
    /// the authenticated session by the WS layer).
    pub fn revoke_invite(
        &mut self,
        caller: WalletAddress,
        token_hash: [u8; 32],
    ) -> Result<(), RelayError> {
        self.require_session(&caller)?;
        let record = self
            .invites
            .get_mut(&token_hash)
            .ok_or(RelayError::InviteUnknown)?;
        if record.inviter != caller {
            return Err(RelayError::NotAuthorized);
        }
        record.revoked = true;
        self.persist_invite(&token_hash)?;
        Ok(())
    }

    /// **INVITE-S2 (joiner self-admits).** Validate the presented raw `token` against the
    /// invite store — must exist, be for `group_id` (group-bound), be unrevoked,
    /// unconsumed, and unexpired — then CONSUME it (single-use), add the redeemer to the
    /// routing roster (so it can publish its external commit and receive fan-out, exactly
    /// as `onboard` does), append the referral row (inviter = the minter, joiner = the
    /// redeemer), and return the stored PUBLIC `GroupInfo` + the group's current routing
    /// epoch. Fails closed on any invalid/expired/consumed/revoked token or an
    /// out-of-bound KeyPackage.
    ///
    /// The relay is server-blind: it NEVER parses the MLS KeyPackage (that would link the
    /// MLS engine into the relay). Its only KeyPackage check is a structural bound; the
    /// existing members validate the KeyPackage cryptographically when they merge the
    /// resulting external commit. `joiner` is bound to the authenticated session upstream.
    pub fn redeem_invite(
        &mut self,
        joiner: WalletAddress,
        group_id: GroupId,
        token: &[u8],
        key_package: &[u8],
        now_ms: u64,
    ) -> Result<(Vec<u8>, u64), RelayError> {
        // Structural KeyPackage bound only (server-blind — no MLS parse here).
        if key_package.is_empty() || key_package.len() > Self::MAX_CIPHERTEXT_BYTES {
            return Err(RelayError::InviteRedeem(RedeemError::InvalidKeyPackage));
        }
        let token_hash = *blake3::hash(token).as_bytes();
        let (group_info, inviter) = {
            let record = self
                .invites
                .get(&token_hash)
                .ok_or(RelayError::InviteRedeem(RedeemError::UnknownToken))?;
            // Group-bound: the token admits ONLY into the group it was minted for.
            if record.group_id != group_id {
                return Err(RelayError::InviteRedeem(RedeemError::UnknownToken));
            }
            if record.revoked {
                return Err(RelayError::InviteRedeem(RedeemError::Revoked));
            }
            if record.consumed {
                return Err(RelayError::InviteRedeem(RedeemError::Consumed));
            }
            if now_ms > record.expires_at {
                return Err(RelayError::InviteRedeem(RedeemError::Expired));
            }
            (record.group_info.clone(), record.inviter)
        };
        // The group must still exist; take its current routing epoch and add the redeemer
        // to the roster (the moment it legitimately becomes a routing member).
        let epoch = {
            let state = self
                .groups
                .get_mut(&group_id)
                .ok_or(RelayError::InviteRedeem(RedeemError::UnknownToken))?;
            state.members.insert(joiner);
            state.current_epoch
        };
        // Consume (single-use) + record the referral. Persist all three mutations; a store
        // failure is a hard error BEFORE we hand back the GroupInfo, so a redeem we could
        // not durably mark consumed is never observable (no single-use replay after crash).
        if let Some(rec) = self.invites.get_mut(&token_hash) {
            rec.consumed = true;
        }
        let seq = self.referrals.len() as u64;
        let referral = ReferralRecord {
            inviter,
            joiner,
            group_id,
            token_hash,
            ts: now_ms,
        };
        self.referrals.push(referral);
        self.persist_invite(&token_hash)?;
        self.persist_group(&group_id)?;
        self.persist_referral(seq, &self.referrals[seq as usize])?;
        Ok((group_info, epoch))
    }

    /// **INVITE-S2 attribution.** Per inviter, the count of DISTINCT joiners they admitted
    /// (a re-used token can only be redeemed once, but an inviter may mint many invites;
    /// distinctness dedupes any joiner counted twice). The airdrop scorer consumes this;
    /// scoring is out of scope here.
    pub fn referral_tally(&self) -> Vec<(WalletAddress, u64)> {
        let mut per_inviter: std::collections::BTreeMap<WalletAddress, BTreeSet<WalletAddress>> =
            std::collections::BTreeMap::new();
        for r in &self.referrals {
            per_inviter.entry(r.inviter).or_default().insert(r.joiner);
        }
        per_inviter
            .into_iter()
            .map(|(inviter, joiners)| (inviter, joiners.len() as u64))
            .collect()
    }

    /// The number of referral rows recorded (introspection / tests).
    pub fn referral_count(&self) -> usize {
        self.referrals.len()
    }

    // ─────────────────────────── groups ───────────────────────────

    /// Register a newly created group with its creator as the first member.
    pub fn register_group(
        &mut self,
        group_id: GroupId,
        creator: WalletAddress,
        now_ms: u64,
    ) -> Result<(), RelayError> {
        self.require_session(&creator)?;
        if self.groups.contains_key(&group_id) {
            return Err(RelayError::GroupExists);
        }
        let mut state = GroupState::default();
        state.creator = Some(creator);
        state.members.insert(creator);
        self.groups.insert(group_id, state);
        self.persist_group(&group_id)?;
        self.audit_append(AuditEvent::GroupCreated { group_id, creator }, now_ms)?;
        Ok(())
    }

    /// Onboard a member: add to the roster, stash the public ratchet tree, and
    /// deliver the Welcome to the joiner's mailbox. The MLS Add/Commit themselves
    /// are submitted as envelopes; this updates the routing roster + audit.
    #[allow(clippy::too_many_arguments)] // each argument is a distinct onboard input; grouping them would only obscure.
    pub fn onboard(
        &mut self,
        group_id: GroupId,
        admin: WalletAddress,
        admin_assertion: Option<&RoleAssertion>,
        joiner: WalletAddress,
        welcome: Envelope,
        ratchet_tree: Vec<u8>,
        now_ms: u64,
    ) -> Result<(), RelayError> {
        self.require_session(&admin)?;
        // RBAC (FWA-C11-03): adding a member is a membership-mutating op. Mirror
        // `offboard` — the owner is the trust anchor; anyone else must present an
        // owner-signed assertion whose role carries `AddMember`. Without this any
        // member could insert an arbitrary joiner into the routing roster and
        // overwrite the stored public ratchet tree served to future joiners.
        // Look up THIS group's creator, scoped strictly to `group_id` (never a global
        // list) — the creator of group A must not gain any authority over group B.
        let group_creator = self
            .groups
            .get(&group_id)
            .ok_or(RelayError::GroupUnknown)?
            .creator;
        // RBAC (FWA-C11-03): adding a member is a membership-mutating op. Authorized iff
        // the actor is the global workspace owner, THIS group's creator (their own group),
        // or presents an owner-signed assertion whose role carries `AddMember`. A plain
        // member with none of these is rejected — otherwise any member could insert an
        // arbitrary joiner into the routing roster and overwrite the stored ratchet tree.
        let authorized = admin == self.owner
            || group_creator == Some(admin)
            || match admin_assertion {
                Some(a) => {
                    rbac::verify_grant_chain(a, admin, self.owner, now_ms)
                        .map_err(RelayError::Rbac)?;
                    rbac::can(a.role, Capability::AddMember)
                }
                None => false,
            };
        if !authorized {
            return Err(RelayError::NotAuthorized);
        }
        {
            let state = self.groups.get(&group_id).ok_or(RelayError::GroupUnknown)?;
            if !state.members.contains(&admin) {
                return Err(RelayError::NotAMember);
            }
        }
        debug_assert_eq!(welcome.kind, EnvelopeKind::Welcome);
        // Add the joiner to the routing roster FIRST, so the Welcome (whose sole
        // recipient is the joiner) satisfies the `recipients ⊆ roster` check the
        // ordered path now enforces (CM2-B-A005). Onboarding is exactly the moment a
        // wallet legitimately becomes a routing member, so this is where it belongs.
        {
            let state = self
                .groups
                .get_mut(&group_id)
                .ok_or(RelayError::GroupUnknown)?;
            state.members.insert(joiner);
        }
        // Deliver the Welcome on the durable ordered path (stored + audited + fanned
        // to the joiner's mailbox). Bind its sender to the authenticated admin so an
        // admin cannot post a Welcome attributed to another member (FWA-C11-01).
        self.submit_as(admin, welcome, now_ms)?;
        // Stash the public ratchet tree, persist, and audit the membership change.
        let epoch = {
            let state = self
                .groups
                .get_mut(&group_id)
                .ok_or(RelayError::GroupUnknown)?;
            state.ratchet_tree = ratchet_tree;
            state.current_epoch
        };
        self.persist_group(&group_id)?;
        self.audit_append(
            AuditEvent::MemberAdded {
                group_id,
                member: joiner,
                epoch: EpochId(epoch),
            },
            now_ms,
        )?;
        Ok(())
    }

    /// The public ratchet tree a joiner needs to process its Welcome.
    pub fn ratchet_tree(&self, group_id: &GroupId) -> Option<&[u8]> {
        self.groups.get(group_id).map(|g| g.ratchet_tree.as_slice())
    }

    /// **Atomic offboard.** Revoke a member's role AND their future-message access in
    /// one operation: the RBAC check, the MLS Remove commit (which rotates the group
    /// secret), the roster drop, and the audit all happen together at one epoch. The
    /// actor must be the workspace owner or hold an owner-signed assertion whose role
    /// can `RemoveMember`. The removed member keeps prior plaintext but cannot decrypt
    /// anything from the new epoch forward (forward security — `PLANSET/02` §3.2/§4.3).
    pub fn offboard(&mut self, req: OffboardRequest, now_ms: u64) -> Result<u64, RelayError> {
        let OffboardRequest {
            group_id,
            admin,
            admin_assertion,
            removed,
            remove_commit,
            ratchet_tree,
        } = req;
        self.require_session(&admin)?;
        // RBAC: owner is the trust anchor; anyone else must present an owner-signed
        // assertion whose role carries RemoveMember.
        // Look up THIS group's creator, scoped strictly to `group_id`.
        let group_creator = self
            .groups
            .get(&group_id)
            .ok_or(RelayError::GroupUnknown)?
            .creator;
        // Guardrail: only the global workspace owner may offboard the global owner. A
        // per-group creator (or a delegated assertion-holder) must never be able to
        // remove the trust anchor, even from a group they created.
        if removed == self.owner && admin != self.owner {
            return Err(RelayError::NotAuthorized);
        }
        // RBAC: authorized iff the global owner, THIS group's creator (their own group),
        // or an owner-signed assertion whose role carries RemoveMember.
        let authorized = admin == self.owner
            || group_creator == Some(admin)
            || match admin_assertion {
                Some(a) => {
                    rbac::verify_grant_chain(a, admin, self.owner, now_ms)
                        .map_err(RelayError::Rbac)?;
                    rbac::can(a.role, Capability::RemoveMember)
                }
                None => false,
            };
        if !authorized {
            return Err(RelayError::NotAuthorized);
        }
        {
            let state = self.groups.get(&group_id).ok_or(RelayError::GroupUnknown)?;
            if !state.members.contains(&admin) || !state.members.contains(&removed) {
                return Err(RelayError::NotAMember);
            }
        }
        debug_assert_eq!(remove_commit.kind, EnvelopeKind::Commit);
        // Apply the Remove commit on the ordered path (first-writer-wins, receipt
        // audit, fan-out to the REMAINING members). Bind its sender to the
        // authenticated admin (FWA-C11-01).
        let seq = self.submit_as(admin, remove_commit, now_ms)?;
        // Atomic with the commit: drop from the roster, refresh the public ratchet
        // tree, and record the offboard as a single logical event pair.
        let epoch = {
            let state = self
                .groups
                .get_mut(&group_id)
                .ok_or(RelayError::GroupUnknown)?;
            state.members.remove(&removed);
            state.ratchet_tree = ratchet_tree;
            state.current_epoch
        };
        // Revoke the removed member's relay session (CM2-B-B019): the MLS Remove denies
        // future plaintext, but the server-side authorization must be revoked too, or a
        // still-connected offboarded member keeps passing `require_session`.
        self.end_session(&removed);
        self.persist_group(&group_id)?;
        self.audit_append(
            AuditEvent::MemberRemoved {
                group_id,
                member: removed,
                epoch: EpochId(epoch),
            },
            now_ms,
        )?;
        self.audit_append(
            AuditEvent::RoleRevoked {
                subject: removed,
                scope: Some(group_id),
            },
            now_ms,
        )?;
        Ok(seq)
    }

    // ─────────────────────── submit / deliver ───────────────────────

    /// Accept an envelope **from an authenticated connection**, binding the
    /// envelope's `sender` to the session principal `authed` (FWA-C11-01).
    ///
    /// The relay does NOT trust the client-supplied `envelope.sender`: it must
    /// equal the wallet that authenticated this connection. A member therefore
    /// cannot forge another member's sender to mis-attribute the audit receipt
    /// or control another member's recipient set. This is the ONLY public
    /// entry point for client-originated submissions; internal trusted callers
    /// (`onboard`/`offboard`) use [`submit`](Self::submit) with the connection's
    /// already-authenticated wallet.
    pub fn submit_as(
        &mut self,
        authed: WalletAddress,
        envelope: Envelope,
        now_ms: u64,
    ) -> Result<u64, RelayError> {
        // Bind sender to the authenticated principal. Reject (do not silently
        // overwrite) a mismatched client-supplied sender so the spoof is visible
        // and fail-closed.
        if envelope.sender != authed {
            return Err(RelayError::SenderMismatch);
        }
        self.submit(envelope, now_ms)
    }

    /// Accept an envelope: assign its `group_seq`, enforce Commit ordering, store
    /// the ciphertext, audit the receipt, and fan out to recipient mailboxes.
    /// Returns the assigned sequence number.
    ///
    /// **Trusted internal path.** The caller guarantees `envelope.sender` is the
    /// authenticated principal (the WS layer routes client submits through
    /// [`submit_as`](Self::submit_as), which binds it; `onboard`/`offboard` pass
    /// envelopes whose sender is the connection's authenticated `admin`).
    fn submit(&mut self, mut envelope: Envelope, now_ms: u64) -> Result<u64, RelayError> {
        self.require_session(&envelope.sender)?;
        let ciphertext_hash = *blake3::hash(&envelope.ciphertext).as_bytes();
        let size = envelope.ciphertext.len() as u64;

        let state = self
            .groups
            .get_mut(&envelope.group_id)
            .ok_or(RelayError::GroupUnknown)?;
        if !state.members.contains(&envelope.sender) {
            return Err(RelayError::NotAMember);
        }

        // A005: bound the ciphertext and validate the recipient set against the
        // roster. Without this one authenticated member fans a single submit out to
        // arbitrarily many invented non-member mailboxes (which `deliver_pending`
        // never drains, since it only visits connected wallets) and/or ships an
        // unbounded ciphertext — a memory-exhaustion DoS on the single-droplet relay.
        if envelope.ciphertext.len() > Self::MAX_CIPHERTEXT_BYTES {
            return Err(RelayError::CiphertextTooLarge {
                size,
                max: Self::MAX_CIPHERTEXT_BYTES as u64,
            });
        }
        if envelope.recipients.len() > Self::MAX_RECIPIENTS {
            return Err(RelayError::TooManyRecipients {
                count: envelope.recipients.len(),
                max: Self::MAX_RECIPIENTS,
            });
        }
        for r in &envelope.recipients {
            if !state.members.contains(r) {
                return Err(RelayError::RecipientNotAMember);
            }
        }

        // R1: a group has ONE accepted Commit per epoch. First writer wins;
        // fail closed on a conflicting Commit (a different ciphertext for an epoch
        // already committed). Identical resubmission is idempotent.
        if envelope.kind == EnvelopeKind::Commit {
            match state.accepted_commit.get(&envelope.epoch.0) {
                Some(existing) if *existing != ciphertext_hash => {
                    return Err(RelayError::EpochAlreadyCommitted {
                        epoch: envelope.epoch.0,
                    });
                }
                Some(_) => {
                    // B014: identical resubmission — genuinely idempotent. Return the
                    // seq already assigned to this epoch's accepted Commit and STOP.
                    // Falling through (the prior behavior) appended a duplicate to the
                    // durable log, re-persisted, re-fanned-out, and inserted a second
                    // EnvelopeReceipt into the tamper-evident audit chain on every replay.
                    let prior = state
                        .log
                        .iter()
                        .find(|e| e.kind == EnvelopeKind::Commit && e.epoch.0 == envelope.epoch.0)
                        .and_then(|e| e.group_seq);
                    return prior.ok_or(RelayError::EpochAlreadyCommitted {
                        epoch: envelope.epoch.0,
                    });
                }
                None => {
                    // A003: a new Commit MUST advance the epoch by exactly one.
                    // Without this a member squats arbitrary future epochs with junk
                    // ciphertext — each accepted first-writer-wins and persisted —
                    // permanently bricking the group's membership machinery,
                    // including the Remove Commit that would evict them (they become
                    // unremovable). Contiguity also bounds `accepted_commit` growth
                    // to the group's genuine epoch count.
                    let expected = state.current_epoch.checked_add(1);
                    if Some(envelope.epoch.0) != expected {
                        return Err(RelayError::NonContiguousEpoch {
                            expected: expected.unwrap_or(u64::MAX),
                            got: envelope.epoch.0,
                        });
                    }
                    state
                        .accepted_commit
                        .insert(envelope.epoch.0, ciphertext_hash);
                    state.current_epoch = envelope.epoch.0;
                }
            }
        }

        let seq = state.next_seq;
        state.next_seq += 1;
        envelope.group_seq = Some(seq);
        state.log.push(envelope.clone());

        // Persist the ciphertext envelope + the group's updated metadata (durable,
        // replayable on restart — R10).
        let gid = envelope.group_id;
        self.persist_envelope(&gid, seq, &envelope)?;
        self.persist_group(&gid)?;

        // Fan out to the named recipients (the relay's unavoidable metadata — R4).
        for r in &envelope.recipients {
            self.mailboxes.entry(*r).or_default().push(envelope.clone());
        }

        self.audit_append(
            AuditEvent::EnvelopeReceipt {
                group_id: envelope.group_id,
                group_seq: seq,
                epoch: envelope.epoch,
                sender: envelope.sender,
                kind: envelope.kind,
                ciphertext_hash,
                size,
            },
            now_ms,
        )?;
        Ok(seq)
    }

    /// Drain a wallet's mailbox (the client's poll). In-order by arrival.
    pub fn fetch(&mut self, wallet: &WalletAddress) -> Vec<Envelope> {
        self.mailboxes
            .get_mut(wallet)
            .map(std::mem::take)
            .unwrap_or_default()
    }

    // ─────────────────────── introspection / audit ───────────────────────

    /// The ordered ciphertext log for a group — what the relay durably stores.
    pub fn group_log(&self, group_id: &GroupId) -> Option<&[Envelope]> {
        self.groups.get(group_id).map(|g| g.log.as_slice())
    }

    pub fn group_members(&self, group_id: &GroupId) -> Option<Vec<WalletAddress>> {
        self.groups
            .get(group_id)
            .map(|g| g.members.iter().copied().collect())
    }

    /// Number of registered groups (for the admin health snapshot).
    pub fn group_count(&self) -> usize {
        self.groups.len()
    }

    pub fn audit(&self) -> &AuditChain {
        &self.audit
    }
}

#[derive(Debug, thiserror::Error)]
pub enum RelayError {
    #[error("session not authenticated (SIWE handshake required)")]
    NotAuthenticated,
    #[error("actor not authorized for this membership operation")]
    NotAuthorized,
    #[error("SIWE verification failed: {0}")]
    Siwe(comms_core::identity::IdentityError),
    #[error("binding attestation failed: {0}")]
    Binding(comms_core::identity::IdentityError),
    #[error("nonce unknown or already used")]
    NonceRejected,
    #[error("relay domain mismatch")]
    DomainMismatch,
    #[error("unknown group")]
    GroupUnknown,
    #[error("group already registered")]
    GroupExists,
    #[error("sender is not a member of the group")]
    NotAMember,
    #[error("envelope sender does not match the authenticated session principal")]
    SenderMismatch,
    #[error("epoch {epoch} already has a different accepted commit (first-writer-wins)")]
    EpochAlreadyCommitted { epoch: u64 },
    #[error("non-contiguous commit epoch: expected {expected}, got {got}")]
    NonContiguousEpoch { expected: u64, got: u64 },
    #[error("a recipient is not a member of the group")]
    RecipientNotAMember,
    #[error("too many recipients: {count} (max {max})")]
    TooManyRecipients { count: usize, max: usize },
    #[error("ciphertext too large: {size} bytes (max {max})")]
    CiphertextTooLarge { size: u64, max: u64 },
    #[error("no key package available for wallet")]
    NoKeyPackage,
    #[error("key package quota exceeded for wallet (max {max})")]
    KeyPackageQuotaExceeded { max: usize },
    #[error("no such invite")]
    InviteUnknown,
    #[error("invite quota exceeded (max {max})")]
    InviteQuotaExceeded { max: usize },
    #[error("invite redeem refused: {}", .0.as_str())]
    InviteRedeem(RedeemError),
    #[error("rbac check failed: {0}")]
    Rbac(RbacError),
    #[error(transparent)]
    Audit(#[from] AuditError),
    #[error(transparent)]
    Store(#[from] StoreError),
    #[error("decode error: {0}")]
    Decode(comms_proto::ProtoError),
    #[error("corrupt store key")]
    CorruptKey,
}

#[cfg(test)]
mod tests {
    use super::*;
    use comms_core::identity::EthWallet;
    use comms_proto::{EpochId, CITRATE_CHAIN_ID};

    fn login(relay: &mut DeliveryService, wallet: &EthWallet, now: u64) {
        let nonce = relay.issue_challenge(now);
        let msg = SiweMessage {
            domain: relay.domain().to_string(),
            address: wallet.address(),
            statement: "Sign in to citrate-comms".into(),
            uri: format!("wss://{}", relay.domain()),
            version: "1".into(),
            chain_id: CITRATE_CHAIN_ID,
            nonce,
            issued_at_ms: now,
            expiration_ms: now + 600_000,
        };
        let sig = wallet.sign_siwe(&msg);
        relay.authenticate(&msg, &sig, now).unwrap();
    }

    fn envelope(
        group: GroupId,
        sender: WalletAddress,
        kind: EnvelopeKind,
        epoch: u64,
        ct: &[u8],
        to: &[WalletAddress],
    ) -> Envelope {
        Envelope {
            group_id: group,
            epoch: EpochId(epoch),
            kind,
            sender,
            recipients: to.to_vec(),
            ciphertext: ct.to_vec(),
            group_seq: None,
        }
    }

    #[test]
    fn claims_inbox_roundtrips_ciphertext_server_blind_and_allows_non_members() {
        let owner = EthWallet::generate();
        let invitee = EthWallet::generate(); // authenticated but NOT a member of any group
        let mut relay = DeliveryService::new("relay.citrate.ai", owner.address(), 0).unwrap();
        login(&mut relay, &owner, 10);
        login(&mut relay, &invitee, 11);
        let token_hash = [9u8; 32];
        let sealed = b"SEALED-CLAIM-CIPHERTEXT".to_vec();
        relay
            .submit_claim(
                &invitee.address(),
                ClaimSubmission {
                    token_hash,
                    ciphertext: sealed.clone(),
                },
            )
            .unwrap();
        let got = relay.poll_claims(&owner.address(), &token_hash).unwrap();
        assert_eq!(got.len(), 1);
        assert_eq!(got[0].ciphertext, sealed);
        assert_eq!(got[0].token_hash, token_hash);
        relay
            .submit_claim(
                &invitee.address(),
                ClaimSubmission {
                    token_hash,
                    ciphertext: sealed.clone(),
                },
            )
            .unwrap();
        assert_eq!(
            relay
                .poll_claims(&owner.address(), &token_hash)
                .unwrap()
                .len(),
            1
        );
        relay.clear_claims(&token_hash);
        assert!(relay
            .poll_claims(&owner.address(), &token_hash)
            .unwrap()
            .is_empty());
    }

    #[test]
    fn claims_inbox_requires_an_authenticated_session() {
        let owner = EthWallet::generate();
        let stranger = EthWallet::generate();
        let mut relay = DeliveryService::new("relay.citrate.ai", owner.address(), 0).unwrap();
        let r = relay.submit_claim(
            &stranger.address(),
            ClaimSubmission {
                token_hash: [1u8; 32],
                ciphertext: vec![1, 2, 3],
            },
        );
        assert!(matches!(r, Err(RelayError::NotAuthenticated)));
        login(&mut relay, &owner, 10);
        let r2 = relay.poll_claims(&stranger.address(), &[1u8; 32]);
        assert!(matches!(r2, Err(RelayError::NotAuthenticated)));
    }

    /// CM2-B-A007: a genuine (earliest) claim must SURVIVE a squatter flooding the inbox.
    /// Oldest-first eviction let anyone who learned the invite token delete it; newest-drop
    /// preserves it.
    #[test]
    fn a007_genuine_claim_survives_squatting() {
        let owner = EthWallet::generate();
        let attacker = EthWallet::generate();
        let mut relay = DeliveryService::new("relay.citrate.ai", owner.address(), 0).unwrap();
        login(&mut relay, &owner, 10);
        login(&mut relay, &attacker, 11);
        let th = [9u8; 32];
        let genuine = b"GENUINE-CONNECT-REQUEST".to_vec();
        relay
            .submit_claim(&owner.address(), ClaimSubmission { token_hash: th, ciphertext: genuine.clone() })
            .unwrap();
        // Flood with distinct junk well past the cap.
        for i in 0..40u16 {
            let ct = vec![(i & 0xff) as u8; 8 + i as usize];
            relay
                .submit_claim(&attacker.address(), ClaimSubmission { token_hash: th, ciphertext: ct })
                .unwrap();
        }
        let got = relay.poll_claims(&owner.address(), &th).unwrap();
        assert!(got.len() <= DeliveryService::MAX_CLAIMS_PER_TOKEN);
        assert!(
            got.iter().any(|c| c.ciphertext == genuine),
            "genuine claim was evicted by squatting"
        );
    }

    /// CM2-B-A011 / B019: a session must be revocable — end_session drops it, and a
    /// session-gated call then fails closed. (The WS teardown + offboard both call this.)
    #[test]
    fn b019_session_is_revocable() {
        let owner = EthWallet::generate();
        let mut relay = DeliveryService::new("relay.citrate.ai", owner.address(), 0).unwrap();
        login(&mut relay, &owner, 10);
        assert!(relay.has_session(&owner.address()));
        relay
            .submit_claim(&owner.address(), ClaimSubmission { token_hash: [3u8; 32], ciphertext: vec![1] })
            .unwrap();
        relay.end_session(&owner.address());
        assert!(!relay.has_session(&owner.address()));
        let after = relay.submit_claim(
            &owner.address(),
            ClaimSubmission { token_hash: [3u8; 32], ciphertext: vec![2] },
        );
        assert!(matches!(after, Err(RelayError::NotAuthenticated)));
    }

    #[test]
    fn ciphertext_only_store_and_audit_verifies() {
        let alice = EthWallet::generate();
        let bob = EthWallet::generate();
        let mut relay = DeliveryService::new("relay.citrate.ai", alice.address(), 0).unwrap();
        login(&mut relay, &alice, 10);
        login(&mut relay, &bob, 11);

        let gid = GroupId([7; 32]);
        relay.register_group(gid, alice.address(), 12).unwrap();
        relay
            .onboard(
                gid,
                alice.address(),
                None,
                bob.address(),
                envelope(
                    gid,
                    alice.address(),
                    EnvelopeKind::Welcome,
                    1,
                    b"welcome-ct",
                    &[bob.address()],
                ),
                b"ratchet-tree".to_vec(),
                13,
            )
            .unwrap();

        let secret_plaintext = b"this is a secret message";
        let ct = b"OPAQUE-CIPHERTEXT-BLOB"; // stand-in ciphertext for the relay-only test
        relay
            .submit_as(
                alice.address(),
                envelope(
                    gid,
                    alice.address(),
                    EnvelopeKind::Application,
                    1,
                    ct,
                    &[bob.address()],
                ),
                14,
            )
            .unwrap();

        // The relay's durable store contains ciphertext only — never the plaintext.
        // The log holds the Welcome (durable) + the application envelope.
        let log = relay.group_log(&gid).unwrap();
        assert_eq!(log.len(), 2);
        for e in log {
            assert_ne!(e.ciphertext.as_slice(), secret_plaintext);
            assert!(e.group_seq.is_some());
        }
        assert!(log
            .iter()
            .any(|e| e.kind == EnvelopeKind::Application && e.ciphertext == ct));
        // Bob receives the fanned-out envelope.
        let inbox = relay.fetch(&bob.address());
        assert_eq!(
            inbox
                .iter()
                .filter(|e| e.kind == EnvelopeKind::Application)
                .count(),
            1
        );
        // The audit chain is intact offline.
        relay.audit().verify_integrity().unwrap();
    }

    #[test]
    fn first_writer_wins_per_epoch() {
        let alice = EthWallet::generate();
        let mut relay = DeliveryService::new("relay.citrate.ai", alice.address(), 0).unwrap();
        login(&mut relay, &alice, 1);
        let gid = GroupId([1; 32]);
        relay.register_group(gid, alice.address(), 2).unwrap();

        // First commit for epoch 1 is accepted.
        relay
            .submit_as(
                alice.address(),
                envelope(
                    gid,
                    alice.address(),
                    EnvelopeKind::Commit,
                    1,
                    b"commit-A",
                    &[],
                ),
                3,
            )
            .unwrap();
        // A DIFFERENT commit for the same epoch is rejected (no fork).
        let err = relay
            .submit_as(
                alice.address(),
                envelope(
                    gid,
                    alice.address(),
                    EnvelopeKind::Commit,
                    1,
                    b"commit-B",
                    &[],
                ),
                4,
            )
            .unwrap_err();
        assert!(matches!(
            err,
            RelayError::EpochAlreadyCommitted { epoch: 1 }
        ));
        // Re-submitting the IDENTICAL commit is idempotent (no error).
        relay
            .submit_as(
                alice.address(),
                envelope(
                    gid,
                    alice.address(),
                    EnvelopeKind::Commit,
                    1,
                    b"commit-A",
                    &[],
                ),
                5,
            )
            .unwrap();
    }

    #[test]
    fn unauthenticated_submit_is_rejected() {
        let alice = EthWallet::generate();
        let mut relay = DeliveryService::new("relay.citrate.ai", alice.address(), 0).unwrap();
        let gid = GroupId([1; 32]);
        // No login → register fails fail-closed.
        assert!(matches!(
            relay.register_group(gid, alice.address(), 1),
            Err(RelayError::NotAuthenticated)
        ));
    }

    #[test]
    fn persists_and_restarts() {
        let dir = tempfile::tempdir().unwrap();
        let alice = EthWallet::generate();
        let bob = EthWallet::generate();
        let gid = GroupId([5; 32]);
        let master = [1u8; 32];

        // First run: durable relay does a full onboard + message.
        {
            let mut relay =
                DeliveryService::open(dir.path(), "relay.citrate.ai", alice.address(), master, 0)
                    .unwrap();
            login(&mut relay, &alice, 10);
            login(&mut relay, &bob, 11);
            relay.register_group(gid, alice.address(), 12).unwrap();
            relay
                .onboard(
                    gid,
                    alice.address(),
                    None,
                    bob.address(),
                    envelope(
                        gid,
                        alice.address(),
                        EnvelopeKind::Welcome,
                        1,
                        b"welcome-ct",
                        &[bob.address()],
                    ),
                    b"ratchet-tree".to_vec(),
                    13,
                )
                .unwrap();
            relay
                .submit_as(
                    alice.address(),
                    envelope(
                        gid,
                        alice.address(),
                        EnvelopeKind::Application,
                        1,
                        b"CIPHERTEXT-BLOB",
                        &[bob.address()],
                    ),
                    14,
                )
                .unwrap();
            assert_eq!(relay.group_log(&gid).unwrap().len(), 2); // welcome + application
        }

        // Second run: reopen the SAME store — state replays from disk.
        {
            let relay =
                DeliveryService::open(dir.path(), "relay.citrate.ai", alice.address(), master, 999)
                    .unwrap();
            // Roster survived.
            let members = relay.group_members(&gid).unwrap();
            assert!(members.contains(&alice.address()) && members.contains(&bob.address()));
            // Ciphertext envelope log survived, in order, with assigned seqs.
            let log = relay.group_log(&gid).unwrap();
            assert_eq!(log.len(), 2);
            assert_eq!(log[0].group_seq, Some(0));
            assert_eq!(log[1].group_seq, Some(1));
            assert_eq!(log[1].ciphertext, b"CIPHERTEXT-BLOB");
            // Audit chain survived AND verifies offline (tamper-evident across restart).
            relay.audit().verify_integrity().unwrap();
            assert!(relay.audit().len() >= 4);
        }
    }

    #[test]
    fn non_member_cannot_submit() {
        let alice = EthWallet::generate();
        let mallory = EthWallet::generate();
        let mut relay = DeliveryService::new("relay.citrate.ai", alice.address(), 0).unwrap();
        login(&mut relay, &alice, 1);
        login(&mut relay, &mallory, 2);
        let gid = GroupId([1; 32]);
        relay.register_group(gid, alice.address(), 3).unwrap();
        // Mallory is authenticated but not a member.
        let err = relay
            .submit_as(
                mallory.address(),
                envelope(
                    gid,
                    mallory.address(),
                    EnvelopeKind::Application,
                    0,
                    b"x",
                    &[],
                ),
                4,
            )
            .unwrap_err();
        assert!(matches!(err, RelayError::NotAMember));
    }

    /// FWA-C11-01 (HIGH) red test — sender spoofing. Mallory and Alice are BOTH
    /// authenticated members of group G. Mallory submits an envelope whose
    /// `sender` field names *Alice*. The relay MUST bind the sender to the
    /// authenticated principal (Mallory) and reject the spoof — otherwise the
    /// audit receipt + fan-out would be attributed to Alice for a message
    /// Mallory authored, and Mallory would control Alice's recipient set.
    ///
    /// Mirrors `evidence/fwa_c11_sender_spoof.rs`. Before the fix this passed
    /// `require_session(Alice)` + `members.contains(Alice)` and was accepted &
    /// audited under Alice's identity. After the fix it is rejected.
    #[test]
    fn submit_binds_sender_to_authenticated_session() {
        let alice = EthWallet::generate();
        let mallory = EthWallet::generate();
        let mut relay = DeliveryService::new("relay.citrate.ai", alice.address(), 0).unwrap();
        login(&mut relay, &alice, 1);
        login(&mut relay, &mallory, 2);
        let gid = GroupId([9; 32]);
        relay.register_group(gid, alice.address(), 3).unwrap();
        // Onboard Mallory so she is a genuine member (so the rejection is on the
        // sender-binding, not on membership).
        relay
            .onboard(
                gid,
                alice.address(),
                None,
                mallory.address(),
                envelope(
                    gid,
                    alice.address(),
                    EnvelopeKind::Welcome,
                    1,
                    b"welcome",
                    &[mallory.address()],
                ),
                b"rt".to_vec(),
                4,
            )
            .unwrap();

        let audit_len_before = relay.audit().len();

        // Mallory (authed) tries to submit AS Alice (spoofed sender).
        let spoof = envelope(
            gid,
            alice.address(),
            EnvelopeKind::Application,
            1,
            b"FORGED",
            &[mallory.address()],
        );
        let err = relay.submit_as(mallory.address(), spoof, 5).unwrap_err();
        assert!(
            matches!(err, RelayError::SenderMismatch),
            "spoofed sender must be rejected, got {err:?}"
        );

        // Nothing was recorded under Alice's identity: no new audit receipt, no
        // forged envelope in the log.
        assert_eq!(
            relay.audit().len(),
            audit_len_before,
            "spoofed submit must not write an audit receipt"
        );
        let alice_forged = relay
            .group_log(&gid)
            .unwrap()
            .iter()
            .any(|e| e.kind == EnvelopeKind::Application && e.ciphertext == b"FORGED");
        assert!(
            !alice_forged,
            "forged envelope must not enter the durable log"
        );

        // And the honest path still works: Mallory submits as herself.
        let ok = envelope(
            gid,
            mallory.address(),
            EnvelopeKind::Application,
            1,
            b"HONEST",
            &[alice.address()],
        );
        relay.submit_as(mallory.address(), ok, 6).unwrap();
    }

    /// FWA-C11-03 (MED) red test — `onboard` must enforce RBAC. A plain member
    /// (here Mallory, a `Member` with no `AddMember` capability and no owner-signed
    /// grant) must NOT be able to drive `onboard` to insert an arbitrary joiner into
    /// the routing roster / overwrite the public ratchet tree. Owner-driven onboard
    /// (and onboard with a valid owner-signed `AddMember` grant) still works.
    #[test]
    fn onboard_requires_add_member_authorization() {
        use comms_proto::Role;
        let owner = EthWallet::generate(); // workspace owner / trust anchor
        let mallory = EthWallet::generate(); // a plain member
        let victim = EthWallet::generate(); // wallet Mallory tries to inject
        let mut relay = DeliveryService::new("relay.citrate.ai", owner.address(), 0).unwrap();
        login(&mut relay, &owner, 1);
        login(&mut relay, &mallory, 2);
        let gid = GroupId([3; 32]);
        relay.register_group(gid, owner.address(), 3).unwrap();
        // Owner onboards Mallory (legitimately).
        relay
            .onboard(
                gid,
                owner.address(),
                None,
                mallory.address(),
                envelope(
                    gid,
                    owner.address(),
                    EnvelopeKind::Welcome,
                    1,
                    b"w1",
                    &[mallory.address()],
                ),
                b"rt1".to_vec(),
                4,
            )
            .unwrap();

        // Mallory (a Member, no grant) tries to onboard the victim → rejected.
        let err = relay
            .onboard(
                gid,
                mallory.address(),
                None,
                victim.address(),
                envelope(
                    gid,
                    mallory.address(),
                    EnvelopeKind::Welcome,
                    1,
                    b"w2",
                    &[victim.address()],
                ),
                b"rt2".to_vec(),
                5,
            )
            .unwrap_err();
        assert!(
            matches!(err, RelayError::NotAuthorized),
            "non-owner without AddMember grant must be rejected, got {err:?}"
        );
        assert!(
            !relay
                .group_members(&gid)
                .unwrap()
                .contains(&victim.address()),
            "victim must NOT have entered the roster"
        );

        // With an owner-signed Admin grant (Admin holds AddMember), Mallory CAN onboard.
        let grant = rbac::sign_role_assertion(
            &owner,
            Role::Owner,
            mallory.address(),
            Role::Admin,
            None,
            None,
        )
        .unwrap();
        relay
            .onboard(
                gid,
                mallory.address(),
                Some(&grant),
                victim.address(),
                envelope(
                    gid,
                    mallory.address(),
                    EnvelopeKind::Welcome,
                    1,
                    b"w3",
                    &[victim.address()],
                ),
                b"rt3".to_vec(),
                6,
            )
            .unwrap();
        assert!(relay
            .group_members(&gid)
            .unwrap()
            .contains(&victim.address()));
    }

    /// Per-group creator RBAC — the wallet that CREATED a group is authorized for that
    /// group's membership ops (onboard + offboard) WITHOUT an owner-signed assertion,
    /// even though it is not the global workspace owner. This is the fix for
    /// "actor not authorized for this membership operation" on user-owned groups.
    #[test]
    fn creator_can_onboard_and_offboard_their_own_group() {
        let owner = EthWallet::generate(); // global workspace owner (trust anchor)
        let creator = EthWallet::generate(); // a normal user who creates a group
        let member = EthWallet::generate();
        let mut relay = DeliveryService::new("relay.citrate.ai", owner.address(), 0).unwrap();
        login(&mut relay, &owner, 1);
        login(&mut relay, &creator, 2);
        login(&mut relay, &member, 3);
        let gid = GroupId([10; 32]);
        relay.register_group(gid, creator.address(), 4).unwrap();

        // Creator onboards a member into their OWN group — no assertion.
        relay
            .onboard(
                gid,
                creator.address(),
                None,
                member.address(),
                envelope(
                    gid,
                    creator.address(),
                    EnvelopeKind::Welcome,
                    1,
                    b"w",
                    &[member.address()],
                ),
                b"rt".to_vec(),
                5,
            )
            .unwrap();
        assert!(
            relay.group_members(&gid).unwrap().contains(&member.address()),
            "the group creator must be able to onboard into their own group"
        );

        // Creator offboards the member — no assertion. The Remove commit is the group's
        // next contiguous epoch (group is at 0, so epoch 1).
        relay
            .offboard(
                OffboardRequest {
                    group_id: gid,
                    admin: creator.address(),
                    admin_assertion: None,
                    removed: member.address(),
                    remove_commit: envelope(
                        gid,
                        creator.address(),
                        EnvelopeKind::Commit,
                        1,
                        b"rm",
                        &[],
                    ),
                    ratchet_tree: b"rt2".to_vec(),
                },
                6,
            )
            .unwrap();
        assert!(
            !relay.group_members(&gid).unwrap().contains(&member.address()),
            "the group creator must be able to offboard from their own group"
        );
    }

    /// Per-group SCOPING — the creator of group A has NO authority in group B, even when
    /// they are an ordinary member of B. Authorization compares against THIS group's
    /// creator, never a global list.
    #[test]
    fn creator_of_group_a_is_rejected_in_group_b() {
        let owner = EthWallet::generate();
        let creator_a = EthWallet::generate();
        let creator_b = EthWallet::generate();
        let victim = EthWallet::generate();
        let mut relay = DeliveryService::new("relay.citrate.ai", owner.address(), 0).unwrap();
        login(&mut relay, &owner, 1);
        login(&mut relay, &creator_a, 2);
        login(&mut relay, &creator_b, 3);
        let gid_b = GroupId([12; 32]);
        relay.register_group(gid_b, creator_b.address(), 4).unwrap();
        // B's creator adds A's creator as an ordinary member of B (so the rejection below
        // is the AUTH check, not the membership check).
        relay
            .onboard(
                gid_b,
                creator_b.address(),
                None,
                creator_a.address(),
                envelope(
                    gid_b,
                    creator_b.address(),
                    EnvelopeKind::Welcome,
                    1,
                    b"w",
                    &[creator_a.address()],
                ),
                b"rt".to_vec(),
                5,
            )
            .unwrap();
        // creator_a is a MEMBER of B but not B's creator → must be rejected.
        let err = relay
            .onboard(
                gid_b,
                creator_a.address(),
                None,
                victim.address(),
                envelope(
                    gid_b,
                    creator_a.address(),
                    EnvelopeKind::Welcome,
                    1,
                    b"w2",
                    &[victim.address()],
                ),
                b"rt2".to_vec(),
                6,
            )
            .unwrap_err();
        assert!(
            matches!(err, RelayError::NotAuthorized),
            "creator of A must not be authorized in B, got {err:?}"
        );
        assert!(
            !relay.group_members(&gid_b).unwrap().contains(&victim.address()),
            "victim must NOT have entered group B's roster"
        );
    }

    /// A plain member of a creator-owned group (not creator, not owner, no assertion) is
    /// still rejected — the per-group-creator grant does not leak to other members.
    #[test]
    fn plain_member_of_a_creator_group_is_rejected() {
        let owner = EthWallet::generate();
        let creator = EthWallet::generate();
        let member = EthWallet::generate();
        let victim = EthWallet::generate();
        let mut relay = DeliveryService::new("relay.citrate.ai", owner.address(), 0).unwrap();
        login(&mut relay, &owner, 1);
        login(&mut relay, &creator, 2);
        login(&mut relay, &member, 3);
        let gid = GroupId([13; 32]);
        relay.register_group(gid, creator.address(), 4).unwrap();
        relay
            .onboard(
                gid,
                creator.address(),
                None,
                member.address(),
                envelope(
                    gid,
                    creator.address(),
                    EnvelopeKind::Welcome,
                    1,
                    b"w",
                    &[member.address()],
                ),
                b"rt".to_vec(),
                5,
            )
            .unwrap();
        let err = relay
            .onboard(
                gid,
                member.address(),
                None,
                victim.address(),
                envelope(
                    gid,
                    member.address(),
                    EnvelopeKind::Welcome,
                    1,
                    b"w2",
                    &[victim.address()],
                ),
                b"rt2".to_vec(),
                6,
            )
            .unwrap_err();
        assert!(
            matches!(err, RelayError::NotAuthorized),
            "a plain member (non-creator) must be rejected, got {err:?}"
        );
    }

    /// Backward-compat fallback — a group whose persisted snapshot predates the `creator`
    /// field (creator == None) authorizes ONLY the global owner, never a former creator,
    /// and must not panic. Also proves an old 5-field snapshot deserializes to None.
    #[test]
    fn creator_none_falls_back_to_owner_only() {
        // (a) An old on-disk snapshot (the exact 5 pre-change fields, no `creator`) must
        // still deserialize — ciborium encodes structs as maps, so the missing key is
        // filled by #[serde(default)] → None (this is the on-disk backward-compat path).
        #[derive(serde::Serialize)]
        struct OldSnapshot {
            members: Vec<WalletAddress>,
            current_epoch: u64,
            next_seq: u64,
            accepted_commit: Vec<(u64, [u8; 32])>,
            ratchet_tree: Vec<u8>,
        }
        let old = OldSnapshot {
            members: Vec::new(),
            current_epoch: 0,
            next_seq: 0,
            accepted_commit: Vec::new(),
            ratchet_tree: Vec::new(),
        };
        let bytes = canonical::to_vec(&old).unwrap();
        let snap: GroupSnapshot = canonical::from_slice(&bytes).unwrap();
        assert!(
            snap.creator.is_none(),
            "a pre-change snapshot must default creator to None (no decode error)"
        );

        // (b) A group with creator == None authorizes only the global owner.
        let owner = EthWallet::generate();
        let alice = EthWallet::generate(); // the would-be creator
        let victim = EthWallet::generate();
        let mut relay = DeliveryService::new("relay.citrate.ai", owner.address(), 0).unwrap();
        login(&mut relay, &owner, 1);
        login(&mut relay, &alice, 2);
        let gid = GroupId([14; 32]);
        relay.register_group(gid, alice.address(), 3).unwrap();
        // Alice (creator) adds the owner as a member, so we can show the owner path works
        // under the fallback; then we simulate a pre-change group by clearing `creator`.
        relay
            .onboard(
                gid,
                alice.address(),
                None,
                owner.address(),
                envelope(
                    gid,
                    alice.address(),
                    EnvelopeKind::Welcome,
                    1,
                    b"w0",
                    &[owner.address()],
                ),
                b"rt0".to_vec(),
                4,
            )
            .unwrap();
        relay.groups.get_mut(&gid).unwrap().creator = None;

        // Alice (would-be creator, now None) is no longer authorized without an assertion.
        let err = relay
            .onboard(
                gid,
                alice.address(),
                None,
                victim.address(),
                envelope(
                    gid,
                    alice.address(),
                    EnvelopeKind::Welcome,
                    1,
                    b"w1",
                    &[victim.address()],
                ),
                b"rt1".to_vec(),
                5,
            )
            .unwrap_err();
        assert!(
            matches!(err, RelayError::NotAuthorized),
            "creator=None must fall back to owner-only, got {err:?}"
        );
        // The global owner (a member) still can, under the fallback.
        relay
            .onboard(
                gid,
                owner.address(),
                None,
                victim.address(),
                envelope(
                    gid,
                    owner.address(),
                    EnvelopeKind::Welcome,
                    1,
                    b"w2",
                    &[victim.address()],
                ),
                b"rt2".to_vec(),
                6,
            )
            .unwrap();
        assert!(relay.group_members(&gid).unwrap().contains(&victim.address()));
    }

    /// CM2-B-A003 red→green — commit epochs MUST be contiguous. A member cannot
    /// squat a future epoch with junk to brick the group's membership machinery
    /// (which would also block their own offboard, making them unremovable).
    #[test]
    fn commit_epoch_must_be_contiguous() {
        let alice = EthWallet::generate();
        let mut relay = DeliveryService::new("relay.citrate.ai", alice.address(), 0).unwrap();
        login(&mut relay, &alice, 1);
        let gid = GroupId([4; 32]);
        relay.register_group(gid, alice.address(), 2).unwrap();

        // RED primitive (property P6): a Commit at `epoch = u64::MAX` for a group at
        // epoch 0 is now REJECTED. Before the fix it was accepted first-writer-wins
        // and persisted — squatting the epoch forever.
        let squat = relay
            .submit_as(
                alice.address(),
                envelope(
                    gid,
                    alice.address(),
                    EnvelopeKind::Commit,
                    u64::MAX,
                    b"junk",
                    &[],
                ),
                3,
            )
            .unwrap_err();
        assert!(
            matches!(squat, RelayError::NonContiguousEpoch { got, .. } if got == u64::MAX),
            "far-future commit must be refused, got {squat:?}"
        );

        // A merely-skipped epoch (2 while the group is at 0) is refused too.
        let skip = relay
            .submit_as(
                alice.address(),
                envelope(gid, alice.address(), EnvelopeKind::Commit, 2, b"skip", &[]),
                4,
            )
            .unwrap_err();
        assert!(
            matches!(
                skip,
                RelayError::NonContiguousEpoch {
                    expected: 1,
                    got: 2
                }
            ),
            "skipped epoch must be refused, got {skip:?}"
        );

        // GREEN: the genuine next epoch (exactly current+1) is accepted, and the one
        // after it — the squat never blocked them, so the group is not bricked.
        relay
            .submit_as(
                alice.address(),
                envelope(
                    gid,
                    alice.address(),
                    EnvelopeKind::Commit,
                    1,
                    b"commit-1",
                    &[],
                ),
                5,
            )
            .unwrap();
        relay
            .submit_as(
                alice.address(),
                envelope(
                    gid,
                    alice.address(),
                    EnvelopeKind::Commit,
                    2,
                    b"commit-2",
                    &[],
                ),
                6,
            )
            .unwrap();
    }

    /// CM2-B-A005 red→green — a submit's `recipients` must be a subset of the roster
    /// and the ciphertext bounded, so one member cannot fan a single submit out into
    /// unbounded non-member mailboxes (never drained) and OOM the single-droplet relay.
    #[test]
    fn recipients_must_be_a_subset_of_the_roster_and_bounded() {
        let alice = EthWallet::generate();
        let bob = EthWallet::generate();
        let stranger = EthWallet::generate(); // never a member of any group
        let mut relay = DeliveryService::new("relay.citrate.ai", alice.address(), 0).unwrap();
        login(&mut relay, &alice, 1);
        login(&mut relay, &bob, 2);
        let gid = GroupId([6; 32]);
        relay.register_group(gid, alice.address(), 3).unwrap();
        relay
            .onboard(
                gid,
                alice.address(),
                None,
                bob.address(),
                envelope(
                    gid,
                    alice.address(),
                    EnvelopeKind::Welcome,
                    1,
                    b"w",
                    &[bob.address()],
                ),
                b"rt".to_vec(),
                4,
            )
            .unwrap();

        // RED: a non-member recipient (an invented wallet) is rejected. Before the
        // fix this allocated a mailbox `deliver_pending` never drains.
        let err = relay
            .submit_as(
                alice.address(),
                envelope(
                    gid,
                    alice.address(),
                    EnvelopeKind::Application,
                    1,
                    b"x",
                    &[stranger.address()],
                ),
                5,
            )
            .unwrap_err();
        assert!(
            matches!(err, RelayError::RecipientNotAMember),
            "non-member recipient must be refused, got {err:?}"
        );

        // GREEN: an in-roster recipient is accepted.
        relay
            .submit_as(
                alice.address(),
                envelope(
                    gid,
                    alice.address(),
                    EnvelopeKind::Application,
                    1,
                    b"x",
                    &[bob.address()],
                ),
                6,
            )
            .unwrap();

        // And an oversized ciphertext is refused by the size cap.
        let huge = vec![0u8; DeliveryService::MAX_CIPHERTEXT_BYTES + 1];
        let big = relay
            .submit_as(
                alice.address(),
                envelope(
                    gid,
                    alice.address(),
                    EnvelopeKind::Application,
                    1,
                    &huge,
                    &[bob.address()],
                ),
                7,
            )
            .unwrap_err();
        assert!(
            matches!(big, RelayError::CiphertextTooLarge { .. }),
            "oversized ciphertext must be refused, got {big:?}"
        );
    }

    // ─────────────────── INVITE-S2 token-authorized self-admit ───────────────────

    /// Build a group owned by `owner` and return its id. The stored GroupInfo is opaque to
    /// the relay, so these relay-level tests use a stand-in blob (the MLS-level self-admit
    /// is proven in `comms-core::mls`; the full stack in the daemon's ws tests).
    fn owner_group(relay: &mut DeliveryService, owner: &EthWallet, gid: GroupId, now: u64) {
        relay.register_group(gid, owner.address(), now).unwrap();
    }

    #[test]
    fn invite_redeem_is_single_use_and_records_the_referral() {
        let owner = EthWallet::generate();
        let invitee = EthWallet::generate(); // authenticated, but NOT a member yet
        let mut relay = DeliveryService::new("relay.citrate.ai", owner.address(), 0).unwrap();
        login(&mut relay, &owner, 10);
        login(&mut relay, &invitee, 11);
        let gid = GroupId([21; 32]);
        owner_group(&mut relay, &owner, gid, 12);

        let token = b"invite-token-abc".to_vec();
        let token_hash = *blake3::hash(&token).as_bytes();
        let group_info = b"PUBLIC-GROUP-INFO-BLOB".to_vec();
        relay
            .publish_invite(owner.address(), gid, token_hash, group_info.clone(), u64::MAX)
            .unwrap();

        // First redeem: succeeds, returns the stored GroupInfo, adds the joiner to the roster.
        let (gi, _epoch) = relay
            .redeem_invite(invitee.address(), gid, &token, b"KP-BYTES", 100)
            .expect("first redeem succeeds");
        assert_eq!(gi, group_info, "redeem returns the stored public GroupInfo");
        assert!(
            relay.group_members(&gid).unwrap().contains(&invitee.address()),
            "redeemer joins the routing roster"
        );
        // Attribution recorded: inviter -> 1 distinct joiner.
        assert_eq!(relay.referral_count(), 1);
        assert_eq!(relay.referral_tally(), vec![(owner.address(), 1)]);

        // Second redeem of the SAME token: single-use → Consumed (a leaked link is now dead).
        let err = relay
            .redeem_invite(invitee.address(), gid, &token, b"KP-BYTES", 101)
            .unwrap_err();
        assert!(
            matches!(err, RelayError::InviteRedeem(RedeemError::Consumed)),
            "second redeem must fail closed as consumed, got {err:?}"
        );
        assert_eq!(relay.referral_count(), 1, "a refused redeem records no referral");
    }

    #[test]
    fn invite_expired_token_is_refused() {
        let owner = EthWallet::generate();
        let invitee = EthWallet::generate();
        let mut relay = DeliveryService::new("relay.citrate.ai", owner.address(), 0).unwrap();
        login(&mut relay, &owner, 10);
        login(&mut relay, &invitee, 11);
        let gid = GroupId([22; 32]);
        owner_group(&mut relay, &owner, gid, 12);
        let token = b"ttl-token".to_vec();
        let token_hash = *blake3::hash(&token).as_bytes();
        relay
            .publish_invite(owner.address(), gid, token_hash, b"GI".to_vec(), 1_000)
            .unwrap();
        // now (2_000) is past expires_at (1_000).
        let err = relay
            .redeem_invite(invitee.address(), gid, &token, b"KP", 2_000)
            .unwrap_err();
        assert!(
            matches!(err, RelayError::InviteRedeem(RedeemError::Expired)),
            "expired token must be refused, got {err:?}"
        );
    }

    #[test]
    fn invite_revoked_token_is_refused_and_only_minter_may_revoke() {
        let owner = EthWallet::generate();
        let invitee = EthWallet::generate();
        let mut relay = DeliveryService::new("relay.citrate.ai", owner.address(), 0).unwrap();
        login(&mut relay, &owner, 10);
        login(&mut relay, &invitee, 11);
        let gid = GroupId([23; 32]);
        owner_group(&mut relay, &owner, gid, 12);
        let token = b"revoke-token".to_vec();
        let token_hash = *blake3::hash(&token).as_bytes();
        relay
            .publish_invite(owner.address(), gid, token_hash, b"GI".to_vec(), u64::MAX)
            .unwrap();

        // A non-minter cannot revoke.
        let denied = relay.revoke_invite(invitee.address(), token_hash).unwrap_err();
        assert!(matches!(denied, RelayError::NotAuthorized), "got {denied:?}");

        // The minter revokes → redeem then fails closed.
        relay.revoke_invite(owner.address(), token_hash).unwrap();
        let err = relay
            .redeem_invite(invitee.address(), gid, &token, b"KP", 100)
            .unwrap_err();
        assert!(
            matches!(err, RelayError::InviteRedeem(RedeemError::Revoked)),
            "revoked token must be refused, got {err:?}"
        );
    }

    #[test]
    fn invite_unknown_token_wrong_group_and_bad_key_package_are_refused() {
        let owner = EthWallet::generate();
        let invitee = EthWallet::generate();
        let mut relay = DeliveryService::new("relay.citrate.ai", owner.address(), 0).unwrap();
        login(&mut relay, &owner, 10);
        login(&mut relay, &invitee, 11);
        let gid = GroupId([24; 32]);
        let other = GroupId([99; 32]);
        owner_group(&mut relay, &owner, gid, 12);
        owner_group(&mut relay, &owner, other, 13);
        let token = b"known-token".to_vec();
        let token_hash = *blake3::hash(&token).as_bytes();
        relay
            .publish_invite(owner.address(), gid, token_hash, b"GI".to_vec(), u64::MAX)
            .unwrap();

        // Unknown token.
        let unknown = relay
            .redeem_invite(invitee.address(), gid, b"never-minted", b"KP", 100)
            .unwrap_err();
        assert!(matches!(unknown, RelayError::InviteRedeem(RedeemError::UnknownToken)));

        // Known token, WRONG group (group-bound) → UnknownToken (fail closed).
        let wrong_group = relay
            .redeem_invite(invitee.address(), other, &token, b"KP", 100)
            .unwrap_err();
        assert!(matches!(
            wrong_group,
            RelayError::InviteRedeem(RedeemError::UnknownToken)
        ));

        // Empty KeyPackage → InvalidKeyPackage (structural bound; the relay never parses MLS).
        let bad_kp = relay
            .redeem_invite(invitee.address(), gid, &token, b"", 100)
            .unwrap_err();
        assert!(matches!(
            bad_kp,
            RelayError::InviteRedeem(RedeemError::InvalidKeyPackage)
        ));

        // None of the refusals consumed the invite: the genuine redeem still works.
        relay
            .redeem_invite(invitee.address(), gid, &token, b"KP", 100)
            .expect("the invite survived every refused attempt");
    }

    #[test]
    fn non_member_cannot_mint_an_invite() {
        let owner = EthWallet::generate();
        let stranger = EthWallet::generate(); // authenticated, not a member of the group
        let mut relay = DeliveryService::new("relay.citrate.ai", owner.address(), 0).unwrap();
        login(&mut relay, &owner, 10);
        login(&mut relay, &stranger, 11);
        let gid = GroupId([25; 32]);
        owner_group(&mut relay, &owner, gid, 12);
        let err = relay
            .publish_invite(stranger.address(), gid, [7; 32], b"GI".to_vec(), u64::MAX)
            .unwrap_err();
        assert!(matches!(err, RelayError::NotAMember), "got {err:?}");
    }

    #[test]
    fn invites_and_referrals_survive_restart_single_use_intact() {
        let dir = tempfile::tempdir().unwrap();
        let owner = EthWallet::generate();
        let invitee = EthWallet::generate();
        let gid = GroupId([26; 32]);
        let master = [4u8; 32];
        let token = b"durable-token".to_vec();
        let token_hash = *blake3::hash(&token).as_bytes();

        {
            let mut relay =
                DeliveryService::open(dir.path(), "relay.citrate.ai", owner.address(), master, 0)
                    .unwrap();
            login(&mut relay, &owner, 10);
            login(&mut relay, &invitee, 11);
            relay.register_group(gid, owner.address(), 12).unwrap();
            relay
                .publish_invite(owner.address(), gid, token_hash, b"GI-DURABLE".to_vec(), u64::MAX)
                .unwrap();
            relay
                .redeem_invite(invitee.address(), gid, &token, b"KP", 100)
                .expect("redeem before restart");
            assert_eq!(relay.referral_count(), 1);
        }

        // Reopen the SAME store: the consumed invite + the referral replay from disk.
        {
            let relay =
                DeliveryService::open(dir.path(), "relay.citrate.ai", owner.address(), master, 999)
                    .unwrap();
            assert_eq!(relay.referral_count(), 1, "referral survived restart");
            assert_eq!(relay.referral_tally(), vec![(owner.address(), 1)]);
            assert!(
                relay.group_members(&gid).unwrap().contains(&invitee.address()),
                "the redeemer's roster membership survived restart"
            );
        }

        // A redeem AFTER restart must still see the invite as consumed (no single-use replay).
        {
            let mut relay =
                DeliveryService::open(dir.path(), "relay.citrate.ai", owner.address(), master, 1000)
                    .unwrap();
            login(&mut relay, &invitee, 1001);
            let err = relay
                .redeem_invite(invitee.address(), gid, &token, b"KP", 1002)
                .unwrap_err();
            assert!(
                matches!(err, RelayError::InviteRedeem(RedeemError::Consumed)),
                "single-use must survive restart, got {err:?}"
            );
        }
    }
}
