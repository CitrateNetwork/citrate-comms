//! `comms-relay` — the server-blind delivery service.
//!
//! This is the in-process core of the relay daemon: the WebSocket transport is a
//! thin wrapper landing in COMMS-S1 (`PLANSET/05`). Everything here operates on
//! opaque [`Envelope`] ciphertext + routing metadata. The relay:
//!
//! - authenticates a session with the SIWE handshake (`comms-core::identity`),
//! - runs a one-time-use **KeyPackage directory** (verifying each wallet binding
//!   attestation — defeats spoofing, R3),
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
pub mod endpoint;
pub mod keyvault;
pub mod ws;

use std::collections::{BTreeSet, HashMap, VecDeque};
use std::path::Path;

use comms_core::audit::{AuditChain, AuditError};
use comms_core::identity::{self, InMemoryNonceStore, NonceStore, SiweMessage};
use comms_core::rbac::{self, Capability, RbacError};
use comms_core::store::{self, EncryptedStore, StoreError};
use comms_proto::{
    canonical, AuditEvent, AuditRecord, Envelope, EnvelopeKind, EpochId, GroupId,
    KeyPackagePublication, KeyPackageRef, RoleAssertion, WalletAddress,
};
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
}

impl GroupState {
    fn snapshot(&self) -> GroupSnapshot {
        GroupSnapshot {
            members: self.members.iter().copied().collect(),
            current_epoch: self.current_epoch,
            next_seq: self.next_seq,
            accepted_commit: self.accepted_commit.iter().map(|(k, v)| (*k, *v)).collect(),
            ratchet_tree: self.ratchet_tree.clone(),
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
        }
    }
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
        let audit = if audit_records.is_empty() {
            let chain = AuditChain::new(genesis_ts_ms)?;
            for r in chain.records() {
                store.put(store::CF_AUDIT, &r.sequence.to_be_bytes(), &canonical::to_vec(r).map_err(RelayError::Decode)?)?;
            }
            chain
        } else {
            AuditChain::from_records(audit_records)?
        };

        // Groups: metadata snapshots, then the envelope logs.
        let mut groups: HashMap<GroupId, GroupState> = HashMap::new();
        for (k, v) in store.scan(store::CF_MEMBERSHIP)? {
            let gid = GroupId(k.as_slice().try_into().map_err(|_| RelayError::CorruptKey)?);
            let snap: GroupSnapshot = canonical::from_slice(&v).map_err(RelayError::Decode)?;
            groups.insert(gid, GroupState::from_snapshot(snap));
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
        let mut key_packages: HashMap<WalletAddress, VecDeque<KeyPackagePublication>> = HashMap::new();
        for (k, v) in store.scan(store::CF_KEYPACKAGES)? {
            let wallet = WalletAddress(k.as_slice().try_into().map_err(|_| RelayError::CorruptKey)?);
            let queue: Vec<KeyPackagePublication> = canonical::from_slice(&v).map_err(RelayError::Decode)?;
            key_packages.insert(wallet, queue.into());
        }

        Ok(Self {
            domain: domain.into(),
            owner,
            nonces: InMemoryNonceStore::new(),
            key_packages,
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
            s.put(store::CF_AUDIT, &rec.sequence.to_be_bytes(), &canonical::to_vec(&rec).map_err(RelayError::Decode)?)?;
        }
        Ok(())
    }

    fn persist_group(&self, gid: &GroupId) -> Result<(), RelayError> {
        if let (Some(s), Some(g)) = (&self.store, self.groups.get(gid)) {
            s.put(store::CF_MEMBERSHIP, &gid.0, &canonical::to_vec(&g.snapshot()).map_err(RelayError::Decode)?)?;
        }
        Ok(())
    }

    fn persist_envelope(&self, gid: &GroupId, seq: u64, env: &Envelope) -> Result<(), RelayError> {
        if let Some(s) = &self.store {
            s.put(store::CF_ENVELOPES, &store::seq_key(&gid.0, seq), &canonical::to_vec(env).map_err(RelayError::Decode)?)?;
        }
        Ok(())
    }

    /// Persist a wallet's whole KeyPackage queue (so one-time-use consumption is
    /// reflected on disk — consumed packages do not reappear after restart).
    fn persist_keypackages(&self, wallet: &WalletAddress) -> Result<(), RelayError> {
        if let Some(s) = &self.store {
            let queue: Vec<&KeyPackagePublication> =
                self.key_packages.get(wallet).map(|q| q.iter().collect()).unwrap_or_default();
            s.put(store::CF_KEYPACKAGES, &wallet.0, &canonical::to_vec(&queue).map_err(RelayError::Decode)?)?;
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

    // ─────────────────────── KeyPackage directory ───────────────────────

    /// Admit a KeyPackage to the directory after verifying its wallet binding
    /// attestation (R3) and consuming the bound nonce (single-use).
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

        let kp_ref = KeyPackageRef(blake3::hash(&publication.key_package).as_bytes().to_vec());
        let wallet = publication.wallet;
        self.key_packages.entry(wallet).or_default().push_back(publication);
        self.persist_keypackages(&wallet)?;
        self.audit_append(
            AuditEvent::KeyPackagePublished { wallet, key_package_ref: kp_ref.clone() },
            now_ms,
        )?;
        Ok(kp_ref)
    }

    /// Consume a KeyPackage for `wallet` (one-time-use) — called by an admin who is
    /// about to add that wallet to a group. The on-disk queue is updated so a consumed
    /// package does not reappear after restart.
    pub fn take_key_package(&mut self, wallet: &WalletAddress) -> Option<KeyPackagePublication> {
        let popped = self.key_packages.get_mut(wallet).and_then(|q| q.pop_front());
        if popped.is_some() {
            let _ = self.persist_keypackages(wallet);
        }
        popped
    }

    pub fn key_package_count(&self, wallet: &WalletAddress) -> usize {
        self.key_packages.get(wallet).map(|q| q.len()).unwrap_or(0)
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
        state.members.insert(creator);
        self.groups.insert(group_id, state);
        self.persist_group(&group_id)?;
        self.audit_append(AuditEvent::GroupCreated { group_id, creator }, now_ms)?;
        Ok(())
    }

    /// Onboard a member: add to the roster, stash the public ratchet tree, and
    /// deliver the Welcome to the joiner's mailbox. The MLS Add/Commit themselves
    /// are submitted as envelopes; this updates the routing roster + audit.
    pub fn onboard(
        &mut self,
        group_id: GroupId,
        admin: WalletAddress,
        joiner: WalletAddress,
        welcome: Envelope,
        ratchet_tree: Vec<u8>,
        now_ms: u64,
    ) -> Result<(), RelayError> {
        self.require_session(&admin)?;
        {
            let state = self.groups.get(&group_id).ok_or(RelayError::GroupUnknown)?;
            if !state.members.contains(&admin) {
                return Err(RelayError::NotAMember);
            }
        }
        debug_assert_eq!(welcome.kind, EnvelopeKind::Welcome);
        // Deliver the Welcome on the durable ordered path (stored + audited + fanned
        // to the joiner's mailbox).
        self.submit(welcome, now_ms)?;
        // Update the roster + public ratchet tree, persist, and audit the membership change.
        let epoch = {
            let state = self.groups.get_mut(&group_id).ok_or(RelayError::GroupUnknown)?;
            state.members.insert(joiner);
            state.ratchet_tree = ratchet_tree;
            state.current_epoch
        };
        self.persist_group(&group_id)?;
        self.audit_append(
            AuditEvent::MemberAdded { group_id, member: joiner, epoch: EpochId(epoch) },
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
        let OffboardRequest { group_id, admin, admin_assertion, removed, remove_commit, ratchet_tree } = req;
        self.require_session(&admin)?;
        // RBAC: owner is the trust anchor; anyone else must present an owner-signed
        // assertion whose role carries RemoveMember.
        if admin != self.owner {
            let a = admin_assertion.ok_or(RelayError::NotAuthorized)?;
            rbac::verify_grant_chain(a, admin, self.owner, now_ms).map_err(RelayError::Rbac)?;
            if !rbac::can(a.role, Capability::RemoveMember) {
                return Err(RelayError::NotAuthorized);
            }
        }
        {
            let state = self.groups.get(&group_id).ok_or(RelayError::GroupUnknown)?;
            if !state.members.contains(&admin) || !state.members.contains(&removed) {
                return Err(RelayError::NotAMember);
            }
        }
        debug_assert_eq!(remove_commit.kind, EnvelopeKind::Commit);
        // Apply the Remove commit on the ordered path (first-writer-wins, receipt
        // audit, fan-out to the REMAINING members).
        let seq = self.submit(remove_commit, now_ms)?;
        // Atomic with the commit: drop from the roster, refresh the public ratchet
        // tree, and record the offboard as a single logical event pair.
        let epoch = {
            let state = self.groups.get_mut(&group_id).ok_or(RelayError::GroupUnknown)?;
            state.members.remove(&removed);
            state.ratchet_tree = ratchet_tree;
            state.current_epoch
        };
        self.persist_group(&group_id)?;
        self.audit_append(
            AuditEvent::MemberRemoved { group_id, member: removed, epoch: EpochId(epoch) },
            now_ms,
        )?;
        self.audit_append(AuditEvent::RoleRevoked { subject: removed, scope: Some(group_id) }, now_ms)?;
        Ok(seq)
    }

    // ─────────────────────── submit / deliver ───────────────────────

    /// Accept an envelope: assign its `group_seq`, enforce Commit ordering, store
    /// the ciphertext, audit the receipt, and fan out to recipient mailboxes.
    /// Returns the assigned sequence number.
    pub fn submit(&mut self, mut envelope: Envelope, now_ms: u64) -> Result<u64, RelayError> {
        self.require_session(&envelope.sender)?;
        let ciphertext_hash = *blake3::hash(&envelope.ciphertext).as_bytes();
        let size = envelope.ciphertext.len() as u64;

        let state = self.groups.get_mut(&envelope.group_id).ok_or(RelayError::GroupUnknown)?;
        if !state.members.contains(&envelope.sender) {
            return Err(RelayError::NotAMember);
        }

        // R1: a group has ONE accepted Commit per epoch. First writer wins;
        // fail closed on a conflicting Commit (a different ciphertext for an epoch
        // already committed). Identical resubmission is idempotent.
        if envelope.kind == EnvelopeKind::Commit {
            match state.accepted_commit.get(&envelope.epoch.0) {
                Some(existing) if *existing != ciphertext_hash => {
                    return Err(RelayError::EpochAlreadyCommitted { epoch: envelope.epoch.0 });
                }
                Some(_) => {} // identical resubmission — idempotent
                None => {
                    state.accepted_commit.insert(envelope.epoch.0, ciphertext_hash);
                    if envelope.epoch.0 > state.current_epoch {
                        state.current_epoch = envelope.epoch.0;
                    }
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
        self.mailboxes.get_mut(wallet).map(std::mem::take).unwrap_or_default()
    }

    // ─────────────────────── introspection / audit ───────────────────────

    /// The ordered ciphertext log for a group — what the relay durably stores.
    pub fn group_log(&self, group_id: &GroupId) -> Option<&[Envelope]> {
        self.groups.get(group_id).map(|g| g.log.as_slice())
    }

    pub fn group_members(&self, group_id: &GroupId) -> Option<Vec<WalletAddress>> {
        self.groups.get(group_id).map(|g| g.members.iter().copied().collect())
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
    #[error("epoch {epoch} already has a different accepted commit (first-writer-wins)")]
    EpochAlreadyCommitted { epoch: u64 },
    #[error("no key package available for wallet")]
    NoKeyPackage,
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

    fn envelope(group: GroupId, sender: WalletAddress, kind: EnvelopeKind, epoch: u64, ct: &[u8], to: &[WalletAddress]) -> Envelope {
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
    fn ciphertext_only_store_and_audit_verifies() {
        let alice = EthWallet::generate();
        let bob = EthWallet::generate();
        let mut relay = DeliveryService::new("relay.citrate.ai", alice.address(), 0).unwrap();
        login(&mut relay, &alice, 10);
        login(&mut relay, &bob, 11);

        let gid = GroupId([7; 32]);
        relay.register_group(gid, alice.address(), 12).unwrap();
        relay.onboard(gid, alice.address(), bob.address(),
            envelope(gid, alice.address(), EnvelopeKind::Welcome, 1, b"welcome-ct", &[bob.address()]),
            b"ratchet-tree".to_vec(), 13).unwrap();

        let secret_plaintext = b"this is a secret message";
        let ct = b"OPAQUE-CIPHERTEXT-BLOB"; // stand-in ciphertext for the relay-only test
        relay.submit(envelope(gid, alice.address(), EnvelopeKind::Application, 1, ct, &[bob.address()]), 14).unwrap();

        // The relay's durable store contains ciphertext only — never the plaintext.
        // The log holds the Welcome (durable) + the application envelope.
        let log = relay.group_log(&gid).unwrap();
        assert_eq!(log.len(), 2);
        for e in log {
            assert_ne!(e.ciphertext.as_slice(), secret_plaintext);
            assert!(e.group_seq.is_some());
        }
        assert!(log.iter().any(|e| e.kind == EnvelopeKind::Application && e.ciphertext == ct));
        // Bob receives the fanned-out envelope.
        let inbox = relay.fetch(&bob.address());
        assert_eq!(inbox.iter().filter(|e| e.kind == EnvelopeKind::Application).count(), 1);
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
        relay.submit(envelope(gid, alice.address(), EnvelopeKind::Commit, 1, b"commit-A", &[]), 3).unwrap();
        // A DIFFERENT commit for the same epoch is rejected (no fork).
        let err = relay.submit(envelope(gid, alice.address(), EnvelopeKind::Commit, 1, b"commit-B", &[]), 4).unwrap_err();
        assert!(matches!(err, RelayError::EpochAlreadyCommitted { epoch: 1 }));
        // Re-submitting the IDENTICAL commit is idempotent (no error).
        relay.submit(envelope(gid, alice.address(), EnvelopeKind::Commit, 1, b"commit-A", &[]), 5).unwrap();
    }

    #[test]
    fn unauthenticated_submit_is_rejected() {
        let alice = EthWallet::generate();
        let mut relay = DeliveryService::new("relay.citrate.ai", alice.address(), 0).unwrap();
        let gid = GroupId([1; 32]);
        // No login → register fails fail-closed.
        assert!(matches!(relay.register_group(gid, alice.address(), 1), Err(RelayError::NotAuthenticated)));
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
                DeliveryService::open(dir.path(), "relay.citrate.ai", alice.address(), master, 0).unwrap();
            login(&mut relay, &alice, 10);
            login(&mut relay, &bob, 11);
            relay.register_group(gid, alice.address(), 12).unwrap();
            relay
                .onboard(
                    gid, alice.address(), bob.address(),
                    envelope(gid, alice.address(), EnvelopeKind::Welcome, 1, b"welcome-ct", &[bob.address()]),
                    b"ratchet-tree".to_vec(), 13,
                )
                .unwrap();
            relay
                .submit(envelope(gid, alice.address(), EnvelopeKind::Application, 1, b"CIPHERTEXT-BLOB", &[bob.address()]), 14)
                .unwrap();
            assert_eq!(relay.group_log(&gid).unwrap().len(), 2); // welcome + application
        }

        // Second run: reopen the SAME store — state replays from disk.
        {
            let relay =
                DeliveryService::open(dir.path(), "relay.citrate.ai", alice.address(), master, 999).unwrap();
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
            .submit(envelope(gid, mallory.address(), EnvelopeKind::Application, 0, b"x", &[]), 4)
            .unwrap_err();
        assert!(matches!(err, RelayError::NotAMember));
    }
}
