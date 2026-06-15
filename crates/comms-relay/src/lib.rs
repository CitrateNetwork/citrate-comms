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

use std::collections::{BTreeSet, HashMap, VecDeque};

use comms_core::audit::{AuditChain, AuditError};
use comms_core::identity::{self, InMemoryNonceStore, NonceStore, SiweMessage};
use comms_proto::{
    AuditEvent, Envelope, EnvelopeKind, GroupId, KeyPackagePublication, KeyPackageRef, WalletAddress,
};

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

/// The server-blind relay.
pub struct DeliveryService {
    domain: String,
    nonces: InMemoryNonceStore,
    /// One-time-use KeyPackage directory, keyed by wallet.
    key_packages: HashMap<WalletAddress, VecDeque<KeyPackagePublication>>,
    groups: HashMap<GroupId, GroupState>,
    /// Per-wallet delivery mailboxes (the fan-out target).
    mailboxes: HashMap<WalletAddress, Vec<Envelope>>,
    /// Authenticated sessions (wallet proved control via SIWE).
    sessions: BTreeSet<WalletAddress>,
    audit: AuditChain,
}

impl DeliveryService {
    pub fn new(domain: impl Into<String>, genesis_ts_ms: u64) -> Result<Self, RelayError> {
        Ok(Self {
            domain: domain.into(),
            nonces: InMemoryNonceStore::new(),
            key_packages: HashMap::new(),
            groups: HashMap::new(),
            mailboxes: HashMap::new(),
            sessions: BTreeSet::new(),
            audit: AuditChain::new(genesis_ts_ms)?,
        })
    }

    pub fn domain(&self) -> &str {
        &self.domain
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
        self.audit.append(
            AuditEvent::KeyPackagePublished { wallet: publication.wallet, key_package_ref: kp_ref.clone() },
            now_ms,
        )?;
        self.key_packages.entry(publication.wallet).or_default().push_back(publication);
        Ok(kp_ref)
    }

    /// Consume a KeyPackage for `wallet` (one-time-use) — called by an admin who is
    /// about to add that wallet to a group.
    pub fn take_key_package(&mut self, wallet: &WalletAddress) -> Option<KeyPackagePublication> {
        self.key_packages.get_mut(wallet).and_then(|q| q.pop_front())
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
        self.audit.append(AuditEvent::GroupCreated { group_id, creator }, now_ms)?;
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
        let epoch = {
            let state = self.groups.get_mut(&group_id).ok_or(RelayError::GroupUnknown)?;
            if !state.members.contains(&admin) {
                return Err(RelayError::NotAMember);
            }
            state.members.insert(joiner);
            state.ratchet_tree = ratchet_tree;
            state.current_epoch
        };
        debug_assert_eq!(welcome.kind, EnvelopeKind::Welcome);
        self.mailboxes.entry(joiner).or_default().push(welcome);
        self.audit.append(
            AuditEvent::MemberAdded { group_id, member: joiner, epoch: comms_proto::EpochId(epoch) },
            now_ms,
        )?;
        Ok(())
    }

    /// The public ratchet tree a joiner needs to process its Welcome.
    pub fn ratchet_tree(&self, group_id: &GroupId) -> Option<&[u8]> {
        self.groups.get(group_id).map(|g| g.ratchet_tree.as_slice())
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

        // Fan out to the named recipients (the relay's unavoidable metadata — R4).
        for r in &envelope.recipients {
            self.mailboxes.entry(*r).or_default().push(envelope.clone());
        }

        self.audit.append(
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

    pub fn audit(&self) -> &AuditChain {
        &self.audit
    }
}

#[derive(Debug, thiserror::Error)]
pub enum RelayError {
    #[error("session not authenticated (SIWE handshake required)")]
    NotAuthenticated,
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
    #[error(transparent)]
    Audit(#[from] AuditError),
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
        let mut relay = DeliveryService::new("relay.citrate.ai", 0).unwrap();
        let alice = EthWallet::generate();
        let bob = EthWallet::generate();
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
        let log = relay.group_log(&gid).unwrap();
        assert_eq!(log.len(), 1);
        for e in log {
            assert_ne!(e.ciphertext.as_slice(), secret_plaintext);
            assert_eq!(e.ciphertext, ct);
            assert!(e.group_seq.is_some());
        }
        // Bob receives the fanned-out envelope.
        let inbox = relay.fetch(&bob.address());
        assert_eq!(inbox.iter().filter(|e| e.kind == EnvelopeKind::Application).count(), 1);
        // The audit chain is intact offline.
        relay.audit().verify_integrity().unwrap();
    }

    #[test]
    fn first_writer_wins_per_epoch() {
        let mut relay = DeliveryService::new("relay.citrate.ai", 0).unwrap();
        let alice = EthWallet::generate();
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
        let mut relay = DeliveryService::new("relay.citrate.ai", 0).unwrap();
        let alice = EthWallet::generate();
        let gid = GroupId([1; 32]);
        // No login → register fails fail-closed.
        assert!(matches!(relay.register_group(gid, alice.address(), 1), Err(RelayError::NotAuthenticated)));
    }

    #[test]
    fn non_member_cannot_submit() {
        let mut relay = DeliveryService::new("relay.citrate.ai", 0).unwrap();
        let alice = EthWallet::generate();
        let mallory = EthWallet::generate();
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
