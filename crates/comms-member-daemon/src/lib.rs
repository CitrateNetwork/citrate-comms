//! citrate-comms member daemon — the core.
//!
//! Runs a **wallet-owned MLS member** plus an **in-process server-blind relay** ([`DeliveryService`])
//! in one process, and (in the binary) exposes a loopback UDS JSON IPC. This is the member-client
//! sidecar for citrate-core Commons: the heavy MLS + relay tree lives HERE, so `src-tauri` stays lean
//! (it links no comms crate — it just spawns this daemon and speaks light JSON over a socket).
//!
//! Increment 1 (this module): the owner's group lifecycle — create a group, add a member (real MLS
//! commit + welcome), send an encrypted message, and decrypt inbound messages from members. The MLS
//! orchestration mirrors the working reference in `comms-client::backend` (bootstrap), generalized
//! into a driven daemon. Cross-process member join (a remote joiner fetching welcome/tree from the
//! relay), the UDS server, and RBAC roster/remove are the next increments.
//!
//! Single-owner note: the relay excludes the sender from delivery, so a lone owner's messages are
//! not echoed back — meaningful traffic requires ≥2 members, which the round-trip test exercises.

use comms_core::identity::{EthWallet, SiweMessage};
use comms_core::mls::{GroupHandle, MlsMember};
use comms_proto::{
    Envelope, EnvelopeKind, EpochId, GroupId, KeyPackagePublication, WalletAddress, CITRATE_CHAIN_ID,
};
use comms_relay::DeliveryService;

pub mod ipc;
pub mod server;

/// A member-daemon error. `Display` is safe to surface over the IPC.
#[derive(Debug, thiserror::Error)]
pub enum DaemonError {
    #[error("relay error: {0}")]
    Relay(String),
    #[error("mls error: {0}")]
    Mls(String),
    #[error("no such group: {0}")]
    NoGroup(String),
    #[error("no key package published for {0}")]
    NoKeyPackage(String),
    #[error("invalid utf-8 in a decrypted message")]
    BadUtf8,
}

/// The welcome material a newly-added member needs to join (returned so a joiner — cross-process in
/// a later increment, or the round-trip test now — can complete the join).
#[derive(Debug, Clone)]
pub struct AddResult {
    pub member: WalletAddress,
    pub welcome: Vec<u8>,
    pub ratchet_tree: Vec<u8>,
}

/// A decrypted inbound message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Msg {
    pub group: GroupId,
    pub sender: WalletAddress,
    pub body: String,
}

/// Per-group MLS state the daemon owns.
struct GroupState {
    id: GroupId,
    name: String,
    handle: GroupHandle,
    /// Current epoch (bumped on each membership commit).
    epoch: u64,
    /// Members including the owner (recipients derive from this).
    members: Vec<WalletAddress>,
}

/// The member daemon: the owner's wallet + MLS identity, the in-process relay, and the owner's
/// groups.
pub struct MemberDaemon {
    domain: String,
    wallet: EthWallet,
    mls: MlsMember,
    relay: DeliveryService,
    groups: Vec<GroupState>,
    /// A monotonically-advancing clock (ms) so SIWE nonces/challenges stay fresh across ops.
    now: u64,
}

impl MemberDaemon {
    /// Bring up the daemon for `wallet`: mint the MLS identity, open the in-process relay owned by
    /// this wallet, authenticate (SIWE), and publish the owner's key package. `now` seeds the clock.
    pub fn new(wallet: EthWallet, domain: impl Into<String>, now: u64) -> Result<Self, DaemonError> {
        let domain = domain.into();
        let mls = MlsMember::new(&wallet.address().0).map_err(|e| DaemonError::Mls(e.to_string()))?;
        let mut relay = DeliveryService::new(&domain, wallet.address(), 0)
            .map_err(|e| DaemonError::Relay(e.to_string()))?;
        let mut d_now = now;
        login(&mut relay, &wallet, &domain, d_now)?;
        d_now += 1;
        publish_kp(&mut relay, &wallet, &mls, &domain, d_now)?;
        Ok(MemberDaemon {
            domain,
            wallet,
            mls,
            relay,
            groups: Vec::new(),
            now: d_now + 1,
        })
    }

    /// The owner's wallet address.
    pub fn owner(&self) -> WalletAddress {
        self.wallet.address()
    }

    fn tick(&mut self) -> u64 {
        self.now += 1;
        self.now
    }

    /// Create a group owned by this member. Returns its stable [`GroupId`].
    pub fn create_group(&mut self, name: impl Into<String>) -> Result<GroupId, DaemonError> {
        let handle = self
            .mls
            .create_group()
            .map_err(|e| DaemonError::Mls(e.to_string()))?;
        let gid = GroupId(*blake3::hash(&handle.group_id()).as_bytes());
        let now = self.tick();
        self.relay
            .register_group(gid, self.wallet.address(), now)
            .map_err(|e| DaemonError::Relay(e.to_string()))?;
        self.groups.push(GroupState {
            id: gid,
            name: name.into(),
            handle,
            epoch: 0,
            members: vec![self.wallet.address()],
        });
        Ok(gid)
    }

    /// The owner's groups, as `(id, name)`.
    pub fn list_groups(&self) -> Vec<(GroupId, String)> {
        self.groups.iter().map(|g| (g.id, g.name.clone())).collect()
    }

    /// Add `member` to `gid`. Requires the member to have published a key package to the relay
    /// (they do so on their own startup). Produces the real MLS commit + welcome, submits the
    /// commit to existing members, and onboards the joiner. Returns the welcome material.
    pub fn add_member(
        &mut self,
        gid: GroupId,
        member: WalletAddress,
    ) -> Result<AddResult, DaemonError> {
        let owner = self.wallet.address();
        let now = self.tick();
        let kp = self
            .relay
            .take_key_package(&member)
            .ok_or_else(|| DaemonError::NoKeyPackage(hex::encode(member.0)))?;
        let gi = self
            .groups
            .iter()
            .position(|g| g.id == gid)
            .ok_or_else(|| DaemonError::NoGroup(hex::encode(gid.0)))?;
        // Snapshot the recipients (existing members, minus the owner-sender) BEFORE the mutation.
        let commit_recipients: Vec<WalletAddress> = self.groups[gi]
            .members
            .iter()
            .copied()
            .filter(|a| *a != owner)
            .collect();
        // Disjoint field borrows: self.mls (immutable) + self.groups[gi] (mutable).
        let (commit, welcome, ratchet_tree, epoch) = {
            let mls = &self.mls;
            let g = &mut self.groups[gi];
            let out = g
                .handle
                .add(mls, &kp.key_package)
                .map_err(|e| DaemonError::Mls(e.to_string()))?;
            g.epoch += 1;
            g.members.push(member);
            (out.commit, out.welcome, out.ratchet_tree, g.epoch)
        };
        // Deliver the commit to existing members, then onboard the joiner (welcome + tree).
        submit_commit(&mut self.relay, gid, owner, epoch, commit, commit_recipients, now)?;
        onboard(
            &mut self.relay,
            gid,
            owner,
            member,
            epoch,
            welcome.clone(),
            ratchet_tree.clone(),
            now,
        )?;
        Ok(AddResult {
            member,
            welcome,
            ratchet_tree,
        })
    }

    /// Encrypt `text` to the group and submit it to the members (excluding the owner-sender).
    pub fn send(&mut self, gid: GroupId, text: &str) -> Result<(), DaemonError> {
        let owner = self.wallet.address();
        let now = self.tick();
        let gi = self
            .groups
            .iter()
            .position(|g| g.id == gid)
            .ok_or_else(|| DaemonError::NoGroup(hex::encode(gid.0)))?;
        let (ct, epoch, recipients) = {
            let mls = &self.mls;
            let g = &mut self.groups[gi];
            let ct = g
                .handle
                .send(mls, text.as_bytes())
                .map_err(|e| DaemonError::Mls(e.to_string()))?;
            let recipients: Vec<WalletAddress> =
                g.members.iter().copied().filter(|a| *a != owner).collect();
            (ct, g.epoch, recipients)
        };
        self.relay
            .submit_as(
                owner,
                Envelope {
                    group_id: gid,
                    epoch: EpochId(epoch),
                    kind: EnvelopeKind::Application,
                    sender: owner,
                    recipients,
                    ciphertext: ct,
                    group_seq: None,
                },
                now,
            )
            .map_err(|e| DaemonError::Relay(e.to_string()))?;
        Ok(())
    }

    /// Drain the owner's mailbox and decrypt the Application messages for `gid`.
    pub fn poll_messages(&mut self, gid: GroupId) -> Result<Vec<Msg>, DaemonError> {
        let owner = self.wallet.address();
        let mls = &self.mls;
        let g = self
            .groups
            .iter_mut()
            .find(|g| g.id == gid)
            .ok_or_else(|| DaemonError::NoGroup(hex::encode(gid.0)))?;
        let mut out = Vec::new();
        for e in self.relay.fetch(&owner) {
            if e.kind != EnvelopeKind::Application || e.group_id != gid {
                continue;
            }
            let pt = g
                .handle
                .receive(mls, &e.ciphertext)
                .map_err(|err| DaemonError::Mls(err.to_string()))?;
            let body = String::from_utf8(pt).map_err(|_| DaemonError::BadUtf8)?;
            out.push(Msg {
                group: gid,
                sender: e.sender,
                body,
            });
        }
        Ok(out)
    }

    /// Test/next-increment accessor: the in-process relay (a real joiner is remote and fetches from
    /// it; the round-trip test drives a second member through it).
    pub fn relay_mut(&mut self) -> &mut DeliveryService {
        &mut self.relay
    }
    /// The relay domain (a joining member must match it in its SIWE/key-package publication).
    pub fn domain(&self) -> &str {
        &self.domain
    }
}

// ---------------------------------------------------------------------------
// Relay handshake helpers (mirrors comms-client::backend's login/publish_kp/submit/onboard).
// ---------------------------------------------------------------------------

/// SIWE login: the wallet signs the relay's challenge nonce.
pub fn login(
    relay: &mut DeliveryService,
    w: &EthWallet,
    domain: &str,
    now: u64,
) -> Result<(), DaemonError> {
    let nonce = relay.issue_challenge(now);
    let msg = SiweMessage {
        domain: domain.into(),
        address: w.address(),
        statement: "Sign in to citrate-comms".into(),
        uri: format!("wss://{domain}"),
        version: "1".into(),
        chain_id: CITRATE_CHAIN_ID,
        nonce,
        issued_at_ms: now,
        expiration_ms: now + 600_000,
    };
    let sig = w.sign_siwe(&msg);
    relay
        .authenticate(&msg, &sig, now)
        .map(|_| ())
        .map_err(|e| DaemonError::Relay(e.to_string()))
}

/// Publish `w`'s MLS key package to the relay (wallet-bound), so others can add them.
pub fn publish_kp(
    relay: &mut DeliveryService,
    w: &EthWallet,
    m: &MlsMember,
    domain: &str,
    now: u64,
) -> Result<(), DaemonError> {
    let sig_pub = m.sig_pubkey();
    let nonce = relay.issue_challenge(now);
    let pubn = KeyPackagePublication {
        wallet: w.address(),
        key_package: m
            .fresh_key_package()
            .map_err(|e| DaemonError::Mls(e.to_string()))?,
        mls_sig_pubkey: sig_pub.clone(),
        binding_attestation: w.sign_binding(&sig_pub, domain, &nonce).to_vec(),
        nonce,
        relay_domain: domain.into(),
    };
    relay
        .publish_key_package(pubn, now)
        .map(|_| ())
        .map_err(|e| DaemonError::Relay(e.to_string()))
}

fn submit_commit(
    relay: &mut DeliveryService,
    gid: GroupId,
    admin: WalletAddress,
    epoch: u64,
    commit: Vec<u8>,
    recipients: Vec<WalletAddress>,
    now: u64,
) -> Result<(), DaemonError> {
    relay
        .submit_as(
            admin,
            Envelope {
                group_id: gid,
                epoch: EpochId(epoch),
                kind: EnvelopeKind::Commit,
                sender: admin,
                recipients,
                ciphertext: commit,
                group_seq: None,
            },
            now,
        )
        .map(|_| ())
        .map_err(|e| DaemonError::Relay(e.to_string()))
}

#[allow(clippy::too_many_arguments)]
fn onboard(
    relay: &mut DeliveryService,
    gid: GroupId,
    admin: WalletAddress,
    joiner: WalletAddress,
    epoch: u64,
    welcome: Vec<u8>,
    tree: Vec<u8>,
    now: u64,
) -> Result<(), DaemonError> {
    relay
        .onboard(
            gid,
            admin,
            None,
            joiner,
            Envelope {
                group_id: gid,
                epoch: EpochId(epoch),
                kind: EnvelopeKind::Welcome,
                sender: admin,
                recipients: vec![joiner],
                ciphertext: welcome,
                group_seq: None,
            },
            tree,
            now,
        )
        .map_err(|e| DaemonError::Relay(e.to_string()))
}

#[cfg(test)]
mod tests {
    include!("daemon_tests.rs");
}
