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
use comms_core::rbac;
use comms_proto::{
    Envelope, EnvelopeKind, EpochId, GroupId, KeyPackagePublication, Role, RoleAssertion,
    WalletAddress, CITRATE_CHAIN_ID,
};

pub mod ipc;
pub mod relay;
pub mod server;

use relay::{InProcessRelay, Relay};

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
    #[error("not a member of this group: {0}")]
    NoMember(String),
    #[error("rbac error: {0}")]
    Rbac(String),
    #[error("invalid utf-8 in a decrypted message")]
    BadUtf8,
}

/// A member of a group as the daemon tracks it: the wallet, the MLS signature pubkey (to map to a
/// leaf for removal), and the current role.
#[derive(Debug, Clone)]
struct MemberInfo {
    wallet: WalletAddress,
    /// The member's OpenMLS signature public key (from their published key package).
    sig_pubkey: Vec<u8>,
    role: Role,
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
    members: Vec<MemberInfo>,
}

impl GroupState {
    /// The delivery recipients for a message sent by `sender` (everyone but the sender).
    fn recipients(&self, sender: WalletAddress) -> Vec<WalletAddress> {
        self.members
            .iter()
            .map(|m| m.wallet)
            .filter(|a| *a != sender)
            .collect()
    }
}

/// The member daemon: the owner's wallet + MLS identity, the in-process relay, and the owner's
/// groups.
pub struct MemberDaemon {
    domain: String,
    wallet: EthWallet,
    mls: MlsMember,
    relay: Box<dyn Relay>,
    groups: Vec<GroupState>,
    /// A monotonically-advancing clock (ms) so SIWE nonces/challenges stay fresh across ops.
    now: u64,
}

impl MemberDaemon {
    /// Bring up the daemon for `wallet` over a fresh IN-PROCESS relay owned by this wallet (single
    /// node). For a networked relay, use [`Self::new_with_relay`] with a `WsRelay`.
    pub fn new(wallet: EthWallet, domain: impl Into<String>, now: u64) -> Result<Self, DaemonError> {
        let domain = domain.into();
        let relay: Box<dyn Relay> =
            Box::new(InProcessRelay::new(&domain, wallet.address()).map_err(DaemonError::Relay)?);
        Self::new_with_relay(wallet, relay, domain, now)
    }

    /// Bring up the daemon for `wallet` over an INJECTED relay (in-process or a networked WS relay):
    /// mint the MLS identity, authenticate (SIWE), and publish the owner's key package.
    pub fn new_with_relay(
        wallet: EthWallet,
        mut relay: Box<dyn Relay>,
        domain: impl Into<String>,
        now: u64,
    ) -> Result<Self, DaemonError> {
        let domain = domain.into();
        let mls = MlsMember::new(&wallet.address().0).map_err(|e| DaemonError::Mls(e.to_string()))?;
        let mut d_now = now;
        login(relay.as_mut(), &wallet, &domain, d_now)?;
        d_now += 1;
        publish_kp(relay.as_mut(), &wallet, &mls, &domain, d_now)?;
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
            members: vec![MemberInfo {
                wallet: self.wallet.address(),
                sig_pubkey: self.mls.sig_pubkey(),
                role: Role::Owner,
            }],
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
            .map_err(DaemonError::Relay)?
            .ok_or_else(|| DaemonError::NoKeyPackage(hex::encode(member.0)))?;
        let gi = self
            .groups
            .iter()
            .position(|g| g.id == gid)
            .ok_or_else(|| DaemonError::NoGroup(hex::encode(gid.0)))?;
        // Snapshot the recipients (existing members, minus the owner-sender) BEFORE the mutation.
        let commit_recipients = self.groups[gi].recipients(owner);
        let member_sig = kp.mls_sig_pubkey.clone();
        // Disjoint field borrows: self.mls (immutable) + self.groups[gi] (mutable).
        let (commit, welcome, ratchet_tree, epoch) = {
            let mls = &self.mls;
            let g = &mut self.groups[gi];
            let out = g
                .handle
                .add(mls, &kp.key_package)
                .map_err(|e| DaemonError::Mls(e.to_string()))?;
            g.epoch += 1;
            g.members.push(MemberInfo {
                wallet: member,
                sig_pubkey: member_sig,
                role: Role::Member,
            });
            (out.commit, out.welcome, out.ratchet_tree, g.epoch)
        };
        // Deliver the commit to existing members, then onboard the joiner (welcome + tree).
        submit_commit(self.relay.as_mut(), gid, owner, epoch, commit, commit_recipients, now)?;
        onboard(
            self.relay.as_mut(),
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
            let recipients = g.recipients(owner);
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

    /// The group roster: `(wallet, role)` for every current member (owner first).
    pub fn roster(&self, gid: GroupId) -> Result<Vec<(WalletAddress, Role)>, DaemonError> {
        let g = self
            .groups
            .iter()
            .find(|g| g.id == gid)
            .ok_or_else(|| DaemonError::NoGroup(hex::encode(gid.0)))?;
        Ok(g.members.iter().map(|m| (m.wallet, m.role)).collect())
    }

    /// Grant/change `member`'s role in `gid`, signed by the owner. Returns the owner-signed
    /// [`RoleAssertion`] (the relay + clients enforce it) and updates the local roster. Refuses if
    /// the owner may not grant that role (e.g. transferring ownership).
    pub fn assign_role(
        &mut self,
        gid: GroupId,
        member: WalletAddress,
        role: Role,
    ) -> Result<RoleAssertion, DaemonError> {
        let assertion =
            rbac::sign_role_assertion(&self.wallet, Role::Owner, member, role, Some(gid), None)
                .map_err(|e| DaemonError::Rbac(format!("{e:?}")))?;
        let g = self
            .groups
            .iter_mut()
            .find(|g| g.id == gid)
            .ok_or_else(|| DaemonError::NoGroup(hex::encode(gid.0)))?;
        let mi = g
            .members
            .iter_mut()
            .find(|m| m.wallet == member)
            .ok_or_else(|| DaemonError::NoMember(hex::encode(member.0)))?;
        mi.role = role;
        Ok(assertion)
    }

    /// Offboard `member` from `gid`: a real MLS Remove commit (rotates the group secret) + the
    /// relay-side atomic offboard (drops the roster + refreshes the tree in one epoch, so the
    /// removed member cannot decrypt anything from the new epoch forward). The owner is the relay's
    /// trust anchor, so no admin assertion is needed.
    pub fn offboard(&mut self, gid: GroupId, member: WalletAddress) -> Result<(), DaemonError> {
        let owner = self.wallet.address();
        let now = self.tick();
        let gi = self
            .groups
            .iter()
            .position(|g| g.id == gid)
            .ok_or_else(|| DaemonError::NoGroup(hex::encode(gid.0)))?;
        // Map the member's wallet → their MLS leaf via the tracked signature key.
        let sig = self.groups[gi]
            .members
            .iter()
            .find(|m| m.wallet == member)
            .map(|m| m.sig_pubkey.clone())
            .ok_or_else(|| DaemonError::NoMember(hex::encode(member.0)))?;
        let (remove_commit, ratchet_tree, epoch) = {
            let mls = &self.mls;
            let g = &mut self.groups[gi];
            let leaf = g.handle.member_index_by_sig(&sig).ok_or_else(|| {
                DaemonError::NoMember(format!("no MLS leaf for {}", hex::encode(member.0)))
            })?;
            let out = g
                .handle
                .remove(mls, leaf)
                .map_err(|e| DaemonError::Mls(e.to_string()))?;
            g.epoch += 1;
            g.members.retain(|m| m.wallet != member);
            (out.commit, out.ratchet_tree, g.epoch)
        };
        let remaining = self.groups[gi].recipients(owner);
        let remove_commit_env = Envelope {
            group_id: gid,
            epoch: EpochId(epoch),
            kind: EnvelopeKind::Commit,
            sender: owner,
            recipients: remaining,
            ciphertext: remove_commit,
            group_seq: None,
        };
        self.relay
            .offboard(gid, owner, member, remove_commit_env, ratchet_tree, now)
            .map_err(DaemonError::Relay)?;
        Ok(())
    }

    /// Test/next-increment accessor: the relay seam (the round-trip test drives a second member
    /// through it).
    pub fn relay_mut(&mut self) -> &mut dyn Relay {
        self.relay.as_mut()
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
    relay: &mut dyn Relay,
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
    relay: &mut dyn Relay,
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
    relay: &mut dyn Relay,
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
    relay: &mut dyn Relay,
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
        .map_err(DaemonError::Relay)
}

#[cfg(test)]
mod tests {
    include!("daemon_tests.rs");
}
