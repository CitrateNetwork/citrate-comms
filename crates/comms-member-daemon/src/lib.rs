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
    ClaimSubmission, Envelope, EnvelopeKind, EpochId, GroupId, KeyPackagePublication, Role,
    RoleAssertion, WalletAddress, CITRATE_CHAIN_ID,
};

use std::path::PathBuf;
use zeroize::Zeroizing;

pub mod ipc;
pub mod persist;
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
    #[error("state persistence error: {0}")]
    Persist(String),
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
    /// Durable-state config (issue #3). `None` = in-memory only (groups do NOT survive a
    /// restart — the historical behavior, kept for tests and the inline-seed fallback).
    /// `Some` = snapshot every MLS + registry mutation to an encrypted file and rehydrate
    /// it on startup.
    persist: Option<PersistCtx>,
}

/// Where and how the daemon persists its encrypted state.
struct PersistCtx {
    dir: PathBuf,
    /// The 32-byte state key, derived from the identity seed and wiped on drop.
    key: Zeroizing<[u8; 32]>,
}

impl MemberDaemon {
    /// Bring up the daemon for `wallet` over a fresh IN-PROCESS relay owned by this wallet (single
    /// node). For a networked relay, use [`Self::new_with_relay`] with a `WsRelay`.
    pub fn new(
        wallet: EthWallet,
        domain: impl Into<String>,
        now: u64,
    ) -> Result<Self, DaemonError> {
        let domain = domain.into();
        let relay: Box<dyn Relay> =
            Box::new(InProcessRelay::new(&domain, wallet.address()).map_err(DaemonError::Relay)?);
        Self::new_with_relay(wallet, relay, domain, now)
    }

    /// Bring up the daemon for `wallet` over an INJECTED relay (in-process or a networked WS relay):
    /// mint the MLS identity, authenticate (SIWE), and publish the owner's key package.
    /// In-memory only — for a restart-durable daemon use [`Self::new_with_relay_persistent`].
    pub fn new_with_relay(
        wallet: EthWallet,
        relay: Box<dyn Relay>,
        domain: impl Into<String>,
        now: u64,
    ) -> Result<Self, DaemonError> {
        Self::build(wallet, relay, domain.into(), now, None)
    }

    /// Like [`Self::new`] but DURABLE (issue #3): snapshots MLS + group state to an
    /// encrypted file under `state_dir` and rehydrates it on startup, so groups survive
    /// a full restart. `seed` is the 32-byte identity seed (the daemon derives the
    /// state key from it and holds only the derived key, not the seed).
    pub fn new_persistent(
        wallet: EthWallet,
        domain: impl Into<String>,
        now: u64,
        state_dir: PathBuf,
        seed: &[u8; 32],
    ) -> Result<Self, DaemonError> {
        let domain = domain.into();
        let relay: Box<dyn Relay> =
            Box::new(InProcessRelay::new(&domain, wallet.address()).map_err(DaemonError::Relay)?);
        Self::new_with_relay_persistent(wallet, relay, domain, now, state_dir, seed)
    }

    /// Like [`Self::new_with_relay`] but DURABLE (issue #3): see [`Self::new_persistent`].
    pub fn new_with_relay_persistent(
        wallet: EthWallet,
        relay: Box<dyn Relay>,
        domain: impl Into<String>,
        now: u64,
        state_dir: PathBuf,
        seed: &[u8; 32],
    ) -> Result<Self, DaemonError> {
        let ctx = PersistCtx {
            dir: state_dir,
            key: persist::derive_state_key(seed),
        };
        Self::build(wallet, relay, domain.into(), now, Some(ctx))
    }

    /// The one construction path. `persist = Some` rehydrates any existing encrypted
    /// state (fail-closed on a corrupt/foreign file — never a silent empty start) and
    /// snapshots the freshly-published KeyPackage before returning; `None` is the
    /// historical in-memory behavior.
    fn build(
        wallet: EthWallet,
        mut relay: Box<dyn Relay>,
        domain: String,
        now: u64,
        persist: Option<PersistCtx>,
    ) -> Result<Self, DaemonError> {
        let identity = wallet.address().0;

        // Rehydrate from disk if persistence is on and a state file exists.
        let restored = match &persist {
            Some(ctx) => {
                match persist::load_state(&ctx.dir, &ctx.key, &identity)
                    .map_err(|e| DaemonError::Persist(e.to_string()))?
                {
                    Some(state) => Some(Self::rehydrate(state)?),
                    None => None,
                }
            }
            None => None,
        };

        let (mls, groups) = match restored {
            Some(mg) => mg,
            None => (
                MlsMember::new(&identity).map_err(|e| DaemonError::Mls(e.to_string()))?,
                Vec::new(),
            ),
        };

        // Authenticate + (re)publish this member's KeyPackage to whatever relay we were
        // given (a fresh in-process relay, or a reconnected WS relay). `publish_kp`
        // mints a new KeyPackage into the keystore, so we persist afterwards.
        let mut d_now = now;
        login(relay.as_mut(), &wallet, &domain, d_now)?;
        d_now += 1;
        publish_kp(relay.as_mut(), &wallet, &mls, &domain, d_now)?;

        let daemon = MemberDaemon {
            domain,
            wallet,
            mls,
            relay,
            groups,
            now: d_now + 1,
            persist,
        };
        daemon.persist_state()?;
        Ok(daemon)
    }

    /// Rebuild the MLS member + group registry from a decrypted, identity-verified
    /// [`persist::StateFile`]. Each group is reloaded from the rehydrated keystore via
    /// `MlsGroup::load` — no re-create, no new epoch.
    fn rehydrate(state: persist::StateFile) -> Result<(MlsMember, Vec<GroupState>), DaemonError> {
        let mls = MlsMember::restore(&state.identity, &state.sig_pubkey, &state.mls_snapshot)
            .map_err(|e| DaemonError::Mls(e.to_string()))?;
        let mut groups = Vec::with_capacity(state.groups.len());
        for pg in state.groups {
            let handle = mls
                .load_group(&pg.mls_group_id)
                .map_err(|e| DaemonError::Mls(e.to_string()))?;
            groups.push(GroupState {
                id: pg.id,
                name: pg.name,
                handle,
                epoch: pg.epoch,
                members: pg
                    .members
                    .into_iter()
                    .map(|m| MemberInfo {
                        wallet: m.wallet,
                        sig_pubkey: m.sig_pubkey,
                        role: m.role,
                    })
                    .collect(),
            });
        }
        Ok((mls, groups))
    }

    /// Snapshot MLS secrets + the group registry to the encrypted state file. No-op
    /// when persistence is disabled. Called after every state mutation.
    fn persist_state(&self) -> Result<(), DaemonError> {
        let ctx = match &self.persist {
            Some(c) => c,
            None => return Ok(()),
        };
        let mls_snapshot = self
            .mls
            .snapshot_storage()
            .map_err(|e| DaemonError::Mls(e.to_string()))?;
        let groups = self
            .groups
            .iter()
            .map(|g| persist::PersistedGroup {
                id: g.id,
                mls_group_id: g.handle.group_id(),
                name: g.name.clone(),
                epoch: g.epoch,
                members: g
                    .members
                    .iter()
                    .map(|m| persist::PersistedMember {
                        wallet: m.wallet,
                        sig_pubkey: m.sig_pubkey.clone(),
                        role: m.role,
                    })
                    .collect(),
            })
            .collect();
        let state = persist::StateFile::new(
            self.wallet.address().0.to_vec(),
            self.mls.sig_pubkey(),
            mls_snapshot,
            groups,
        );
        persist::write_state(&ctx.dir, &ctx.key, &state)
            .map_err(|e| DaemonError::Persist(e.to_string()))
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
        self.persist_state()?;
        Ok(gid)
    }

    /// The owner's groups, as `(id, name)`.
    pub fn list_groups(&self) -> Vec<(GroupId, String)> {
        self.groups.iter().map(|g| (g.id, g.name.clone())).collect()
    }

    /// The live MLS epoch of `gid`, read from the (possibly restored) group handle.
    /// After a restart this reflects the reloaded OpenMLS group state — proof that a
    /// persisted group came back as a real, usable MLS group and not just a registry
    /// row (issue #3).
    pub fn mls_epoch(&self, gid: GroupId) -> Result<u64, DaemonError> {
        self.groups
            .iter()
            .find(|g| g.id == gid)
            .map(|g| g.handle.epoch())
            .ok_or_else(|| DaemonError::NoGroup(hex::encode(gid.0)))
    }

    /// Join a group this member was ADDED to on a shared relay (cross-node). Fetches the pending
    /// Welcome + the ratchet tree from the relay, joins the MLS group, and reconstructs the roster
    /// from the relay (addresses only — a joiner is not the admin, so it does not learn others'
    /// signature keys or roles). After this the member can decrypt group messages and address its own.
    pub fn join_group(&mut self, gid: GroupId, name: impl Into<String>) -> Result<(), DaemonError> {
        let me = self.wallet.address();
        // The Welcome was delivered to this member's mailbox when the owner onboarded them.
        let welcome = self
            .relay
            .fetch(&me)
            .into_iter()
            .find(|e| e.kind == EnvelopeKind::Welcome && e.group_id == gid)
            .ok_or_else(|| {
                DaemonError::Relay(format!(
                    "no pending welcome for group {}",
                    hex::encode(gid.0)
                ))
            })?;
        let tree = self
            .relay
            .ratchet_tree(gid)
            .map_err(DaemonError::Relay)?
            .ok_or_else(|| DaemonError::Relay("group has no ratchet tree".into()))?;
        let handle = self
            .mls
            .join(&welcome.ciphertext, &tree)
            .map_err(|e| DaemonError::Mls(e.to_string()))?;
        let epoch = handle.epoch();
        let member_addrs = self
            .relay
            .group_members(gid)
            .map_err(DaemonError::Relay)?
            .unwrap_or_default();
        let members = member_addrs
            .into_iter()
            .map(|w| MemberInfo {
                wallet: w,
                sig_pubkey: if w == me {
                    self.mls.sig_pubkey()
                } else {
                    Vec::new()
                },
                role: Role::Member,
            })
            .collect();
        self.groups.push(GroupState {
            id: gid,
            name: name.into(),
            handle,
            epoch,
            members,
        });
        self.persist_state()?;
        Ok(())
    }

    /// **INVITE-S2 (owner mints).** Export this group's PUBLIC `GroupInfo` and publish a
    /// single-use, group-bound, owner-TTL'd invite to the relay under `token_hash`
    /// (`= BLAKE3(token)`, computed by the caller — the token itself never touches the
    /// relay). After this the owner can go OFFLINE: a token-holder self-admits by external
    /// commit with no further owner action.
    pub fn publish_invite(
        &mut self,
        gid: GroupId,
        token_hash: [u8; 32],
        expires_at: u64,
    ) -> Result<(), DaemonError> {
        let inviter = self.wallet.address();
        let gi = self
            .groups
            .iter()
            .position(|g| g.id == gid)
            .ok_or_else(|| DaemonError::NoGroup(hex::encode(gid.0)))?;
        let group_info = self.groups[gi]
            .handle
            .export_group_info(&self.mls)
            .map_err(|e| DaemonError::Mls(e.to_string()))?;
        self.relay
            .publish_invite(inviter, gid, token_hash, group_info, expires_at)
            .map_err(DaemonError::Relay)?;
        Ok(())
    }

    /// **INVITE-S2 (owner revokes).** Tombstone a previously-minted invite so every later
    /// redeem of it fails closed.
    pub fn revoke_invite(&mut self, token_hash: [u8; 32]) -> Result<(), DaemonError> {
        let caller = self.wallet.address();
        self.relay
            .revoke_invite(caller, token_hash)
            .map_err(DaemonError::Relay)
    }

    /// **INVITE-S2 (invitee self-admits).** Redeem an invite by its raw `token`: the relay
    /// validates + consumes it and returns the owner's PUBLIC `GroupInfo`; this member then
    /// self-admits by MLS external commit, publishes the resulting commit to the existing
    /// members, and records the joined group locally (durable via the Phase-1 persistence
    /// path, so the new group survives a restart). No owner action is required at join time.
    pub fn redeem_invite(
        &mut self,
        gid: GroupId,
        token: Vec<u8>,
        name: impl Into<String>,
    ) -> Result<(), DaemonError> {
        let joiner = self.wallet.address();
        let now = self.tick();
        // A fresh KeyPackage accompanies the redeem (mutates the keystore → persist below).
        let key_package = self
            .mls
            .fresh_key_package()
            .map_err(|e| DaemonError::Mls(e.to_string()))?;
        let (group_info, _mint_epoch) = self
            .relay
            .redeem_invite(joiner, gid, token, key_package, now)
            .map_err(DaemonError::Relay)?;
        // Self-admit by external commit — no owner participation.
        let (handle, commit) = self
            .mls
            .external_commit_join(&group_info)
            .map_err(|e| DaemonError::Mls(e.to_string()))?;
        let commit_epoch = handle.epoch();
        // The relay added us to the routing roster at redeem; learn the existing members so
        // the external commit fans out to them.
        let members = self
            .relay
            .group_members(gid)
            .map_err(DaemonError::Relay)?
            .unwrap_or_default();
        let recipients: Vec<WalletAddress> =
            members.into_iter().filter(|a| *a != joiner).collect();
        submit_commit(
            self.relay.as_mut(),
            gid,
            joiner,
            commit_epoch,
            commit,
            recipients.clone(),
            now,
        )?;
        // Record local group state: existing members (addresses only — a joiner does not
        // learn others' MLS signature keys) + self.
        let mut member_infos: Vec<MemberInfo> = recipients
            .iter()
            .map(|w| MemberInfo {
                wallet: *w,
                sig_pubkey: Vec::new(),
                role: Role::Member,
            })
            .collect();
        member_infos.push(MemberInfo {
            wallet: joiner,
            sig_pubkey: self.mls.sig_pubkey(),
            role: Role::Member,
        });
        self.groups.push(GroupState {
            id: gid,
            name: name.into(),
            handle,
            epoch: commit_epoch,
            members: member_infos,
        });
        self.persist_state()?;
        Ok(())
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
        // The relay is untrusted (RFC 9420 §3; `01_SCOPE.md` §2). Verify HERE, in
        // the client admitting the member, that this KeyPackage genuinely belongs
        // to `member` before it is added and before its `mls_sig_pubkey` is trusted
        // as this member's identity. A hostile relay that skips its own check and
        // substitutes a KeyPackage is rejected here (CM2-B-A001).
        comms_core::mls::verify_incoming_key_package(&kp, &member)
            .map_err(|e| DaemonError::Mls(e.to_string()))?;
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
        submit_commit(
            self.relay.as_mut(),
            gid,
            owner,
            epoch,
            commit,
            commit_recipients,
            now,
        )?;
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
        self.persist_state()?;
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
        // `create_message` ratcheted the MLS message-generation state; persist so a
        // restart does not reuse a generation (which would reuse an AEAD nonce).
        self.persist_state()?;
        Ok(())
    }

    /// Drain the owner's mailbox and decrypt the Application messages for `gid`. Incoming
    /// **Commit** envelopes (a membership change committed by another member — notably a
    /// self-admitted joiner's INVITE-S2 external commit) are merged here too, advancing this
    /// member to the shared epoch and reconciling the roster from the authenticated MLS tree
    /// (not relay metadata). Envelopes are processed in delivery order, so a Commit that
    /// precedes application traffic at the new epoch is applied first.
    pub fn poll_messages(&mut self, gid: GroupId) -> Result<Vec<Msg>, DaemonError> {
        let me = self.wallet.address();
        let mls = &self.mls;
        let g = self
            .groups
            .iter_mut()
            .find(|g| g.id == gid)
            .ok_or_else(|| DaemonError::NoGroup(hex::encode(gid.0)))?;
        let mut out = Vec::new();
        let mut changed = false;
        for e in self.relay.fetch(&me) {
            if e.group_id != gid {
                continue;
            }
            match e.kind {
                EnvelopeKind::Commit => {
                    // Merge an incoming membership commit (e.g. a self-admitted joiner).
                    g.handle
                        .process_commit(mls, &e.ciphertext)
                        .map_err(|err| DaemonError::Mls(err.to_string()))?;
                    g.epoch = g.handle.epoch();
                    reconcile_roster(g);
                    changed = true;
                }
                EnvelopeKind::Application => {
                    let received = g
                        .handle
                        .receive(mls, &e.ciphertext)
                        .map_err(|err| DaemonError::Mls(err.to_string()))?;
                    let body =
                        String::from_utf8(received.plaintext).map_err(|_| DaemonError::BadUtf8)?;
                    // Attribute from the authenticated MLS credential, not the
                    // relay-controlled `e.sender` routing field (CM2-B-A002).
                    let sender = WalletAddress::from_identity(&received.sender_identity)
                        .ok_or_else(|| {
                            DaemonError::Mls("authenticated sender identity is not a wallet".into())
                        })?;
                    out.push(Msg {
                        group: gid,
                        sender,
                        body,
                    });
                    changed = true;
                }
                // Welcome/Proposal are not consumed here.
                _ => continue,
            }
        }
        // Processing advanced the inbound ratchet / epoch; persist so the restored state
        // reflects what was already consumed. Skip the write if nothing changed.
        if changed {
            self.persist_state()?;
        }
        Ok(out)
    }

    /// The group roster: `(wallet, role)` for every current member (owner first).
    /// CONNECT-S1 — submit a sealed claim to the relay's server-blind claims-inbox (invitee side).
    pub fn submit_claim(
        &mut self,
        token_hash: [u8; 32],
        ciphertext: Vec<u8>,
    ) -> Result<(), DaemonError> {
        self.relay
            .as_mut()
            .submit_claim(
                self.wallet.address(),
                ClaimSubmission {
                    token_hash,
                    ciphertext,
                },
            )
            .map_err(DaemonError::Relay)
    }

    /// CONNECT-S1 — poll the relay's claims-inbox by invite token hash (owner side).
    pub fn poll_claims(&mut self, token_hash: [u8; 32]) -> Result<Vec<Vec<u8>>, DaemonError> {
        let claims = self
            .relay
            .as_mut()
            .poll_claims(self.wallet.address(), token_hash)
            .map_err(DaemonError::Relay)?;
        Ok(claims.into_iter().map(|c| c.ciphertext).collect())
    }

    pub fn roster(&self, gid: GroupId) -> Result<Vec<(WalletAddress, Role)>, DaemonError> {
        let g = self
            .groups
            .iter()
            .find(|g| g.id == gid)
            .ok_or_else(|| DaemonError::NoGroup(hex::encode(gid.0)))?;
        Ok(g.members.iter().map(|m| (m.wallet, m.role)).collect())
    }

    /// Apply an owner/admin-signed role grant. The daemon VERIFIES ONLY — it never signs (Rule 3):
    /// the caller (citrate-core's SignatureCeremony) produced the signature. Verifies the grant chain
    /// against this group's owner, checks the assertion is scoped to this group (if scoped) and names
    /// a current member, then records the role. Rejects any unverifiable / expired / escalating /
    /// wrong-scope / non-member assertion (reusing comms-core `rbac`).
    pub fn assign_role(
        &mut self,
        gid: GroupId,
        assertion: &RoleAssertion,
    ) -> Result<(), DaemonError> {
        let owner = self.wallet.address();
        let now = self.tick();
        rbac::verify_grant_chain(assertion, assertion.subject, owner, now)
            .map_err(|e| DaemonError::Rbac(format!("{e:?}")))?;
        if let Some(scope) = assertion.scope {
            if scope != gid {
                return Err(DaemonError::Rbac(format!(
                    "assertion scope {} is not this group",
                    hex::encode(scope.0)
                )));
            }
        }
        let g = self
            .groups
            .iter_mut()
            .find(|g| g.id == gid)
            .ok_or_else(|| DaemonError::NoGroup(hex::encode(gid.0)))?;
        let mi = g
            .members
            .iter_mut()
            .find(|m| m.wallet == assertion.subject)
            .ok_or_else(|| DaemonError::NoMember(hex::encode(assertion.subject.0)))?;
        mi.role = assertion.role;
        self.persist_state()?;
        Ok(())
    }

    /// Revoke/demote a subject's role via an owner/admin-signed assertion (the caller sets the
    /// assertion's `role` to the demoted role, e.g. `Member`). Daemon VERIFIES ONLY — same grant-chain
    /// check as `assign_role`; the verb documents intent (a demotion) while sharing the keyless path.
    pub fn revoke_role(
        &mut self,
        gid: GroupId,
        assertion: &RoleAssertion,
    ) -> Result<(), DaemonError> {
        let owner = self.wallet.address();
        let now = self.tick();
        rbac::verify_grant_chain(assertion, assertion.subject, owner, now)
            .map_err(|e| DaemonError::Rbac(format!("{e:?}")))?;
        if let Some(scope) = assertion.scope {
            if scope != gid {
                return Err(DaemonError::Rbac(format!(
                    "assertion scope {} is not this group",
                    hex::encode(scope.0)
                )));
            }
        }
        let g = self
            .groups
            .iter_mut()
            .find(|g| g.id == gid)
            .ok_or_else(|| DaemonError::NoGroup(hex::encode(gid.0)))?;
        let mi = g
            .members
            .iter_mut()
            .find(|m| m.wallet == assertion.subject)
            .ok_or_else(|| DaemonError::NoMember(hex::encode(assertion.subject.0)))?;
        mi.role = assertion.role;
        self.persist_state()?;
        Ok(())
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
        self.persist_state()?;
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
    /// Flag-A — whether the relay link is currently usable (in-process is always up; a networked
    /// `WsRelay` reports its live socket). Surfaced over IPC as `relayStatus` so citrate-core reports
    /// a relay DROP instead of a false "healthy". Cheap + bounded (see [`Relay::is_connected`]).
    pub fn relay_connected(&self) -> bool {
        self.relay.is_connected()
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

/// Reconcile a group's tracked roster against the authenticated MLS membership after an
/// incoming Commit (INVITE-S2 external commit, or any other member-driven change): add any
/// newly-present wallet, and backfill an MLS signature key we did not previously hold (so a
/// later Remove can still map the wallet to its leaf). Attribution is from the MLS tree —
/// never relay metadata (CM2-B-A002). Removals are handled on the offboard path, not here.
fn reconcile_roster(g: &mut GroupState) {
    for (identity, sig) in g.handle.authenticated_members() {
        let Some(wallet) = WalletAddress::from_identity(&identity) else {
            continue;
        };
        match g.members.iter_mut().find(|m| m.wallet == wallet) {
            Some(existing) => {
                if existing.sig_pubkey.is_empty() && !sig.is_empty() {
                    existing.sig_pubkey = sig;
                }
            }
            None => g.members.push(MemberInfo {
                wallet,
                sig_pubkey: sig,
                role: Role::Member,
            }),
        }
    }
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
