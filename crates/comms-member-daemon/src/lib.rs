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

pub mod client;
pub mod grants;
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
    /// GC-2: why recent incoming role grants were refused (newest last, bounded by
    /// [`GRANT_LOG_CAP`]). In memory only.
    grant_log: Vec<String>,
    /// Envelopes already fetched from the relay but not yet consumed: a `poll_messages(g1)` that
    /// drains a Commit or Application for `g2`, or a Welcome for a group not joined yet. `fetch`
    /// DRAINS the relay session, so without this buffer those envelopes were silently dropped —
    /// a second group's traffic was lost to the first group's poll, and an unrelated poll ate a
    /// pending Welcome. Persisted with the rest of the encrypted state (GC-1): the relay already
    /// handed these over and deleted its copy, so a daemon restart must not lose them. Bounded by
    /// [`INBOX_CAP`].
    inbox: Vec<Envelope>,
    /// comms #51 item 1: per group, the highest relay `group_seq` this member has consumed
    /// (processed, even if processing failed, or joined from). The relay resends what it never
    /// saw acknowledged, so anything at or below the mark is a copy and is dropped. Persisted.
    consumed: std::collections::BTreeMap<GroupId, u64>,
}

/// What [`MemberDaemon::rehydrate`] rebuilds from a state file: the MLS member, the groups, the
/// inbox and the per-group consumed marks.
type Rehydrated = (
    MlsMember,
    Vec<GroupState>,
    Vec<Envelope>,
    std::collections::BTreeMap<GroupId, u64>,
);

/// Upper bound on [`MemberDaemon::grant_log`].
const GRANT_LOG_CAP: usize = 64;

/// GC-2: a member's role as every client derives it: the group-context owner is `Owner`,
/// anyone else has their roster role (a stale `Owner` in the roster reads as `Admin`).
fn effective_role(g: &GroupState, who: WalletAddress) -> Role {
    if g.handle.owner() == Some(who.0) {
        return Role::Owner;
    }
    match g.members.iter().find(|m| m.wallet == who).map(|m| m.role) {
        Some(Role::Owner) => Role::Admin,
        Some(r) => r,
        None => Role::Guest,
    }
}

/// GC-2: after an ownership change, the new owner is `Owner` and the previous one `Admin`.
fn apply_owner_change(g: &mut GroupState, before: Option<[u8; 20]>, after: Option<[u8; 20]>) {
    for m in g.members.iter_mut() {
        if Some(m.wallet.0) == after {
            m.role = Role::Owner;
        } else if Some(m.wallet.0) == before {
            m.role = Role::Admin;
        }
    }
}

/// GC-2: check an incoming grant (decrypted from `sender`'s authenticated MLS message)
/// against the group owner and this member's roster. Returns why it is refused.
fn check_grant(
    g: &GroupState,
    gid: GroupId,
    sender: WalletAddress,
    a: &RoleAssertion,
    now: u64,
) -> Result<(), String> {
    let owner = g
        .handle
        .owner()
        .ok_or("role grants not available for this group (created before 0.6.0)")?;
    rbac::verify_role_assertion(a, now).map_err(|e| format!("role grant refused: {e}"))?;
    if a.scope != Some(gid) {
        return Err("role grant for another group".into());
    }
    if a.issuer != sender {
        return Err("role grant not sent by its issuer".into());
    }
    let issuer_role = effective_role(g, a.issuer);
    if !rbac::can(issuer_role, rbac::Capability::AssignRole) {
        return Err(format!("role grant from non-admin {}", a.issuer.to_hex()));
    }
    // Admin gates money-adjacent surfaces (a group's FL offers are shown only from an owner or
    // admin), so making an admin is the owner's alone (#49 review).
    if a.role == Role::Admin && a.issuer.0 != owner {
        return Err("only the owner grants Admin".into());
    }
    // ... and only the owner takes it away (comms #51): the subject's current role here is Admin.
    if effective_role(g, a.subject) == Role::Admin && a.role != Role::Admin && a.issuer.0 != owner {
        return Err("only the owner demotes an Admin".into());
    }
    if !rbac::can_grant(issuer_role, a.role) {
        return Err(format!(
            "role grant exceeds the issuer's role ({issuer_role:?} cannot grant {:?})",
            a.role
        ));
    }
    if a.subject.0 == owner {
        return Err("the owner's role changes only by an ownership transfer".into());
    }
    if !g.members.iter().any(|m| m.wallet == a.subject) {
        return Err("role grant for someone who is not a member".into());
    }
    Ok(())
}

/// Upper bound on [`MemberDaemon::inbox`]: oldest envelopes beyond it are dropped, so a group that is
/// never polled cannot grow the daemon's memory without bound.
const INBOX_CAP: usize = 4096;

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

        let (mls, groups, inbox, consumed) = match restored {
            Some(mg) => mg,
            None => (
                MlsMember::new(&identity).map_err(|e| DaemonError::Mls(e.to_string()))?,
                Vec::new(),
                Vec::new(),
                std::collections::BTreeMap::new(),
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
            grant_log: Vec::new(),
            inbox,
            consumed,
        };
        daemon.persist_state()?;
        Ok(daemon)
    }

    /// Rebuild the MLS member + group registry from a decrypted, identity-verified
    /// [`persist::StateFile`]. Each group is reloaded from the rehydrated keystore via
    /// `MlsGroup::load` — no re-create, no new epoch.
    fn rehydrate(state: persist::StateFile) -> Result<Rehydrated, DaemonError> {
        let inbox = state.inbox;
        let consumed = state.consumed.into_iter().collect();
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
        Ok((mls, groups, inbox, consumed))
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
        let mut state = persist::StateFile::new(
            self.wallet.address().0.to_vec(),
            self.mls.sig_pubkey(),
            mls_snapshot,
            groups,
        );
        state.inbox = self.inbox.clone();
        state.consumed = self.consumed.iter().map(|(g, s)| (*g, *s)).collect();
        persist::write_state(&ctx.dir, &ctx.key, &state)
            .map_err(|e| DaemonError::Persist(e.to_string()))
    }

    /// GC-2: sign a role grant for `member` in `gid` with this member's comms key and send it
    /// to the group as an MLS application message. Every member verifies it against the
    /// group owner (the authenticated group-context extension) and its own roster before
    /// applying it.
    pub fn grant_role(
        &mut self,
        gid: GroupId,
        member: WalletAddress,
        role: Role,
        not_after: Option<u64>,
    ) -> Result<(), DaemonError> {
        let me = self.wallet.address();
        let gi = self
            .groups
            .iter()
            .position(|g| g.id == gid)
            .ok_or_else(|| DaemonError::NoGroup(hex::encode(gid.0)))?;
        let g = &self.groups[gi];
        let owner = g.handle.owner().ok_or_else(|| {
            DaemonError::Rbac(
                "role grants not available for this group (created before 0.6.0)".into(),
            )
        })?;
        if member.0 == owner {
            return Err(DaemonError::Rbac(
                "the owner's role changes only by an ownership transfer".into(),
            ));
        }
        if !g.members.iter().any(|m| m.wallet == member) {
            return Err(DaemonError::NoMember(hex::encode(member.0)));
        }
        let my_role = effective_role(g, me);
        if role == Role::Admin && me.0 != owner {
            return Err(DaemonError::Rbac("only the owner grants Admin".into()));
        }
        if effective_role(g, member) == Role::Admin && role != Role::Admin && me.0 != owner {
            return Err(DaemonError::Rbac("only the owner demotes an Admin".into()));
        }
        // Signed with this member's COMMS key (the device-sealed comms identity, planset
        // 2026-11-07-v060 02 §5), not the custody wallet. The anti-escalation rule (`can_grant`)
        // is checked here and again by every receiver.
        //
        // No grant `generation` (that is `sign_group_grant`, for the relay's membership ops):
        // inside the group, MLS stops replay and receivers require issuer == authenticated
        // sender, so a generation would add nothing here.
        let a =
            rbac::sign_role_assertion(&self.wallet, my_role, member, role, Some(gid), not_after)
                .map_err(|e| DaemonError::Rbac(e.to_string()))?;
        self.send(gid, &grants::encode_grant_message(&a))?;
        // Applied locally only once the grant went out (#49 review P3).
        if let Some(m) = self.groups[gi]
            .members
            .iter_mut()
            .find(|m| m.wallet == member)
        {
            m.role = role;
        }
        Ok(())
    }

    /// GC-2: hand `gid` to `new_owner` (a current member). Only the current owner can.
    pub fn transfer_ownership(
        &mut self,
        gid: GroupId,
        new_owner: WalletAddress,
    ) -> Result<(), DaemonError> {
        let me = self.wallet.address();
        let now = self.tick();
        let gi = self
            .groups
            .iter()
            .position(|g| g.id == gid)
            .ok_or_else(|| DaemonError::NoGroup(hex::encode(gid.0)))?;
        let (commit, epoch, recipients) = {
            let mls = &self.mls;
            let g = &mut self.groups[gi];
            let owner = g.handle.owner().ok_or_else(|| {
                DaemonError::Rbac(
                    "role grants not available for this group (created before 0.6.0)".into(),
                )
            })?;
            if owner != me.0 {
                return Err(DaemonError::Rbac(
                    "only the group owner can transfer it".into(),
                ));
            }
            if !g.members.iter().any(|m| m.wallet == new_owner) {
                return Err(DaemonError::NoMember(hex::encode(new_owner.0)));
            }
            let commit = g
                .handle
                .transfer_owner(mls, new_owner.0)
                .map_err(|e| DaemonError::Mls(e.to_string()))?;
            g.epoch = g.handle.epoch();
            apply_owner_change(g, Some(owner), Some(new_owner.0));
            (commit, g.epoch, g.recipients(me))
        };
        self.persist_state()?;
        submit_commit(self.relay.as_mut(), gid, me, epoch, commit, recipients, now)
    }

    /// Tests only: a group made the pre-0.6.0 way (no owner extension).
    #[cfg(test)]
    pub(crate) fn create_group_without_owner_for_test(
        &mut self,
        name: &str,
    ) -> Result<GroupId, DaemonError> {
        self.create_group_inner(name.to_string(), false)
    }

    /// GC-2: the group's owner as the authenticated group context names it (`None` for a
    /// group created before 0.6.0, where role grants are not available).
    pub fn group_owner(&self, gid: GroupId) -> Option<WalletAddress> {
        self.groups
            .iter()
            .find(|g| g.id == gid)
            .and_then(|g| g.handle.owner())
            .map(WalletAddress)
    }

    /// GC-2: why recent incoming role grants were refused (newest last, bounded).
    pub fn grant_rejections(&self) -> Vec<String> {
        self.grant_log.clone()
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
        self.create_group_inner(name.into(), true)
    }

    /// `owned`: name this member as owner in the group context (GC-2). Always true outside
    /// tests; `false` reproduces a group made before 0.6.0.
    fn create_group_inner(&mut self, name: String, owned: bool) -> Result<GroupId, DaemonError> {
        let handle = if owned {
            self.mls.create_group_owned(self.wallet.address().0)
        } else {
            self.mls.create_group()
        }
        .map_err(|e| DaemonError::Mls(e.to_string()))?;
        let gid = GroupId(*blake3::hash(&handle.group_id()).as_bytes());
        let now = self.tick();
        self.relay
            .register_group(gid, self.wallet.address(), now)
            .map_err(|e| DaemonError::Relay(e.to_string()))?;
        self.groups.push(GroupState {
            id: gid,
            name,
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
        // The Welcome was delivered to this member's mailbox when the owner onboarded them.
        let mut all = self.take_inbox();
        let pos = all
            .iter()
            .position(|e| e.kind == EnvelopeKind::Welcome && e.group_id == gid);
        let welcome = match pos {
            Some(i) => all.remove(i),
            None => {
                self.stash(all);
                return Err(DaemonError::Relay(format!(
                    "no pending welcome for group {}",
                    hex::encode(gid.0)
                )));
            }
        };
        // Everything else that was fetched stays buffered for the op that consumes it.
        self.stash(all);
        match self.join_with_welcome(gid, &welcome.ciphertext, name.into()) {
            Ok(()) => {
                self.mark_consumed(&welcome);
                Ok(())
            }
            Err(e) => {
                // Keep the Welcome so a retry (e.g. after a transient relay error fetching the
                // tree) can still use it.
                self.stash(vec![welcome]);
                Err(e)
            }
        }
    }

    /// **Headless join.** Join EVERY group this member has a pending Welcome for, without the caller
    /// knowing the group ids. A human owner adds this member by address ("Add by address" in Commons)
    /// and the Welcome lands in this member's mailbox; a headless member (an ops bot) cannot be told
    /// the id out of band, so it accepts whatever it was added to. Returns the newly joined group
    /// ids (empty = nothing pending). Envelopes that are not join candidates stay buffered.
    ///
    /// Only an owner/admin of a group can produce a Welcome for it (the relay enforces that), so
    /// this admits the member to nothing a group's own owner did not choose.
    pub fn join_pending(&mut self) -> Result<Vec<GroupId>, DaemonError> {
        let all = self.take_inbox();
        let mut joined: Vec<GroupId> = Vec::new();
        let mut rest = Vec::new();
        let mut first_err = None;
        for e in all {
            let candidate = e.kind == EnvelopeKind::Welcome
                && !joined.contains(&e.group_id)
                && !self.groups.iter().any(|g| g.id == e.group_id);
            if !candidate {
                rest.push(e);
                continue;
            }
            match self.join_with_welcome(e.group_id, &e.ciphertext, String::new()) {
                Ok(()) => {
                    self.mark_consumed(&e);
                    joined.push(e.group_id)
                }
                // A Welcome we cannot process is not retried forever; surface the first failure
                // if nothing at all could be joined.
                Err(err) => {
                    first_err.get_or_insert(err);
                }
            }
        }
        self.stash(rest);
        match (joined.is_empty(), first_err) {
            (true, Some(err)) => Err(err),
            _ => Ok(joined),
        }
    }

    /// Record that `e` was consumed (comms #51 item 1), and persist the mark.
    fn mark_consumed(&mut self, e: &Envelope) {
        if let Some(s) = e.group_seq {
            let m = self.consumed.entry(e.group_id).or_insert(s);
            if *m < s {
                *m = s;
            }
            if let Err(err) = self.persist_state() {
                eprintln!("member-daemon: could not persist the consumed mark, will retry: {err}");
            }
        }
    }

    /// Process one Welcome: fetch the group's public ratchet tree, join the MLS group, and record
    /// the roster from the relay (addresses only — a joiner is not the admin, so it does not learn
    /// others' signature keys or roles).
    fn join_with_welcome(
        &mut self,
        gid: GroupId,
        welcome: &[u8],
        name: String,
    ) -> Result<(), DaemonError> {
        let me = self.wallet.address();
        let tree = self
            .relay
            .ratchet_tree(gid)
            .map_err(DaemonError::Relay)?
            .ok_or_else(|| DaemonError::Relay("group has no ratchet tree".into()))?;
        let handle = self
            .mls
            .join(welcome, &tree)
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
            name,
            handle,
            epoch,
            members,
        });
        self.persist_state()?;
        Ok(())
    }

    /// Everything waiting for this member: envelopes an earlier op fetched but did not consume,
    /// then whatever the relay has delivered since (in delivery order).
    ///
    /// GC-1 review P2: newly fetched envelopes go into the persisted inbox first, and only then
    /// is the relay told it may delete them, so a crash or a dropped socket anywhere in between
    /// leaves the relay's copy in place and it is sent again.
    fn take_inbox(&mut self) -> Vec<Envelope> {
        let me = self.wallet.address();
        let mut fresh = self.relay.fetch(&me);
        // comms #51 item 1: drop copies the relay resent (no ack reached it): already consumed,
        // already in the inbox, or twice in this batch. The ack below still covers them.
        let acked_copies = !fresh.is_empty();
        let mut seen: std::collections::BTreeSet<(GroupId, u64)> = self
            .inbox
            .iter()
            .filter_map(|e| e.group_seq.map(|s| (e.group_id, s)))
            .collect();
        fresh.retain(|e| match e.group_seq {
            Some(s) => {
                let consumed = self.consumed.get(&e.group_id).is_some_and(|m| s <= *m);
                !consumed && seen.insert((e.group_id, s))
            }
            None => true,
        });
        if fresh.is_empty() && acked_copies {
            if let Err(e) = self.relay.ack_delivered() {
                eprintln!("member-daemon: relay ack failed, it will resend: {e}");
            }
        }
        if !fresh.is_empty() {
            self.inbox.extend(fresh);
            match self.persist_state() {
                Ok(()) => {
                    if let Err(e) = self.relay.ack_delivered() {
                        eprintln!("member-daemon: relay ack failed, it will resend: {e}");
                    }
                }
                Err(e) => eprintln!("member-daemon: inbox not persisted, not acknowledging: {e}"),
            }
        }
        std::mem::take(&mut self.inbox)
    }

    /// Put fetched-but-unconsumed envelopes back, keeping only those a later op can still use: any
    /// envelope for a group we are in (another group's poll consumes it), and Welcomes for groups
    /// we have not joined (join candidates). Anything else could never be consumed and is dropped.
    ///
    /// GC-1: whenever the inbox changes here it is persisted, so fetched-but-unconsumed mail
    /// survives a daemon restart. A failed write is logged and left for the next persist (the
    /// envelopes stay in memory meanwhile).
    fn stash(&mut self, envs: Vec<Envelope>) {
        let groups = &self.groups;
        let before = self.inbox.len();
        self.inbox.extend(envs.into_iter().filter(|e| {
            groups.iter().any(|g| g.id == e.group_id) || e.kind == EnvelopeKind::Welcome
        }));
        if self.inbox.len() > INBOX_CAP {
            let excess = self.inbox.len() - INBOX_CAP;
            self.inbox.drain(..excess);
        }
        if self.inbox.len() != before {
            if let Err(e) = self.persist_state() {
                eprintln!("member-daemon: could not persist the inbox, will retry: {e}");
            }
        }
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
    /// redeem of it fails closed. With `report_used`, an invite that was already redeemed is
    /// refused with the relay's `INVITE_ALREADY_USED` message (passed through as
    /// [`DaemonError::Relay`]).
    pub fn revoke_invite(
        &mut self,
        token_hash: [u8; 32],
        report_used: bool,
    ) -> Result<(), DaemonError> {
        let caller = self.wallet.address();
        self.relay
            .revoke_invite(caller, token_hash, report_used)
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
        let recipients: Vec<WalletAddress> = members.into_iter().filter(|a| *a != joiner).collect();
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
        // `create_message` ratcheted the MLS message-generation state. Persist it BEFORE the
        // relay sees the ciphertext: if the relay took it but the answer was lost, or the daemon
        // died right after submitting, a restart must not encrypt again under the same
        // generation. A failed submit then only skips a generation, which receivers tolerate.
        self.persist_state()?;
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

    /// Drain the owner's mailbox and decrypt the Application messages for `gid`. Incoming
    /// **Commit** envelopes (a membership change committed by another member — notably a
    /// self-admitted joiner's INVITE-S2 external commit) are merged here too, advancing this
    /// member to the shared epoch and reconciling the roster from the authenticated MLS tree
    /// (not relay metadata). Envelopes are processed in delivery order, so a Commit that
    /// precedes application traffic at the new epoch is applied first.
    pub fn poll_messages(&mut self, gid: GroupId) -> Result<Vec<Msg>, DaemonError> {
        // Check membership BEFORE draining, so an unknown group id cannot eat other groups' mail.
        if !self.groups.iter().any(|g| g.id == gid) {
            return Err(DaemonError::NoGroup(hex::encode(gid.0)));
        }
        let envs = self.take_inbox();
        let now = self.tick();
        let mut rejected: Vec<String> = Vec::new();
        let mut out = Vec::new();
        let mut changed = false;
        // Envelopes for OTHER groups (and anything left after a failure) go back to the inbox
        // instead of being dropped: `fetch` drained them from the relay session.
        let mut keep = Vec::new();
        let mut failure = None;
        let mut mark = self.consumed.get(&gid).copied();
        {
            let mls = &self.mls;
            let g = self
                .groups
                .iter_mut()
                .find(|g| g.id == gid)
                .ok_or_else(|| DaemonError::NoGroup(hex::encode(gid.0)))?;
            let mut iter = envs.into_iter();
            for e in iter.by_ref() {
                if e.group_id != gid {
                    keep.push(e);
                    continue;
                }
                // comms #51 item 1: a copy of something already consumed is dropped unread.
                if let Some(s) = e.group_seq {
                    if mark.is_some_and(|m| s <= m) {
                        continue;
                    }
                    mark = Some(s);
                }
                match e.kind {
                    EnvelopeKind::Commit => {
                        // Merge an incoming membership commit (e.g. a self-admitted joiner).
                        let owner_before = g.handle.owner();
                        if let Err(err) = g.handle.process_commit(mls, &e.ciphertext) {
                            failure = Some(DaemonError::Mls(err.to_string()));
                            break;
                        }
                        g.epoch = g.handle.epoch();
                        reconcile_roster(g);
                        let owner_after = g.handle.owner();
                        if owner_after != owner_before {
                            apply_owner_change(g, owner_before, owner_after);
                        }
                        changed = true;
                    }
                    EnvelopeKind::Application => {
                        let received = match g.handle.receive(mls, &e.ciphertext) {
                            Ok(r) => r,
                            Err(err) => {
                                failure = Some(DaemonError::Mls(err.to_string()));
                                break;
                            }
                        };
                        changed = true;
                        let body = match String::from_utf8(received.plaintext) {
                            Ok(b) => b,
                            Err(_) => {
                                failure = Some(DaemonError::BadUtf8);
                                break;
                            }
                        };
                        // Attribute from the authenticated MLS credential, not the
                        // relay-controlled `e.sender` routing field (CM2-B-A002).
                        let sender = match WalletAddress::from_identity(&received.sender_identity) {
                            Some(s) => s,
                            None => {
                                failure = Some(DaemonError::Mls(
                                    "authenticated sender identity is not a wallet".into(),
                                ));
                                break;
                            }
                        };
                        // GC-2: a role grant is applied (or refused), never shown as chat.
                        if let Some(parsed) = grants::decode_grant_message(&body) {
                            match parsed
                                .and_then(|a| check_grant(g, gid, sender, &a, now).map(|()| a))
                            {
                                Ok(a) => {
                                    if let Some(m) =
                                        g.members.iter_mut().find(|m| m.wallet == a.subject)
                                    {
                                        m.role = a.role;
                                    }
                                }
                                Err(why) => rejected.push(why),
                            }
                            continue;
                        }
                        out.push(Msg {
                            group: gid,
                            sender,
                            body,
                        });
                    }
                    // Welcome/Proposal are not consumed here.
                    _ => continue,
                }
            }
            // On failure the failing envelope is consumed (retrying it cannot succeed); the ones
            // after it are kept for the next poll.
            keep.extend(iter);
        }
        if let Some(m) = mark {
            self.consumed.insert(gid, m);
        }
        self.stash(keep);
        for why in rejected {
            eprintln!("member-daemon: {why}");
            self.grant_log.push(why);
        }
        if self.grant_log.len() > GRANT_LOG_CAP {
            let excess = self.grant_log.len() - GRANT_LOG_CAP;
            self.grant_log.drain(..excess);
        }
        // Processing advanced the inbound ratchet / epoch; persist so the restored state
        // reflects what was already consumed. Skip the write if nothing changed.
        if changed {
            self.persist_state()?;
        }
        match failure {
            Some(err) => Err(err),
            None => Ok(out),
        }
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
