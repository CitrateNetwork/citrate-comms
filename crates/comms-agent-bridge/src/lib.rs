//! `comms-agent-bridge` — bridges an AI agent into citrate-comms as a first-class
//! cryptographic MLS member (COMMS-S3).
//!
//! The bridge IS the MLS client for the agent: it holds the agent's MLS group state and
//! signature key, decrypts the channel, and posts the agent's replies — talking to
//! `nist-agent` / `citrate-agent-runtime` over a Unix-domain socket using the JSON-per-line
//! framing from `nist-agent-daemon/src/ipc.rs`. Inbound application messages become
//! [`AgentInbound`] events; the runtime replies with [`AgentOutbound`] commands.
//!
//! Compliance posture (`PLANSET/06_AGENT_INTEGRATION_SPEC.md`): the agent decrypts using
//! its OWN leaf secret, obtained via a visible MLS Add — a participant, not a wiretap. The
//! role=agent **guardrail** is enforced here against the same `comms-core::rbac` matrix the
//! rest of the system uses: the bridge refuses any membership-mutating action.

#![forbid(unsafe_code)]

use comms_core::domain::{ChatMessage, Lamport};
use comms_core::identity::{EthWallet, SiweMessage};
use comms_core::mls::{GroupHandle, MlsMember};
use comms_core::rbac::{can, verify_grant_chain, Capability};
use comms_proto::{
    Envelope, EnvelopeKind, EpochId, GroupId, KeyPackagePublication, Role, RoleAssertion,
    WalletAddress, CITRATE_CHAIN_ID,
};
use comms_relay::{keyvault, DeliveryService};
use serde::{Deserialize, Serialize};

pub mod ipc;
pub mod socket;

/// OS-keyring service the agent's durable identity is sealed under (shares the
/// citrate-comms keychain namespace with the relay's at-rest master key).
pub const KEYRING_SERVICE: &str = "citrate-comms";

/// Keyring account for an agent's durable secp256k1 wallet secret, per workspace `did`.
/// (The MLS signature key is OpenMLS-managed and re-minted per run; the *wallet* is the
/// stable identity the sponsor [`RoleAssertion`] and SIWE handshake bind to.)
pub fn wallet_keyring_account(did: &str) -> String {
    format!("agent:{did}:wallet")
}

/// An event the bridge emits to the agent runtime (decrypted channel activity).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "lowercase")]
pub enum AgentInbound {
    /// A decrypted application message the agent can read.
    Message { group: String, sender: String, text: String },
    /// A channel system event surfaced to the agent.
    System { group: String, text: String },
}

/// A command the agent runtime sends back to the bridge.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "lowercase")]
pub enum AgentOutbound {
    /// Post a message to a channel the agent is a member of (allowed).
    Send { group: String, text: String },
    /// Membership-mutating actions — an agent must NOT do these. Present so the bridge
    /// can reject them explicitly (the role=agent guardrail).
    AddMember { group: String, member: String },
    RemoveMember { group: String, member: String },
}

/// An agent participating in a channel as a real MLS member.
pub struct AgentBridge {
    did: String,
    wallet: EthWallet,
    mls: MlsMember,
    group: Option<GroupHandle>,
    gid: Option<GroupId>,
    members: Vec<WalletAddress>,
    epoch: u64,
    /// The owner/admin-signed grant that authorizes this agent (role=agent). Until set
    /// (and verified against the workspace owner), the bridge will not post — fail-closed.
    sponsor: Option<RoleAssertion>,
}

impl AgentBridge {
    fn from_wallet(did: &str, wallet: EthWallet) -> Result<Self, BridgeError> {
        let mls = MlsMember::new(did.as_bytes()).map_err(|e| BridgeError::Mls(e.to_string()))?;
        Ok(Self {
            did: did.into(),
            wallet,
            mls,
            group: None,
            gid: None,
            members: Vec::new(),
            epoch: 0,
            sponsor: None,
        })
    }

    /// Provision an agent with an **ephemeral** wallet identity (tests / one-shot use).
    /// Prefer [`AgentBridge::provision`] in production so the identity is keyring-backed
    /// and stable across restarts.
    pub fn new(did: &str) -> Result<Self, BridgeError> {
        Self::from_wallet(did, EthWallet::generate())
    }

    /// Provision an agent with a **durable, keyring-backed** wallet identity. The agent's
    /// 32-byte secp256k1 secret is loaded from (or, on first run, generated into and sealed
    /// in) the host OS keyring under `service` / `agent:<did>:wallet`. Restarting the bridge
    /// yields the same wallet address — the subject the sponsor [`RoleAssertion`] names.
    ///
    /// Set `CITRATE_COMMS_MASTER_KEY`-style overrides are not honored here; the keyring is
    /// the source of truth. Pass [`KEYRING_SERVICE`] for the standard namespace.
    pub fn provision(did: &str, service: &str) -> Result<Self, BridgeError> {
        let account = wallet_keyring_account(did);
        let secret = keyvault::load_or_create_master_key(service, &account)
            .map_err(|e| BridgeError::Keyvault(e.to_string()))?;
        let wallet = EthWallet::from_secret_key(&secret)
            .map_err(|e| BridgeError::Keyvault(e.to_string()))?;
        Self::from_wallet(did, wallet)
    }

    /// Record the owner/admin-signed grant that authorizes this agent. The assertion must
    /// be validly signed by the `workspace_owner`, unexpired, name **this agent's wallet**
    /// as the subject, and grant `role=agent`. Until this succeeds the bridge refuses to
    /// post (fail-closed). Returns the agent's effective role on success.
    pub fn accept_sponsor(
        &mut self,
        sponsor: RoleAssertion,
        workspace_owner: WalletAddress,
        now: u64,
    ) -> Result<Role, BridgeError> {
        if sponsor.role != Role::Agent {
            return Err(BridgeError::BadSponsor(format!(
                "grant is role={:?}, expected Agent",
                sponsor.role
            )));
        }
        verify_grant_chain(&sponsor, self.wallet.address(), workspace_owner, now)
            .map_err(|e| BridgeError::BadSponsor(e.to_string()))?;
        let role = sponsor.role;
        self.sponsor = Some(sponsor);
        Ok(role)
    }

    /// Whether the agent currently holds a verified sponsor grant.
    pub fn is_sponsored(&self) -> bool {
        self.sponsor.is_some()
    }

    pub fn did(&self) -> &str {
        &self.did
    }
    pub fn wallet(&self) -> WalletAddress {
        self.wallet.address()
    }
    pub fn sig_pubkey(&self) -> Vec<u8> {
        self.mls.sig_pubkey()
    }
    pub fn is_member(&self) -> bool {
        self.group.is_some()
    }

    /// SIWE-authenticate the agent's wallet to the relay (the connect handshake).
    pub fn authenticate(&self, relay: &mut DeliveryService, domain: &str, now: u64) -> Result<(), BridgeError> {
        let nonce = relay.issue_challenge(now);
        let msg = SiweMessage {
            domain: domain.into(),
            address: self.wallet.address(),
            statement: format!("Agent {} sign-in", self.did),
            uri: format!("wss://{domain}"),
            version: "1".into(),
            chain_id: CITRATE_CHAIN_ID,
            nonce,
            issued_at_ms: now,
            expiration_ms: now + 600_000,
        };
        let sig = self.wallet.sign_siwe(&msg);
        relay.authenticate(&msg, &sig, now).map(|_| ()).map_err(|e| BridgeError::Relay(e.to_string()))
    }

    /// Publish the agent's KeyPackage (with its wallet binding attestation) so an admin
    /// can add it to a channel.
    pub fn publish_key_package(&self, relay: &mut DeliveryService, domain: &str, now: u64) -> Result<(), BridgeError> {
        let sig_pub = self.mls.sig_pubkey();
        let nonce = relay.issue_challenge(now);
        let pubn = KeyPackagePublication {
            wallet: self.wallet.address(),
            key_package: self.mls.fresh_key_package().map_err(|e| BridgeError::Mls(e.to_string()))?,
            mls_sig_pubkey: sig_pub.clone(),
            binding_attestation: self.wallet.sign_binding(&sig_pub, domain, &nonce).to_vec(),
            nonce,
            relay_domain: domain.into(),
        };
        relay.publish_key_package(pubn, now).map(|_| ()).map_err(|e| BridgeError::Relay(e.to_string()))
    }

    /// Join the channel from the Welcome an admin produced when adding the agent.
    pub fn join(&mut self, welcome: &[u8], ratchet_tree: &[u8], gid: GroupId, members: Vec<WalletAddress>) -> Result<(), BridgeError> {
        let group = self.mls.join(welcome, ratchet_tree).map_err(|e| BridgeError::Mls(e.to_string()))?;
        self.epoch = group.epoch();
        self.group = Some(group);
        self.gid = Some(gid);
        self.members = members;
        Ok(())
    }

    /// Drain the relay mailbox, decrypt, and emit IPC events for the agent runtime.
    pub fn poll(&mut self, relay: &mut DeliveryService) -> Vec<AgentInbound> {
        let mut out = Vec::new();
        let (Some(gid), Some(group)) = (self.gid, self.group.as_mut()) else {
            return out;
        };
        let group_hex = format!("0x{}", hex::encode(&gid.0[..4]));
        for e in relay.fetch(&self.wallet.address()) {
            if e.kind != EnvelopeKind::Application {
                continue;
            }
            let Ok(pt) = group.receive(&self.mls, &e.ciphertext) else { continue };
            let Ok(msg) = ChatMessage::decode(&pt) else { continue };
            out.push(AgentInbound::Message {
                group: group_hex.clone(),
                sender: e.sender.to_hex(),
                text: msg.body,
            });
        }
        out
    }

    /// Act on a command from the agent runtime. `Send` is allowed (post); any
    /// membership-mutating command is **refused** (role=agent guardrail). Returns the
    /// relay sequence number of the submitted message on success.
    pub fn handle(&mut self, relay: &mut DeliveryService, cmd: AgentOutbound, now: u64) -> Result<u64, BridgeError> {
        match cmd {
            AgentOutbound::Send { text, .. } => {
                // Fail-closed: the agent may only act under a verified owner/admin sponsor.
                let sponsor = self.sponsor.as_ref().ok_or(BridgeError::Unsponsored)?;
                // ...and that sponsorship must STILL be live. This used to be
                // `is_none()` alone, so `not_after` was consulted once at
                // `accept_sponsor` and never again. A bridge is a long-running process:
                // an agent sponsored for an hour kept posting for as long as the process
                // lived, under a grant that had lapsed. An expiry the owner signs has to
                // bind every action, not just the first.
                if let Some(exp) = sponsor.not_after {
                    if now >= exp {
                        return Err(BridgeError::SponsorExpired);
                    }
                }
                // The guardrail is the same rbac matrix the rest of the system uses.
                if !can(Role::Agent, Capability::PostMessage) {
                    return Err(BridgeError::Forbidden("post"));
                }
                let gid = self.gid.ok_or(BridgeError::NotJoined)?;
                let group = self.group.as_mut().ok_or(BridgeError::NotJoined)?;
                let payload = ChatMessage {
                    thread_id: None,
                    parent_id: None,
                    body: text,
                    sent: Lamport { counter: 0, actor: self.wallet.address() },
                }
                .encode()
                .map_err(|e| BridgeError::Codec(e.to_string()))?;
                let ct = group.send(&self.mls, &payload).map_err(|e| BridgeError::Mls(e.to_string()))?;
                let recipients: Vec<WalletAddress> =
                    self.members.iter().copied().filter(|a| *a != self.wallet.address()).collect();
                relay
                    .submit_as(
                        // The bridge IS this agent's MLS client; bind the envelope sender
                        // to the agent's own authenticated wallet (FWA-C11-01).
                        self.wallet.address(),
                        Envelope {
                            group_id: gid,
                            epoch: EpochId(self.epoch),
                            kind: EnvelopeKind::Application,
                            sender: self.wallet.address(),
                            recipients,
                            ciphertext: ct,
                            group_seq: None,
                        },
                        now,
                    )
                    .map_err(|e| BridgeError::Relay(e.to_string()))
            }
            // role=agent: read + post only, NEVER membership mutation.
            AgentOutbound::AddMember { .. } => Err(BridgeError::Forbidden("add-member")),
            AgentOutbound::RemoveMember { .. } => Err(BridgeError::Forbidden("remove-member")),
        }
    }

    /// Run the bridge against a connected runtime (`sink`/`source` from
    /// [`AgentConn::split`](socket::AgentConn::split)) and an in-process relay. On each
    /// `poll_interval` tick it drains decrypted channel activity to the runtime; whenever
    /// the runtime sends a command it is applied (a guardrail rejection is reported back as
    /// a `System` event, not a hard error). Returns `Ok(())` when the runtime disconnects.
    pub async fn serve(
        &mut self,
        sink: &mut socket::AgentSink,
        source: &mut socket::AgentSource,
        relay: &mut DeliveryService,
        poll_interval: std::time::Duration,
        mut now: impl FnMut() -> u64,
    ) -> Result<(), socket::SocketError> {
        let mut tick = tokio::time::interval(poll_interval);
        loop {
            tokio::select! {
                _ = tick.tick() => {
                    for ev in self.poll(relay) {
                        sink.send_event(&ev).await?;
                    }
                }
                cmd = source.recv_command() => {
                    match cmd? {
                        Some(c) => {
                            if let Err(e) = self.handle(relay, c, now()) {
                                // Surface guardrail rejections to the runtime; keep serving.
                                sink.send_event(&AgentInbound::System {
                                    group: String::new(),
                                    text: format!("command rejected: {e}"),
                                })
                                .await?;
                            }
                        }
                        None => return Ok(()), // clean EOF — runtime disconnected
                    }
                }
            }
        }
    }
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum BridgeError {
    #[error("agent is not allowed to perform this action: {0} (role=agent is read+post only)")]
    Forbidden(&'static str),
    #[error("agent has no verified sponsor grant — refusing to act (fail-closed)")]
    Unsponsored,
    #[error("the agent's sponsor grant has expired — refusing to act (fail-closed)")]
    SponsorExpired,
    #[error("invalid sponsor grant: {0}")]
    BadSponsor(String),
    #[error("keyring/provisioning error: {0}")]
    Keyvault(String),
    #[error("agent has not joined a channel")]
    NotJoined,
    #[error("mls error: {0}")]
    Mls(String),
    #[error("relay error: {0}")]
    Relay(String),
    #[error("codec error: {0}")]
    Codec(String),
}

#[cfg(test)]
mod tests {
    use super::*;
    use comms_core::mls::MlsMember as Member;
    use comms_core::rbac::sign_role_assertion;

    const DOMAIN: &str = "relay.citrate.internal";

    fn login(relay: &mut DeliveryService, w: &EthWallet, now: u64) {
        let nonce = relay.issue_challenge(now);
        let msg = SiweMessage {
            domain: DOMAIN.into(), address: w.address(), statement: "in".into(),
            uri: format!("wss://{DOMAIN}"), version: "1".into(), chain_id: CITRATE_CHAIN_ID,
            nonce, issued_at_ms: now, expiration_ms: now + 600_000,
        };
        let sig = w.sign_siwe(&msg);
        relay.authenticate(&msg, &sig, now).unwrap();
    }

    /// A sponsorship that has EXPIRED must stop the agent acting.
    ///
    /// `RoleAssertion.not_after` is expressed by the owner, signed by the owner, and
    /// checked by `verify_role_assertion` — once, at `accept_sponsor`. After that the
    /// bridge stored `Some(assertion)` and every subsequent action asked only
    /// `self.sponsor.is_none()`, so the expiry the owner set was never consulted again.
    ///
    /// A bridge is a long-running process. An agent sponsored for an hour kept posting
    /// for as long as the process lived — days, in a deployment — under a grant that had
    /// lapsed. That is the opposite of what an expiry is for, and it is why an owner
    /// bounding an agent's authority in time could not actually do so.
    ///
    /// `handle()` already receives `now`, so nothing had to be plumbed to fix it.
    #[test]
    fn an_expired_sponsorship_stops_the_agent() {
        let now = 1_000u64;
        let admin_w = EthWallet::generate();
        let mut relay = DeliveryService::new(DOMAIN, admin_w.address(), 0).unwrap();
        login(&mut relay, &admin_w, now);

        let admin_m = Member::new(&admin_w.address().0).unwrap();
        let mut agent = AgentBridge::new("did:citrate:expiring-agent").unwrap();
        agent.authenticate(&mut relay, DOMAIN, now).unwrap();
        agent.publish_key_package(&mut relay, DOMAIN, now).unwrap();

        let mut admin_g = admin_m.create_group().unwrap();
        let gid = GroupId(*blake3::hash(&admin_g.group_id()).as_bytes());
        relay.register_group(gid, admin_w.address(), now).unwrap();
        let agent_kp = relay.take_key_package(&agent.wallet()).unwrap();
        let add = admin_g.add(&admin_m, &agent_kp.key_package).unwrap();
        relay.submit_as(admin_w.address(), Envelope { group_id: gid, epoch: EpochId(1), kind: EnvelopeKind::Commit, sender: admin_w.address(), recipients: vec![], ciphertext: add.commit, group_seq: None }, now).unwrap();
        relay.onboard(gid, admin_w.address(), None, agent.wallet(), Envelope { group_id: gid, epoch: EpochId(1), kind: EnvelopeKind::Welcome, sender: admin_w.address(), recipients: vec![agent.wallet()], ciphertext: add.welcome.clone(), group_seq: None }, add.ratchet_tree.clone(), now).unwrap();
        agent.join(&add.welcome, &add.ratchet_tree, gid, vec![admin_w.address(), agent.wallet()]).unwrap();

        // Sponsored for one minute.
        let expires_at = now + 60_000;
        let grant = sign_role_assertion(&admin_w, Role::Owner, agent.wallet(), Role::Agent, Some(gid), Some(expires_at)).unwrap();
        agent.accept_sponsor(grant, admin_w.address(), now).unwrap();

        // Inside the window: allowed.
        assert!(
            agent
                .handle(&mut relay, AgentOutbound::Send { group: "deals".into(), text: "in window".into() }, now + 30_000)
                .is_ok(),
            "an unexpired sponsorship must still permit posting"
        );

        // AT `not_after` exactly: refused. This pins the boundary to the same semantics
        // `verify_role_assertion` already uses (`now_ms >= exp`). If the re-check used
        // `>` instead, the bridge and the verifier would disagree about the instant a
        // grant dies — `accept_sponsor` would reject an assertion that `handle` still
        // honoured, which is a worse state than either rule alone.
        assert_eq!(
            agent.handle(
                &mut relay,
                AgentOutbound::Send { group: "deals".into(), text: "exactly at expiry".into() },
                expires_at,
            ),
            Err(BridgeError::SponsorExpired),
            "expiry must bind at `not_after`, matching verify_role_assertion"
        );

        // Past `not_after`: refused. The owner set a bound; it has to mean something.
        assert_eq!(
            agent.handle(
                &mut relay,
                AgentOutbound::Send { group: "deals".into(), text: "after the grant lapsed".into() },
                expires_at + 1,
            ),
            Err(BridgeError::SponsorExpired),
            "an agent must not act under a lapsed grant"
        );

        // And it stays refused — this is not a one-shot check.
        assert_eq!(
            agent.handle(
                &mut relay,
                AgentOutbound::Send { group: "deals".into(), text: "still trying".into() },
                expires_at + 86_400_000,
            ),
            Err(BridgeError::SponsorExpired)
        );
    }

    /// Admin creates a channel; an agent bridge is added as a real MLS member, receives a
    /// decrypted message as an IPC event, posts a reply the admin decrypts, and is refused
    /// any membership-mutating command.
    #[test]
    fn agent_participates_as_a_member_and_is_guardrailed() {
        let now = 1_000u64;
        let admin_w = EthWallet::generate();
        let mut relay = DeliveryService::new(DOMAIN, admin_w.address(), 0).unwrap();
        login(&mut relay, &admin_w, now);

        let admin_m = Member::new(&admin_w.address().0).unwrap();
        let mut agent = AgentBridge::new("did:citrate:crm-agent").unwrap();
        agent.authenticate(&mut relay, DOMAIN, now).unwrap();
        agent.publish_key_package(&mut relay, DOMAIN, now).unwrap();

        // Admin creates the channel and adds the agent (a visible MLS Add).
        let mut admin_g = admin_m.create_group().unwrap();
        let gid = GroupId(*blake3::hash(&admin_g.group_id()).as_bytes());
        relay.register_group(gid, admin_w.address(), now).unwrap();
        let agent_kp = relay.take_key_package(&agent.wallet()).unwrap();
        let add = admin_g.add(&admin_m, &agent_kp.key_package).unwrap();
        relay.submit_as(admin_w.address(), Envelope { group_id: gid, epoch: EpochId(1), kind: EnvelopeKind::Commit, sender: admin_w.address(), recipients: vec![], ciphertext: add.commit, group_seq: None }, now).unwrap();
        relay.onboard(gid, admin_w.address(), None, agent.wallet(), Envelope { group_id: gid, epoch: EpochId(1), kind: EnvelopeKind::Welcome, sender: admin_w.address(), recipients: vec![agent.wallet()], ciphertext: add.welcome.clone(), group_seq: None }, add.ratchet_tree.clone(), now).unwrap();
        agent.join(&add.welcome, &add.ratchet_tree, gid, vec![admin_w.address(), agent.wallet()]).unwrap();
        assert!(agent.is_member());

        // The admin (workspace owner) sponsors the agent: a signed role=agent grant scoped
        // to this channel. Until accepted, the bridge fails closed on any post.
        assert_eq!(
            agent.handle(&mut relay, AgentOutbound::Send { group: "deals".into(), text: "early".into() }, now),
            Err(BridgeError::Unsponsored)
        );
        let grant = sign_role_assertion(&admin_w, Role::Owner, agent.wallet(), Role::Agent, Some(gid), Some(now + 86_400_000)).unwrap();
        agent.accept_sponsor(grant, admin_w.address(), now).unwrap();
        assert!(agent.is_sponsored());

        // Admin posts a message; the agent decrypts it as an IPC `message` event.
        let payload = ChatMessage { thread_id: None, parent_id: None, body: "Can you summarize the Northwind thread?".into(), sent: Lamport { counter: 1, actor: admin_w.address() } }.encode().unwrap();
        let ct = admin_g.send(&admin_m, &payload).unwrap();
        relay.submit_as(admin_w.address(), Envelope { group_id: gid, epoch: EpochId(1), kind: EnvelopeKind::Application, sender: admin_w.address(), recipients: vec![agent.wallet()], ciphertext: ct, group_seq: None }, now).unwrap();

        let inbox = agent.poll(&mut relay);
        assert_eq!(inbox.len(), 1);
        match &inbox[0] {
            AgentInbound::Message { sender, text, .. } => {
                assert_eq!(*sender, admin_w.address().to_hex());
                assert!(text.contains("summarize the Northwind"));
            }
            _ => panic!("expected a message event"),
        }

        // The agent posts a reply; the admin decrypts it.
        let seq = agent.handle(&mut relay, AgentOutbound::Send { group: "deals".into(), text: "Summary: Northwind wants a self-hosted, air-gapped pilot; moved to Proposal.".into() }, now).unwrap();
        assert!(seq > 0);
        let admin_inbox = relay.fetch(&admin_w.address());
        let app = admin_inbox.iter().find(|e| e.kind == EnvelopeKind::Application).unwrap();
        let pt = admin_g.receive(&admin_m, &app.ciphertext).unwrap();
        assert!(ChatMessage::decode(&pt).unwrap().body.contains("Northwind wants a self-hosted"));

        // The guardrail: the agent is refused any membership-mutating command.
        assert_eq!(agent.handle(&mut relay, AgentOutbound::AddMember { group: "deals".into(), member: "0xabc".into() }, now), Err(BridgeError::Forbidden("add-member")));
        assert_eq!(agent.handle(&mut relay, AgentOutbound::RemoveMember { group: "deals".into(), member: "0xabc".into() }, now), Err(BridgeError::Forbidden("remove-member")));

        // The audit chain recorded the agent's envelope + the visible Add.
        relay.audit().verify_integrity().unwrap();
    }

    /// The keyring-backed identity is STABLE in its secret: the same sealed secret always
    /// yields the same wallet address (the subject a sponsor grant names), so restarting
    /// the bridge — which reloads the same secret from the keyring — keeps the same agent.
    /// (`keyring::mock` is per-entry and can't model a restart, so we assert the
    /// determinism the guarantee reduces to, then smoke-test `provision` end to end.)
    #[test]
    fn provisioned_identity_is_deterministic_in_its_secret() {
        let secret = [7u8; 32];
        let a = EthWallet::from_secret_key(&secret).unwrap();
        let b = EthWallet::from_secret_key(&secret).unwrap();
        assert_eq!(a.address(), b.address(), "a fixed secret yields a fixed wallet");
        let c = EthWallet::from_secret_key(&[9u8; 32]).unwrap();
        assert_ne!(a.address(), c.address(), "a different secret is a different agent");

        // provision() wires the keyring through to a valid, usable wallet identity.
        keyring::set_default_credential_builder(keyring::mock::default_credential_builder());
        let agent = AgentBridge::provision("did:citrate:ops-agent", KEYRING_SERVICE).unwrap();
        assert_ne!(agent.wallet().0, [0u8; 20]);
        // Ephemeral provisioning (no keyring) is, by contrast, fresh each time.
        assert_ne!(AgentBridge::new("did:x").unwrap().wallet(), AgentBridge::new("did:x").unwrap().wallet());
    }

    /// The sponsor gate rejects grants that are not a valid, owner-signed role=agent
    /// assertion for THIS agent — wrong role, wrong issuer, wrong subject, or expired.
    #[test]
    fn sponsor_gate_rejects_bad_grants() {
        let now = 2_000u64;
        let owner = EthWallet::generate();
        let imposter = EthWallet::generate();
        let mut agent = AgentBridge::new("did:citrate:crm-agent").unwrap();

        // Wrong role: owner grants Admin, not Agent.
        let admin_grant = sign_role_assertion(&owner, Role::Owner, agent.wallet(), Role::Admin, None, None).unwrap();
        assert!(matches!(agent.accept_sponsor(admin_grant, owner.address(), now), Err(BridgeError::BadSponsor(_))));

        // Wrong issuer: a non-owner "sponsors" the agent.
        let imposter_grant = sign_role_assertion(&imposter, Role::Owner, agent.wallet(), Role::Agent, None, None).unwrap();
        assert!(matches!(agent.accept_sponsor(imposter_grant, owner.address(), now), Err(BridgeError::BadSponsor(_))));

        // Wrong subject: owner grants role=agent to someone else.
        let other = EthWallet::generate();
        let other_grant = sign_role_assertion(&owner, Role::Owner, other.address(), Role::Agent, None, None).unwrap();
        assert!(matches!(agent.accept_sponsor(other_grant, owner.address(), now), Err(BridgeError::BadSponsor(_))));

        // Expired grant.
        let expired = sign_role_assertion(&owner, Role::Owner, agent.wallet(), Role::Agent, None, Some(now - 1)).unwrap();
        assert!(matches!(agent.accept_sponsor(expired, owner.address(), now), Err(BridgeError::BadSponsor(_))));

        // A valid grant is accepted.
        let good = sign_role_assertion(&owner, Role::Owner, agent.wallet(), Role::Agent, None, Some(now + 1_000)).unwrap();
        assert_eq!(agent.accept_sponsor(good, owner.address(), now).unwrap(), Role::Agent);
        assert!(agent.is_sponsored());
    }

    /// WP-3.6 full integration through the Unix socket: an admin posts a message; the
    /// bridge's `serve` loop decrypts it and pushes it to a connected runtime over the
    /// (0600, bearer-gated) socket; the runtime replies with a `send` command; the bridge
    /// encrypts + submits it; the admin decrypts the agent's reply. No plaintext ever
    /// crosses the socket as ciphertext — only the agent's own decrypted view does.
    #[tokio::test]
    async fn serve_round_trips_a_message_over_the_socket() {
        use std::time::Duration;
        let now = 5_000u64;
        let admin_w = EthWallet::generate();
        let mut relay = DeliveryService::new(DOMAIN, admin_w.address(), 0).unwrap();
        login(&mut relay, &admin_w, now);

        let admin_m = Member::new(&admin_w.address().0).unwrap();
        let mut agent = AgentBridge::new("did:citrate:crm-agent").unwrap();
        agent.authenticate(&mut relay, DOMAIN, now).unwrap();
        agent.publish_key_package(&mut relay, DOMAIN, now).unwrap();

        // Admin creates the channel, adds the agent, sponsors it.
        let mut admin_g = admin_m.create_group().unwrap();
        let gid = GroupId(*blake3::hash(&admin_g.group_id()).as_bytes());
        relay.register_group(gid, admin_w.address(), now).unwrap();
        let agent_kp = relay.take_key_package(&agent.wallet()).unwrap();
        let add = admin_g.add(&admin_m, &agent_kp.key_package).unwrap();
        relay.submit_as(admin_w.address(), Envelope { group_id: gid, epoch: EpochId(1), kind: EnvelopeKind::Commit, sender: admin_w.address(), recipients: vec![], ciphertext: add.commit, group_seq: None }, now).unwrap();
        relay.onboard(gid, admin_w.address(), None, agent.wallet(), Envelope { group_id: gid, epoch: EpochId(1), kind: EnvelopeKind::Welcome, sender: admin_w.address(), recipients: vec![agent.wallet()], ciphertext: add.welcome.clone(), group_seq: None }, add.ratchet_tree.clone(), now).unwrap();
        agent.join(&add.welcome, &add.ratchet_tree, gid, vec![admin_w.address(), agent.wallet()]).unwrap();
        let grant = sign_role_assertion(&admin_w, Role::Owner, agent.wallet(), Role::Agent, Some(gid), Some(now + 86_400_000)).unwrap();
        agent.accept_sponsor(grant, admin_w.address(), now).unwrap();

        // Admin posts a message into the channel.
        let payload = ChatMessage { thread_id: None, parent_id: None, body: "What's the status of the Northwind deal?".into(), sent: Lamport { counter: 1, actor: admin_w.address() } }.encode().unwrap();
        let ct = admin_g.send(&admin_m, &payload).unwrap();
        relay.submit_as(admin_w.address(), Envelope { group_id: gid, epoch: EpochId(1), kind: EnvelopeKind::Application, sender: admin_w.address(), recipients: vec![agent.wallet()], ciphertext: ct, group_seq: None }, now).unwrap();

        // Bind the bearer-gated socket; accept + connect concurrently.
        let dir = tempfile::tempdir().unwrap();
        let sock_path = dir.path().join("agent.sock");
        let bearer = socket::random_bearer().unwrap();
        let sock = socket::AgentSocket::bind(&sock_path, bearer.clone()).unwrap();
        let (conn, client) = tokio::join!(
            sock.accept(),
            socket::RuntimeClient::connect(&sock_path, bearer.clone()),
        );
        let (mut sink, mut source) = conn.unwrap().split();
        let mut client = client.unwrap();

        // Drive the bridge's serve loop and the runtime script concurrently.
        let serve = agent.serve(&mut sink, &mut source, &mut relay, Duration::from_millis(2), || now);
        let runtime = async move {
            // The runtime receives the admin's decrypted message…
            let ev = client.recv_event().await.unwrap().unwrap();
            assert!(matches!(ev, AgentInbound::Message { ref text, .. } if text.contains("Northwind")));
            // …and replies. The bridge encrypts + submits it.
            client.send_command(&AgentOutbound::Send { group: "deals".into(), text: "Northwind is in Proposal; pilot is air-gapped.".into() }).await.unwrap();
            // Give the bridge a beat to submit before we EOF the loop.
            tokio::time::sleep(Duration::from_millis(10)).await;
            drop(client); // clean EOF ends serve
        };
        let (serve_res, ()) = tokio::join!(serve, runtime);
        serve_res.unwrap();

        // The admin decrypts the agent's reply off the relay.
        let admin_inbox = relay.fetch(&admin_w.address());
        let app = admin_inbox.iter().find(|e| e.kind == EnvelopeKind::Application).expect("agent reply routed");
        let pt = admin_g.receive(&admin_m, &app.ciphertext).unwrap();
        assert!(ChatMessage::decode(&pt).unwrap().body.contains("Northwind is in Proposal"));
        relay.audit().verify_integrity().unwrap();
    }

    /// WP-4.4 (`PLANSET/07` §4) — the executable server-blind proof, with REAL MLS
    /// ciphertext through a PERSISTENT relay. A unique plaintext canary is sealed into an
    /// MLS message and submitted; we then assert the canary appears (a) nowhere in the
    /// on-the-wire ciphertext (MLS made it opaque) and (b) nowhere in the relay's on-disk
    /// RocksDB files (the at-rest AES-256-GCM layer encrypts even the stored ciphertext).
    /// This is the relay-cannot-read-messages invariant, end to end.
    #[test]
    fn relay_persists_only_ciphertext_on_disk() {
        // A canary unlikely to occur by chance; we search the raw store for it.
        const CANARY: &[u8] = b"CANARY-7f3a9c2e-Northwind-pilot-is-air-gapped";
        let now = 7_000u64;
        let dir = tempfile::tempdir().unwrap();
        let master = [42u8; 32];
        let admin_w = EthWallet::generate();

        let plaintext_ct = {
            let mut relay =
                DeliveryService::open(dir.path(), DOMAIN, admin_w.address(), master, 0).unwrap();
            login(&mut relay, &admin_w, now);
            let admin_m = Member::new(&admin_w.address().0).unwrap();
            let mut admin_g = admin_m.create_group().unwrap();
            let gid = GroupId(*blake3::hash(&admin_g.group_id()).as_bytes());
            relay.register_group(gid, admin_w.address(), now).unwrap();

            // Seal the canary inside a real MLS-encrypted ChatMessage.
            let body = String::from_utf8(CANARY.to_vec()).unwrap();
            let payload = ChatMessage { thread_id: None, parent_id: None, body, sent: Lamport { counter: 1, actor: admin_w.address() } }.encode().unwrap();
            let ct = admin_g.send(&admin_m, &payload).unwrap();
            // (a) The wire ciphertext is opaque — the canary is not in it.
            assert!(!contains_subseq(&ct, CANARY), "MLS ciphertext leaked the plaintext");
            relay.submit_as(admin_w.address(), Envelope { group_id: gid, epoch: EpochId(1), kind: EnvelopeKind::Application, sender: admin_w.address(), recipients: vec![], ciphertext: ct.clone(), group_seq: None }, now).unwrap();
            ct
            // relay drops here → RocksDB flushes and closes.
        };
        // Sanity: the ciphertext we submitted was non-trivial.
        assert!(plaintext_ct.len() > CANARY.len());

        // (b) Walk every file the relay wrote and assert the canary is absent everywhere —
        // SST, WAL (.log), MANIFEST, CURRENT — because the at-rest layer encrypts values.
        let mut files_scanned = 0usize;
        for path in walk_files(dir.path()) {
            let bytes = std::fs::read(&path).unwrap_or_default();
            files_scanned += 1;
            assert!(
                !contains_subseq(&bytes, CANARY),
                "plaintext canary found on disk in {}",
                path.display()
            );
        }
        assert!(files_scanned > 0, "expected the relay to have written files");
    }

    /// Naive substring search over bytes (test-only).
    fn contains_subseq(haystack: &[u8], needle: &[u8]) -> bool {
        if needle.is_empty() || haystack.len() < needle.len() {
            return false;
        }
        haystack.windows(needle.len()).any(|w| w == needle)
    }

    /// Recursively collect every regular file under `root` (test-only).
    fn walk_files(root: &std::path::Path) -> Vec<std::path::PathBuf> {
        let mut out = Vec::new();
        let mut stack = vec![root.to_path_buf()];
        while let Some(dir) = stack.pop() {
            let Ok(entries) = std::fs::read_dir(&dir) else { continue };
            for entry in entries.flatten() {
                let p = entry.path();
                if p.is_dir() {
                    stack.push(p);
                } else {
                    out.push(p);
                }
            }
        }
        out
    }
}
