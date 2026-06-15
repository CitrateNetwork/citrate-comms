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
use comms_core::rbac::{can, Capability};
use comms_proto::{
    Envelope, EnvelopeKind, EpochId, GroupId, KeyPackagePublication, Role, WalletAddress,
    CITRATE_CHAIN_ID,
};
use comms_relay::DeliveryService;
use serde::{Deserialize, Serialize};

pub mod ipc;

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
}

impl AgentBridge {
    /// Provision an agent. Its MLS credential identity binds the `did` (in production the
    /// signing key is sealed in the OS keyring; here it is in-memory for the bridge).
    pub fn new(did: &str) -> Result<Self, BridgeError> {
        let wallet = EthWallet::generate();
        let mls = MlsMember::new(did.as_bytes()).map_err(|e| BridgeError::Mls(e.to_string()))?;
        Ok(Self { did: did.into(), wallet, mls, group: None, gid: None, members: Vec::new(), epoch: 0 })
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
                    .submit(
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
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum BridgeError {
    #[error("agent is not allowed to perform this action: {0} (role=agent is read+post only)")]
    Forbidden(&'static str),
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
        relay.submit(Envelope { group_id: gid, epoch: EpochId(1), kind: EnvelopeKind::Commit, sender: admin_w.address(), recipients: vec![], ciphertext: add.commit, group_seq: None }, now).unwrap();
        relay.onboard(gid, admin_w.address(), agent.wallet(), Envelope { group_id: gid, epoch: EpochId(1), kind: EnvelopeKind::Welcome, sender: admin_w.address(), recipients: vec![agent.wallet()], ciphertext: add.welcome.clone(), group_seq: None }, add.ratchet_tree.clone(), now).unwrap();
        agent.join(&add.welcome, &add.ratchet_tree, gid, vec![admin_w.address(), agent.wallet()]).unwrap();
        assert!(agent.is_member());

        // Admin posts a message; the agent decrypts it as an IPC `message` event.
        let payload = ChatMessage { thread_id: None, parent_id: None, body: "Can you summarize the Northwind thread?".into(), sent: Lamport { counter: 1, actor: admin_w.address() } }.encode().unwrap();
        let ct = admin_g.send(&admin_m, &payload).unwrap();
        relay.submit(Envelope { group_id: gid, epoch: EpochId(1), kind: EnvelopeKind::Application, sender: admin_w.address(), recipients: vec![agent.wallet()], ciphertext: ct, group_seq: None }, now).unwrap();

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
}
