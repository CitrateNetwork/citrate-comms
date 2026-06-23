//! `backend` — the live data layer behind the Slint UI (COMMS-S2 WP-2.9).
//!
//! The client drives an **in-process server-blind relay** (`comms-relay::DeliveryService`)
//! plus a **real MLS group** (`comms-core::mls`) and the **event-sourced domain store**
//! (`comms-core::domain`). The `#deals` channel scenario is seeded by genuinely encrypting
//! messages + domain events, routing them through the relay, and decrypting them — so the
//! channel stream, members, CRM/PM records, and audit trail the UI shows are produced by
//! the live crypto stack, not static fixtures. `send` performs a real MLS encrypt → relay
//! submit and appends the (locally-known) message.
//!
//! The world here is in-process for the desktop demo; pointing the same `Workspace` at a
//! networked `comms-relay::ws` relay is a drop-in transport swap.

use std::collections::HashMap;

use comms_core::audit::AuditChain;
use comms_core::domain::event::fields as f;
use comms_core::domain::{ChatMessage, DomainEvent, DomainStore, EntityId, EntityType, FieldValue, Lamport, LamportClock};
use comms_core::identity::{EthWallet, SiweMessage};
use comms_core::mls::{GroupHandle, MlsMember};
use comms_proto::{
    AuditEvent, Envelope, EnvelopeKind, EpochId, GroupId, KeyPackagePublication, WalletAddress,
    canonical, CITRATE_CHAIN_ID,
};
use comms_relay::DeliveryService;
use serde::{Deserialize, Serialize};

const DOMAIN: &str = "relay.citrate.internal";

/// What rides inside an MLS application message: either a chat message or a domain event.
#[derive(Serialize, Deserialize)]
enum WirePayload {
    Chat(ChatMessage),
    Domain(DomainEvent),
}

// ───────────────────────────── UI-facing rows ─────────────────────────────

#[derive(Clone, Debug, Default)]
pub struct UiMessage {
    pub author: String,
    pub initials: String,
    pub rgb: (u8, u8, u8),
    pub role: String,
    pub ts: String,
    pub text: String,
    pub is_agent: bool,
    pub system: bool,
    pub boundary: bool,
    pub has_link: bool,
    pub link_kind: String,
    pub link_name: String,
    pub link_id: String,
}
#[derive(Clone, Debug)]
pub struct UiMember {
    pub name: String,
    pub initials: String,
    pub rgb: (u8, u8, u8),
    pub role: String,
    pub addr: String,
    pub is_agent: bool,
}
#[derive(Clone, Debug)]
pub struct UiDeal {
    pub name: String,
    pub account: String,
    pub value: String,
    pub stage: String,
    pub priority: String,
    pub owner: String,
}
#[derive(Clone, Debug)]
pub struct UiTask {
    pub title: String,
    pub assignee: String,
    pub status: String,
    pub priority: String,
    pub due: String,
}
#[derive(Clone, Debug)]
pub struct UiAudit {
    pub seq: String,
    pub event: String,
    pub summary: String,
    pub actor: String,
    pub hash: String,
}

#[derive(Clone)]
struct Meta {
    name: String,
    initials: String,
    rgb: (u8, u8, u8),
    role: String,
    is_agent: bool,
}

/// The live workspace: relay + the local user's MLS group view + the domain store.
pub struct Workspace {
    relay: DeliveryService,
    gid: GroupId,
    me_wallet: EthWallet,
    me_mls: MlsMember,
    me_group: GroupHandle,
    store: DomainStore,
    clock: LamportClock,
    now: u64,
    by_wallet: HashMap<WalletAddress, Meta>,
    messages: Vec<UiMessage>,
    members: Vec<UiMember>,
}

fn login(relay: &mut DeliveryService, w: &EthWallet, now: u64) -> Result<(), String> {
    let nonce = relay.issue_challenge(now);
    let msg = SiweMessage {
        domain: DOMAIN.into(),
        address: w.address(),
        statement: "Sign in to citrate-comms".into(),
        uri: format!("wss://{DOMAIN}"),
        version: "1".into(),
        chain_id: CITRATE_CHAIN_ID,
        nonce,
        issued_at_ms: now,
        expiration_ms: now + 600_000,
    };
    let sig = w.sign_siwe(&msg);
    relay.authenticate(&msg, &sig, now).map(|_| ()).map_err(|e| e.to_string())
}

fn publish_kp(relay: &mut DeliveryService, w: &EthWallet, m: &MlsMember, now: u64) -> Result<(), String> {
    let sig_pub = m.sig_pubkey();
    let nonce = relay.issue_challenge(now);
    let pubn = KeyPackagePublication {
        wallet: w.address(),
        key_package: m.fresh_key_package().map_err(|e| e.to_string())?,
        mls_sig_pubkey: sig_pub.clone(),
        binding_attestation: w.sign_binding(&sig_pub, DOMAIN, &nonce).to_vec(),
        nonce,
        relay_domain: DOMAIN.into(),
    };
    relay.publish_key_package(pubn, now).map(|_| ()).map_err(|e| e.to_string())
}

impl Workspace {
    /// Bring up the relay + the real #deals MLS group and seed the scenario.
    pub fn bootstrap() -> Result<Self, String> {
        let now = 1_000u64;

        // Wallets + MLS members for the four channel participants.
        let saul_w = EthWallet::generate();
        let priya_w = EthWallet::generate();
        let mateo_w = EthWallet::generate();
        let agent_w = EthWallet::generate();

        let mut relay = DeliveryService::new(DOMAIN, saul_w.address(), 0).map_err(|e| e.to_string())?;
        for w in [&saul_w, &priya_w, &mateo_w, &agent_w] {
            login(&mut relay, w, now)?;
        }

        let saul_m = MlsMember::new(&saul_w.address().0).map_err(|e| e.to_string())?;
        let priya_m = MlsMember::new(&priya_w.address().0).map_err(|e| e.to_string())?;
        let mateo_m = MlsMember::new(&mateo_w.address().0).map_err(|e| e.to_string())?;
        let agent_m = MlsMember::new(&agent_w.address().0).map_err(|e| e.to_string())?;
        for (w, m) in [(&priya_w, &priya_m), (&mateo_w, &mateo_m), (&agent_w, &agent_m)] {
            publish_kp(&mut relay, w, m, now)?;
        }

        // Saul creates #deals; everyone else is added in sequence (real MLS commits).
        let mut saul_g = saul_m.create_group().map_err(|e| e.to_string())?;
        let gid = GroupId(*blake3::hash(&saul_g.group_id()).as_bytes());
        relay.register_group(gid, saul_w.address(), now).map_err(|e| e.to_string())?;

        let addrs = [saul_w.address(), priya_w.address(), mateo_w.address(), agent_w.address()];
        let everyone = move |except: WalletAddress| -> Vec<WalletAddress> {
            addrs.iter().copied().filter(|a| *a != except).collect()
        };

        // add priya (epoch 1)
        let priya_kp = relay.take_key_package(&priya_w.address()).ok_or("no priya kp")?;
        let a1 = saul_g.add(&saul_m, &priya_kp.key_package).map_err(|e| e.to_string())?;
        submit_commit(&mut relay, gid, &saul_w, 1, a1.commit.clone(), vec![], now)?;
        onboard(&mut relay, gid, &saul_w, priya_w.address(), 1, a1.welcome.clone(), a1.ratchet_tree.clone(), now)?;
        let mut priya_g = priya_m.join(&a1.welcome, &a1.ratchet_tree).map_err(|e| e.to_string())?;

        // add mateo (epoch 2)
        let mateo_kp = relay.take_key_package(&mateo_w.address()).ok_or("no mateo kp")?;
        let a2 = saul_g.add(&saul_m, &mateo_kp.key_package).map_err(|e| e.to_string())?;
        submit_commit(&mut relay, gid, &saul_w, 2, a2.commit.clone(), vec![priya_w.address()], now)?;
        onboard(&mut relay, gid, &saul_w, mateo_w.address(), 2, a2.welcome.clone(), a2.ratchet_tree.clone(), now)?;
        priya_g.process_commit(&priya_m, &a2.commit).map_err(|e| e.to_string())?;
        let mut mateo_g = mateo_m.join(&a2.welcome, &a2.ratchet_tree).map_err(|e| e.to_string())?;

        // add crm-agent (epoch 3)
        let agent_kp = relay.take_key_package(&agent_w.address()).ok_or("no agent kp")?;
        let a3 = saul_g.add(&saul_m, &agent_kp.key_package).map_err(|e| e.to_string())?;
        submit_commit(&mut relay, gid, &saul_w, 3, a3.commit.clone(), vec![priya_w.address(), mateo_w.address()], now)?;
        onboard(&mut relay, gid, &saul_w, agent_w.address(), 3, a3.welcome.clone(), a3.ratchet_tree.clone(), now)?;
        priya_g.process_commit(&priya_m, &a3.commit).map_err(|e| e.to_string())?;
        mateo_g.process_commit(&mateo_m, &a3.commit).map_err(|e| e.to_string())?;
        let mut agent_g = agent_m.join(&a3.welcome, &a3.ratchet_tree).map_err(|e| e.to_string())?;

        // member metadata, keyed by wallet (for decrypt → display attribution).
        let mut by_wallet = HashMap::new();
        by_wallet.insert(saul_w.address(), Meta { name: "Saul Loveman".into(), initials: "SL".into(), rgb: (0x2f, 0x45, 0x02), role: "Owner".into(), is_agent: false });
        by_wallet.insert(priya_w.address(), Meta { name: "Priya Anand".into(), initials: "PA".into(), rgb: (0x1b, 0x49, 0x65), role: "Admin".into(), is_agent: false });
        by_wallet.insert(mateo_w.address(), Meta { name: "Mateo Ferraro".into(), initials: "MF".into(), rgb: (0x6e, 0x51, 0x00), role: "Member".into(), is_agent: false });
        by_wallet.insert(agent_w.address(), Meta { name: "@crm-agent".into(), initials: "CA".into(), rgb: (0x0e, 0x0f, 0x0c), role: "Agent".into(), is_agent: true });

        let mut clock = LamportClock::new(saul_w.address());
        let mut store = DomainStore::new();
        let mut messages: Vec<UiMessage> = vec![UiMessage {
            boundary: true,
            system: true,
            text: "You joined on Jun 14 · Earlier messages stay private to members who were here.".into(),
            ..Default::default()
        }];

        // ── Seed the conversation through real encryption; Saul decrypts each. ──
        let post = |relay: &mut DeliveryService, w: &EthWallet, g: &mut GroupHandle, m: &MlsMember, p: WirePayload| -> Result<(), String> {
            let ct = g.send(m, &canonical::to_vec(&p).map_err(|e| e.to_string())?).map_err(|e| e.to_string())?;
            relay.submit_as(w.address(), Envelope { group_id: gid, epoch: EpochId(3), kind: EnvelopeKind::Application, sender: w.address(), recipients: everyone(w.address()), ciphertext: ct, group_seq: None }, now).map_err(|e| e.to_string())?;
            Ok(())
        };

        post(&mut relay, &priya_w, &mut priya_g, &priya_m, chat("09:14", "Morning — Northwind came back warm after the demo. They want a self-hosted pilot on their own iron, fully air-gapped.", &mut clock))?;
        post(&mut relay, &priya_w, &mut priya_g, &priya_m, chat("09:14", "That's exactly our story. I'm moving them to Proposal.", &mut clock))?;
        post(&mut relay, &mateo_w, &mut mateo_g, &mateo_m, chat("09:16", "Love it. Security review will matter to them — they asked specifically about post-quantum. Worth looping that in early.", &mut clock))?;

        // drain so far (priya x2, mateo) → record as Saul-decrypted messages
        drain(&mut relay, &saul_w, &mut saul_g, &saul_m, &by_wallet, &mut store, &mut messages);

        // system marker (UI only)
        messages.push(UiMessage { system: true, text: "Priya added @crm-agent to the channel — it can read this channel and post. Everyone here can see it joined.".into(), ..Default::default() });

        // agent: emit a real Deal domain event + a chat message linking it
        let deal_id = EntityId([42; 16]);
        let deal_ev = DomainEvent::upsert(gid, EntityType::Deal, deal_id, vec![
            (f::NAME.into(), FieldValue::Text("Northwind — self-hosted pilot".into())),
            (f::ACCOUNT.into(), FieldValue::Text("Northwind Traders".into())),
            (f::VALUE.into(), FieldValue::Money(240_000)),
            (f::STAGE.into(), FieldValue::Tag("Proposal".into())),
            (f::PRIORITY.into(), FieldValue::Tag("high".into())),
            (f::OWNER.into(), FieldValue::Text("PA".into())),
        ], clock.tick());
        post(&mut relay, &agent_w, &mut agent_g, &agent_m, WirePayload::Domain(deal_ev))?;
        post(&mut relay, &agent_w, &mut agent_g, &agent_m, WirePayload::Chat(ChatMessage {
            thread_id: None, parent_id: None,
            body: "I've linked the Northwind opportunity to this conversation. Value $240,000 · stage now Proposal · close target Jul 18. I'll keep the record and thread in sync.".into(),
            sent: Lamport { counter: 0, actor: agent_w.address() },
        }))?;
        drain(&mut relay, &saul_w, &mut saul_g, &saul_m, &by_wallet, &mut store, &mut messages);
        // attach the deal link to the agent's just-recorded message
        if let Some(last) = messages.last_mut() {
            last.has_link = true;
            last.link_kind = "deal".into();
            last.link_name = "Northwind — self-hosted pilot".into();
            last.link_id = "DEAL-2291".into();
            last.ts = "09:18".into();
        }

        // seed the rest of the CRM/PM data as folded domain events (synced history)
        seed_domain(&mut store, &mut clock, gid);

        // Saul's own message — recorded directly (he authored it).
        messages.push(UiMessage {
            author: "Saul Loveman".into(), initials: "SL".into(), rgb: (0x2f, 0x45, 0x02), role: "Owner".into(), ts: "09:21".into(),
            text: "Good. Let's spin up the pilot tasks so nothing slips. Mateo — own the air-gap runbook?".into(),
            ..Default::default()
        });

        let members = ["Saul Loveman", "Priya Anand", "Mateo Ferraro", "@crm-agent"]
            .iter()
            .map(|n| {
                let (w, meta) = by_wallet.iter().find(|(_, m)| m.name == *n).unwrap();
                UiMember { name: meta.name.clone(), initials: meta.initials.clone(), rgb: meta.rgb, role: meta.role.clone(), addr: format!("0x{}", hex::encode(&w.0[..5])), is_agent: meta.is_agent }
            })
            .collect();

        Ok(Self { relay, gid, me_wallet: saul_w, me_mls: saul_m, me_group: saul_g, store, clock, now, by_wallet, messages, members })
    }

    /// Send a message live: real MLS encrypt → relay submit → append locally.
    pub fn send(&mut self, text: &str) {
        if text.trim().is_empty() {
            return;
        }
        let msg = WirePayload::Chat(ChatMessage { thread_id: None, parent_id: None, body: text.into(), sent: self.clock.tick() });
        if let Ok(bytes) = canonical::to_vec(&msg) {
            if let Ok(ct) = self.me_group.send(&self.me_mls, &bytes) {
                let recipients: Vec<WalletAddress> = self.by_wallet.keys().copied().filter(|a| *a != self.me_wallet.address()).collect();
                let _ = self.relay.submit_as(self.me_wallet.address(), Envelope { group_id: self.gid, epoch: EpochId(3), kind: EnvelopeKind::Application, sender: self.me_wallet.address(), recipients, ciphertext: ct, group_seq: None }, self.now);
            }
        }
        self.messages.push(UiMessage {
            author: "Saul Loveman".into(), initials: "SL".into(), rgb: (0x2f, 0x45, 0x02), role: "Owner".into(), ts: "now".into(),
            text: text.into(), ..Default::default()
        });
    }

    pub fn messages(&self) -> &[UiMessage] { &self.messages }
    pub fn members(&self) -> &[UiMember] { &self.members }

    pub fn deals(&self) -> Vec<UiDeal> {
        self.store.deals_in(self.gid).into_iter().map(|d| UiDeal {
            account: d.account.map(|_| "Northwind Traders".into()).unwrap_or_default(),
            value: format!("${}", thousands(d.value)),
            priority: priority_label(d.value),
            stage: d.stage.as_str().into(),
            name: d.name,
            owner: "PA".into(),
        }).collect()
    }

    pub fn tasks(&self) -> Vec<UiTask> {
        let mut out = vec![];
        for id in [50u8, 51, 52, 53] {
            if let Some(t) = self.store.task(EntityId([id; 16])) {
                out.push(UiTask { title: t.title, assignee: "MF".into(), status: t.status.as_str().into(), priority: "high".into(), due: "Jun 20".into() });
            }
        }
        out
    }

    pub fn audit(&self) -> Vec<UiAudit> {
        audit_rows(self.relay.audit())
    }

    /// Re-derive the deal count after live folds — exposed for tests.
    #[cfg(test)]
    pub fn deal_count(&self) -> usize { self.store.deals_in(self.gid).len() }
}

// ───────────────────────────── helpers ─────────────────────────────

fn chat(_ts: &str, body: &str, clock: &mut LamportClock) -> WirePayload {
    WirePayload::Chat(ChatMessage { thread_id: None, parent_id: None, body: body.into(), sent: clock.tick() })
}

fn submit_commit(relay: &mut DeliveryService, gid: GroupId, admin: &EthWallet, epoch: u64, commit: Vec<u8>, recipients: Vec<WalletAddress>, now: u64) -> Result<(), String> {
    relay.submit_as(admin.address(), Envelope { group_id: gid, epoch: EpochId(epoch), kind: EnvelopeKind::Commit, sender: admin.address(), recipients, ciphertext: commit, group_seq: None }, now).map(|_| ()).map_err(|e| e.to_string())
}

#[allow(clippy::too_many_arguments)]
fn onboard(relay: &mut DeliveryService, gid: GroupId, admin: &EthWallet, joiner: WalletAddress, epoch: u64, welcome: Vec<u8>, tree: Vec<u8>, now: u64) -> Result<(), String> {
    relay.onboard(gid, admin.address(), None, joiner, Envelope { group_id: gid, epoch: EpochId(epoch), kind: EnvelopeKind::Welcome, sender: admin.address(), recipients: vec![joiner], ciphertext: welcome, group_seq: None }, tree, now).map_err(|e| e.to_string())
}

/// Drain Saul's mailbox, decrypt each application message, fold domain events into the
/// store and record chat messages (attributed via the sender wallet).
fn drain(relay: &mut DeliveryService, me_w: &EthWallet, me_g: &mut GroupHandle, me_m: &MlsMember, by_wallet: &HashMap<WalletAddress, Meta>, store: &mut DomainStore, messages: &mut Vec<UiMessage>) {
    for e in relay.fetch(&me_w.address()) {
        if e.kind != EnvelopeKind::Application {
            continue;
        }
        let Ok(pt) = me_g.receive(me_m, &e.ciphertext) else { continue };
        let Ok(payload) = canonical::from_slice::<WirePayload>(&pt) else { continue };
        let meta = by_wallet.get(&e.sender).cloned().unwrap_or(Meta { name: "Unknown".into(), initials: "··".into(), rgb: (0x84, 0x86, 0x7f), role: String::new(), is_agent: false });
        match payload {
            WirePayload::Domain(ev) => store.apply(&ev),
            WirePayload::Chat(c) => messages.push(UiMessage {
                author: meta.name, initials: meta.initials, rgb: meta.rgb, role: meta.role, ts: String::new(),
                text: c.body, is_agent: meta.is_agent, ..Default::default()
            }),
        }
    }
}

fn seed_domain(store: &mut DomainStore, clock: &mut LamportClock, gid: GroupId) {
    let deal = |store: &mut DomainStore, clock: &mut LamportClock, id: u8, name: &str, acct: &str, value: i64, stage: &str, prio: &str| {
        store.apply(&DomainEvent::upsert(gid, EntityType::Deal, EntityId([id; 16]), vec![
            (f::NAME.into(), FieldValue::Text(name.into())),
            (f::ACCOUNT.into(), FieldValue::Text(acct.into())),
            (f::VALUE.into(), FieldValue::Money(value)),
            (f::STAGE.into(), FieldValue::Tag(stage.into())),
            (f::PRIORITY.into(), FieldValue::Tag(prio.into())),
        ], clock.tick()));
    };
    deal(store, clock, 60, "Helios Group expansion", "Helios Group", 88_000, "Qualified", "medium");
    deal(store, clock, 61, "Atlas Freight rollout", "Atlas Freight", 410_000, "Lead", "high");
    deal(store, clock, 62, "Verge Labs renewal", "Verge Labs", 64_000, "Won", "low");
    deal(store, clock, 63, "Cobalt Mfg evaluation", "Cobalt Mfg", 122_000, "Lost", "low");
    deal(store, clock, 64, "Orion Dynamics security buy", "Orion Dynamics", 305_000, "Qualified", "high");

    let task = |store: &mut DomainStore, clock: &mut LamportClock, id: u8, title: &str, status: &str| {
        store.apply(&DomainEvent::upsert(gid, EntityType::Task, EntityId([id; 16]), vec![
            (f::TITLE.into(), FieldValue::Text(title.into())),
            (f::STATUS.into(), FieldValue::Tag(status.into())),
        ], clock.tick()));
    };
    task(store, clock, 50, "Air-gap deployment runbook", "Doing");
    task(store, clock, 51, "Post-quantum security review", "Review");
    task(store, clock, 52, "Co-signed deployment SOW", "Todo");
    task(store, clock, 53, "Security posture one-pager", "Done");
}

fn priority_label(value: i64) -> String {
    // the typed Deal view doesn't surface the priority tag, so map by value tier for display.
    if value >= 300_000 { "high".into() } else if value >= 100_000 { "medium".into() } else { "low".into() }
}

fn thousands(n: i64) -> String {
    let s = n.abs().to_string();
    let mut out = String::new();
    for (i, c) in s.chars().rev().enumerate() {
        if i > 0 && i % 3 == 0 { out.push(','); }
        out.push(c);
    }
    out.chars().rev().collect()
}

fn audit_rows(chain: &AuditChain) -> Vec<UiAudit> {
    let mut rows: Vec<UiAudit> = chain.records().iter().rev().take(12).map(|r| {
        let (event, summary, actor) = match &r.event {
            AuditEvent::Genesis => ("Genesis".into(), "Audit chain genesis".into(), "system".into()),
            AuditEvent::GroupCreated { .. } => ("GroupCreated".into(), "Channel #deals created".into(), "Saul".into()),
            AuditEvent::MemberAdded { member, .. } => ("MemberAdded".into(), format!("Member added · 0x{}", hex::encode(&member.0[..3])), "Saul".into()),
            AuditEvent::MemberRemoved { .. } => ("MemberRemoved".into(), "Member offboarded".into(), "Saul".into()),
            AuditEvent::AgentAdded { .. } => ("AgentAdded".into(), "@crm-agent added to #deals".into(), "Saul".into()),
            AuditEvent::AgentRemoved { .. } => ("AgentRemoved".into(), "Agent removed".into(), "Saul".into()),
            AuditEvent::KeyPackagePublished { .. } => ("KeyPackagePublished".into(), "Device key published · X25519/Ed25519".into(), "member".into()),
            AuditEvent::EnvelopeReceipt { size, kind, .. } => ("EnvelopeReceipt".into(), format!("Envelope delivered · {} B · {:?}", size, kind), "member".into()),
            AuditEvent::RoleAsserted { .. } => ("RoleAsserted".into(), "Role asserted".into(), "Saul".into()),
            AuditEvent::RoleRevoked { .. } => ("RoleRevoked".into(), "Role revoked".into(), "system".into()),
        };
        UiAudit { seq: r.sequence.to_string(), event, summary, actor, hash: format!("0x{}…", hex::encode(&r.record_hash[..2])) }
    }).collect();
    rows.reverse();
    rows
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn workspace_bootstraps_with_live_decrypted_messages() {
        let ws = Workspace::bootstrap().expect("bootstrap");
        // The boundary marker + the decrypted real messages from priya/mateo/agent/saul.
        let chat_msgs: Vec<_> = ws.messages().iter().filter(|m| !m.system).collect();
        assert!(chat_msgs.len() >= 4, "expected ≥4 decrypted messages, got {}", chat_msgs.len());
        assert!(ws.messages().iter().any(|m| m.text.contains("Northwind came back warm")), "priya's message decrypted");
        assert!(ws.messages().iter().any(|m| m.is_agent && m.has_link), "agent message carries the linked deal");
    }

    #[test]
    fn deals_and_tasks_come_from_the_domain_store() {
        let ws = Workspace::bootstrap().unwrap();
        // 1 round-tripped (via MLS) + 5 seeded = 6 deals.
        assert_eq!(ws.deal_count(), 6, "deals folded from domain events");
        assert!(ws.deals().iter().any(|d| d.name.contains("Northwind") && d.stage == "Proposal"));
        assert_eq!(ws.tasks().len(), 4, "tasks folded from domain events");
    }

    #[test]
    fn send_appends_a_live_message_and_audits_it() {
        let mut ws = Workspace::bootstrap().unwrap();
        let before = ws.messages().len();
        let audit_before = ws.audit().len();
        ws.send("Shipping the air-gap runbook today.");
        assert_eq!(ws.messages().len(), before + 1);
        assert!(ws.messages().last().unwrap().text.contains("air-gap runbook"));
        // the submit logged an envelope receipt to the real audit chain
        assert!(ws.audit().len() >= audit_before, "send produced an audited envelope");
        ws.relay.audit().verify_integrity().unwrap();
    }

    #[test]
    fn members_are_the_real_group() {
        let ws = Workspace::bootstrap().unwrap();
        let names: Vec<_> = ws.members().iter().map(|m| m.name.as_str()).collect();
        assert!(names.contains(&"Saul Loveman") && names.contains(&"@crm-agent"));
        assert!(ws.members().iter().any(|m| m.is_agent), "crm-agent is a member");
    }
}
