//! COMMS-S0 exit criterion — the full end-to-end path.
//!
//! Two clients SIWE-handshake to a server-blind relay, publish a KeyPackage (with a
//! wallet binding attestation), create a 2-member MLS group, and exchange an
//! application message. We then assert the relay's durable store holds only
//! ciphertext (never the plaintext) and that its BLAKE3 audit chain verifies offline.
//!
//! This exercises real crypto throughout: secp256k1 SIWE recovery, the binding
//! attestation, and OpenMLS group encryption. The relay is the in-process
//! `DeliveryService`; the WebSocket transport wrapper lands in COMMS-S1.

use comms_core::domain::event::fields as f;
use comms_core::domain::{DealStage, DomainEvent, DomainStore, EntityId, EntityType, FieldValue, Lamport};
use comms_core::identity::{EthWallet, SiweMessage};
use comms_core::mls::MlsMember;
use comms_proto::{Envelope, EnvelopeKind, EpochId, GroupId, KeyPackagePublication, CITRATE_CHAIN_ID};
use comms_relay::{DeliveryService, OffboardRequest};

/// SIWE login helper — mirrors the handshake a client performs on connect.
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

/// Stable 32-byte group id derived from the MLS group id (length-agnostic).
fn group_id_of(member_group: &comms_core::mls::GroupHandle) -> GroupId {
    GroupId(*blake3::hash(&member_group.group_id()).as_bytes())
}

#[test]
fn two_members_exchange_a_message_through_a_blind_relay() {
    // ── 1. Both parties authenticate with SIWE (wallet = durable identity). ──
    let alice_wallet = EthWallet::generate();
    let bob_wallet = EthWallet::generate();
    // Alice is the workspace owner (the RBAC trust anchor).
    let mut relay = DeliveryService::new("relay.citrate.ai", alice_wallet.address(), 0).unwrap();
    login(&mut relay, &alice_wallet, 10);
    login(&mut relay, &bob_wallet, 11);

    // ── 2. Bob builds his MLS identity and publishes a KeyPackage with a
    //       wallet-signed binding attestation (defeats spoofing — R3). ──
    let bob_member = MlsMember::new(&bob_wallet.address().0).unwrap();
    let bob_sig_pub = bob_member.sig_pubkey();
    let bob_kp_bytes = bob_member.fresh_key_package().unwrap();

    let pub_nonce = relay.issue_challenge(12);
    let attestation = bob_wallet.sign_binding(&bob_sig_pub, relay.domain(), &pub_nonce);
    let publication = KeyPackagePublication {
        wallet: bob_wallet.address(),
        key_package: bob_kp_bytes,
        mls_sig_pubkey: bob_sig_pub,
        binding_attestation: attestation.to_vec(),
        nonce: pub_nonce,
        relay_domain: relay.domain().to_string(),
    };
    relay.publish_key_package(publication, 12).unwrap();
    assert_eq!(relay.key_package_count(&bob_wallet.address()), 1);

    // ── 3. Alice creates the group and registers it with the relay. ──
    let alice_member = MlsMember::new(&alice_wallet.address().0).unwrap();
    let mut alice_group = alice_member.create_group().unwrap();
    let gid = group_id_of(&alice_group);
    relay.register_group(gid, alice_wallet.address(), 13).unwrap();
    assert_eq!(alice_group.epoch(), 0);

    // ── 4. Alice pulls Bob's KeyPackage (one-time-use) and adds him. ──
    let bobs_kp = relay.take_key_package(&bob_wallet.address()).unwrap();
    assert_eq!(relay.key_package_count(&bob_wallet.address()), 0, "KeyPackage is one-time-use");

    let add = alice_group.add(&alice_member, &bobs_kp.key_package).unwrap();
    assert_eq!(alice_group.epoch(), 1, "epoch advances by exactly 1 (MonotoneEpoch)");

    // The Commit goes to existing members (none besides Alice here) for ordering/audit.
    let commit_env = Envelope {
        group_id: gid, epoch: EpochId(1), kind: EnvelopeKind::Commit,
        sender: alice_wallet.address(), recipients: vec![], ciphertext: add.commit.clone(), group_seq: None,
    };
    relay.submit(commit_env, 14).unwrap();

    // Onboard Bob: roster update + Welcome delivered to his mailbox + public ratchet tree.
    let welcome_env = Envelope {
        group_id: gid, epoch: EpochId(1), kind: EnvelopeKind::Welcome,
        sender: alice_wallet.address(), recipients: vec![bob_wallet.address()],
        ciphertext: add.welcome.clone(), group_seq: None,
    };
    relay.onboard(gid, alice_wallet.address(), bob_wallet.address(), welcome_env, add.ratchet_tree.clone(), 15).unwrap();

    // ── 5. Bob joins from his Welcome + the relay's public ratchet tree. ──
    let inbox = relay.fetch(&bob_wallet.address());
    let welcome = inbox.iter().find(|e| e.kind == EnvelopeKind::Welcome).expect("welcome delivered");
    let ratchet_tree = relay.ratchet_tree(&gid).unwrap().to_vec();
    let mut bob_group = bob_member.join(&welcome.ciphertext, &ratchet_tree).unwrap();
    assert_eq!(bob_group.group_id(), alice_group.group_id());
    assert_eq!(bob_group.epoch(), 1);

    // ── 6. Alice → Bob application message, routed through the blind relay. ──
    let plaintext = b"deal with Acme closes Friday; loop in @crm-agent";
    let ciphertext = alice_group.send(&alice_member, plaintext).unwrap();
    let app_env = Envelope {
        group_id: gid, epoch: EpochId(1), kind: EnvelopeKind::Application,
        sender: alice_wallet.address(), recipients: vec![bob_wallet.address()],
        ciphertext: ciphertext.clone(), group_seq: None,
    };
    let seq = relay.submit(app_env, 16).unwrap();
    // Order so far: Commit(0), Welcome(1, via onboard), Application(2).
    assert_eq!(seq, 2, "third accepted envelope in the group gets group_seq 2");

    // Bob fetches and decrypts.
    let inbox = relay.fetch(&bob_wallet.address());
    let app = inbox.iter().find(|e| e.kind == EnvelopeKind::Application).expect("app delivered");
    let decrypted = bob_group.receive(&bob_member, &app.ciphertext).unwrap();
    assert_eq!(decrypted, plaintext, "Bob decrypts Alice's message");

    // ── 7. The server-blind invariant: the relay's durable store is ciphertext-only. ──
    let log = relay.group_log(&gid).unwrap();
    assert_eq!(log.len(), 3, "relay stored the Commit + Welcome + Application envelopes");
    for e in log {
        assert_ne!(e.ciphertext.as_slice(), plaintext, "relay never stores plaintext");
        assert!(e.group_seq.is_some(), "every stored envelope has a total-order seq");
    }
    // The MLS ciphertext on the wire is genuinely not the plaintext.
    assert_ne!(ciphertext.as_slice(), plaintext);

    // The relay has no means to decrypt: `comms_core::mls` is not even linked into the
    // relay crate (default-features = false). The only group secrets exist on the
    // alice_member / bob_member providers, never on the relay.

    // ── 8. The audit chain verifies offline (airgap-grade tamper evidence). ──
    relay.audit().verify_integrity().unwrap();

    // Audit recorded the metadata events (group create, key package, member add, receipts) — never content.
    let n = relay.audit().len();
    assert!(n >= 5, "expected genesis + group + kp + member-add + >=2 receipts, got {n}");
}

/// COMMS-S1 (WP-1.3) — atomic offboard. An owner removes a member; from the next
/// epoch the removed member cannot decrypt, and the relay records role + access
/// revocation together. Demonstrates forward security as the enforcement mechanism.
#[test]
fn offboard_atomically_revokes_role_and_future_access() {
    let alice_wallet = EthWallet::generate(); // owner
    let bob_wallet = EthWallet::generate();
    let mut relay = DeliveryService::new("relay.citrate.ai", alice_wallet.address(), 0).unwrap();
    login(&mut relay, &alice_wallet, 10);
    login(&mut relay, &bob_wallet, 11);

    // Bob publishes a KeyPackage; Alice creates the group and adds him.
    let bob_member = MlsMember::new(&bob_wallet.address().0).unwrap();
    let bob_sig_pub = bob_member.sig_pubkey();
    let pub_nonce = relay.issue_challenge(12);
    relay
        .publish_key_package(
            KeyPackagePublication {
                wallet: bob_wallet.address(),
                key_package: bob_member.fresh_key_package().unwrap(),
                mls_sig_pubkey: bob_sig_pub.clone(),
                binding_attestation: bob_wallet.sign_binding(&bob_sig_pub, relay.domain(), &pub_nonce).to_vec(),
                nonce: pub_nonce,
                relay_domain: relay.domain().to_string(),
            },
            12,
        )
        .unwrap();

    let alice_member = MlsMember::new(&alice_wallet.address().0).unwrap();
    let mut alice_group = alice_member.create_group().unwrap();
    let gid = group_id_of(&alice_group);
    relay.register_group(gid, alice_wallet.address(), 13).unwrap();

    let bobs_kp = relay.take_key_package(&bob_wallet.address()).unwrap();
    let add = alice_group.add(&alice_member, &bobs_kp.key_package).unwrap();
    relay
        .submit(
            Envelope { group_id: gid, epoch: EpochId(1), kind: EnvelopeKind::Commit,
                sender: alice_wallet.address(), recipients: vec![], ciphertext: add.commit, group_seq: None },
            14,
        )
        .unwrap();
    let welcome_env = Envelope { group_id: gid, epoch: EpochId(1), kind: EnvelopeKind::Welcome,
        sender: alice_wallet.address(), recipients: vec![bob_wallet.address()], ciphertext: add.welcome, group_seq: None };
    relay.onboard(gid, alice_wallet.address(), bob_wallet.address(), welcome_env, add.ratchet_tree, 15).unwrap();
    let inbox = relay.fetch(&bob_wallet.address());
    let welcome = inbox.iter().find(|e| e.kind == EnvelopeKind::Welcome).unwrap();
    let ratchet_tree = relay.ratchet_tree(&gid).unwrap().to_vec();
    let mut bob_group = bob_member.join(&welcome.ciphertext, &ratchet_tree).unwrap();

    // Pre-offboard: Bob can read.
    let ct1 = alice_group.send(&alice_member, b"before offboard").unwrap();
    assert_eq!(bob_group.receive(&bob_member, &ct1).unwrap(), b"before offboard");

    // ── OFFBOARD: Alice removes Bob (MLS Remove → epoch 2), then the relay applies it atomically. ──
    let bob_leaf = alice_group.member_index_by_sig(&bob_sig_pub).expect("bob is a member");
    let removal = alice_group.remove(&alice_member, bob_leaf).unwrap();
    assert_eq!(alice_group.epoch(), 2, "remove commit advances the epoch");

    let remove_commit = Envelope { group_id: gid, epoch: EpochId(2), kind: EnvelopeKind::Commit,
        sender: alice_wallet.address(), recipients: vec![], ciphertext: removal.commit, group_seq: None };
    // Alice is the owner → no assertion needed (the trust anchor).
    relay.offboard(
        OffboardRequest {
            group_id: gid,
            admin: alice_wallet.address(),
            admin_assertion: None,
            removed: bob_wallet.address(),
            remove_commit,
            ratchet_tree: removal.ratchet_tree,
        },
        16,
    ).unwrap();

    // Bob is off the roster.
    let members = relay.group_members(&gid).unwrap();
    assert!(!members.contains(&bob_wallet.address()), "removed member is off the roster");

    // ── Forward security: a post-offboard message cannot be decrypted by Bob. ──
    let ct2 = alice_group.send(&alice_member, b"after offboard - confidential").unwrap();
    assert!(
        bob_group.receive(&bob_member, &ct2).is_err(),
        "removed member must not decrypt messages from the new epoch"
    );

    // Audit recorded the offboard (MemberRemoved + RoleRevoked) and still verifies.
    relay.audit().verify_integrity().unwrap();
    let saw_removed = relay.audit().records().iter().any(|r| matches!(
        r.event, comms_proto::AuditEvent::MemberRemoved { .. }));
    let saw_revoked = relay.audit().records().iter().any(|r| matches!(
        r.event, comms_proto::AuditEvent::RoleRevoked { .. }));
    assert!(saw_removed && saw_revoked, "offboard recorded both member removal and role revocation");
}

/// COMMS-S1 (WP-1.8) — a CRM record (a Deal) replicates end-to-end over MLS through
/// the server-blind relay: encoded as a domain event, MLS-encrypted, fanned out, then
/// decoded + folded by the recipient. Both members converge; the relay sees only ciphertext.
#[test]
fn domain_record_replicates_e2e_over_relay() {
    let alice_wallet = EthWallet::generate(); // owner
    let bob_wallet = EthWallet::generate();
    let mut relay = DeliveryService::new("relay.citrate.ai", alice_wallet.address(), 0).unwrap();
    login(&mut relay, &alice_wallet, 10);
    login(&mut relay, &bob_wallet, 11);

    // Onboard Bob into a 2-member group.
    let bob_member = MlsMember::new(&bob_wallet.address().0).unwrap();
    let bob_sig_pub = bob_member.sig_pubkey();
    let pub_nonce = relay.issue_challenge(12);
    relay
        .publish_key_package(
            KeyPackagePublication {
                wallet: bob_wallet.address(),
                key_package: bob_member.fresh_key_package().unwrap(),
                mls_sig_pubkey: bob_sig_pub.clone(),
                binding_attestation: bob_wallet.sign_binding(&bob_sig_pub, relay.domain(), &pub_nonce).to_vec(),
                nonce: pub_nonce,
                relay_domain: relay.domain().to_string(),
            },
            12,
        )
        .unwrap();
    let alice_member = MlsMember::new(&alice_wallet.address().0).unwrap();
    let mut alice_group = alice_member.create_group().unwrap();
    let gid = group_id_of(&alice_group);
    relay.register_group(gid, alice_wallet.address(), 13).unwrap();
    let bobs_kp = relay.take_key_package(&bob_wallet.address()).unwrap();
    let add = alice_group.add(&alice_member, &bobs_kp.key_package).unwrap();
    relay.submit(Envelope { group_id: gid, epoch: EpochId(1), kind: EnvelopeKind::Commit, sender: alice_wallet.address(), recipients: vec![], ciphertext: add.commit, group_seq: None }, 14).unwrap();
    let welcome = Envelope { group_id: gid, epoch: EpochId(1), kind: EnvelopeKind::Welcome, sender: alice_wallet.address(), recipients: vec![bob_wallet.address()], ciphertext: add.welcome, group_seq: None };
    relay.onboard(gid, alice_wallet.address(), bob_wallet.address(), welcome, add.ratchet_tree.clone(), 15).unwrap();
    let inbox = relay.fetch(&bob_wallet.address());
    let w = inbox.iter().find(|e| e.kind == EnvelopeKind::Welcome).unwrap();
    let mut bob_group = bob_member.join(&w.ciphertext, relay.ratchet_tree(&gid).unwrap()).unwrap();

    // ── Alice creates a Deal (a domain event), MLS-encrypts it, and submits. ──
    let deal_id = EntityId([42; 16]);
    let ev = DomainEvent::upsert(
        gid,
        EntityType::Deal,
        deal_id,
        vec![
            (f::NAME.into(), FieldValue::Text("Acme Corp - Q3".into())),
            (f::STAGE.into(), FieldValue::Tag("Proposal".into())),
            (f::VALUE.into(), FieldValue::Money(2_500_000)),
        ],
        Lamport { counter: 1, actor: alice_wallet.address() },
    );
    let payload = ev.encode().unwrap();
    let ciphertext = alice_group.send(&alice_member, &payload).unwrap();
    relay.submit(Envelope { group_id: gid, epoch: EpochId(1), kind: EnvelopeKind::Application, sender: alice_wallet.address(), recipients: vec![bob_wallet.address()], ciphertext, group_seq: None }, 16).unwrap();

    let mut alice_store = DomainStore::new();
    alice_store.apply(&ev);

    // ── Bob receives, decrypts, decodes, and folds — converging on the same Deal. ──
    let inbox = relay.fetch(&bob_wallet.address());
    let app = inbox.iter().find(|e| e.kind == EnvelopeKind::Application).unwrap();
    let plain = bob_group.receive(&bob_member, &app.ciphertext).unwrap();
    let bob_ev = DomainEvent::decode(&plain).unwrap();
    let mut bob_store = DomainStore::new();
    bob_store.apply(&bob_ev);

    assert_eq!(alice_store.deal(deal_id), bob_store.deal(deal_id), "both members converge on the Deal");
    let d = bob_store.deal(deal_id).unwrap();
    assert_eq!(d.name, "Acme Corp - Q3");
    assert_eq!(d.stage, DealStage::Proposal);
    assert_eq!(d.value, 2_500_000);

    // ── The relay never saw the deal content — its store holds only ciphertext. ──
    for e in relay.group_log(&gid).unwrap() {
        assert!(
            !e.ciphertext.windows(4).any(|w| w == b"Acme"),
            "the relay must not see CRM record content"
        );
    }
}
