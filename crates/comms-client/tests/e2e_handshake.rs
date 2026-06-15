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

use comms_core::identity::{EthWallet, SiweMessage};
use comms_core::mls::MlsMember;
use comms_proto::{Envelope, EnvelopeKind, EpochId, GroupId, KeyPackagePublication, CITRATE_CHAIN_ID};
use comms_relay::DeliveryService;

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
    let mut relay = DeliveryService::new("relay.citrate.ai", 0).unwrap();

    // ── 1. Both parties authenticate with SIWE (wallet = durable identity). ──
    let alice_wallet = EthWallet::generate();
    let bob_wallet = EthWallet::generate();
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
    assert_eq!(seq, 1, "second accepted envelope in the group gets group_seq 1");

    // Bob fetches and decrypts.
    let inbox = relay.fetch(&bob_wallet.address());
    let app = inbox.iter().find(|e| e.kind == EnvelopeKind::Application).expect("app delivered");
    let decrypted = bob_group.receive(&bob_member, &app.ciphertext).unwrap();
    assert_eq!(decrypted, plaintext, "Bob decrypts Alice's message");

    // ── 7. The server-blind invariant: the relay's durable store is ciphertext-only. ──
    let log = relay.group_log(&gid).unwrap();
    assert_eq!(log.len(), 2, "relay stored the Commit + the Application envelope");
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
