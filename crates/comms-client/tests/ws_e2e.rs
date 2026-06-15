//! COMMS-S1 (WP-1.6) — the message-exchange path over a real WebSocket.
//!
//! Two clients connect to a `RelayServer` over `ws://127.0.0.1:<port>`, run the SIWE
//! handshake over the socket, publish/consume a KeyPackage, create a group, and
//! exchange an MLS-encrypted message that the relay fans out as a server push. The
//! relay only ever sees opaque ciphertext.

use comms_core::identity::{EthWallet, SiweMessage};
use comms_core::mls::{GroupHandle, MlsMember};
use comms_proto::{Envelope, EnvelopeKind, EpochId, GroupId, KeyPackagePublication, CITRATE_CHAIN_ID};
use comms_relay::ws::{RelayClient, RelayServer};
use comms_relay::DeliveryService;

const DOMAIN: &str = "relay.citrate.ai";

fn siwe(domain: &str, w: &EthWallet, nonce: String) -> SiweMessage {
    SiweMessage {
        domain: domain.into(),
        address: w.address(),
        statement: "Sign in to citrate-comms".into(),
        uri: format!("wss://{domain}"),
        version: "1".into(),
        chain_id: CITRATE_CHAIN_ID,
        nonce,
        issued_at_ms: 1,
        expiration_ms: u64::MAX,
    }
}

fn gid_of(g: &GroupHandle) -> GroupId {
    GroupId(*blake3::hash(&g.group_id()).as_bytes())
}

/// Await the next pushed envelope of a given kind (skipping others).
async fn next_kind(client: &RelayClient, kind: EnvelopeKind) -> Envelope {
    loop {
        let env = client.next_delivered().await.expect("a delivered envelope");
        if env.kind == kind {
            return env;
        }
    }
}

#[tokio::test]
async fn two_clients_exchange_a_message_over_websocket() {
    // ── Start the relay server on an OS-assigned loopback port. ──
    let alice_w = EthWallet::generate(); // workspace owner
    let bob_w = EthWallet::generate();
    let service = DeliveryService::new(DOMAIN, alice_w.address(), 0).unwrap();
    let server = RelayServer::new(service);
    let (addr, _accept) = server.bind("127.0.0.1:0").await.unwrap();
    let url = format!("ws://{addr}");

    // ── Both clients connect + SIWE-authenticate over the socket. ──
    let (alice, a_nonce) = RelayClient::connect(&url).await.unwrap();
    let a_msg = siwe(DOMAIN, &alice_w, a_nonce);
    let a_sig = alice_w.sign_siwe(&a_msg);
    assert_eq!(alice.authenticate(a_msg, a_sig).await.unwrap(), alice_w.address());

    let (bob, b_nonce) = RelayClient::connect(&url).await.unwrap();
    let b_msg = siwe(DOMAIN, &bob_w, b_nonce);
    let b_sig = bob_w.sign_siwe(&b_msg);
    assert_eq!(bob.authenticate(b_msg, b_sig).await.unwrap(), bob_w.address());

    // ── Bob publishes a KeyPackage (with a wallet binding attestation). ──
    let bob_member = MlsMember::new(&bob_w.address().0).unwrap();
    let bob_sig_pub = bob_member.sig_pubkey();
    let bind_nonce = bob.challenge().await.unwrap();
    bob.publish_key_package(KeyPackagePublication {
        wallet: bob_w.address(),
        key_package: bob_member.fresh_key_package().unwrap(),
        mls_sig_pubkey: bob_sig_pub.clone(),
        binding_attestation: bob_w.sign_binding(&bob_sig_pub, DOMAIN, &bind_nonce).to_vec(),
        nonce: bind_nonce,
        relay_domain: DOMAIN.into(),
    })
    .await
    .unwrap();

    // ── Alice creates the group, pulls Bob's KeyPackage, adds him, onboards. ──
    let alice_member = MlsMember::new(&alice_w.address().0).unwrap();
    let mut alice_group = alice_member.create_group().unwrap();
    let gid = gid_of(&alice_group);
    alice.register_group(gid).await.unwrap();

    let bobs_kp = alice.take_key_package(bob_w.address()).await.unwrap().expect("kp present");
    let add = alice_group.add(&alice_member, &bobs_kp.key_package).unwrap();
    alice
        .submit(Envelope {
            group_id: gid, epoch: EpochId(1), kind: EnvelopeKind::Commit,
            sender: alice_w.address(), recipients: vec![], ciphertext: add.commit, group_seq: None,
        })
        .await
        .unwrap();
    alice
        .onboard(
            gid,
            bob_w.address(),
            Envelope {
                group_id: gid, epoch: EpochId(1), kind: EnvelopeKind::Welcome,
                sender: alice_w.address(), recipients: vec![bob_w.address()], ciphertext: add.welcome, group_seq: None,
            },
            add.ratchet_tree,
        )
        .await
        .unwrap();

    // ── Bob receives the pushed Welcome + the public ratchet tree, and joins. ──
    let welcome = next_kind(&bob, EnvelopeKind::Welcome).await;
    let ratchet_tree = bob.ratchet_tree(gid).await.unwrap().expect("ratchet tree");
    let mut bob_group = bob_member.join(&welcome.ciphertext, &ratchet_tree).unwrap();
    assert_eq!(bob_group.epoch(), 1);

    // ── Alice → Bob application message, delivered as a server push. ──
    let plaintext = b"shipped over a real websocket, end to end";
    let ciphertext = alice_group.send(&alice_member, plaintext).unwrap();
    alice
        .submit(Envelope {
            group_id: gid, epoch: EpochId(1), kind: EnvelopeKind::Application,
            sender: alice_w.address(), recipients: vec![bob_w.address()], ciphertext: ciphertext.clone(), group_seq: None,
        })
        .await
        .unwrap();

    let app = next_kind(&bob, EnvelopeKind::Application).await;
    assert_ne!(app.ciphertext.as_slice(), plaintext, "the wire carries ciphertext, not plaintext");
    let decrypted = bob_group.receive(&bob_member, &app.ciphertext).unwrap();
    assert_eq!(decrypted, plaintext, "Bob decrypts Alice's message received over the socket");
}
