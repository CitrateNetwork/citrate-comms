//! FWA-C11-01 / FWA-C11-03 — over-the-wire coverage of the sender-binding +
//! onboard-RBAC fixes, driven through the real `RelayClient` WebSocket path.
//!
//! These tests exercise the live socket so the mutation campaign cannot survive by
//! no-op'ing the client request methods (`RelayClient::onboard`/`submit`), and they
//! prove the relay rejects a spoofed `Envelope.sender` end-to-end.

use comms_core::identity::{EthWallet, SiweMessage};
use comms_proto::{Envelope, EnvelopeKind, EpochId, GroupId, WalletAddress, CITRATE_CHAIN_ID};
use comms_relay::ws::{RelayClient, RelayServer};
use comms_relay::DeliveryService;

const DOMAIN: &str = "relay.citrate.ai";

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64
}

async fn login(client: &RelayClient, nonce: String, wallet: &EthWallet) -> WalletAddress {
    let now = now_ms();
    let msg = SiweMessage {
        domain: DOMAIN.into(),
        address: wallet.address(),
        statement: "Sign in to citrate-comms".into(),
        uri: format!("wss://{DOMAIN}"),
        version: "1".into(),
        chain_id: CITRATE_CHAIN_ID,
        nonce,
        issued_at_ms: now,
        expiration_ms: now + 600_000,
    };
    let sig = wallet.sign_siwe(&msg);
    client.authenticate(msg, sig).await.unwrap()
}

fn env(gid: GroupId, sender: WalletAddress, kind: EnvelopeKind, epoch: u64, ct: &[u8], to: &[WalletAddress]) -> Envelope {
    Envelope {
        group_id: gid,
        epoch: EpochId(epoch),
        kind,
        sender,
        recipients: to.to_vec(),
        ciphertext: ct.to_vec(),
        group_seq: None,
    }
}

#[tokio::test]
async fn over_the_wire_onboard_and_sender_binding() {
    let alice = EthWallet::generate(); // workspace owner / registrar
    let mallory = EthWallet::generate(); // a genuine member who will try to spoof
    let service = DeliveryService::new(DOMAIN, alice.address(), 0).unwrap();
    let server = RelayServer::new(service);
    let (addr, _h) = server.clone().bind("127.0.0.1:0").await.unwrap();
    let url = format!("ws://{addr}");

    let (alice_c, n1) = RelayClient::connect(&url).await.unwrap();
    login(&alice_c, n1, &alice).await;
    let (mallory_c, n2) = RelayClient::connect(&url).await.unwrap();
    login(&mallory_c, n2, &mallory).await;

    let gid = GroupId([42; 32]);
    alice_c.register_group(gid).await.unwrap();

    // Real onboard over the socket — if `RelayClient::onboard` were a no-op the roster
    // would never gain Mallory and the next assertions fail (kills the Ok(()) mutant).
    alice_c
        .onboard(
            gid,
            mallory.address(),
            None, // alice is the owner / trust anchor
            env(gid, alice.address(), EnvelopeKind::Welcome, 1, b"welcome", &[mallory.address()]),
            b"rt".to_vec(),
        )
        .await
        .unwrap();

    // Mallory honestly submits as herself → accepted.
    let seq = mallory_c
        .submit(env(gid, mallory.address(), EnvelopeKind::Application, 1, b"HONEST", &[alice.address()]))
        .await
        .unwrap();
    assert!(seq >= 1, "honest submit accepted with a seq");

    // FWA-C11-01: Mallory submits an envelope SPOOFING alice as the sender → the relay
    // binds the sender to Mallory's authenticated connection and rejects it.
    let spoof = mallory_c
        .submit(env(gid, alice.address(), EnvelopeKind::Application, 1, b"FORGED", &[mallory.address()]))
        .await;
    assert!(spoof.is_err(), "spoofed sender must be rejected over the wire, got {spoof:?}");
}
