//! E-5 WP-3 — over-the-wire coverage of the advisory `ServerFrame::Notify` fan-out.
//!
//! On an accepted Submit, each *connected* recipient (never the sender) receives a
//! metadata-only Notify ping alongside the delivered envelope, so a native client can
//! raise an OS notification without waiting to decrypt. Notify is advisory and never
//! ordering-relevant — the per-group total order is `group_seq` on the envelope
//! (`formal/RelayCommitOrder.tla`, unchanged). The metadata-only schema itself is
//! asserted by `ws::tests::notify_frame_is_metadata_only`.

use std::time::Duration;

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
async fn submit_fans_out_notify_to_connected_recipients_not_the_sender() {
    let alice = EthWallet::generate(); // workspace owner / sender
    let bob = EthWallet::generate(); // connected recipient
    let service = DeliveryService::new(DOMAIN, alice.address(), 0).unwrap();
    let server = RelayServer::new(service);
    let (addr, _h) = server.clone().bind("127.0.0.1:0").await.unwrap();
    let url = format!("ws://{addr}");

    let (alice_c, n1) = RelayClient::connect(&url).await.unwrap();
    login(&alice_c, n1, &alice).await;
    let (bob_c, n2) = RelayClient::connect(&url).await.unwrap();
    login(&bob_c, n2, &bob).await;

    let gid = GroupId([9; 32]);
    alice_c.register_group(gid).await.unwrap();
    alice_c
        .onboard(
            gid,
            bob.address(),
            None, // alice is the owner / trust anchor
            env(gid, alice.address(), EnvelopeKind::Welcome, 1, b"welcome", &[bob.address()]),
            b"rt".to_vec(),
        )
        .await
        .unwrap();

    let seq = alice_c
        .submit(env(gid, alice.address(), EnvelopeKind::Application, 1, b"CIPHERTEXT", &[bob.address()]))
        .await
        .unwrap();

    // Bob (connected recipient) gets the advisory ping: correct group, kind, and the
    // relay-assigned seq of the accepted envelope.
    let push = tokio::time::timeout(Duration::from_secs(2), bob_c.next_notify())
        .await
        .expect("recipient must receive a Notify ping")
        .expect("client channel open");
    assert_eq!(push.group_id, gid);
    assert_eq!(push.kind, EnvelopeKind::Application);
    assert_eq!(push.group_seq, seq);

    // The envelope itself is still delivered — Notify is advisory, IN ADDITION to
    // delivery, never a replacement for it. (Drain past the onboard Welcome first.)
    let delivered = loop {
        let env = tokio::time::timeout(Duration::from_secs(2), bob_c.next_delivered())
            .await
            .expect("recipient still receives the envelope")
            .expect("client channel open");
        if env.kind == EnvelopeKind::Application {
            break env;
        }
    };
    assert_eq!(delivered.group_seq, Some(seq));

    // The SENDER never receives a Notify about their own message.
    let sender_ping = tokio::time::timeout(Duration::from_millis(300), alice_c.next_notify()).await;
    assert!(sender_ping.is_err(), "sender must not be pinged about their own submit");
}
