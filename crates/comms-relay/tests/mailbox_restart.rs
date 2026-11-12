//! GC-1 (comms#4) over the wire: a member who was offline across a relay restart
//! receives what was queued for them as soon as they sign in again, without waiting
//! for some later submit to trigger delivery.

use std::time::Duration;

use comms_core::identity::{EthWallet, SiweMessage};
use comms_proto::{Envelope, EnvelopeKind, EpochId, GroupId, WalletAddress, CITRATE_CHAIN_ID};
use comms_relay::ws::{RelayClient, RelayServer};
use comms_relay::DeliveryService;

const DOMAIN: &str = "relay.citrate.ai";
const MASTER: [u8; 32] = [0x5a; 32];

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64
}

fn siwe(wallet: &EthWallet, nonce: String, now: u64) -> SiweMessage {
    SiweMessage {
        domain: DOMAIN.into(),
        address: wallet.address(),
        statement: "Sign in to citrate-comms".into(),
        uri: format!("wss://{DOMAIN}"),
        version: "1".into(),
        chain_id: CITRATE_CHAIN_ID,
        nonce,
        issued_at_ms: now,
        expiration_ms: now + 600_000,
    }
}

fn direct_login(relay: &mut DeliveryService, wallet: &EthWallet, now: u64) {
    let nonce = relay.issue_challenge(now);
    let msg = siwe(wallet, nonce, now);
    let sig = wallet.sign_siwe(&msg);
    relay.authenticate(&msg, &sig, now).unwrap();
}

fn env(
    gid: GroupId,
    sender: WalletAddress,
    kind: EnvelopeKind,
    ct: &[u8],
    to: &[WalletAddress],
) -> Envelope {
    Envelope {
        group_id: gid,
        epoch: EpochId(1),
        kind,
        sender,
        recipients: to.to_vec(),
        ciphertext: ct.to_vec(),
        group_seq: None,
    }
}

#[tokio::test]
async fn offline_member_gets_queued_envelopes_on_sign_in_after_relay_restart() {
    let dir = tempfile::tempdir().unwrap();
    let alice = EthWallet::generate();
    let bob = EthWallet::generate();
    let gid = GroupId([0x77; 32]);

    // First relay lifetime: Bob is onboarded but never connects; Alice sends three.
    {
        let now = now_ms();
        let mut svc =
            DeliveryService::open(dir.path(), DOMAIN, alice.address(), MASTER, now).unwrap();
        direct_login(&mut svc, &alice, now);
        direct_login(&mut svc, &bob, now);
        svc.register_group(gid, alice.address(), now).unwrap();
        svc.onboard(
            gid,
            alice.address(),
            None,
            bob.address(),
            env(
                gid,
                alice.address(),
                EnvelopeKind::Welcome,
                b"welcome",
                &[bob.address()],
            ),
            b"rt".to_vec(),
            now,
        )
        .unwrap();
        for ct in [b"one".as_slice(), b"two", b"three"] {
            svc.submit_as(
                alice.address(),
                env(
                    gid,
                    alice.address(),
                    EnvelopeKind::Application,
                    ct,
                    &[bob.address()],
                ),
                now,
            )
            .unwrap();
        }
    } // relay stops; the store is closed

    // Second lifetime: the relay restarts and Bob signs in. Nobody submits anything.
    let svc = DeliveryService::open(dir.path(), DOMAIN, alice.address(), MASTER, now_ms()).unwrap();
    let server = RelayServer::new(svc);
    let (addr, _h) = server.clone().bind("127.0.0.1:0").await.unwrap();
    let (bob_c, nonce) = RelayClient::connect(&format!("ws://{addr}")).await.unwrap();
    let msg = siwe(&bob, nonce, now_ms());
    let sig = bob.sign_siwe(&msg);
    bob_c.authenticate(msg, sig).await.unwrap();

    let mut got: Vec<Vec<u8>> = Vec::new();
    while got.len() < 4 {
        let e = tokio::time::timeout(Duration::from_secs(3), bob_c.next_delivered())
            .await
            .expect("queued envelopes are delivered on sign-in")
            .expect("client channel open");
        got.push(e.ciphertext);
    }
    assert_eq!(
        got,
        vec![
            b"welcome".to_vec(),
            b"one".to_vec(),
            b"two".to_vec(),
            b"three".to_vec()
        ],
        "every queued envelope, in relay order"
    );
}

// GC-1 review P2: with delivery acks on, a delivery the client never acknowledged (its socket
// dropped first) is sent again on the next session; an acknowledged one is not.
#[tokio::test]
async fn an_unacknowledged_delivery_is_sent_again_on_the_next_session() {
    let alice = EthWallet::generate();
    let bob = EthWallet::generate();
    let gid = GroupId([0x78; 32]);
    let mut svc = DeliveryService::new(DOMAIN, alice.address(), 0).unwrap();
    let now = now_ms();
    direct_login(&mut svc, &alice, now);
    direct_login(&mut svc, &bob, now);
    svc.register_group(gid, alice.address(), now).unwrap();
    svc.onboard(
        gid,
        alice.address(),
        None,
        bob.address(),
        env(
            gid,
            alice.address(),
            EnvelopeKind::Welcome,
            b"welcome",
            &[bob.address()],
        ),
        b"rt".to_vec(),
        now,
    )
    .unwrap();
    svc.submit_as(
        alice.address(),
        env(
            gid,
            alice.address(),
            EnvelopeKind::Application,
            b"m1",
            &[bob.address()],
        ),
        now,
    )
    .unwrap();
    let server = RelayServer::new(svc);
    let (addr, _h) = server.clone().bind("127.0.0.1:0").await.unwrap();
    let url = format!("ws://{addr}");

    async fn session(url: &str, bob: &EthWallet) -> RelayClient {
        let (c, nonce) = RelayClient::connect(url).await.unwrap();
        // Before authenticating, so the sign-in delivery pass is tracked too.
        assert!(
            c.enable_delivery_acks().await.unwrap(),
            "this relay tracks deliveries"
        );
        let msg = siwe(bob, nonce, now_ms());
        let sig = bob.sign_siwe(&msg);
        c.authenticate(msg, sig).await.unwrap();
        c
    }
    async fn drain(c: &RelayClient) -> Vec<Vec<u8>> {
        let mut got = Vec::new();
        while let Ok(Some(e)) =
            tokio::time::timeout(Duration::from_millis(600), c.next_delivered()).await
        {
            got.push(e.ciphertext);
        }
        got
    }

    // Session 1 receives both and drops without acknowledging.
    let s1 = session(&url, &bob).await;
    assert_eq!(drain(&s1).await, vec![b"welcome".to_vec(), b"m1".to_vec()]);
    drop(s1);
    tokio::time::sleep(Duration::from_millis(200)).await;

    // Session 2 gets them again, and acknowledges.
    let s2 = session(&url, &bob).await;
    assert_eq!(
        drain(&s2).await,
        vec![b"welcome".to_vec(), b"m1".to_vec()],
        "redelivered"
    );
    s2.ack_delivered().await.unwrap();
    drop(s2);
    tokio::time::sleep(Duration::from_millis(200)).await;

    // Session 3 gets nothing.
    let s3 = session(&url, &bob).await;
    assert!(drain(&s3).await.is_empty(), "acknowledged rows are gone");
}

// comms #51 item 2: delivery, ack tracking and the session are per WALLET, and the relay
// assumes one live session per wallet: the newest session owns them. When an older session of
// the same wallet closes, it must not take the newer session's registration, tracking or
// authentication down with it.
#[tokio::test]
async fn an_older_session_closing_leaves_the_newer_session_of_the_same_wallet_working() {
    let alice = EthWallet::generate();
    let bob = EthWallet::generate();
    let gid = GroupId([0x79; 32]);
    let mut svc = DeliveryService::new(DOMAIN, alice.address(), 0).unwrap();
    let now = now_ms();
    direct_login(&mut svc, &alice, now);
    direct_login(&mut svc, &bob, now);
    svc.register_group(gid, alice.address(), now).unwrap();
    svc.onboard(
        gid,
        alice.address(),
        None,
        bob.address(),
        env(
            gid,
            alice.address(),
            EnvelopeKind::Welcome,
            b"welcome",
            &[bob.address()],
        ),
        b"rt".to_vec(),
        now,
    )
    .unwrap();
    let server = RelayServer::new(svc);
    let (addr, _h) = server.clone().bind("127.0.0.1:0").await.unwrap();
    let url = format!("ws://{addr}");

    async fn raw_session(
        url: &str,
        w: &EthWallet,
    ) -> tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>>
    {
        use comms_proto::canonical;
        use comms_relay::ws::{ClientFrame, ServerFrame};
        use futures_util::{SinkExt, StreamExt};
        use tokio_tungstenite::tungstenite::Message;
        let (mut ws, _) = tokio_tungstenite::connect_async(url).await.unwrap();
        let nonce = loop {
            if let Some(Ok(Message::Binary(b))) = ws.next().await {
                if let Ok(ServerFrame::Challenge { nonce }) = canonical::from_slice(b.as_ref()) {
                    break nonce;
                }
            }
        };
        let msg = siwe(w, nonce, now_ms());
        let sig = w.sign_siwe(&msg);
        for frame in [
            ClientFrame::EnableDeliveryAcks,
            ClientFrame::Authenticate {
                message: msg,
                signature: sig.to_vec(),
            },
        ] {
            ws.send(Message::Binary(canonical::to_vec(&frame).unwrap()))
                .await
                .unwrap();
        }
        loop {
            if let Some(Ok(Message::Binary(b))) = ws.next().await {
                if let Ok(ServerFrame::Authenticated { .. }) = canonical::from_slice(b.as_ref()) {
                    break;
                }
            }
        }
        ws
    }
    async fn session(url: &str, w: &EthWallet) -> RelayClient {
        let (c, nonce) = RelayClient::connect(url).await.unwrap();
        assert!(c.enable_delivery_acks().await.unwrap());
        let msg = siwe(w, nonce, now_ms());
        let sig = w.sign_siwe(&msg);
        c.authenticate(msg, sig).await.unwrap();
        c
    }
    // The old session is a raw socket so the test can close it for real (dropping a
    // RelayClient leaves its socket open while its read task runs).
    let mut old = raw_session(&url, &bob).await;
    let new = session(&url, &bob).await;
    let alice_c = session(&url, &alice).await;

    // The old session closes.
    old.close(None).await.unwrap();
    tokio::time::sleep(Duration::from_millis(300)).await;

    // The newer session still gets pushes, and is still signed in (it can submit).
    alice_c
        .submit(env(
            gid,
            alice.address(),
            EnvelopeKind::Application,
            b"after-close",
            &[bob.address()],
        ))
        .await
        .unwrap();
    let mut got = Vec::new();
    while let Ok(Some(e)) =
        tokio::time::timeout(Duration::from_millis(800), new.next_delivered()).await
    {
        got.push(e.ciphertext);
    }
    assert!(
        got.contains(&b"after-close".to_vec()),
        "the newer session still receives: {got:?}"
    );
    new.submit(env(
        gid,
        bob.address(),
        EnvelopeKind::Application,
        b"reply",
        &[alice.address()],
    ))
    .await
    .expect("the newer session is still authenticated");
}
