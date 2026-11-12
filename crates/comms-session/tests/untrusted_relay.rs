//! The session treats the relay as untrusted. These tests put a rewriting loopback
//! proxy between a `NetSession` and a real `RelayServer` and check that what the relay
//! returns or labels is verified by the client, not believed.
//!
//! Loopback only; relay state is in memory.

use std::sync::Arc;

use comms_core::identity::EthWallet;
use comms_proto::{canonical, EnvelopeKind, WalletAddress};
use comms_relay::ws::{ClientFrame, RelayServer};
use comms_relay::DeliveryService;
use comms_session::NetSession;
use futures_util::{SinkExt, StreamExt};
use tokio::net::TcpListener;
use tokio_tungstenite::tungstenite::Message;

const DOMAIN: &str = "relay.citrate.ai";

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64
}

type Rewrite = Arc<dyn Fn(ClientFrame) -> ClientFrame + Send + Sync>;

/// A transparent WebSocket proxy to `upstream` that applies `rewrite` to every
/// client→relay frame. Returns the proxy's ws:// URL.
async fn proxy(upstream: String, rewrite: Rewrite) -> String {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        while let Ok((stream, _)) = listener.accept().await {
            let upstream = upstream.clone();
            let rewrite = rewrite.clone();
            tokio::spawn(async move {
                let Ok(down) = tokio_tungstenite::accept_async(stream).await else {
                    return;
                };
                let Ok((up, _)) = tokio_tungstenite::connect_async(&upstream).await else {
                    return;
                };
                let (mut down_w, mut down_r) = down.split();
                let (mut up_w, mut up_r) = up.split();
                let c2r = async {
                    while let Some(Ok(msg)) = down_r.next().await {
                        let msg = match msg {
                            Message::Binary(b) => match canonical::from_slice::<ClientFrame>(&b) {
                                Ok(f) => Message::Binary(canonical::to_vec(&rewrite(f)).unwrap()),
                                Err(_) => Message::Binary(b),
                            },
                            other => other,
                        };
                        if up_w.send(msg).await.is_err() {
                            break;
                        }
                    }
                };
                let r2c = async {
                    while let Some(Ok(msg)) = up_r.next().await {
                        if down_w.send(msg).await.is_err() {
                            break;
                        }
                    }
                };
                tokio::select! { _ = c2r => {}, _ = r2c => {} }
            });
        }
    });
    format!("ws://{addr}")
}

async fn relay(owner: WalletAddress) -> String {
    let service = DeliveryService::new(DOMAIN, owner, 0).unwrap();
    let server = RelayServer::new(service);
    let (addr, _h) = server.bind("127.0.0.1:0").await.unwrap();
    format!("ws://{addr}")
}

/// When the relay answers "the KeyPackage for Bob" with another wallet's genuine,
/// validly attested KeyPackage, channel creation must fail before anyone is added.
#[tokio::test]
async fn create_channel_refuses_a_keypackage_the_relay_substituted() {
    let alice_w = EthWallet::generate();
    let bob_w = EthWallet::generate();
    let carol_w = EthWallet::generate();
    let (alice_addr, bob_addr, carol_addr) =
        (alice_w.address(), bob_w.address(), carol_w.address());
    let upstream = relay(alice_addr).await;
    let now = now_ms();

    // Bob and Carol publish genuine KeyPackages directly to the relay.
    let bob = NetSession::login(&upstream, DOMAIN, Box::new(bob_w), now, false)
        .await
        .unwrap();
    bob.publish_keypackage().await.unwrap();
    let carol = NetSession::login(&upstream, DOMAIN, Box::new(carol_w), now, false)
        .await
        .unwrap();
    carol.publish_keypackage().await.unwrap();

    // Alice talks through a relay that serves Carol's package when Bob's is asked for.
    let swap: Rewrite = Arc::new(move |f| match f {
        ClientFrame::TakeKeyPackage { wallet } if wallet == bob_addr => {
            ClientFrame::TakeKeyPackage { wallet: carol_addr }
        }
        other => other,
    });
    let url = proxy(upstream.clone(), swap).await;
    let mut alice = NetSession::login(&url, DOMAIN, Box::new(alice_w), now, false)
        .await
        .unwrap();

    let r = alice.create_channel(&[bob_addr]).await;
    assert!(
        r.is_err(),
        "a KeyPackage for a different wallet than requested must be refused, got {r:?}"
    );
    assert!(
        !alice.in_channel(),
        "no channel may be formed from a substituted package"
    );
}

/// Control for the proxy: with no rewrite, the same flow succeeds through it.
#[tokio::test]
async fn create_channel_succeeds_through_a_transparent_proxy() {
    let alice_w = EthWallet::generate();
    let bob_w = EthWallet::generate();
    let (alice_addr, bob_addr) = (alice_w.address(), bob_w.address());
    let upstream = relay(alice_addr).await;
    let now = now_ms();
    let bob = NetSession::login(&upstream, DOMAIN, Box::new(bob_w), now, false)
        .await
        .unwrap();
    bob.publish_keypackage().await.unwrap();
    let url = proxy(upstream, Arc::new(|f| f)).await;
    let mut alice = NetSession::login(&url, DOMAIN, Box::new(alice_w), now, false)
        .await
        .unwrap();
    alice.create_channel(&[bob_addr]).await.unwrap();
    assert!(alice.in_channel());
}

/// The joiner's roster comes from authenticated MLS membership. A Welcome whose
/// relay-controlled `sender` names some other wallet must not add that wallet to the
/// joiner's recipient set: the joiner's next message goes to the real members only, so
/// the relay accepts it.
#[tokio::test]
async fn welcome_sender_label_does_not_enter_the_joiners_roster() {
    let alice_w = EthWallet::generate();
    let bob_w = EthWallet::generate();
    let (alice_addr, bob_addr) = (alice_w.address(), bob_w.address());
    let phantom = EthWallet::generate().address();
    let url = relay(alice_addr).await;
    let now = now_ms();

    let mut alice = NetSession::login(&url, DOMAIN, Box::new(alice_w), now, false)
        .await
        .unwrap();
    let mut bob = NetSession::login(&url, DOMAIN, Box::new(bob_w), now, false)
        .await
        .unwrap();
    bob.publish_keypackage().await.unwrap();
    let gid = alice.create_channel(&[bob_addr]).await.unwrap();

    let mut welcome = loop {
        let e = bob.next_envelope().await.expect("delivery");
        if e.kind == EnvelopeKind::Welcome {
            break e;
        }
    };
    welcome.sender = phantom; // the relay relabels the Welcome
    assert_eq!(bob.join_from_welcome(&welcome).await.unwrap(), gid);

    // The phantom is not a group member, so a recipient set containing it is refused
    // by the relay. A roster built from MLS membership sends to Alice only.
    bob.send_text("hello")
        .await
        .expect("joiner's roster must be the real members only");
    let _ = alice
        .next_envelope()
        .await
        .expect("alice receives bob's message");
}
