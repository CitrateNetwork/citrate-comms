//! COMMS-S1 (WP-1.7) — the bearer-gated, loopback-only admin surface, and the
//! pause enforcement it drives on the WebSocket transport.

use std::net::SocketAddr;

use comms_core::identity::{EthWallet, SiweMessage};
use comms_proto::{Envelope, EnvelopeKind, EpochId, GroupId, CITRATE_CHAIN_ID};
use comms_relay::admin::serve_admin;
use comms_relay::ws::{RelayClient, RelayServer, WsError};
use comms_relay::DeliveryService;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

const DOMAIN: &str = "relay.citrate.ai";

/// Minimal raw HTTP/1.1 client — returns (status_code, body_text). `Connection: close`
/// lets us read to EOF without parsing content-length.
async fn http(addr: SocketAddr, method: &str, path: &str, bearer: Option<&str>) -> (u16, String) {
    let mut stream = TcpStream::connect(addr).await.unwrap();
    let auth = bearer.map(|t| format!("Authorization: Bearer {t}\r\n")).unwrap_or_default();
    let req = format!(
        "{method} {path} HTTP/1.1\r\nHost: localhost\r\n{auth}Content-Length: 0\r\nConnection: close\r\n\r\n"
    );
    stream.write_all(req.as_bytes()).await.unwrap();
    let mut buf = Vec::new();
    stream.read_to_end(&mut buf).await.unwrap();
    let text = String::from_utf8_lossy(&buf).into_owned();
    let status = text
        .lines()
        .next()
        .and_then(|l| l.split_whitespace().nth(1))
        .and_then(|s| s.parse().ok())
        .unwrap_or(0);
    (status, text)
}

#[tokio::test]
async fn admin_surface_health_auth_pause_resume() {
    let owner = EthWallet::generate();
    let service = DeliveryService::new(DOMAIN, owner.address(), 0).unwrap();
    let server = RelayServer::new(service);
    let token = "s3cr3t-admin-token";
    let (admin, _h) = serve_admin(server.clone(), "127.0.0.1:0", token.into()).await.unwrap();

    // /health is unauthenticated (loopback-only already limits exposure) → 200 JSON.
    let (s, body) = http(admin, "GET", "/health", None).await;
    assert_eq!(s, 200);
    assert!(body.contains("\"paused\":false"));
    assert!(body.contains("relay.citrate.ai"));

    // /pause without a token → 401, state unchanged.
    let (s, _) = http(admin, "POST", "/pause", None).await;
    assert_eq!(s, 401);
    assert!(!server.is_paused());

    // /pause with the WRONG token → 401.
    let (s, _) = http(admin, "POST", "/pause", Some("wrong")).await;
    assert_eq!(s, 401);
    assert!(!server.is_paused());

    // /pause with the right token → 200, now paused.
    let (s, _) = http(admin, "POST", "/pause", Some(token)).await;
    assert_eq!(s, 200);
    assert!(server.is_paused());
    let (_, body) = http(admin, "GET", "/health", None).await;
    assert!(body.contains("\"paused\":true"));
    let (_, status_body) = http(admin, "GET", "/status", None).await;
    assert!(status_body.trim_end().ends_with("paused"));

    // /resume → 200, running again.
    let (s, _) = http(admin, "POST", "/resume", Some(token)).await;
    assert_eq!(s, 200);
    assert!(!server.is_paused());
}

#[tokio::test]
async fn admin_refuses_non_loopback_bind() {
    let owner = EthWallet::generate();
    let service = DeliveryService::new(DOMAIN, owner.address(), 0).unwrap();
    let server = RelayServer::new(service);
    // Fail-closed: the admin surface will not bind a routable address.
    assert!(serve_admin(server, "0.0.0.0:0", "t".into()).await.is_err());
}

#[tokio::test]
async fn paused_relay_rejects_mutations_over_ws() {
    let owner = EthWallet::generate();
    let service = DeliveryService::new(DOMAIN, owner.address(), 0).unwrap();
    let server = RelayServer::new(service);
    let (ws_addr, _accept) = server.clone().bind("127.0.0.1:0").await.unwrap();

    // Connect + authenticate as the owner.
    let (client, nonce) = RelayClient::connect(&format!("ws://{ws_addr}")).await.unwrap();
    let msg = SiweMessage {
        domain: DOMAIN.into(),
        address: owner.address(),
        statement: "Sign in".into(),
        uri: format!("wss://{DOMAIN}"),
        version: "1".into(),
        chain_id: CITRATE_CHAIN_ID,
        nonce,
        issued_at_ms: 1,
        expiration_ms: u64::MAX,
    };
    let sig = owner.sign_siwe(&msg);
    client.authenticate(msg, sig).await.unwrap();

    let gid = GroupId([3; 32]);
    client.register_group(gid).await.unwrap(); // works while running

    // Pause via the server handle (what POST /pause does after auth).
    server.set_paused(true);

    // A mutating op is now rejected (the pause gate fires before any group logic).
    let err = client
        .submit(Envelope {
            group_id: gid, epoch: EpochId(0), kind: EnvelopeKind::Application,
            sender: owner.address(), recipients: vec![], ciphertext: b"x".to_vec(), group_seq: None,
        })
        .await
        .unwrap_err();
    assert!(matches!(err, WsError::Server(ref m) if m.contains("paused")), "got {err:?}");

    // After resume, mutations are accepted again.
    server.set_paused(false);
    client
        .submit(Envelope {
            group_id: gid, epoch: EpochId(0), kind: EnvelopeKind::Application,
            sender: owner.address(), recipients: vec![], ciphertext: b"x".to_vec(), group_seq: None,
        })
        .await
        .unwrap();
}
