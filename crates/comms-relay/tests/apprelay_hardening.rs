//! Over-the-wire coverage for the app/relay hardening fixes, driven through the real
//! `RelayClient` WebSocket path so the relay's behaviour — not a client shim — is under
//! test.
//!
//! - CM2-B-B001: three read/consume frames were dispatched with no auth check, letting
//!   an unauthenticated peer drain KeyPackages and read the roster + ratchet tree.
//! - CM2-B-B008: an envelope's `recipients` were fanned out with no membership check and
//!   no length bound.
//! - CM2-B-B009: an unauthenticated peer could loop `Challenge` without bound.

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

async fn serve() -> (String, EthWallet) {
    let alice = EthWallet::generate();
    let service = DeliveryService::new(DOMAIN, alice.address(), 0).unwrap();
    let server = RelayServer::new(service);
    let (addr, _h) = server.clone().bind("127.0.0.1:0").await.unwrap();
    (format!("ws://{addr}"), alice)
}

// ─────────────────────────── CM2-B-B001 ───────────────────────────

#[tokio::test]
async fn unauthenticated_peer_cannot_read_or_drain_relay_state() {
    let (url, alice) = serve().await;

    // A member publishes real state so there is something to steal.
    let (alice_c, n1) = RelayClient::connect(&url).await.unwrap();
    login(&alice_c, n1, &alice).await;
    let gid = GroupId([7; 32]);
    alice_c.register_group(gid).await.unwrap();

    // Mallory connects but NEVER authenticates.
    let (mallory_c, _n2) = RelayClient::connect(&url).await.unwrap();
    // Control: a mutating call is rejected, proving the connection has no session.
    assert!(mallory_c.register_group(GroupId([9; 32])).await.is_err());

    // The three formerly-unguarded frames must now be refused without a session.
    assert!(
        mallory_c.group_members(gid).await.is_err(),
        "unauthenticated GroupMembers must be refused (roster metadata leak)"
    );
    assert!(
        mallory_c.ratchet_tree(gid).await.is_err(),
        "unauthenticated RatchetTree must be refused (tree metadata leak)"
    );
    assert!(
        mallory_c.take_key_package(alice.address()).await.is_err(),
        "unauthenticated TakeKeyPackage must be refused (destructive drain)"
    );
}

// ─────────────────────────── CM2-B-B008 ───────────────────────────

#[tokio::test]
async fn submit_rejects_non_member_recipients_and_oversized_fanout() {
    let (url, alice) = serve().await;
    let (alice_c, n1) = RelayClient::connect(&url).await.unwrap();
    let alice_addr = login(&alice_c, n1, &alice).await;
    let gid = GroupId([11; 32]);
    alice_c.register_group(gid).await.unwrap();

    // A recipient who is not a member of the group must be rejected (no mailbox
    // placement into arbitrary wallets).
    let outsider = EthWallet::generate().address();
    let e1 = env(gid, alice_addr, EnvelopeKind::Application, 0, b"hi", &[outsider]);
    assert!(
        alice_c.submit(e1).await.is_err(),
        "submit with a non-member recipient must be rejected"
    );

    // An oversized recipient list must be rejected (fan-out amplification / heap DoS),
    // even when every entry is a member.
    let huge: Vec<WalletAddress> = vec![alice_addr; 5000];
    let e2 = env(gid, alice_addr, EnvelopeKind::Application, 0, b"hi", &huge);
    assert!(
        alice_c.submit(e2).await.is_err(),
        "submit with an over-cap recipient list must be rejected"
    );

    // Sanity: a well-formed submit to a member recipient still works.
    let e3 = env(gid, alice_addr, EnvelopeKind::Application, 0, b"hi", &[alice_addr]);
    assert!(alice_c.submit(e3).await.is_ok(), "a valid submit must still succeed");
}

// ─────────────────────────── CM2-B-B009 ───────────────────────────

#[tokio::test]
async fn unauthenticated_challenge_flood_is_capped() {
    let (url, _alice) = serve().await;
    let (mallory_c, _n) = RelayClient::connect(&url).await.unwrap();

    // Loop Challenge well past the per-connection cap; the relay must start refusing.
    let mut refused = 0;
    for _ in 0..64 {
        if mallory_c.challenge().await.is_err() {
            refused += 1;
        }
    }
    assert!(refused > 0, "the relay must cap per-connection challenge requests");
}
