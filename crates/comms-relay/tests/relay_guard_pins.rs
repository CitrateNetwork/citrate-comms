//! Regression pins for relay guards that the existing suite did not exercise.
//!
//! Each test drives a public entry point (the WebSocket transport or the
//! `DeliveryService` API the transport calls) and fails if the guard it names is
//! removed. Everything runs on loopback with in-memory relay state; nothing touches
//! the host beyond an ephemeral 127.0.0.1 port.

use std::time::Duration;

use comms_core::identity::{EthWallet, SiweMessage};
use comms_core::rbac;
use comms_proto::{
    canonical, ClaimSubmission, Envelope, EnvelopeKind, EpochId, GroupId, KeyPackagePublication,
    Role, WalletAddress, CITRATE_CHAIN_ID,
};
use comms_relay::ws::{RelayClient, RelayServer, ServerFrame};
use comms_relay::{DeliveryService, OffboardRequest, RelayError};
use futures_util::{SinkExt, StreamExt};
use tokio_tungstenite::tungstenite::Message;

const DOMAIN: &str = "relay.citrate.ai";

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

async fn ws_login(client: &RelayClient, nonce: String, wallet: &EthWallet) -> WalletAddress {
    let msg = siwe(wallet, nonce, now_ms());
    let sig = wallet.sign_siwe(&msg);
    client.authenticate(msg, sig).await.unwrap()
}

fn svc_login(relay: &mut DeliveryService, wallet: &EthWallet, now: u64) {
    let nonce = relay.issue_challenge(now);
    let msg = siwe(wallet, nonce, now);
    let sig = wallet.sign_siwe(&msg);
    relay.authenticate(&msg, &sig, now).unwrap();
}

fn env(
    gid: GroupId,
    sender: WalletAddress,
    kind: EnvelopeKind,
    epoch: u64,
    ct: &[u8],
    to: &[WalletAddress],
) -> Envelope {
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

/// A KeyPackage publication for `wallet`, attested by `signer` over `nonce`. The relay
/// does not parse MLS bytes, so the package body is an opaque marker.
fn publication(
    wallet: &EthWallet,
    signer: &EthWallet,
    nonce: &str,
    tag: u8,
) -> KeyPackagePublication {
    let mls_sig_pubkey = vec![tag; 32];
    KeyPackagePublication {
        wallet: wallet.address(),
        key_package: vec![tag; 64],
        binding_attestation: signer.sign_binding(&mls_sig_pubkey, DOMAIN, nonce).to_vec(),
        mls_sig_pubkey,
        nonce: nonce.into(),
        relay_domain: DOMAIN.into(),
    }
}

async fn serve(owner: &EthWallet) -> String {
    let service = DeliveryService::new(DOMAIN, owner.address(), 0).unwrap();
    let server = RelayServer::new(service);
    let (addr, _h) = server.clone().bind("127.0.0.1:0").await.unwrap();
    format!("ws://{addr}")
}

// ───────────────────────── WebSocket entry point ─────────────────────────

/// A session may publish KeyPackages only under its own wallet. Even a publication
/// that carries a valid attestation from another wallet is refused when it arrives on
/// a connection authenticated as someone else, and the other wallet's directory stays
/// untouched.
#[tokio::test]
async fn ws_publish_key_package_is_bound_to_the_session_wallet() {
    let alice = EthWallet::generate();
    let mallory = EthWallet::generate();
    let url = serve(&alice).await;

    let (alice_c, n1) = RelayClient::connect(&url).await.unwrap();
    ws_login(&alice_c, n1, &alice).await;
    let (mallory_c, n2) = RelayClient::connect(&url).await.unwrap();
    ws_login(&mallory_c, n2, &mallory).await;

    // A genuine, Alice-attested publication over a live relay nonce, sent on Mallory's
    // connection.
    let nonce = mallory_c.challenge().await.unwrap();
    let foreign = publication(&alice, &alice, &nonce, 0xA1);
    assert!(
        mallory_c.publish_key_package(foreign).await.is_err(),
        "a session must not publish a KeyPackage under another wallet"
    );
    assert_eq!(
        alice_c.take_key_package(alice.address()).await.unwrap(),
        None,
        "nothing may have been added to the other wallet's directory"
    );

    // Control: the same shape on the owner's own connection is accepted.
    let nonce = alice_c.challenge().await.unwrap();
    let own = publication(&alice, &alice, &nonce, 0xA2);
    alice_c.publish_key_package(own.clone()).await.unwrap();
    assert_eq!(
        alice_c.take_key_package(alice.address()).await.unwrap(),
        Some(own)
    );
}

/// The roster is readable by group members only — an authenticated session that is not
/// a member of the group is refused.
#[tokio::test]
async fn ws_group_members_requires_membership_not_just_a_session() {
    let alice = EthWallet::generate();
    let outsider = EthWallet::generate();
    let url = serve(&alice).await;

    let (alice_c, n1) = RelayClient::connect(&url).await.unwrap();
    let alice_addr = ws_login(&alice_c, n1, &alice).await;
    let gid = GroupId([21; 32]);
    alice_c.register_group(gid).await.unwrap();

    let (out_c, n2) = RelayClient::connect(&url).await.unwrap();
    ws_login(&out_c, n2, &outsider).await;
    assert!(
        out_c.group_members(gid).await.is_err(),
        "an authenticated non-member must not read the roster"
    );

    // Control: the member reads it.
    let roster = alice_c.group_members(gid).await.unwrap().expect("roster");
    assert!(roster.contains(&alice_addr));
}

/// Read the next binary server frame, or `None` once the stream has ended.
async fn next_server_frame<S>(read: &mut S) -> Option<ServerFrame>
where
    S: futures_util::Stream<Item = Result<Message, tokio_tungstenite::tungstenite::Error>> + Unpin,
{
    loop {
        match read.next().await {
            Some(Ok(Message::Binary(b))) => return canonical::from_slice(&b).ok(),
            Some(Ok(Message::Close(_))) | Some(Err(_)) | None => return None,
            Some(Ok(_)) => continue,
        }
    }
}

/// Inbound WebSocket messages are capped well below the transport library's 64 MiB
/// default: an oversized message from an unauthenticated peer ends the connection
/// instead of being buffered and parsed.
#[tokio::test]
async fn ws_oversized_inbound_message_closes_the_connection() {
    let owner = EthWallet::generate();
    let url = serve(&owner).await;

    // Control: a small malformed message is read and answered.
    let (ws, _) = tokio_tungstenite::connect_async(&url).await.unwrap();
    let (mut write, mut read) = ws.split();
    assert!(matches!(
        next_server_frame(&mut read).await,
        Some(ServerFrame::Challenge { .. })
    ));
    write
        .send(Message::binary(vec![0xFFu8; 1024]))
        .await
        .unwrap();
    let reply = tokio::time::timeout(Duration::from_secs(10), next_server_frame(&mut read))
        .await
        .expect("relay answers a small message");
    assert!(
        matches!(reply, Some(ServerFrame::Error { ref message }) if message.contains("malformed")),
        "control: a small malformed frame gets an error reply, got {reply:?}"
    );

    // 3 MiB — above the relay's cap, far below the library default.
    let (ws, _) = tokio_tungstenite::connect_async(&url).await.unwrap();
    let (mut write, mut read) = ws.split();
    assert!(matches!(
        next_server_frame(&mut read).await,
        Some(ServerFrame::Challenge { .. })
    ));
    let _ = write
        .send(Message::binary(vec![0xFFu8; 3 * 1024 * 1024]))
        .await;
    let after = tokio::time::timeout(Duration::from_secs(20), next_server_frame(&mut read))
        .await
        .expect("relay must close the connection promptly");
    assert!(
        after.is_none(),
        "an oversized inbound message must end the connection, not be parsed (got {after:?})"
    );
}

// ─────────────────────── DeliveryService entry point ───────────────────────

/// Resubmitting the identical accepted Commit is idempotent: same sequence number, no
/// second log entry, no second audit record, no duplicate delivery.
#[test]
fn identical_commit_resubmission_is_idempotent() {
    let alice = EthWallet::generate();
    let bob = EthWallet::generate();
    let mut relay = DeliveryService::new(DOMAIN, alice.address(), 0).unwrap();
    svc_login(&mut relay, &alice, 1);
    svc_login(&mut relay, &bob, 1);
    let gid = GroupId([31; 32]);
    relay.register_group(gid, alice.address(), 2).unwrap();
    relay
        .onboard(
            gid,
            alice.address(),
            None,
            bob.address(),
            env(
                gid,
                alice.address(),
                EnvelopeKind::Welcome,
                0,
                b"w",
                &[bob.address()],
            ),
            b"rt".to_vec(),
            3,
        )
        .unwrap();
    let _ = relay.fetch(&bob.address());

    let commit = env(
        gid,
        alice.address(),
        EnvelopeKind::Commit,
        1,
        b"commit-1",
        &[bob.address()],
    );
    let seq = relay.submit_as(alice.address(), commit.clone(), 4).unwrap();
    let log_len = relay.group_log(&gid).unwrap().len();
    let audit_len = relay.audit().len();
    assert_eq!(relay.fetch(&bob.address()).len(), 1);

    let again = relay.submit_as(alice.address(), commit, 5).unwrap();
    assert_eq!(
        again, seq,
        "a replayed Commit must return the original sequence number"
    );
    assert_eq!(
        relay.group_log(&gid).unwrap().len(),
        log_len,
        "no second log entry"
    );
    assert_eq!(relay.audit().len(), audit_len, "no second audit record");
    assert!(
        relay.fetch(&bob.address()).is_empty(),
        "no duplicate delivery"
    );
}

/// The per-wallet KeyPackage directory is capped.
#[test]
fn key_package_directory_is_capped_per_wallet() {
    let alice = EthWallet::generate();
    let mut relay = DeliveryService::new(DOMAIN, alice.address(), 0).unwrap();
    svc_login(&mut relay, &alice, 1);
    let mut accepted = 0usize;
    let refused = loop {
        let nonce = relay.issue_challenge(2);
        let p = publication(&alice, &alice, &nonce, (accepted % 251) as u8);
        match relay.publish_key_package(p, 2) {
            Ok(_) => accepted += 1,
            Err(e) => break e,
        }
        assert!(
            accepted <= 1024,
            "the directory accepted {accepted} packages without a cap"
        );
    };
    assert!(
        matches!(refused, RelayError::KeyPackageQuotaExceeded { max } if max == accepted),
        "expected a quota refusal at the cap, got {refused:?} after {accepted}"
    );
    assert_eq!(relay.key_package_count(&alice.address()), accepted);
}

/// Offboarding a member also ends that member's relay session; the admin's session is
/// unaffected.
#[test]
fn offboard_ends_the_removed_members_session() {
    let alice = EthWallet::generate();
    let bob = EthWallet::generate();
    let mut relay = DeliveryService::new(DOMAIN, alice.address(), 0).unwrap();
    svc_login(&mut relay, &alice, 1);
    svc_login(&mut relay, &bob, 1);
    let gid = GroupId([41; 32]);
    relay.register_group(gid, alice.address(), 2).unwrap();
    relay
        .onboard(
            gid,
            alice.address(),
            None,
            bob.address(),
            env(
                gid,
                alice.address(),
                EnvelopeKind::Welcome,
                0,
                b"w",
                &[bob.address()],
            ),
            b"rt".to_vec(),
            3,
        )
        .unwrap();
    assert!(relay.has_session(&bob.address()));

    relay
        .offboard(
            OffboardRequest {
                group_id: gid,
                admin: alice.address(),
                admin_assertion: None,
                removed: bob.address(),
                remove_commit: env(gid, alice.address(), EnvelopeKind::Commit, 1, b"rm", &[]),
                ratchet_tree: b"rt2".to_vec(),
            },
            4,
        )
        .unwrap();
    assert!(
        !relay.has_session(&bob.address()),
        "the removed member's session must end with the offboard"
    );
    assert!(relay.has_session(&alice.address()));
    let after = relay.submit_claim(
        &bob.address(),
        ClaimSubmission {
            token_hash: [1; 32],
            ciphertext: vec![1],
        },
    );
    assert!(matches!(after, Err(RelayError::NotAuthenticated)));
}

/// A delegated grant authorizes onboarding only if its role carries the add-member
/// capability. A member presenting a valid, owner-signed grant for a role without it
/// is refused, and the roster is unchanged.
#[test]
fn onboard_with_a_grant_lacking_add_member_is_refused() {
    let owner = EthWallet::generate();
    let delegate = EthWallet::generate();
    let joiner = EthWallet::generate();
    let mut relay = DeliveryService::new(DOMAIN, owner.address(), 0).unwrap();
    svc_login(&mut relay, &owner, 1);
    svc_login(&mut relay, &delegate, 1);
    let gid = GroupId([51; 32]);
    relay.register_group(gid, owner.address(), 2).unwrap();
    relay
        .onboard(
            gid,
            owner.address(),
            None,
            delegate.address(),
            env(
                gid,
                owner.address(),
                EnvelopeKind::Welcome,
                0,
                b"w",
                &[delegate.address()],
            ),
            b"rt".to_vec(),
            3,
        )
        .unwrap();

    let far = now_ms() + 3_600_000;
    for role in [Role::Member, Role::Partner, Role::Guest, Role::Agent] {
        let grant = rbac::sign_role_assertion(
            &owner,
            Role::Owner,
            delegate.address(),
            role,
            Some(gid),
            Some(far),
        )
        .unwrap();
        let r = relay.onboard(
            gid,
            delegate.address(),
            Some(&grant),
            joiner.address(),
            env(
                gid,
                delegate.address(),
                EnvelopeKind::Welcome,
                0,
                b"w2",
                &[joiner.address()],
            ),
            b"rt-x".to_vec(),
            4,
        );
        assert!(
            matches!(r, Err(RelayError::NotAuthorized)),
            "a {role:?} grant must not authorize onboarding, got {r:?}"
        );
        assert!(!relay
            .group_members(&gid)
            .unwrap()
            .contains(&joiner.address()));
    }

    // Control: an Admin grant does authorize it.
    let admin_grant = rbac::sign_role_assertion(
        &owner,
        Role::Owner,
        delegate.address(),
        Role::Admin,
        Some(gid),
        Some(far),
    )
    .unwrap();
    relay
        .onboard(
            gid,
            delegate.address(),
            Some(&admin_grant),
            joiner.address(),
            env(
                gid,
                delegate.address(),
                EnvelopeKind::Welcome,
                0,
                b"w3",
                &[joiner.address()],
            ),
            b"rt-y".to_vec(),
            5,
        )
        .unwrap();
    assert!(relay
        .group_members(&gid)
        .unwrap()
        .contains(&joiner.address()));
}
