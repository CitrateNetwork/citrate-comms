// comms-member-daemon — WsRelay integration test. A REAL relay WS server + a daemon connecting
// over ws://, proving the networked transport (login + publish_kp + register_group over WS).

use super::*;
use crate::MemberDaemon;
use comms_core::identity::EthWallet;
use comms_relay::ws::RelayServer;

#[test]
fn ws_daemon_connects_and_creates_a_group() {
    let owner_w = EthWallet::generate();
    let owner_addr = owner_w.address();

    // Spawn the relay's WS server on a dedicated runtime/thread (ephemeral port). Kept separate
    // from WsRelay's own runtime so the two block_on contexts never nest.
    let (addr_tx, addr_rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let rt = tokio::runtime::Runtime::new().expect("server rt");
        rt.block_on(async move {
            let service = DeliveryService::new("relay.test", owner_addr, 0).expect("service");
            let server = RelayServer::new(service);
            let (addr, handle) = server.bind("127.0.0.1:0").await.expect("bind");
            addr_tx.send(addr).expect("send addr");
            let _ = handle.await; // serve until the process exits
        });
    });
    let addr = addr_rx.recv().expect("relay bound");
    let url = format!("ws://{addr}");

    // The daemon connects over WS and comes up (SIWE login + key-package publish over WS), then
    // creates a group (register_group over WS). The relay verifies SIWE against its REAL clock, so
    // the daemon must seed a real wall-clock timestamp (the binary does the same).
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .expect("clock");
    let ws = WsRelay::connect_insecure(&url).expect("ws connect");
    let mut daemon =
        MemberDaemon::new_with_relay(owner_w, Box::new(ws), "relay.test", now).expect("daemon/WS");
    let gid = daemon.create_group("deals").expect("create over WS");
    assert_eq!(daemon.list_groups().len(), 1);
    assert_eq!(daemon.list_groups()[0].0, gid);
}

// The real cross-node round-trip: TWO daemons, ONE shared relay, over ws://. The owner creates a
// group and adds a joiner (a second node); the joiner fetches its welcome/tree over WS and joins;
// then encrypted messages flow BOTH ways and each side decrypts the other's. If the WS transport,
// the JOIN, or the MLS were wrong, the plaintext would not come back.
#[test]
fn two_daemons_over_one_relay_exchange_encrypted_messages() {
    let owner_w = EthWallet::generate();
    let owner_addr = owner_w.address();
    let (addr_tx, addr_rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let rt = tokio::runtime::Runtime::new().expect("server rt");
        rt.block_on(async move {
            let service = DeliveryService::new("relay.test", owner_addr, 0).expect("service");
            let server = RelayServer::new(service);
            let (addr, handle) = server.bind("127.0.0.1:0").await.expect("bind");
            addr_tx.send(addr).expect("send addr");
            let _ = handle.await;
        });
    });
    let addr = addr_rx.recv().expect("relay bound");
    let url = format!("ws://{addr}");
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .expect("clock");

    // Owner (node 1) creates the group over the shared relay.
    let owner_ws = WsRelay::connect_insecure(&url).expect("owner ws");
    let mut owner =
        MemberDaemon::new_with_relay(owner_w, Box::new(owner_ws), "relay.test", now).expect("owner");
    let gid = owner.create_group("deals").expect("create");

    // Joiner (node 2) comes up on the SAME relay (its startup publishes its key package).
    let bob_w = EthWallet::generate();
    let bob_addr = bob_w.address();
    let bob_ws = WsRelay::connect_insecure(&url).expect("bob ws");
    let mut bob =
        MemberDaemon::new_with_relay(bob_w, Box::new(bob_ws), "relay.test", now).expect("bob");

    // Owner adds bob → the relay delivers bob's Welcome to bob's mailbox.
    owner.add_member(gid, bob_addr).expect("add bob");

    // Bob joins from the relay (welcome + tree over WS). Retry until the pushed welcome arrives.
    let mut joined = false;
    for _ in 0..60 {
        if bob.join_group(gid, "deals").is_ok() {
            joined = true;
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(50));
    }
    assert!(joined, "bob should join once his welcome is delivered");

    // Owner -> bob (encrypted; bob decrypts).
    owner.send(gid, "hello bob").expect("owner send");
    let mut got_owner_msg = false;
    for _ in 0..40 {
        if bob.poll_messages(gid).unwrap().iter().any(|m| m.body == "hello bob") {
            got_owner_msg = true;
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(50));
    }
    assert!(got_owner_msg, "bob must decrypt the owner's message");

    // Bob -> owner (encrypted; owner decrypts).
    bob.send(gid, "hi owner").expect("bob send");
    let mut got_bob_msg = false;
    for _ in 0..40 {
        if owner.poll_messages(gid).unwrap().iter().any(|m| m.body == "hi owner") {
            got_bob_msg = true;
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(50));
    }
    assert!(got_bob_msg, "owner must decrypt bob's message");
}

// INVITE-S2 end-to-end: token-authorized SELF-ADMIT with the owner offline after mint. The owner
// creates a group and mints ONE invite (export_group_info → publish). A SECOND daemon (fresh
// identity the owner never added) redeems the token, self-admits by MLS external commit, and then
// encrypted messages flow BOTH ways — WITHOUT the owner ever calling add_member. The owner only
// polls (passive receive) to merge the incoming external commit. If the external-commit path, the
// token gate, or the MLS were wrong, the plaintext would not come back.
#[test]
fn two_daemons_self_admit_via_invite_no_owner_add() {
    let owner_w = EthWallet::generate();
    let owner_addr = owner_w.address();
    let (addr_tx, addr_rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let rt = tokio::runtime::Runtime::new().expect("server rt");
        rt.block_on(async move {
            let service = DeliveryService::new("relay.test", owner_addr, 0).expect("service");
            let server = RelayServer::new(service);
            let (addr, handle) = server.bind("127.0.0.1:0").await.expect("bind");
            addr_tx.send(addr).expect("send addr");
            let _ = handle.await;
        });
    });
    let addr = addr_rx.recv().expect("relay bound");
    let url = format!("ws://{addr}");
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .expect("clock");

    // Owner creates the group and mints ONE invite, then does NOTHING else to admit anyone.
    let owner_ws = WsRelay::connect_insecure(&url).expect("owner ws");
    let mut owner =
        MemberDaemon::new_with_relay(owner_w, Box::new(owner_ws), "relay.test", now).expect("owner");
    let gid = owner.create_group("deals").expect("create");

    let token = b"self-admit-token-xyz".to_vec();
    let token_hash = *blake3::hash(&token).as_bytes();
    owner
        .publish_invite(gid, token_hash, now + 600_000)
        .expect("owner mints an invite");

    // A fresh, never-added invitee comes up on the SAME relay and SELF-ADMITS with the token.
    let bob_w = EthWallet::generate();
    let bob_addr = bob_w.address();
    let bob_ws = WsRelay::connect_insecure(&url).expect("bob ws");
    let mut bob =
        MemberDaemon::new_with_relay(bob_w, Box::new(bob_ws), "relay.test", now).expect("bob");
    bob.redeem_invite(gid, token.clone(), "deals")
        .expect("bob self-admits by external commit");

    // The owner merely POLLS (passive) until it has merged bob's external commit — no add_member.
    let mut owner_saw_bob = false;
    for _ in 0..60 {
        let _ = owner.poll_messages(gid).expect("owner poll");
        if owner
            .roster(gid)
            .unwrap()
            .iter()
            .any(|(w, _r)| *w == bob_addr)
        {
            owner_saw_bob = true;
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(50));
    }
    assert!(
        owner_saw_bob,
        "owner must merge the self-admit commit and see bob in the roster (no add_member)"
    );

    // Owner -> bob (encrypted at the shared post-commit epoch; bob decrypts).
    owner.send(gid, "welcome, self-admitted bob").expect("owner send");
    let mut got_owner_msg = false;
    for _ in 0..40 {
        if bob
            .poll_messages(gid)
            .unwrap()
            .iter()
            .any(|m| m.body == "welcome, self-admitted bob")
        {
            got_owner_msg = true;
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(50));
    }
    assert!(got_owner_msg, "bob must decrypt the owner's message after self-admit");

    // Bob -> owner (encrypted; owner decrypts). Full bidirectional proof.
    bob.send(gid, "thanks for the invite").expect("bob send");
    let mut got_bob_msg = false;
    for _ in 0..40 {
        if owner
            .poll_messages(gid)
            .unwrap()
            .iter()
            .any(|m| m.body == "thanks for the invite")
        {
            got_bob_msg = true;
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(50));
    }
    assert!(got_bob_msg, "owner must decrypt the self-admitted member's message");
}

// ---------------------------------------------------------------------------------------------
// Headless member (ops bot) paths — `comms-send` relies on these.
// ---------------------------------------------------------------------------------------------

/// Spawn a real relay WS server (ephemeral port) and return its `ws://` URL.
fn spawn_ws_relay(trust_anchor: WalletAddress) -> String {
    let (addr_tx, addr_rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let rt = tokio::runtime::Runtime::new().expect("server rt");
        rt.block_on(async move {
            let service = DeliveryService::new("relay.test", trust_anchor, 0).expect("service");
            let server = RelayServer::new(service);
            let (addr, handle) = server.bind("127.0.0.1:0").await.expect("bind");
            addr_tx.send(addr).expect("send addr");
            let _ = handle.await;
        });
    });
    format!("ws://{}", addr_rx.recv().expect("relay bound"))
}

fn wall_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .expect("clock")
}

fn ws_member(url: &str, w: EthWallet) -> MemberDaemon {
    let ws = WsRelay::connect_insecure(url).expect("ws connect");
    MemberDaemon::new_with_relay(w, Box::new(ws), "relay.test", wall_ms()).expect("daemon")
}

/// Poll `d` on `gid` until a message with `body` arrives (or give up).
fn await_body(d: &mut MemberDaemon, gid: GroupId, body: &str) -> bool {
    for _ in 0..60 {
        if let Ok(msgs) = d.poll_messages(gid) {
            if msgs.iter().any(|m| m.body == body) {
                return true;
            }
        }
        std::thread::sleep(std::time::Duration::from_millis(50));
    }
    false
}

// The add-by-address path for a member that is never told the group id: the owner adds the bot
// by address, the bot calls `join_pending` and is in — then its alert decrypts on the owner side.
#[test]
fn a_headless_member_added_by_address_joins_pending_and_posts() {
    let owner_w = EthWallet::generate();
    let url = spawn_ws_relay(owner_w.address());
    let mut owner = ws_member(&url, owner_w);
    let gid = owner.create_group("ops").expect("create");

    let bot_w = EthWallet::generate();
    let bot_addr = bot_w.address();
    let mut bot = ws_member(&url, bot_w);
    // Not invited yet: nothing to join, and no group.
    assert!(bot.join_pending().expect("nothing pending").is_empty());
    assert!(bot.list_groups().is_empty());

    owner.add_member(gid, bot_addr).expect("owner adds the bot by address");

    let mut joined = Vec::new();
    for _ in 0..60 {
        joined = bot.join_pending().expect("join pending");
        if !joined.is_empty() {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(50));
    }
    assert_eq!(joined, vec![gid], "the bot joins exactly the group it was added to");
    assert_eq!(bot.list_groups().len(), 1);

    bot.send(gid, "[CRIT] rpc-1 disk 93%").expect("bot send");
    assert!(
        await_body(&mut owner, gid, "[CRIT] rpc-1 disk 93%"),
        "the owner must decrypt the bot's alert"
    );
}

// Red→green for the drained-mailbox bug: `fetch` DRAINS the relay session, so polling group B
// used to throw away group A's traffic. Bob is in TWO groups (A by address, B by invite); a
// message in A must survive a poll of B.
#[test]
fn polling_one_group_does_not_drop_another_groups_messages() {
    let owner_w = EthWallet::generate();
    let url = spawn_ws_relay(owner_w.address());
    let mut owner = ws_member(&url, owner_w);
    let ga = owner.create_group("a").expect("ga");
    let gb = owner.create_group("b").expect("gb");

    let bob_w = EthWallet::generate();
    let bob_addr = bob_w.address();
    let mut bob = ws_member(&url, bob_w);

    // A: by address (uses bob's startup KeyPackage).
    owner.add_member(ga, bob_addr).expect("add to a");
    let mut joined = Vec::new();
    for _ in 0..60 {
        joined = bob.join_pending().expect("join");
        if !joined.is_empty() {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(50));
    }
    assert_eq!(joined, vec![ga]);

    // B: by invite (self-admit; carries its own fresh KeyPackage). Owner merges the commit.
    let token = b"two-groups-token".to_vec();
    owner
        .publish_invite(gb, *blake3::hash(&token).as_bytes(), wall_ms() + 600_000)
        .expect("mint");
    bob.redeem_invite(gb, token, "b").expect("redeem b");
    for _ in 0..40 {
        let _ = owner.poll_messages(gb);
        if owner.roster(gb).map(|r| r.len()).unwrap_or(0) == 2 {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(50));
    }

    owner.send(ga, "for group a").expect("send a");
    // Let the relay push it into bob's session, then poll the OTHER group first.
    std::thread::sleep(std::time::Duration::from_millis(300));
    let in_b = bob.poll_messages(gb).expect("poll b");
    assert!(in_b.iter().all(|m| m.body != "for group a"));
    assert!(
        await_body(&mut bob, ga, "for group a"),
        "group a's message must survive a poll of group b"
    );
}

// The invite-link path with a link EXACTLY as citrate-core mints it (base64url token, owner
// publishes BLAKE3 of the token string's bytes), parsed by `comms-send`'s link parser and redeemed
// through the IPC dispatcher. Proves the token encoding end to end against a real relay.
#[test]
fn a_core_minted_invite_link_redeems_through_the_ipc() {
    let owner_w = EthWallet::generate();
    let url = spawn_ws_relay(owner_w.address());
    let mut owner = ws_member(&url, owner_w);
    let gid = owner.create_group("ops").expect("create");
    let token = "Zm9vYmFyLWNvcmUtbWludGVkLXRva2VuLTAxMjM0NTY3"; // base64url, like random_state() gitleaks:allow (test fixture)
    owner
        .publish_invite(gid, *blake3::hash(token.as_bytes()).as_bytes(), wall_ms() + 600_000)
        .expect("mint");
    let link = format!("citrate://invite?g={}&t={token}&k=02aa", hex::encode(gid.0));

    let mut bot = ws_member(&url, EthWallet::generate());
    let inv = crate::client::parse_invite_link(&link).expect("link");
    let resp = crate::ipc::handle_request(
        &mut bot,
        serde_json::from_value(serde_json::json!({
            "op": "redeemInvite", "group": inv.group, "token": inv.token_hex, "name": "ops"
        }))
        .expect("request"),
    );
    assert_eq!(resp, crate::ipc::Response::Ok);

    // The owner merges the external commit, then reads the bot's alert.
    for _ in 0..40 {
        let _ = owner.poll_messages(gid);
        if owner.roster(gid).map(|r| r.len()).unwrap_or(0) == 2 {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(50));
    }
    bot.send(gid, "[RECOVERED] chain tip advancing").expect("bot send");
    assert!(await_body(&mut owner, gid, "[RECOVERED] chain tip advancing"));
}

// Revoking through the IPC with `report_used` against a real relay: a redeemed invite comes back
// as "invite already used" (the app refuses a claim approval on it); an unused invite closes; a
// request without the field (an older app) keeps the original acknowledgement.
#[test]
fn ipc_revoke_reports_an_already_redeemed_invite() {
    let owner_w = EthWallet::generate();
    let url = spawn_ws_relay(owner_w.address());
    let mut owner = ws_member(&url, owner_w);
    let gid = owner.create_group("ops").expect("create");
    let used = b"fxsec-used-token-0001".to_vec();
    let unused = b"fxsec-unused-token-0002".to_vec();
    for t in [&used, &unused] {
        owner
            .publish_invite(gid, *blake3::hash(t).as_bytes(), wall_ms() + 600_000)
            .expect("mint");
    }
    let mut bob = ws_member(&url, EthWallet::generate());
    bob.redeem_invite(gid, used.clone(), "ops")
        .expect("bob redeems the first invite");

    let revoke = |d: &mut MemberDaemon, token: &[u8], report: Option<bool>| {
        let mut req = serde_json::json!({
            "op": "revokeInvite",
            "token_hash": hex::encode(blake3::hash(token).as_bytes()),
        });
        if let Some(r) = report {
            req["report_used"] = serde_json::Value::Bool(r);
        }
        crate::ipc::handle_request(d, serde_json::from_value(req).expect("request"))
    };

    match revoke(&mut owner, &used, Some(true)) {
        crate::ipc::Response::Error { message } => assert!(
            message.contains(comms_wire::frames::INVITE_ALREADY_USED),
            "unexpected message: {message}"
        ),
        other => panic!("a redeemed invite must not revoke as OK when asked: {other:?}"),
    }
    // An older app (no field) gets the original answer.
    assert_eq!(revoke(&mut owner, &used, None), crate::ipc::Response::Ok);
    // An unused invite closes, and can no longer be redeemed.
    assert_eq!(
        revoke(&mut owner, &unused, Some(true)),
        crate::ipc::Response::Ok
    );
    let mut carol = ws_member(&url, EthWallet::generate());
    assert!(
        carol.redeem_invite(gid, unused, "ops").is_err(),
        "a closed invite can't be redeemed"
    );
}

// ── GC-1 / comms#3 close: a persistent member restarted mid-conversation ──

fn ws_persistent(url: &str, seed: &[u8; 32], dir: &std::path::Path) -> MemberDaemon {
    let w = EthWallet::from_secret_key(seed).expect("wallet from seed");
    let ws = WsRelay::connect_insecure(url).expect("ws connect");
    MemberDaemon::new_with_relay_persistent(
        w,
        Box::new(ws),
        "relay.test",
        wall_ms(),
        dir.to_path_buf(),
        seed,
    )
    .expect("persistent daemon")
}

// The acceptance for comms#3 beyond "list_groups survives": after a full restart the restored MLS
// state is USABLE in both directions over the same relay. If the epoch secrets, the sender ratchet
// or the leaf were restored wrongly, one of the two plaintexts would not come back.
#[test]
fn a_restarted_persistent_member_keeps_talking_in_both_directions() {
    let owner_w = EthWallet::generate();
    let seed = owner_w.secret_bytes();
    let url = spawn_ws_relay(owner_w.address());
    let tmp = tempfile::tempdir().expect("tmp");
    let state = tmp.path().join("state");

    let mut owner = ws_persistent(&url, &seed, &state);
    let gid = owner.create_group("deals").expect("create");
    let bob_w = EthWallet::generate();
    let bob_addr = bob_w.address();
    let mut bob = ws_member(&url, bob_w);
    owner.add_member(gid, bob_addr).expect("add bob");
    let mut joined = Vec::new();
    for _ in 0..60 {
        joined = bob.join_pending().expect("join");
        if !joined.is_empty() {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(50));
    }
    assert_eq!(joined, vec![gid]);
    owner.send(gid, "before restart").expect("send 1");
    assert!(await_body(&mut bob, gid, "before restart"));
    bob.send(gid, "ack 1").expect("bob send 1");
    assert!(await_body(&mut owner, gid, "ack 1"));

    drop(owner); // full shutdown: process gone, socket closed
    let mut owner = ws_persistent(&url, &seed, &state);
    assert_eq!(owner.list_groups().len(), 1);

    owner.send(gid, "after restart").expect("send 2");
    assert!(
        await_body(&mut bob, gid, "after restart"),
        "the peer must decrypt what the restored member sends"
    );
    bob.send(gid, "welcome back").expect("bob send 2");
    assert!(
        await_body(&mut owner, gid, "welcome back"),
        "the restored member must decrypt what the peer sends"
    );
}

// Red→green: `fetch` drains the relay, so mail for group A that a poll of group B fetched lives
// only in the daemon's inbox. It must survive a daemon restart, or it is lost for good (the relay
// already handed it over).
#[test]
fn mail_fetched_for_another_group_survives_a_daemon_restart() {
    let owner_w = EthWallet::generate();
    let url = spawn_ws_relay(owner_w.address());
    let mut owner = ws_member(&url, owner_w);
    let ga = owner.create_group("a").expect("ga");
    let gb = owner.create_group("b").expect("gb");

    let bob_w = EthWallet::generate();
    let bob_addr = bob_w.address();
    let seed = bob_w.secret_bytes();
    let tmp = tempfile::tempdir().expect("tmp");
    let state = tmp.path().join("state");
    let mut bob = ws_persistent(&url, &seed, &state);

    owner.add_member(ga, bob_addr).expect("add to a");
    let mut joined = Vec::new();
    for _ in 0..60 {
        joined = bob.join_pending().expect("join a");
        if !joined.is_empty() {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(50));
    }
    assert_eq!(joined, vec![ga]);
    let token = b"restart-two-groups".to_vec();
    owner
        .publish_invite(gb, *blake3::hash(&token).as_bytes(), wall_ms() + 600_000)
        .expect("mint");
    bob.redeem_invite(gb, token, "b").expect("redeem b");
    for _ in 0..40 {
        let _ = owner.poll_messages(gb);
        if owner.roster(gb).map(|r| r.len()).unwrap_or(0) == 2 {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(50));
    }

    owner.send(ga, "for group a").expect("send a");
    std::thread::sleep(std::time::Duration::from_millis(300));
    // Polling B fetches A's message from the relay and keeps it in the inbox.
    let in_b = bob.poll_messages(gb).expect("poll b");
    assert!(in_b.iter().all(|m| m.body != "for group a"));

    drop(bob); // restart before group A is polled
    let mut bob = ws_persistent(&url, &seed, &state);
    assert!(
        await_body(&mut bob, ga, "for group a"),
        "group a's fetched message must survive the daemon restart"
    );
}

// ── GC-2: signed role grants, chained from the owner in the group context ──

use comms_core::rbac;
use comms_proto::Role;

/// Owner + bob + carol in one group over a real WS relay, everyone joined and caught up.
fn trio() -> (MemberDaemon, MemberDaemon, MemberDaemon, GroupId) {
    let owner_w = EthWallet::generate();
    let url = spawn_ws_relay(owner_w.address());
    let mut owner = ws_member(&url, owner_w);
    let gid = owner.create_group("lab").expect("create");
    let bob_w = EthWallet::generate();
    let carol_w = EthWallet::generate();
    let (bob_a, carol_a) = (bob_w.address(), carol_w.address());
    let mut bob = ws_member(&url, bob_w);
    let mut carol = ws_member(&url, carol_w);
    owner.add_member(gid, bob_a).expect("add bob");
    join_until(&mut bob, gid);
    owner.add_member(gid, carol_a).expect("add carol");
    join_until(&mut carol, gid);
    // Bob merges the commit that added carol.
    settle(&mut [&mut bob, &mut carol], gid);
    (owner, bob, carol, gid)
}

fn join_until(d: &mut MemberDaemon, gid: GroupId) {
    for _ in 0..60 {
        if d.join_pending().expect("join").contains(&gid) {
            return;
        }
        std::thread::sleep(std::time::Duration::from_millis(50));
    }
    panic!("did not join");
}

/// Poll each daemon a few times so pending commits and grants are applied.
fn settle(ds: &mut [&mut MemberDaemon], gid: GroupId) {
    for _ in 0..6 {
        for d in ds.iter_mut() {
            let _ = d.poll_messages(gid);
        }
        std::thread::sleep(std::time::Duration::from_millis(60));
    }
}

fn role_of(d: &MemberDaemon, gid: GroupId, who: WalletAddress) -> Option<Role> {
    d.roster(gid).ok()?.into_iter().find(|(w, _)| *w == who).map(|(_, r)| r)
}

#[test]
fn every_member_sees_the_owner_from_the_group_context() {
    let (owner, bob, carol, gid) = trio();
    let o = owner.owner();
    assert_eq!(owner.group_owner(gid), Some(o));
    assert_eq!(bob.group_owner(gid), Some(o));
    assert_eq!(carol.group_owner(gid), Some(o));
}

#[test]
fn an_owner_grant_is_verified_and_applied_by_every_member() {
    let (mut owner, mut bob, mut carol, gid) = trio();
    let b = bob.owner();
    owner.grant_role(gid, b, Role::Admin, None).expect("owner grants admin");
    assert_eq!(role_of(&owner, gid, b), Some(Role::Admin));
    settle(&mut [&mut bob, &mut carol], gid);
    assert_eq!(role_of(&bob, gid, b), Some(Role::Admin), "bob sees himself as admin");
    assert_eq!(role_of(&carol, gid, b), Some(Role::Admin), "carol sees bob as admin");
    // The grant is not shown as a chat message.
    owner.send(gid, "plain text still flows").expect("send");
    assert!(await_body(&mut carol, gid, "plain text still flows"));

    // The chain: an admin may grant member-level roles, not admin.
    let c = carol.owner();
    bob.grant_role(gid, c, Role::Guest, None).expect("admin grants guest");
    settle(&mut [&mut owner, &mut carol], gid);
    assert_eq!(role_of(&owner, gid, c), Some(Role::Guest));
    assert_eq!(role_of(&carol, gid, c), Some(Role::Guest));
    let err = bob.grant_role(gid, c, Role::Admin, None).expect_err("anti-escalation");
    assert!(err.to_string().contains("cannot grant"), "{err}");
}

#[test]
fn forged_role_grant_rejected() {
    // Bob is a plain member. He signs a grant making himself admin and sends it as an
    // ordinary group message, bypassing his own daemon's check.
    let (mut owner, mut bob, mut carol, gid) = trio();
    let b = bob.owner();
    let forged = crate::grants::encode_grant_message(
        &rbac::sign_role_assertion(&bob.wallet, Role::Owner, b, Role::Admin, Some(gid), None)
            .expect("bob can produce a signature"),
    );
    bob.send(gid, &forged).expect("send the forged grant");
    settle(&mut [&mut owner, &mut carol], gid);
    assert_eq!(role_of(&owner, gid, b), Some(Role::Member), "owner keeps bob as member");
    assert_eq!(role_of(&carol, gid, b), Some(Role::Member), "carol keeps bob as member");
    assert!(
        owner.grant_rejections().iter().any(|r| r.contains("role grant from non-admin")),
        "{:?}",
        owner.grant_rejections()
    );
}

#[test]
fn a_grant_relayed_by_someone_other_than_its_issuer_is_refused() {
    // The owner's genuine grant, re-sent by bob, must not be applied: a grant is accepted
    // only from its issuer's own MLS credential.
    let (owner, mut bob, mut carol, gid) = trio();
    let c = carol.owner();
    let genuine = rbac::sign_role_assertion(&owner.wallet, Role::Owner, c, Role::Admin, Some(gid), None)
        .expect("owner signature");
    bob.send(gid, &crate::grants::encode_grant_message(&genuine)).expect("relay it");
    settle(&mut [&mut carol], gid);
    assert_eq!(role_of(&carol, gid, c), Some(Role::Member));
    assert!(carol.grant_rejections().iter().any(|r| r.contains("not sent by its issuer")));
}

#[test]
fn ownership_transfers_by_the_owner_only() {
    let (mut owner, mut bob, mut carol, gid) = trio();
    let (o, b) = (owner.owner(), bob.owner());
    let err = bob.transfer_ownership(gid, b).expect_err("a member cannot take the group");
    assert!(err.to_string().contains("owner"), "{err}");
    owner.transfer_ownership(gid, b).expect("owner hands over");
    settle(&mut [&mut bob, &mut carol], gid);
    for d in [&owner, &bob, &carol] {
        assert_eq!(d.group_owner(gid), Some(b), "everyone follows the transfer");
    }
    assert_eq!(role_of(&carol, gid, b), Some(Role::Owner));
    assert_eq!(role_of(&carol, gid, o), Some(Role::Admin), "the old owner stays as admin");
    // The new owner's grants are now the anchor.
    let c = carol.owner();
    bob.grant_role(gid, c, Role::Admin, None).expect("new owner grants admin");
    settle(&mut [&mut owner, &mut carol], gid);
    assert_eq!(role_of(&owner, gid, c), Some(Role::Admin));
}

#[test]
fn only_the_owner_can_make_an_admin_even_through_a_crafted_grant() {
    // #49 review P2: Admin gates money-adjacent surfaces (group FL offers), so an Admin grant
    // must come from the owner. Bob is an admin; he signs an Admin grant for carol claiming the
    // Owner role to his own signer, bypassing his daemon's check. Receivers refuse it.
    let (mut owner, mut bob, mut carol, gid) = trio();
    let (b, c) = (bob.owner(), carol.owner());
    owner.grant_role(gid, b, Role::Admin, None).expect("owner makes bob admin");
    settle(&mut [&mut bob, &mut carol], gid);
    assert_eq!(role_of(&carol, gid, b), Some(Role::Admin));
    let crafted =
        rbac::sign_role_assertion(&bob.wallet, Role::Owner, c, Role::Admin, Some(gid), None)
            .expect("bob can produce the signature");
    bob.send(gid, &crate::grants::encode_grant_message(&crafted))
        .expect("send it");
    settle(&mut [&mut owner, &mut carol], gid);
    assert_eq!(role_of(&owner, gid, c), Some(Role::Member));
    assert_eq!(role_of(&carol, gid, c), Some(Role::Member));
    assert!(
        owner
            .grant_rejections()
            .iter()
            .any(|r| r.contains("only the owner grants Admin")),
        "{:?}",
        owner.grant_rejections()
    );
}
