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
    let token = "Zm9vYmFyLWNvcmUtbWludGVkLXRva2VuLTAxMjM0NTY3"; // base64url, like random_state()
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
