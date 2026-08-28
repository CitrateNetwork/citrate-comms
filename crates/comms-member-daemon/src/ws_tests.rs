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
