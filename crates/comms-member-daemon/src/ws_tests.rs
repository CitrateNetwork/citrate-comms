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
