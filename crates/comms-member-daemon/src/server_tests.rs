// comms-member-daemon — UDS server smoke tests. Real socket, real daemon, real MLS underneath.
// Requests are hand-built JSON (the production Request is deserialize-only, by design).

use crate::ipc::Response;
use crate::MemberDaemon;
use comms_core::identity::EthWallet;
use interprocess::local_socket::prelude::*;
use interprocess::local_socket::Stream;
use std::io::{BufRead, BufReader, Write};
use std::path::PathBuf;
use std::time::{Duration, Instant};

/// Connect the client end using the same [`super::endpoint_name`] rule the server binds with, then
/// wrap it in a [`BufReader`] whose `get_mut()` is the write side (the transport is half-duplex).
fn connect_client(path: &PathBuf) -> BufReader<Stream> {
    let path_str = path.to_str().expect("socket path is valid UTF-8");
    let name = super::endpoint_name(path_str).expect("endpoint name");
    let stream = Stream::connect(name).expect("connect");
    BufReader::new(stream)
}

fn tmp_socket(tag: &str) -> PathBuf {
    let mut p = std::env::temp_dir();
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    p.push(format!("citrate-member-{tag}-{nanos}.sock"));
    p
}

/// Spawn the server on a fresh socket in a background thread; returns (socket_path, bearer).
fn spawn_server(tag: &str) -> (PathBuf, String) {
    let path = tmp_socket(tag);
    let bearer = "b".repeat(64);
    let daemon = MemberDaemon::new(EthWallet::generate(), "relay.test", 1000).expect("daemon");
    let p = path.clone();
    let b = bearer.clone();
    std::thread::spawn(move || {
        let _ = super::serve(daemon, &p, &b);
    });
    let start = Instant::now();
    while !path.exists() && start.elapsed() < Duration::from_secs(3) {
        std::thread::sleep(Duration::from_millis(10));
    }
    (path, bearer)
}

#[test]
fn authenticated_client_creates_and_lists_a_group() {
    let (path, bearer) = spawn_server("create");
    let mut reader = connect_client(&path);

    // auth handshake
    writeln!(reader.get_mut(), "{{\"type\":\"auth\",\"token\":\"{bearer}\"}}").unwrap();
    let mut line = String::new();
    reader.read_line(&mut line).unwrap();
    assert!(line.contains("ready"), "auth: {line}");

    // createGroup
    line.clear();
    writeln!(reader.get_mut(), "{{\"op\":\"createGroup\",\"name\":\"deals\"}}").unwrap();
    reader.read_line(&mut line).unwrap();
    let gid = match serde_json::from_str::<Response>(line.trim()).unwrap() {
        Response::GroupCreated { id } => id,
        other => panic!("expected GroupCreated, got {other:?}"),
    };
    assert_eq!(gid.len(), 64);

    // listGroups
    line.clear();
    writeln!(reader.get_mut(), "{{\"op\":\"listGroups\"}}").unwrap();
    reader.read_line(&mut line).unwrap();
    match serde_json::from_str::<Response>(line.trim()).unwrap() {
        Response::Groups { groups } => {
            assert_eq!(groups.len(), 1);
            assert_eq!(groups[0].id, gid);
            assert_eq!(groups[0].name, "deals");
        }
        other => panic!("expected Groups, got {other:?}"),
    }

    // roster the new group over the socket → just the owner, as "owner".
    line.clear();
    writeln!(reader.get_mut(), "{{\"op\":\"roster\",\"group\":\"{gid}\"}}").unwrap();
    reader.read_line(&mut line).unwrap();
    match serde_json::from_str::<Response>(line.trim()).unwrap() {
        Response::Roster { members } => {
            assert_eq!(members.len(), 1);
            assert_eq!(members[0].role, "owner");
        }
        other => panic!("expected Roster, got {other:?}"),
    }

    // a malformed group id is an honest Error, never a panic.
    line.clear();
    writeln!(reader.get_mut(), "{{\"op\":\"send\",\"group\":\"nothex\",\"text\":\"hi\"}}").unwrap();
    reader.read_line(&mut line).unwrap();
    assert!(matches!(
        serde_json::from_str::<Response>(line.trim()).unwrap(),
        Response::Error { .. }
    ));
}

#[test]
fn a_wrong_bearer_is_rejected_before_any_request() {
    let (path, _bearer) = spawn_server("badauth");
    let mut reader = connect_client(&path);
    writeln!(reader.get_mut(), "{{\"type\":\"auth\",\"token\":\"{}\"}}", "z".repeat(64)).unwrap();
    let mut line = String::new();
    reader.read_line(&mut line).unwrap();
    assert!(line.contains("unauthorized"), "got {line}");
    assert!(!line.contains("ready"));
}
