//! The agent socket caps one IPC frame at 1 MiB. These tests drive the cap through the
//! real socket entry points: the bearer handshake in `AgentSocket::accept`, the
//! `AgentConn` command reader, and the split `AgentSource` that `AgentBridge::serve`
//! reads from. Each oversized case has an in-bounds control.
#![cfg(unix)]

use std::path::PathBuf;

use comms_agent_bridge::socket::{AgentSocket, RuntimeClient, SocketError};
use comms_agent_bridge::AgentOutbound;
use tokio::io::AsyncWriteExt;

const CAP: usize = 1024 * 1024;

/// A short socket path inside a fresh temp dir (unix socket paths are length-limited).
fn sock_path(dir: &tempfile::TempDir) -> PathBuf {
    dir.path().join("b.sock")
}

fn short_tempdir() -> tempfile::TempDir {
    tempfile::Builder::new()
        .prefix("cab")
        .tempdir_in("/tmp")
        .expect("tempdir")
}

fn send_of(text_len: usize) -> AgentOutbound {
    AgentOutbound::Send {
        group: "g".into(),
        text: "x".repeat(text_len),
    }
}

#[tokio::test]
async fn an_oversized_command_frame_is_refused_by_the_connection_reader() {
    let dir = short_tempdir();
    let path = sock_path(&dir);
    let sock = AgentSocket::bind(&path, "bearer-1").unwrap();
    let server = tokio::spawn(async move {
        let mut conn = sock.accept().await.unwrap();
        let first = conn.recv_command().await;
        let second = conn.recv_command().await;
        (first, second)
    });

    let mut client = RuntimeClient::connect(&path, "bearer-1").await.unwrap();
    // In-bounds control first, then one frame just over the cap.
    client.send_command(&send_of(1024)).await.unwrap();
    client.send_command(&send_of(CAP + 16)).await.unwrap();
    let (first, second) = server.await.unwrap();

    assert_eq!(
        first.unwrap(),
        Some(send_of(1024)),
        "an in-bounds frame is delivered"
    );
    assert!(
        matches!(second, Err(SocketError::FrameTooLarge(n)) if n == CAP),
        "an over-cap frame must be refused, got {second:?}"
    );
}

#[tokio::test]
async fn an_oversized_command_frame_is_refused_by_the_split_source_used_by_serve() {
    let dir = short_tempdir();
    let path = sock_path(&dir);
    let sock = AgentSocket::bind(&path, "bearer-2").unwrap();
    let server = tokio::spawn(async move {
        let conn = sock.accept().await.unwrap();
        let (_sink, mut source) = conn.split();
        let first = source.recv_command().await;
        let second = source.recv_command().await;
        (first, second)
    });

    let mut client = RuntimeClient::connect(&path, "bearer-2").await.unwrap();
    client.send_command(&send_of(CAP / 2)).await.unwrap();
    client.send_command(&send_of(CAP + 16)).await.unwrap();
    let (first, second) = server.await.unwrap();

    assert_eq!(
        first.unwrap(),
        Some(send_of(CAP / 2)),
        "a half-cap frame is delivered"
    );
    assert!(
        matches!(second, Err(SocketError::FrameTooLarge(n)) if n == CAP),
        "an over-cap frame must be refused, got {second:?}"
    );
}

#[tokio::test]
async fn an_oversized_handshake_is_refused_before_the_bearer_is_compared() {
    let dir = short_tempdir();
    let path = sock_path(&dir);
    let sock = AgentSocket::bind(&path, "bearer-3").unwrap();
    let server = tokio::spawn(async move { sock.accept().await.map(|_| ()) });

    // A raw peer that sends one over-cap handshake line (valid JSON, so only the cap
    // can refuse it before it is parsed).
    let mut raw = tokio::net::UnixStream::connect(&path).await.unwrap();
    let token = "y".repeat(CAP + 16);
    let line = format!("{{\"type\":\"auth\",\"token\":\"{token}\"}}\n");
    raw.write_all(line.as_bytes()).await.unwrap();
    raw.flush().await.unwrap();

    let res = server.await.unwrap();
    assert!(
        matches!(res, Err(SocketError::FrameTooLarge(n)) if n == CAP),
        "an over-cap handshake must be refused as oversized, got {res:?}"
    );
}
