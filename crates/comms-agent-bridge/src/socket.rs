//! Unix-domain-socket transport for the agent bridge (COMMS-S3, WP-3.3).
//!
//! The bridge listens on a Unix-domain socket that the agent runtime
//! (`nist-agent` / `citrate-agent-runtime`) connects to. This is the local,
//! loopback-equivalent control surface for the agent's MLS client — it mirrors the
//! `citrate-node-agent` supervision posture and the `nist-agent-daemon` JSON-per-line
//! framing:
//!
//! * **Local only.** A Unix socket has no network surface; the socket file is created
//!   `0600` so only the owning uid can connect.
//! * **Per-instance bearer.** On connect the runtime must present the bridge's bearer
//!   token (constant-time compared) before any frame is accepted. A wrong/absent token
//!   is rejected and the connection closed — **fail-closed**.
//! * **Framed both ways.** After the handshake the bridge writes [`AgentInbound`] events
//!   (one JSON object per line) and reads [`AgentOutbound`] commands back.
//!
//! The transport is deliberately decoupled from MLS: it never sees plaintext keys, only
//! the already-decrypted [`AgentInbound`] / to-be-encrypted [`AgentOutbound`] frames the
//! [`AgentBridge`](crate::AgentBridge) produces and consumes.

use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::unix::{OwnedReadHalf, OwnedWriteHalf};
use tokio::net::{UnixListener, UnixStream};

use crate::{AgentInbound, AgentOutbound};

/// The connect handshake the runtime sends as its first line: `{"type":"auth","token":"…"}`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "lowercase")]
enum Handshake {
    Auth { token: String },
}

/// The bridge's reply to a handshake: `ready` on success (the runtime waits for it before
/// sending commands). On failure the socket is simply closed (fail-closed).
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "lowercase")]
enum Ack {
    Ready,
}

/// A listening agent-bridge socket. Bind once, then [`accept`](AgentSocket::accept) the
/// runtime connection.
pub struct AgentSocket {
    listener: UnixListener,
    bearer: String,
    path: PathBuf,
}

impl AgentSocket {
    /// Bind the socket at `path` with `0600` permissions, requiring `bearer` on connect.
    /// A stale socket file at `path` is removed first.
    pub fn bind(path: impl AsRef<Path>, bearer: impl Into<String>) -> Result<Self, SocketError> {
        let path = path.as_ref().to_path_buf();
        // Remove a stale socket so bind() doesn't fail with AddrInUse.
        if path.exists() {
            std::fs::remove_file(&path).map_err(SocketError::Io)?;
        }
        let listener = UnixListener::bind(&path).map_err(SocketError::Io)?;
        // Restrict to the owning uid — defense in depth atop the local-only socket.
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).map_err(SocketError::Io)?;
        Ok(Self { listener, bearer: bearer.into(), path })
    }

    /// The socket path (for the daemon to advertise to the runtime).
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Accept one runtime connection and complete the bearer handshake. Returns a framed
    /// [`AgentConn`] only if the presented token matches (constant-time); otherwise the
    /// connection is closed and [`SocketError::Unauthorized`] is returned.
    pub async fn accept(&self) -> Result<AgentConn, SocketError> {
        let (stream, _addr) = self.listener.accept().await.map_err(SocketError::Io)?;
        let (read, write) = stream.into_split();
        let mut conn = AgentConn { reader: BufReader::new(read), writer: write };

        let hello: Handshake = conn.read_frame().await?.ok_or(SocketError::HandshakeClosed)?;
        let Handshake::Auth { token } = hello;
        if !constant_time_eq(token.as_bytes(), self.bearer.as_bytes()) {
            // Fail-closed: drop the connection without leaking which check failed.
            return Err(SocketError::Unauthorized);
        }
        conn.write_frame(&Ack::Ready).await?;
        Ok(conn)
    }
}

impl Drop for AgentSocket {
    fn drop(&mut self) {
        // Best-effort cleanup so a restart can rebind.
        let _ = std::fs::remove_file(&self.path);
    }
}

/// A framed, authenticated connection to the agent runtime. The bridge side sends
/// [`AgentInbound`] events and receives [`AgentOutbound`] commands.
pub struct AgentConn {
    reader: BufReader<OwnedReadHalf>,
    writer: OwnedWriteHalf,
}

impl AgentConn {
    /// Push a decrypted channel event to the runtime.
    pub async fn send_event(&mut self, ev: &AgentInbound) -> Result<(), SocketError> {
        self.write_frame(ev).await
    }

    /// Read the next command from the runtime. `Ok(None)` on a clean EOF (runtime closed).
    pub async fn recv_command(&mut self) -> Result<Option<AgentOutbound>, SocketError> {
        self.read_frame().await
    }

    async fn write_frame<T: Serialize>(&mut self, value: &T) -> Result<(), SocketError> {
        let line = crate::ipc::to_line(value).map_err(SocketError::Codec)?;
        self.writer.write_all(line.as_bytes()).await.map_err(SocketError::Io)?;
        self.writer.flush().await.map_err(SocketError::Io)?;
        Ok(())
    }

    async fn read_frame<T: DeserializeOwned>(&mut self) -> Result<Option<T>, SocketError> {
        let mut line = String::new();
        let n = self.reader.read_line(&mut line).await.map_err(SocketError::Io)?;
        if n == 0 {
            return Ok(None); // clean EOF
        }
        let value = crate::ipc::from_line(&line).map_err(SocketError::Codec)?;
        Ok(Some(value))
    }

    /// Split into independent send/receive halves so a daemon loop can push events and
    /// read commands concurrently (e.g. inside `tokio::select!`) without aliasing.
    pub fn split(self) -> (AgentSink, AgentSource) {
        (AgentSink { writer: self.writer }, AgentSource { reader: self.reader })
    }
}

/// The send half of an [`AgentConn`] — pushes [`AgentInbound`] events to the runtime.
pub struct AgentSink {
    writer: OwnedWriteHalf,
}

impl AgentSink {
    pub async fn send_event(&mut self, ev: &AgentInbound) -> Result<(), SocketError> {
        let line = crate::ipc::to_line(ev).map_err(SocketError::Codec)?;
        self.writer.write_all(line.as_bytes()).await.map_err(SocketError::Io)?;
        self.writer.flush().await.map_err(SocketError::Io)?;
        Ok(())
    }
}

/// The receive half of an [`AgentConn`] — reads [`AgentOutbound`] commands from the runtime.
pub struct AgentSource {
    reader: BufReader<OwnedReadHalf>,
}

impl AgentSource {
    /// `Ok(None)` on a clean EOF (the runtime disconnected).
    pub async fn recv_command(&mut self) -> Result<Option<AgentOutbound>, SocketError> {
        let mut line = String::new();
        let n = self.reader.read_line(&mut line).await.map_err(SocketError::Io)?;
        if n == 0 {
            return Ok(None);
        }
        let cmd = crate::ipc::from_line(&line).map_err(SocketError::Codec)?;
        Ok(Some(cmd))
    }
}

/// The runtime side of the transport — used by `nist-agent` / `citrate-agent-runtime` (and
/// our integration tests) to connect to the bridge, authenticate, then exchange frames.
pub struct RuntimeClient {
    reader: BufReader<OwnedReadHalf>,
    writer: OwnedWriteHalf,
}

impl RuntimeClient {
    /// Connect to the bridge socket and complete the bearer handshake.
    pub async fn connect(path: impl AsRef<Path>, bearer: impl Into<String>) -> Result<Self, SocketError> {
        let stream = UnixStream::connect(path.as_ref()).await.map_err(SocketError::Io)?;
        let (read, write) = stream.into_split();
        let mut me = Self { reader: BufReader::new(read), writer: write };
        me.write_frame(&Handshake::Auth { token: bearer.into() }).await?;
        // Wait for the bridge's ready ack; a closed socket here means rejected.
        let _ack: Ack = me.read_frame().await?.ok_or(SocketError::Unauthorized)?;
        Ok(me)
    }

    /// Send a command to the bridge (e.g. post a reply).
    pub async fn send_command(&mut self, cmd: &AgentOutbound) -> Result<(), SocketError> {
        self.write_frame(cmd).await
    }

    /// Read the next decrypted event from the bridge. `Ok(None)` on a clean EOF.
    pub async fn recv_event(&mut self) -> Result<Option<AgentInbound>, SocketError> {
        self.read_frame().await
    }

    async fn write_frame<T: Serialize>(&mut self, value: &T) -> Result<(), SocketError> {
        let line = crate::ipc::to_line(value).map_err(SocketError::Codec)?;
        self.writer.write_all(line.as_bytes()).await.map_err(SocketError::Io)?;
        self.writer.flush().await.map_err(SocketError::Io)?;
        Ok(())
    }

    async fn read_frame<T: DeserializeOwned>(&mut self) -> Result<Option<T>, SocketError> {
        let mut line = String::new();
        let n = self.reader.read_line(&mut line).await.map_err(SocketError::Io)?;
        if n == 0 {
            return Ok(None);
        }
        let value = crate::ipc::from_line(&line).map_err(SocketError::Codec)?;
        Ok(Some(value))
    }
}

/// Generate a 32-byte per-instance bearer token (hex). The daemon mints one at startup
/// and hands it to the runtime out of band (env/CLI), like the relay admin surface.
pub fn random_bearer() -> Result<String, SocketError> {
    let mut buf = [0u8; 32];
    getrandom::getrandom(&mut buf).map_err(|e| SocketError::Rng(e.to_string()))?;
    Ok(hex::encode(buf))
}

/// Constant-time byte comparison — avoids leaking the bearer via timing.
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

#[derive(Debug, thiserror::Error)]
pub enum SocketError {
    #[error("socket i/o error: {0}")]
    Io(#[source] std::io::Error),
    #[error("frame codec error: {0}")]
    Codec(#[source] serde_json::Error),
    #[error("connection closed before the handshake completed")]
    HandshakeClosed,
    #[error("unauthorized: bearer token did not match")]
    Unauthorized,
    #[error("rng error: {0}")]
    Rng(String),
}

#[cfg(test)]
mod tests {
    use super::*;

    fn socket_path(name: &str) -> PathBuf {
        // tempfile gives a unique dir without Date/rand in the script context.
        let dir = tempfile::tempdir().unwrap();
        // Keep the dir alive by leaking it — the test process is short-lived.
        let dir = Box::leak(Box::new(dir));
        dir.path().join(name)
    }

    #[tokio::test]
    async fn handshake_frames_roundtrip_over_a_real_socket() {
        let path = socket_path("bridge.sock");
        let bearer = "s3cr3t-bearer-token";
        let sock = AgentSocket::bind(&path, bearer).unwrap();

        // The socket file is 0600.
        let mode = std::fs::metadata(&path).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600);

        // Drive server-accept and client-connect concurrently.
        let server = {
            let sock = sock;
            tokio::spawn(async move {
                let mut conn = sock.accept().await.unwrap();
                // Push an event to the runtime.
                conn.send_event(&AgentInbound::Message {
                    group: "0xdeals".into(),
                    sender: "0xadmin".into(),
                    text: "summarize the Northwind thread".into(),
                })
                .await
                .unwrap();
                // Receive the runtime's reply command.
                let cmd = conn.recv_command().await.unwrap();
                // And then a clean EOF after the client drops.
                let eof = conn.recv_command().await.unwrap();
                (cmd, eof)
            })
        };

        let mut client = RuntimeClient::connect(&path, bearer).await.unwrap();
        let ev = client.recv_event().await.unwrap().unwrap();
        assert!(matches!(ev, AgentInbound::Message { ref text, .. } if text.contains("Northwind")));
        client
            .send_command(&AgentOutbound::Send { group: "0xdeals".into(), text: "on it".into() })
            .await
            .unwrap();
        drop(client); // clean EOF

        let (cmd, eof) = server.await.unwrap();
        assert_eq!(cmd, Some(AgentOutbound::Send { group: "0xdeals".into(), text: "on it".into() }));
        assert_eq!(eof, None);
    }

    #[tokio::test]
    async fn wrong_bearer_is_rejected_fail_closed() {
        let path = socket_path("bridge-auth.sock");
        let sock = AgentSocket::bind(&path, "correct-token").unwrap();

        let server = tokio::spawn(async move {
            // accept() must reject the bad bearer.
            sock.accept().await
        });

        let attempt = RuntimeClient::connect(&path, "WRONG-token").await;
        // The client either fails to read the ready ack (socket closed) → Unauthorized.
        assert!(attempt.is_err());

        let server_result = server.await.unwrap();
        assert!(matches!(server_result, Err(SocketError::Unauthorized)));
    }

    #[test]
    fn random_bearer_is_64_hex_chars_and_unique() {
        let a = random_bearer().unwrap();
        let b = random_bearer().unwrap();
        assert_eq!(a.len(), 64);
        assert!(a.chars().all(|c| c.is_ascii_hexdigit()));
        assert_ne!(a, b);
    }
}
