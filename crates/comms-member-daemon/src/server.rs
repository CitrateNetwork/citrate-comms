//! The loopback Unix-domain-socket server. Sync + single-client (the daemon is sync/in-process, and
//! the only consumer is the local citrate-core client), so no async runtime is needed. On connect
//! the client presents the bearer (constant-time compared) before any request is served; the socket
//! file is created `0600`. JSON-per-line framing mirrors `comms-agent-bridge::socket`.

use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::Path;

use serde::Deserialize;
use subtle::ConstantTimeEq;

use crate::ipc::{handle_request, Request, Response};
use crate::MemberDaemon;

/// The client's first line: `{"type":"auth","token":"…"}`.
#[derive(Debug, Deserialize)]
#[serde(tag = "type", rename_all = "lowercase")]
enum Handshake {
    Auth { token: String },
}

/// Bind `socket_path` (created `0600`) and serve requests, one client connection at a time, against
/// `daemon`. Each connection first authenticates with `bearer`. Blocks until the listener errors.
pub fn serve(mut daemon: MemberDaemon, socket_path: &Path, bearer: &str) -> std::io::Result<()> {
    // Clear a stale socket so bind() doesn't fail with AddrInUse.
    let _ = std::fs::remove_file(socket_path);
    let listener = UnixListener::bind(socket_path)?;
    harden_socket(socket_path);
    for stream in listener.incoming() {
        match stream {
            Ok(stream) => {
                if let Err(e) = handle_conn(&mut daemon, stream, bearer) {
                    // A dropped/garbled client connection is not fatal; keep serving.
                    eprintln!("comms-member-daemon: connection ended: {e}");
                }
            }
            Err(e) => return Err(e),
        }
    }
    Ok(())
}

/// Handle one authenticated connection: bearer handshake, then a request/response loop until EOF.
fn handle_conn(
    daemon: &mut MemberDaemon,
    stream: UnixStream,
    bearer: &str,
) -> std::io::Result<()> {
    let mut reader = BufReader::new(stream.try_clone()?);
    let mut writer = stream;

    // --- bearer handshake ---
    let mut line = String::new();
    if reader.read_line(&mut line)? == 0 {
        return Ok(()); // client closed before auth
    }
    let authed = match serde_json::from_str::<Handshake>(line.trim()) {
        Ok(Handshake::Auth { token }) => {
            token.as_bytes().ct_eq(bearer.as_bytes()).into()
        }
        Err(_) => false,
    };
    if !authed {
        let _ = writeln!(
            writer,
            "{}",
            serde_json::to_string(&Response::Error {
                message: "unauthorized".into()
            })
            .unwrap_or_default()
        );
        return Ok(());
    }
    writeln!(writer, "{{\"type\":\"ready\"}}")?;

    // --- request loop ---
    loop {
        line.clear();
        if reader.read_line(&mut line)? == 0 {
            break; // clean EOF — client disconnected
        }
        if line.trim().is_empty() {
            continue;
        }
        let resp = match serde_json::from_str::<Request>(line.trim()) {
            Ok(req) => handle_request(daemon, req),
            Err(e) => Response::Error {
                message: format!("bad request: {e}"),
            },
        };
        let out = serde_json::to_string(&resp).unwrap_or_else(|e| {
            format!("{{\"type\":\"error\",\"message\":\"serialize failed: {e}\"}}")
        });
        writeln!(writer, "{out}")?;
    }
    Ok(())
}

#[cfg(unix)]
fn harden_socket(path: &Path) {
    use std::os::unix::fs::PermissionsExt;
    if let Ok(md) = std::fs::metadata(path) {
        let mut perms = md.permissions();
        perms.set_mode(0o600);
        let _ = std::fs::set_permissions(path, perms);
    }
}

#[cfg(test)]
mod server_tests {
    include!("server_tests.rs");
}
