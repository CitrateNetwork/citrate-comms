//! The loopback local-IPC server. Sync + single-client (the daemon is sync/in-process, and the only
//! consumer is the local citrate-core client), so no async runtime is needed. The transport is a
//! cross-platform local socket ([`interprocess`]): a Unix-domain socket on Unix, a named pipe on
//! Windows. On connect the client presents the bearer (constant-time compared) before any request is
//! served; on Unix the socket file is created `0600`. JSON-per-line framing mirrors
//! `comms-agent-bridge::socket`.

use std::io::{self, BufRead, BufReader, Write};
use std::path::Path;

use interprocess::local_socket::prelude::*;
use interprocess::local_socket::{ListenerOptions, Name, Stream};
use serde::Deserialize;
use subtle::ConstantTimeEq;

use crate::ipc::{handle_request, Request, Response};
use crate::MemberDaemon;

/// Map a socket path to an [`interprocess`] endpoint name. Unix: the path is used verbatim as a
/// filesystem name. Windows: a namespaced name derived from the path's basename, with every char
/// outside `[A-Za-z0-9._-]` replaced by `-`. Both ends of the IPC MUST apply this identical rule so
/// the client and server agree byte-for-byte (the citrate-core client mirrors it).
pub(crate) fn endpoint_name(p: &str) -> io::Result<Name<'static>> {
    #[cfg(unix)]
    {
        p.to_string()
            .to_fs_name::<interprocess::local_socket::GenericFilePath>()
    }
    #[cfg(windows)]
    {
        let base = std::path::Path::new(p)
            .file_name()
            .and_then(|s| s.to_str())
            .unwrap_or("citrate.sock");
        let slug: String = base
            .chars()
            .map(|c| {
                if c.is_ascii_alphanumeric() || c == '.' || c == '_' || c == '-' {
                    c
                } else {
                    '-'
                }
            })
            .collect();
        slug.to_ns_name::<interprocess::local_socket::GenericNamespaced>()
    }
}

/// The client's first line: `{"type":"auth","token":"…"}`.
#[derive(Debug, Deserialize)]
#[serde(tag = "type", rename_all = "lowercase")]
enum Handshake {
    Auth { token: String },
}

/// Bind `socket_path` (on Unix, created `0600`) and serve requests, one client connection at a time,
/// against `daemon`. Each connection first authenticates with `bearer`. Blocks until the listener
/// errors.
pub fn serve(mut daemon: MemberDaemon, socket_path: &Path, bearer: &str) -> std::io::Result<()> {
    // Clear a stale socket file so bind() doesn't fail with AddrInUse (Unix filesystem name only;
    // the Windows named-pipe namespace has no such file to remove).
    #[cfg(unix)]
    let _ = std::fs::remove_file(socket_path);
    let path_str = socket_path.to_str().ok_or_else(|| {
        io::Error::new(io::ErrorKind::InvalidInput, "socket path is not valid UTF-8")
    })?;
    let listener = ListenerOptions::new()
        .name(endpoint_name(path_str)?)
        .create_sync()?;
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
///
/// The [`interprocess`] [`Stream`] is bidirectional and has no `try_clone`; since the protocol is
/// strictly half-duplex (request in, response out), we buffer reads through a [`BufReader`] and
/// write through its `get_mut()` — byte-identical framing to the previous `UnixStream` split.
fn handle_conn(daemon: &mut MemberDaemon, stream: Stream, bearer: &str) -> std::io::Result<()> {
    let mut reader = BufReader::new(stream);

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
            reader.get_mut(),
            "{}",
            serde_json::to_string(&Response::Error {
                message: "unauthorized".into()
            })
            .unwrap_or_default()
        );
        return Ok(());
    }
    writeln!(reader.get_mut(), "{{\"type\":\"ready\"}}")?;

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
        writeln!(reader.get_mut(), "{out}")?;
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

/// No-op on non-Unix: the Windows named-pipe endpoint has no filesystem mode to restrict; the
/// named-pipe namespace is already scoped to the local session.
#[cfg(not(unix))]
fn harden_socket(_path: &Path) {}

#[cfg(test)]
mod server_tests {
    include!("server_tests.rs");
}
