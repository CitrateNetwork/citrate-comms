//! The CLIENT side of the daemon's loopback IPC, and the logic of the `comms-send` binary.
//!
//! `comms-send` is for a HEADLESS member — an ops bot that posts alerts into a team group. It is a
//! thin, scriptable client: it holds no key and no MLS state (the daemon does), it only speaks the
//! same bearer-authenticated JSON-per-line protocol citrate-core Commons speaks. Every subcommand
//! prints one JSON object on stdout and exits with a code a script can branch on (see `EXIT_*`).
//!
//! How a headless member gets into a group (either path; both are the supported Commons flows):
//! - **Add by address.** The owner pastes the bot's address (`comms-send whoami`) into
//!   *Groups → Members → Add by address*. The Welcome lands in the bot's mailbox and
//!   `comms-send join-pending` joins it — no group id needs to be passed around.
//! - **Invite link.** The owner mints a link (*Invite by @handle* / *Copy link*,
//!   `citrate://invite?g=…&t=…`) and the operator runs `comms-send redeem --link '<link>'`.

use std::io::{BufRead, BufReader, Write};
use std::path::Path;

use interprocess::local_socket::prelude::*;
use interprocess::local_socket::Stream;
use serde_json::{json, Value};

use crate::ipc::{GroupView, Response};

/// Success.
pub const EXIT_OK: i32 = 0;
/// The daemon answered with an error (relay rejected the op, MLS failure, …).
pub const EXIT_ERROR: i32 = 1;
/// Bad command line.
pub const EXIT_USAGE: i32 = 2;
/// The daemon is unreachable, or rejected the bearer.
pub const EXIT_DAEMON: i32 = 3;
/// The daemon is up but its link to the relay is down (restart it to reconnect).
pub const EXIT_RELAY_DOWN: i32 = 4;
/// This member is not in the requested group (or in no group at all): it has not been invited yet.
pub const EXIT_NOT_MEMBER: i32 = 5;

/// Largest message `send` accepts. Alerts are short; anything bigger is a caller bug, and it is
/// refused rather than silently truncated.
pub const MAX_TEXT_BYTES: usize = 16 * 1024;

/// A client-side failure. Carries messages, never the bearer.
#[derive(Debug, thiserror::Error)]
pub enum ClientError {
    #[error("cannot reach the member daemon at {0}: {1}")]
    Connect(String, String),
    #[error("the member daemon rejected the bearer token")]
    Unauthorized,
    #[error("ipc i/o error: {0}")]
    Io(String),
    #[error("unexpected response from the member daemon: {0}")]
    Protocol(String),
}

/// An authenticated connection to a running member daemon.
pub struct IpcClient {
    reader: BufReader<Stream>,
}

impl IpcClient {
    /// Connect to the daemon's socket and present `bearer`. Fails closed on a wrong bearer.
    pub fn connect(socket: &Path, bearer: &str) -> Result<Self, ClientError> {
        let shown = socket.display().to_string();
        let path_str = socket
            .to_str()
            .ok_or_else(|| ClientError::Connect(shown.clone(), "path is not UTF-8".into()))?;
        let name = crate::server::endpoint_name(path_str)
            .map_err(|e| ClientError::Connect(shown.clone(), e.to_string()))?;
        let stream = Stream::connect(name)
            .map_err(|e| ClientError::Connect(shown.clone(), e.to_string()))?;
        let mut reader = BufReader::new(stream);
        let hello = json!({"type": "auth", "token": bearer}).to_string();
        writeln!(reader.get_mut(), "{hello}").map_err(|e| ClientError::Io(e.to_string()))?;
        let mut line = String::new();
        reader
            .read_line(&mut line)
            .map_err(|e| ClientError::Io(e.to_string()))?;
        if line.contains("\"ready\"") {
            Ok(IpcClient { reader })
        } else if line.contains("unauthorized") {
            Err(ClientError::Unauthorized)
        } else {
            Err(ClientError::Protocol(line.trim().to_string()))
        }
    }

    /// Send one request (a JSON object with an `op` tag) and read its response.
    pub fn call(&mut self, req: &Value) -> Result<Response, ClientError> {
        writeln!(self.reader.get_mut(), "{req}").map_err(|e| ClientError::Io(e.to_string()))?;
        let mut line = String::new();
        let n = self
            .reader
            .read_line(&mut line)
            .map_err(|e| ClientError::Io(e.to_string()))?;
        if n == 0 {
            return Err(ClientError::Io("daemon closed the connection".into()));
        }
        serde_json::from_str::<Response>(line.trim())
            .map_err(|e| ClientError::Protocol(format!("{e}: {}", line.trim())))
    }
}

/// A parsed `citrate://invite?g=<group>&t=<token>[&k=…][&n=<hex name>]` link.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Invite {
    /// The 32-byte group id, hex.
    pub group: String,
    /// The raw invite token as the daemon's `redeemInvite` wants it: HEX of the token's bytes.
    pub token_hex: String,
    /// The group's display name, when the link carries one.
    pub name: String,
}

/// Parse an invite link minted by citrate-core (`group_invite_create`).
///
/// The token in the link is a base64url STRING, and the owner publishes `BLAKE3(token.as_bytes())`
/// to the relay; the relay recomputes `BLAKE3(raw)` from what the redeemer sends, and the daemon's
/// `redeemInvite` op takes `raw` as hex. So the bytes to send are the token's ASCII bytes,
/// hex-encoded — NOT a hex-decode of the token (which fails for base64url).
pub fn parse_invite_link(link: &str) -> Result<Invite, String> {
    let query = link
        .split_once('?')
        .map(|(_, q)| q)
        .ok_or("that is not an invite link (no query string)")?;
    let param = |key: &str| -> Option<String> {
        query.split('&').find_map(|pair| {
            let (k, v) = pair.split_once('=')?;
            (k == key).then(|| v.trim().to_string())
        })
    };
    let group = param("g").ok_or("invite link has no group (g=)")?;
    let gid_ok = group.len() == 64 && group.chars().all(|c| c.is_ascii_hexdigit());
    if !gid_ok {
        return Err(format!(
            "invite group id must be 64 hex chars, got {:?}",
            group
        ));
    }
    let token = param("t")
        .filter(|t| !t.is_empty())
        .ok_or("invite link has no token (t=)")?;
    let name = param("n")
        .and_then(|h| hex::decode(h).ok())
        .and_then(|b| String::from_utf8(b).ok())
        .unwrap_or_default();
    Ok(Invite {
        group: group.to_ascii_lowercase(),
        token_hex: hex::encode(token.as_bytes()),
        name,
    })
}

/// Which group `send` targets.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GroupSel {
    /// The only group this member is in (fails if it is in none, or in more than one).
    Auto,
    /// An explicit 64-hex group id.
    Id(String),
}

/// One `comms-send` subcommand.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Command {
    Whoami,
    Status,
    JoinPending,
    Join { group: String },
    Redeem { link: String },
    Send { group: GroupSel, text: String },
}

/// Where the daemon is, from flags (preferred) or the daemon's own env names.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Opts {
    pub socket: Option<String>,
    pub bearer_file: Option<String>,
}

pub const USAGE: &str = "usage: comms-send [--socket PATH] [--bearer-file PATH] <command>
commands:
  whoami                         this member's address (give it to the group owner)
  status                         address, relay link, joined groups, member yes/no
  join-pending                   join every group this member was added to by address
  join --group <hex>             join one group this member was added to
  redeem --link <invite-link>    self-admit with a citrate://invite?g=..&t=.. link
  send [--group <hex>|auto] (--text <msg> | --stdin)
env: CITRATE_MEMBER_SOCKET, CITRATE_MEMBER_BEARER_FILE (same as the daemon)";

/// Parse argv (without the program name). `stdin_text` supplies the body for `send --stdin`.
pub fn parse_args(
    args: &[String],
    stdin_text: impl FnOnce() -> Result<String, String>,
) -> Result<(Opts, Command), String> {
    let mut opts = Opts::default();
    let mut rest: Vec<&str> = Vec::new();
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--socket" | "--bearer-file" => {
                let v = args
                    .get(i + 1)
                    .ok_or_else(|| format!("{} needs a value", args[i]))?
                    .clone();
                if args[i] == "--socket" {
                    opts.socket = Some(v);
                } else {
                    opts.bearer_file = Some(v);
                }
                i += 2;
            }
            other => {
                rest.push(other);
                i += 1;
            }
        }
    }
    let (cmd, flags) = rest.split_first().ok_or("missing command")?;
    let flag = |name: &str| -> Option<String> {
        flags
            .iter()
            .position(|f| *f == name)
            .and_then(|p| flags.get(p + 1).map(|v| v.to_string()))
    };
    let has = |name: &str| flags.contains(&name);
    let command = match *cmd {
        "whoami" => Command::Whoami,
        "status" => Command::Status,
        "join-pending" => Command::JoinPending,
        "join" => Command::Join {
            group: flag("--group").ok_or("join needs --group <hex>")?,
        },
        "redeem" => Command::Redeem {
            link: flag("--link").ok_or("redeem needs --link <invite-link>")?,
        },
        "send" => {
            let group = match flag("--group").as_deref() {
                None | Some("auto") => GroupSel::Auto,
                Some(g) => GroupSel::Id(g.to_ascii_lowercase()),
            };
            let text = match (flag("--text"), has("--stdin")) {
                (Some(t), false) => t,
                (None, true) => stdin_text()?,
                (Some(_), true) => return Err("pass --text or --stdin, not both".into()),
                (None, false) => return Err("send needs --text <msg> or --stdin".into()),
            };
            if text.trim().is_empty() {
                return Err("refusing to send an empty message".into());
            }
            if text.len() > MAX_TEXT_BYTES {
                return Err(format!(
                    "message is {} bytes; the limit is {MAX_TEXT_BYTES}",
                    text.len()
                ));
            }
            Command::Send { group, text }
        }
        other => return Err(format!("unknown command {other:?}")),
    };
    Ok((opts, command))
}

/// What a subcommand produced: an exit code and the JSON printed on stdout.
#[derive(Debug, Clone, PartialEq)]
pub struct Outcome {
    pub code: i32,
    pub json: Value,
}

fn fail(code: i32, msg: impl Into<String>) -> Outcome {
    Outcome {
        code,
        json: json!({"ok": false, "error": msg.into()}),
    }
}

fn client_fail(e: ClientError) -> Outcome {
    let code = match e {
        ClientError::Connect(..) | ClientError::Unauthorized => EXIT_DAEMON,
        _ => EXIT_ERROR,
    };
    fail(code, e.to_string())
}

fn list_groups(c: &mut IpcClient) -> Result<Vec<GroupView>, Outcome> {
    match c.call(&json!({"op": "listGroups"})) {
        Ok(Response::Groups { groups }) => Ok(groups),
        Ok(Response::Error { message }) => Err(fail(EXIT_ERROR, message)),
        Ok(other) => Err(fail(EXIT_ERROR, format!("unexpected: {other:?}"))),
        Err(e) => Err(client_fail(e)),
    }
}

fn relay_up(c: &mut IpcClient) -> Result<bool, Outcome> {
    match c.call(&json!({"op": "relayStatus"})) {
        Ok(Response::RelayStatus { connected }) => Ok(connected),
        Ok(other) => Err(fail(EXIT_ERROR, format!("unexpected: {other:?}"))),
        Err(e) => Err(client_fail(e)),
    }
}

fn whoami(c: &mut IpcClient) -> Result<String, Outcome> {
    match c.call(&json!({"op": "whoami"})) {
        Ok(Response::Whoami { address }) => Ok(address),
        Ok(other) => Err(fail(EXIT_ERROR, format!("unexpected: {other:?}"))),
        Err(e) => Err(client_fail(e)),
    }
}

fn ok_or_fail(r: Result<Response, ClientError>, done: Value) -> Outcome {
    match r {
        Ok(Response::Ok) => Outcome {
            code: EXIT_OK,
            json: done,
        },
        Ok(Response::Error { message }) => fail(EXIT_ERROR, message),
        Ok(other) => fail(EXIT_ERROR, format!("unexpected: {other:?}")),
        Err(e) => client_fail(e),
    }
}

/// Run one subcommand against a connected daemon.
pub fn run(c: &mut IpcClient, cmd: Command) -> Outcome {
    match run_inner(c, cmd) {
        Ok(o) | Err(o) => o,
    }
}

fn run_inner(c: &mut IpcClient, cmd: Command) -> Result<Outcome, Outcome> {
    Ok(match cmd {
        Command::Whoami => Outcome {
            code: EXIT_OK,
            json: json!({"ok": true, "address": whoami(c)?}),
        },
        Command::Status => {
            let address = whoami(c)?;
            let relay = relay_up(c)?;
            let groups = list_groups(c)?;
            Outcome {
                code: EXIT_OK,
                json: json!({
                    "ok": true,
                    "address": address,
                    "relayConnected": relay,
                    "member": !groups.is_empty(),
                    "groups": groups,
                }),
            }
        }
        Command::JoinPending => {
            if !relay_up(c)? {
                return Err(fail(EXIT_RELAY_DOWN, "relay link is down"));
            }
            match c.call(&json!({"op": "joinPending"})) {
                Ok(Response::Joined { groups }) => Outcome {
                    code: EXIT_OK,
                    json: json!({"ok": true, "joined": groups}),
                },
                Ok(Response::Error { message }) => fail(EXIT_ERROR, message),
                Ok(other) => fail(EXIT_ERROR, format!("unexpected: {other:?}")),
                Err(e) => client_fail(e),
            }
        }
        Command::Join { group } => ok_or_fail(
            c.call(&json!({"op": "joinGroup", "group": group})),
            json!({"ok": true, "joined": [group]}),
        ),
        Command::Redeem { link } => {
            let inv = parse_invite_link(&link).map_err(|m| fail(EXIT_USAGE, m))?;
            let name = if inv.name.is_empty() {
                "Invited group".to_string()
            } else {
                inv.name.clone()
            };
            ok_or_fail(
                c.call(&json!({
                    "op": "redeemInvite",
                    "group": inv.group,
                    "token": inv.token_hex,
                    "name": name,
                })),
                json!({"ok": true, "joined": [inv.group]}),
            )
        }
        Command::Send { group, text } => {
            if !relay_up(c)? {
                return Err(fail(EXIT_RELAY_DOWN, "relay link is down"));
            }
            let groups = list_groups(c)?;
            let gid = match group {
                GroupSel::Id(g) => {
                    if !groups.iter().any(|v| v.id == g) {
                        return Err(fail(EXIT_NOT_MEMBER, format!("not a member of group {g}")));
                    }
                    g
                }
                GroupSel::Auto => match groups.as_slice() {
                    [only] => only.id.clone(),
                    [] => return Err(fail(EXIT_NOT_MEMBER, "not a member of any group yet")),
                    _ => {
                        return Err(fail(
                            EXIT_NOT_MEMBER,
                            "member of several groups; pass --group <hex>",
                        ))
                    }
                },
            };
            // Merge pending membership Commits first, so the message is sent at the group's
            // CURRENT epoch and reaches members who joined since our last send. A poll failure is
            // reported but does not block the alert.
            let (drained, poll_error) = match c.call(&json!({"op": "poll", "group": gid})) {
                Ok(Response::Messages { messages }) => (messages.len(), Value::Null),
                Ok(Response::Error { message }) => (0, Value::String(message)),
                Ok(other) => (0, Value::String(format!("unexpected: {other:?}"))),
                Err(e) => return Err(client_fail(e)),
            };
            ok_or_fail(
                c.call(&json!({"op": "send", "group": gid, "text": text})),
                json!({"ok": true, "group": gid, "drained": drained, "pollError": poll_error}),
            )
        }
    })
}

#[cfg(test)]
mod client_tests {
    include!("client_tests.rs");
}
