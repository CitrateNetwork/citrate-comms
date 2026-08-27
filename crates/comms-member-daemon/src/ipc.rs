//! The daemon's loopback JSON-per-line IPC — the surface the lean client (citrate-core Commons)
//! speaks. Requests/responses are line-delimited JSON; `handle_request` maps one request onto the
//! [`MemberDaemon`] and is pure over it (socket-free), so it is tested directly.
//!
//! Ids cross the wire as hex (group id = 32-byte, member = 20-byte address); the dispatcher parses
//! them, so a malformed id is an honest `Error` response, never a panic.

use serde::{Deserialize, Serialize};

use comms_proto::{GroupId, WalletAddress};

use crate::MemberDaemon;

/// A request from the client. `op` tags the variant.
#[derive(Debug, Clone, Deserialize)]
#[serde(tag = "op", rename_all = "camelCase")]
pub enum Request {
    CreateGroup { name: String },
    ListGroups,
    /// Add a member (who must have published a key package to the relay) to a group.
    AddMember { group: String, member: String },
    Send { group: String, text: String },
    /// Drain + decrypt the owner's mailbox for a group.
    Poll { group: String },
}

/// One group in a listing.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct GroupView {
    pub id: String,
    pub name: String,
}

/// One decrypted message.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct MsgView {
    pub sender: String,
    pub body: String,
}

/// A response to the client. `type` tags the variant.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "type", rename_all = "camelCase")]
pub enum Response {
    Ok,
    GroupCreated { id: String },
    Groups { groups: Vec<GroupView> },
    /// The welcome material a REMOTE joiner needs (hex); the owner-client ignores it.
    Added {
        member: String,
        welcome: String,
        ratchet_tree: String,
    },
    Messages { messages: Vec<MsgView> },
    Error { message: String },
}

fn parse_gid(hex_str: &str) -> Result<GroupId, String> {
    let bytes = hex::decode(hex_str).map_err(|_| format!("bad group id hex: {hex_str}"))?;
    let arr: [u8; 32] = bytes
        .try_into()
        .map_err(|_| format!("group id must be 32 bytes: {hex_str}"))?;
    Ok(GroupId(arr))
}

fn parse_addr(hex_str: &str) -> Result<WalletAddress, String> {
    let s = hex_str.strip_prefix("0x").unwrap_or(hex_str);
    let bytes = hex::decode(s).map_err(|_| format!("bad address hex: {hex_str}"))?;
    let arr: [u8; 20] = bytes
        .try_into()
        .map_err(|_| format!("address must be 20 bytes: {hex_str}"))?;
    Ok(WalletAddress(arr))
}

/// Map one request onto the daemon. Never panics — every failure becomes an `Error` response.
pub fn handle_request(daemon: &mut MemberDaemon, req: Request) -> Response {
    match req {
        Request::CreateGroup { name } => match daemon.create_group(name) {
            Ok(gid) => Response::GroupCreated {
                id: hex::encode(gid.0),
            },
            Err(e) => Response::Error {
                message: e.to_string(),
            },
        },
        Request::ListGroups => Response::Groups {
            groups: daemon
                .list_groups()
                .into_iter()
                .map(|(id, name)| GroupView {
                    id: hex::encode(id.0),
                    name,
                })
                .collect(),
        },
        Request::AddMember { group, member } => {
            let gid = match parse_gid(&group) {
                Ok(g) => g,
                Err(m) => return Response::Error { message: m },
            };
            let addr = match parse_addr(&member) {
                Ok(a) => a,
                Err(m) => return Response::Error { message: m },
            };
            match daemon.add_member(gid, addr) {
                Ok(add) => Response::Added {
                    member: hex::encode(add.member.0),
                    welcome: hex::encode(add.welcome),
                    ratchet_tree: hex::encode(add.ratchet_tree),
                },
                Err(e) => Response::Error {
                    message: e.to_string(),
                },
            }
        }
        Request::Send { group, text } => {
            let gid = match parse_gid(&group) {
                Ok(g) => g,
                Err(m) => return Response::Error { message: m },
            };
            match daemon.send(gid, &text) {
                Ok(()) => Response::Ok,
                Err(e) => Response::Error {
                    message: e.to_string(),
                },
            }
        }
        Request::Poll { group } => {
            let gid = match parse_gid(&group) {
                Ok(g) => g,
                Err(m) => return Response::Error { message: m },
            };
            match daemon.poll_messages(gid) {
                Ok(msgs) => Response::Messages {
                    messages: msgs
                        .into_iter()
                        .map(|m| MsgView {
                            sender: hex::encode(m.sender.0),
                            body: m.body,
                        })
                        .collect(),
                },
                Err(e) => Response::Error {
                    message: e.to_string(),
                },
            }
        }
    }
}
