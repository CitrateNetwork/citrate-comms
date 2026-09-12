//! The daemon's loopback JSON-per-line IPC — the surface the lean client (citrate-core Commons)
//! speaks. Requests/responses are line-delimited JSON; `handle_request` maps one request onto the
//! [`MemberDaemon`] and is pure over it (socket-free), so it is tested directly.
//!
//! Ids cross the wire as hex (group id = 32-byte, member = 20-byte address); the dispatcher parses
//! them, so a malformed id is an honest `Error` response, never a panic.

use serde::{Deserialize, Serialize};

use comms_proto::{GroupId, Role, RoleAssertion, WalletAddress};

use crate::MemberDaemon;

/// A request from the client. `op` tags the variant.
#[derive(Debug, Clone, Deserialize)]
#[serde(tag = "op", rename_all = "camelCase")]
pub enum Request {
    CreateGroup {
        name: String,
    },
    ListGroups,
    /// Add a member (who must have published a key package to the relay) to a group.
    AddMember {
        group: String,
        member: String,
    },
    Send {
        group: String,
        text: String,
    },
    /// Drain + decrypt the owner's mailbox for a group.
    Poll {
        group: String,
    },
    /// The (wallet, role) roster of a group.
    Roster {
        group: String,
    },
    /// CONNECT-S1 — submit a sealed claim to the server-blind claims-inbox (invitee). Both hex.
    SubmitClaim {
        token_hash: String,
        ciphertext: String,
    },
    /// CONNECT-S1 — poll the claims-inbox by invite token hash (owner). Hex.
    PollClaims {
        token_hash: String,
    },
    /// INVITE-S2 — owner mints a single-use, group-bound invite. `tokenHash` is 32-byte hex
    /// (`BLAKE3(token)`; the raw token stays with the owner/link and never reaches the relay).
    /// `expiresAt` is Unix ms.
    PublishInvite {
        group: String,
        token_hash: String,
        expires_at: u64,
    },
    /// INVITE-S2 — owner revokes an invite by its token hash (32-byte hex).
    RevokeInvite {
        token_hash: String,
    },
    /// INVITE-S2 — invitee self-admits by external commit using the RAW invite `token` (hex).
    RedeemInvite {
        group: String,
        token: String,
        name: String,
    },
    /// Apply an owner/admin-signed role grant. The signature was produced by citrate-core's
    /// SignatureCeremony; the daemon VERIFIES it (never signs — Rule 3).
    AssignRole {
        group: String,
        assertion: RoleAssertion,
    },
    /// Revoke/demote a subject's role via an owner/admin-signed assertion the daemon verifies.
    RevokeRole {
        group: String,
        assertion: RoleAssertion,
    },
    /// Remove a member (MLS remove + relay atomic offboard).
    Offboard {
        group: String,
        member: String,
    },
    /// Join a group this member was added to on a shared relay (fetch welcome/tree + MLS join).
    JoinGroup {
        group: String,
    },
    /// Flag-A — report whether the networked relay link is currently up. Cheap health query (no group
    /// state); citrate-core uses it so a mid-session relay DROP shows as "degraded", not "healthy".
    RelayStatus,
}

/// One roster entry: the member address (hex) + role string.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct RosterEntry {
    pub address: String,
    pub role: String,
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
    GroupCreated {
        id: String,
    },
    Groups {
        groups: Vec<GroupView>,
    },
    /// The welcome material a REMOTE joiner needs (hex); the owner-client ignores it.
    Added {
        member: String,
        welcome: String,
        ratchet_tree: String,
    },
    Messages {
        messages: Vec<MsgView>,
    },
    Roster {
        members: Vec<RosterEntry>,
    },
    /// CONNECT-S1 — the polled claim ciphertexts (hex; opaque). Owner decrypts with the invite key.
    Claims {
        ciphertexts: Vec<String>,
    },
    /// Flag-A — the networked relay-link state (answer to `RelayStatus`). `connected: false` = the
    /// relay is configured but the link is down, so relayed ops will fail until it reconnects.
    RelayStatus {
        connected: bool,
    },
    Error {
        message: String,
    },
}

/// The bridge role vocabulary (matches the GroupRole DTO on the client).
fn role_str(role: Role) -> &'static str {
    match role {
        Role::Owner => "owner",
        Role::Admin => "admin",
        Role::Member => "member",
        Role::Partner => "partner",
        Role::Guest => "guest",
        Role::Agent => "agent",
    }
}

fn parse_gid(hex_str: &str) -> Result<GroupId, String> {
    let bytes = hex::decode(hex_str).map_err(|_| format!("bad group id hex: {hex_str}"))?;
    let arr: [u8; 32] = bytes
        .try_into()
        .map_err(|_| format!("group id must be 32 bytes: {hex_str}"))?;
    Ok(GroupId(arr))
}

/// Parse a 32-byte token hash from hex (INVITE-S2 / CONNECT-S1 inbox key).
fn parse_token_hash(hex_str: &str) -> Result<[u8; 32], String> {
    let bytes = hex::decode(hex_str).map_err(|_| format!("bad token hash hex: {hex_str}"))?;
    bytes
        .try_into()
        .map_err(|_| format!("token hash must be 32 bytes: {hex_str}"))
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
        Request::Roster { group } => {
            let gid = match parse_gid(&group) {
                Ok(g) => g,
                Err(m) => return Response::Error { message: m },
            };
            match daemon.roster(gid) {
                Ok(rows) => Response::Roster {
                    members: rows
                        .into_iter()
                        .map(|(addr, role)| RosterEntry {
                            address: hex::encode(addr.0),
                            role: role_str(role).to_string(),
                        })
                        .collect(),
                },
                Err(e) => Response::Error {
                    message: e.to_string(),
                },
            }
        }
        Request::SubmitClaim {
            token_hash,
            ciphertext,
        } => {
            let th = match hex::decode(&token_hash)
                .ok()
                .and_then(|b| <[u8; 32]>::try_from(b).ok())
            {
                Some(t) => t,
                None => {
                    return Response::Error {
                        message: "tokenHash must be 32-byte hex".into(),
                    }
                }
            };
            let ct = match hex::decode(&ciphertext) {
                Ok(c) => c,
                Err(_) => {
                    return Response::Error {
                        message: "ciphertext must be hex".into(),
                    }
                }
            };
            match daemon.submit_claim(th, ct) {
                Ok(()) => Response::Ok,
                Err(e) => Response::Error {
                    message: e.to_string(),
                },
            }
        }
        Request::PollClaims { token_hash } => {
            let th = match hex::decode(&token_hash)
                .ok()
                .and_then(|b| <[u8; 32]>::try_from(b).ok())
            {
                Some(t) => t,
                None => {
                    return Response::Error {
                        message: "tokenHash must be 32-byte hex".into(),
                    }
                }
            };
            match daemon.poll_claims(th) {
                Ok(cts) => Response::Claims {
                    ciphertexts: cts.into_iter().map(hex::encode).collect(),
                },
                Err(e) => Response::Error {
                    message: e.to_string(),
                },
            }
        }
        Request::PublishInvite {
            group,
            token_hash,
            expires_at,
        } => {
            let gid = match parse_gid(&group) {
                Ok(g) => g,
                Err(m) => return Response::Error { message: m },
            };
            let th = match parse_token_hash(&token_hash) {
                Ok(t) => t,
                Err(m) => return Response::Error { message: m },
            };
            match daemon.publish_invite(gid, th, expires_at) {
                Ok(()) => Response::Ok,
                Err(e) => Response::Error {
                    message: e.to_string(),
                },
            }
        }
        Request::RevokeInvite { token_hash } => {
            let th = match parse_token_hash(&token_hash) {
                Ok(t) => t,
                Err(m) => return Response::Error { message: m },
            };
            match daemon.revoke_invite(th) {
                Ok(()) => Response::Ok,
                Err(e) => Response::Error {
                    message: e.to_string(),
                },
            }
        }
        Request::RedeemInvite {
            group,
            token,
            name,
        } => {
            let gid = match parse_gid(&group) {
                Ok(g) => g,
                Err(m) => return Response::Error { message: m },
            };
            let tok = match hex::decode(&token) {
                Ok(t) => t,
                Err(_) => {
                    return Response::Error {
                        message: "token must be hex".into(),
                    }
                }
            };
            match daemon.redeem_invite(gid, tok, name) {
                Ok(()) => Response::Ok,
                Err(e) => Response::Error {
                    message: e.to_string(),
                },
            }
        }
        Request::AssignRole { group, assertion } => {
            let gid = match parse_gid(&group) {
                Ok(g) => g,
                Err(m) => return Response::Error { message: m },
            };
            match daemon.assign_role(gid, &assertion) {
                Ok(()) => Response::Ok,
                Err(e) => Response::Error {
                    message: e.to_string(),
                },
            }
        }
        Request::RevokeRole { group, assertion } => {
            let gid = match parse_gid(&group) {
                Ok(g) => g,
                Err(m) => return Response::Error { message: m },
            };
            match daemon.revoke_role(gid, &assertion) {
                Ok(()) => Response::Ok,
                Err(e) => Response::Error {
                    message: e.to_string(),
                },
            }
        }
        Request::Offboard { group, member } => {
            let gid = match parse_gid(&group) {
                Ok(g) => g,
                Err(m) => return Response::Error { message: m },
            };
            let addr = match parse_addr(&member) {
                Ok(a) => a,
                Err(m) => return Response::Error { message: m },
            };
            match daemon.offboard(gid, addr) {
                Ok(()) => Response::Ok,
                Err(e) => Response::Error {
                    message: e.to_string(),
                },
            }
        }
        Request::JoinGroup { group } => {
            let gid = match parse_gid(&group) {
                Ok(g) => g,
                Err(m) => return Response::Error { message: m },
            };
            match daemon.join_group(gid, "") {
                Ok(()) => Response::Ok,
                Err(e) => Response::Error {
                    message: e.to_string(),
                },
            }
        }
        // Flag-A — a pure health query: never touches group/MLS state, never fails (a down link is a
        // valid answer, `connected: false`, not an error).
        Request::RelayStatus => Response::RelayStatus {
            connected: daemon.relay_connected(),
        },
    }
}
