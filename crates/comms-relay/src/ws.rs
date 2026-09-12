//! `ws` — the WebSocket transport for the server-blind relay (COMMS-S1 WP-1.6).
//!
//! [`RelayServer`] wraps a [`DeliveryService`] behind a `tokio-tungstenite` socket and
//! pushes delivered envelopes to connected recipients. The wire carries CBOR-framed
//! [`ClientFrame`]/[`ServerFrame`] messages; the SIWE handshake runs over the socket on
//! connect. Everything crossing the wire is opaque MLS ciphertext + routing metadata —
//! the relay still reads nothing.
//!
//! The matching connector, [`RelayClient`], and the frames themselves now live in
//! `comms-wire` and are re-exported below: a program that only talks to a relay should
//! not have to link one.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use comms_proto::{canonical, EnvelopeKind, GroupId, WalletAddress};
use futures_util::{SinkExt, StreamExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{mpsc, Mutex};
use tokio::task::JoinHandle;
use tokio_tungstenite::tungstenite::protocol::WebSocketConfig;
use tokio_tungstenite::tungstenite::Message;

// ─────────────────────── CM2-B-B009: resource bounds ───────────────────────
// The relay is the product's single router + total-order authority (R10); an
// unauthenticated peer must not be able to grow its memory without bound.
/// Largest inbound WebSocket message accepted (tungstenite's default is 64 MiB — far
/// larger than any legitimate envelope; an unauthenticated peer could send it on repeat).
const MAX_WS_MESSAGE_SIZE: usize = 2 * 1024 * 1024; // 2 MiB
/// Largest single WebSocket frame accepted.
const MAX_WS_FRAME_SIZE: usize = 1024 * 1024; // 1 MiB
/// Challenge nonces are issued pre-authentication (they bootstrap SIWE) and inserted
/// into the issuer's nonce store; cap how many one connection may request so an
/// unauthenticated peer cannot inflate that store by looping `Challenge`.
const MAX_CHALLENGES_PER_CONN: u32 = 32;
/// Ceiling on concurrent connections, so the count of live pre-auth connections (and
/// thus the total pre-auth nonce footprint) is bounded regardless of the peer.
const MAX_CONNECTIONS: usize = 4096;

use crate::{DeliveryService, OffboardRequest};

/// Wall-clock millis (the relay daemon is a real process, unlike the deterministic tests).
fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

// ─────────────────────── the client half lives in comms-wire ───────────────────────
//
// `ClientFrame`, `ServerFrame`, `NotifyPush`, `RelayClient` and `WsError` were MOVED
// verbatim to the `comms-wire` crate, so a program can talk to a relay without
// linking the relay itself (RocksDB + axum + the OS keyring). They are re-exported
// here unchanged, so every existing `comms_relay::ws::…` path — including this
// crate's own tests — resolves to exactly the same types.
pub use comms_wire::client::{NotifyPush, RelayClient, WsError};
pub use comms_wire::frames::{ClientFrame, ServerFrame};

// ─────────────────────────── server ───────────────────────────

type Registry = Arc<Mutex<HashMap<WalletAddress, mpsc::UnboundedSender<ServerFrame>>>>;

/// A server-blind relay served over WebSocket.
pub struct RelayServer {
    service: Arc<Mutex<DeliveryService>>,
    registry: Registry,
    /// When set (via the admin surface), the relay rejects new mutating operations
    /// (submit/onboard/offboard/register/publish) but keeps serving reads.
    paused: Arc<AtomicBool>,
    /// CM2-B-B009: live connection count, capped at [`MAX_CONNECTIONS`].
    conns: Arc<AtomicUsize>,
}

impl RelayServer {
    pub fn new(service: DeliveryService) -> Arc<Self> {
        Arc::new(Self {
            service: Arc::new(Mutex::new(service)),
            registry: Arc::new(Mutex::new(HashMap::new())),
            paused: Arc::new(AtomicBool::new(false)),
            conns: Arc::new(AtomicUsize::new(0)),
        })
    }

    /// Whether the relay is currently paused (rejecting mutations).
    pub fn is_paused(&self) -> bool {
        self.paused.load(Ordering::Relaxed)
    }

    /// Pause/resume new mutating operations (driven by the admin surface).
    pub fn set_paused(&self, paused: bool) {
        self.paused.store(paused, Ordering::Relaxed);
    }

    /// Number of currently-connected, authenticated wallets.
    pub async fn connected(&self) -> usize {
        self.registry.lock().await.len()
    }

    /// The relay's logical domain (bound in the SIWE handshake).
    pub async fn domain(&self) -> String {
        self.service.lock().await.domain().to_string()
    }

    /// `(group_count, audit_record_count)` — for the admin health snapshot.
    pub async fn snapshot(&self) -> (usize, usize) {
        let svc = self.service.lock().await;
        (svc.group_count(), svc.audit().len())
    }

    /// Bind and start accepting connections. Returns the bound address (use port 0 to
    /// let the OS choose) and the accept-loop task handle.
    pub async fn bind(
        self: Arc<Self>,
        addr: &str,
    ) -> std::io::Result<(SocketAddr, JoinHandle<()>)> {
        let listener = TcpListener::bind(addr).await?;
        let local = listener.local_addr()?;
        let handle = tokio::spawn(async move {
            while let Ok((stream, _peer)) = listener.accept().await {
                // CM2-B-B009: bound concurrent connections. Over the cap we drop the
                // socket immediately rather than spawn an unbounded task/nonce footprint.
                if self.conns.load(Ordering::Relaxed) >= MAX_CONNECTIONS {
                    drop(stream);
                    continue;
                }
                self.conns.fetch_add(1, Ordering::Relaxed);
                let server = self.clone();
                tokio::spawn(async move {
                    let _ = server.clone().handle_conn(stream).await;
                    server.conns.fetch_sub(1, Ordering::Relaxed);
                });
            }
        });
        Ok((local, handle))
    }

    async fn handle_conn(self: Arc<Self>, stream: TcpStream) -> Result<(), WsError> {
        // CM2-B-B009: cap inbound message/frame size (tungstenite defaults to 64 MiB).
        let config = WebSocketConfig {
            max_message_size: Some(MAX_WS_MESSAGE_SIZE),
            max_frame_size: Some(MAX_WS_FRAME_SIZE),
            ..Default::default()
        };
        let ws = tokio_tungstenite::accept_async_with_config(stream, Some(config))
            .await
            .map_err(|e| WsError::Ws(e.to_string()))?;
        let (mut write, mut read) = ws.split();
        let (out_tx, mut out_rx) = mpsc::unbounded_channel::<ServerFrame>();

        // Writer task: serialize outbound frames to the socket.
        let writer = tokio::spawn(async move {
            while let Some(frame) = out_rx.recv().await {
                if let Ok(bytes) = canonical::to_vec(&frame) {
                    if write.send(Message::Binary(bytes)).await.is_err() {
                        break;
                    }
                }
            }
        });

        // Issue the SIWE challenge immediately.
        let nonce = {
            let mut svc = self.service.lock().await;
            svc.issue_challenge(now_ms())
        };
        let _ = out_tx.send(ServerFrame::Challenge { nonce });

        let mut authed: Option<WalletAddress> = None;
        // CM2-B-B009: the auto-issued challenge above counts as the first.
        let mut challenge_count: u32 = 1;
        while let Some(msg) = read.next().await {
            let bytes = match msg {
                Ok(Message::Binary(b)) => b,
                Ok(Message::Close(_)) | Err(_) => break,
                Ok(_) => continue,
            };
            match canonical::from_slice::<ClientFrame>(bytes.as_ref()) {
                Ok(frame) => {
                    // CM2-B-B009: rate-cap pre-auth challenge requests per connection so a
                    // peer cannot inflate the nonce store by looping `Challenge`.
                    if matches!(frame, ClientFrame::Challenge) {
                        challenge_count += 1;
                        if challenge_count > MAX_CHALLENGES_PER_CONN {
                            let _ = out_tx.send(ServerFrame::Error {
                                message: "too many challenge requests".into(),
                            });
                            continue;
                        }
                    }
                    self.dispatch(frame, &out_tx, &mut authed).await
                }
                Err(_) => {
                    let _ = out_tx.send(ServerFrame::Error {
                        message: "malformed frame".into(),
                    });
                }
            }
        }

        if let Some(w) = authed {
            self.registry.lock().await.remove(&w);
            // CM2-B-A011 / B019: end the authenticated session on disconnect so it does
            // not persist for the process lifetime (no revocation + unbounded growth).
            self.service.lock().await.end_session(&w);
        }
        writer.abort();
        Ok(())
    }

    async fn dispatch(
        &self,
        frame: ClientFrame,
        out_tx: &mpsc::UnboundedSender<ServerFrame>,
        authed: &mut Option<WalletAddress>,
    ) {
        let now = now_ms();
        // Pause gate: while paused, reject new mutating operations (reads still work).
        let mutating = matches!(
            frame,
            ClientFrame::PublishKeyPackage(_)
                | ClientFrame::TakeKeyPackage { .. }
                | ClientFrame::RegisterGroup { .. }
                | ClientFrame::Onboard { .. }
                | ClientFrame::Submit(_)
                | ClientFrame::SubmitClaim(_)
                | ClientFrame::Offboard { .. }
        );
        if mutating && self.is_paused() {
            return send_err(out_tx, "relay is paused");
        }
        match frame {
            ClientFrame::Challenge => {
                let nonce = { self.service.lock().await.issue_challenge(now) };
                let _ = out_tx.send(ServerFrame::Challenge { nonce });
            }
            ClientFrame::Authenticate { message, signature } => {
                let sig: [u8; 65] = match signature.as_slice().try_into() {
                    Ok(s) => s,
                    Err(_) => return send_err(out_tx, "signature must be 65 bytes"),
                };
                let result = {
                    let mut svc = self.service.lock().await;
                    svc.authenticate(&message, &sig, now)
                };
                match result {
                    Ok(addr) => {
                        self.registry.lock().await.insert(addr, out_tx.clone());
                        *authed = Some(addr);
                        let _ = out_tx.send(ServerFrame::Authenticated { address: addr });
                    }
                    Err(e) => send_err(out_tx, &e.to_string()),
                }
            }
            ClientFrame::PublishKeyPackage(pubn) => {
                // FWA-C11-01 (sweep): bind the publication's `wallet` to THIS
                // connection's authenticated principal. The wallet-binding attestation
                // already cryptographically proves control of `pubn.wallet`, but we also
                // refuse a session publishing under any identity other than its own — no
                // WS handler may write a client-named identity that differs from `authed`.
                let Some(addr) = *authed else {
                    return send_err(out_tx, "not authenticated");
                };
                if pubn.wallet != addr {
                    return send_err(
                        out_tx,
                        "key package wallet does not match the authenticated session",
                    );
                }
                let r = { self.service.lock().await.publish_key_package(pubn, now) };
                match r {
                    Ok(_) => ack(out_tx, None),
                    Err(e) => send_err(out_tx, &e.to_string()),
                }
            }
            ClientFrame::TakeKeyPackage { wallet } => {
                // CM2-B-A004: consuming a wallet's one-time KeyPackage is destructive
                // (it pops the directory and persists the result). It MUST require an
                // authenticated session — otherwise any unauthenticated network peer
                // who knows a target's (public) address drains every KeyPackage the
                // victim publishes, so they can never be invited to a channel.
                let Some(_addr) = *authed else {
                    return send_err(out_tx, "not authenticated");
                };
                let kp = { self.service.lock().await.take_key_package(&wallet) };
                let _ = out_tx.send(ServerFrame::KeyPackage(kp));
            }
            ClientFrame::SubmitClaim(sub) => {
                let Some(addr) = *authed else {
                    return send_err(out_tx, "not authenticated");
                };
                let r = { self.service.lock().await.submit_claim(&addr, sub) };
                match r {
                    Ok(_) => ack(out_tx, None),
                    Err(e) => send_err(out_tx, &e.to_string()),
                }
            }
            ClientFrame::PollClaims { token_hash } => {
                let Some(addr) = *authed else {
                    return send_err(out_tx, "not authenticated");
                };
                let r = { self.service.lock().await.poll_claims(&addr, &token_hash) };
                match r {
                    Ok(claims) => {
                        let _ = out_tx.send(ServerFrame::Claims(claims));
                    }
                    Err(e) => send_err(out_tx, &e.to_string()),
                }
            }
            ClientFrame::RegisterGroup { group_id } => {
                let Some(addr) = *authed else {
                    return send_err(out_tx, "not authenticated");
                };
                let r = {
                    self.service
                        .lock()
                        .await
                        .register_group(group_id, addr, now)
                };
                match r {
                    Ok(_) => ack(out_tx, None),
                    Err(e) => send_err(out_tx, &e.to_string()),
                }
            }
            ClientFrame::Onboard {
                group_id,
                joiner,
                admin_assertion,
                welcome,
                ratchet_tree,
            } => {
                let Some(addr) = *authed else {
                    return send_err(out_tx, "not authenticated");
                };
                let r = {
                    self.service.lock().await.onboard(
                        group_id,
                        addr,
                        admin_assertion.as_ref(),
                        joiner,
                        welcome,
                        ratchet_tree,
                        now,
                    )
                };
                match r {
                    Ok(_) => {
                        ack(out_tx, None);
                        self.deliver_pending().await;
                    }
                    Err(e) => send_err(out_tx, &e.to_string()),
                }
            }
            ClientFrame::Submit(env) => {
                // FWA-C11-01: bind the envelope's sender to THIS connection's
                // authenticated principal — never trust the frame's sender field.
                let Some(addr) = *authed else {
                    return send_err(out_tx, "not authenticated");
                };
                // Routing metadata for the advisory Notify fan-out (E-5 WP-3) — captured
                // before the envelope moves into the service. Metadata only.
                let (group_id, kind, recipients) = (env.group_id, env.kind, env.recipients.clone());
                let r = { self.service.lock().await.submit_as(addr, env, now) };
                match r {
                    Ok(seq) => {
                        ack(out_tx, Some(seq));
                        self.deliver_pending().await;
                        self.notify_recipients(group_id, kind, seq, &recipients, addr)
                            .await;
                    }
                    Err(e) => send_err(out_tx, &e.to_string()),
                }
            }
            ClientFrame::RatchetTree { group_id } => {
                // CM2-B-A004: the public ratchet tree and the roster are group state;
                // serving them to an unauthenticated peer lets anyone holding a group
                // id — including a *removed* member, who keeps it forever — keep
                // reading membership after eviction. Gate on an authenticated session.
                let Some(_addr) = *authed else {
                    return send_err(out_tx, "not authenticated");
                };
                let rt = {
                    self.service
                        .lock()
                        .await
                        .ratchet_tree(&group_id)
                        .map(|s| s.to_vec())
                };
                let _ = out_tx.send(ServerFrame::RatchetTree(rt));
            }
            ClientFrame::GroupMembers { group_id } => {
                // CM2-B-A004: the roster is group state, not public.
                let Some(addr) = *authed else {
                    return send_err(out_tx, "not authenticated");
                };
                // CIT-COMMS-003: bind the roster read to MEMBERSHIP, not merely to any
                // authenticated session. The wallet set is the group's social graph;
                // only a member should read it. (RatchetTree stays session-gated because
                // a joiner needs it to process its Welcome before it is a member.)
                let members = self.service.lock().await.group_members(&group_id);
                match &members {
                    Some(roster) if roster.contains(&addr) => {
                        let _ = out_tx.send(ServerFrame::Members(members));
                    }
                    _ => send_err(out_tx, "not a member of this group"),
                }
            }
            ClientFrame::Offboard {
                group_id,
                removed,
                admin_assertion,
                remove_commit,
                ratchet_tree,
            } => {
                let Some(addr) = *authed else {
                    return send_err(out_tx, "not authenticated");
                };
                let r = {
                    self.service.lock().await.offboard(
                        OffboardRequest {
                            group_id,
                            admin: addr,
                            admin_assertion: admin_assertion.as_ref(),
                            removed,
                            remove_commit,
                            ratchet_tree,
                        },
                        now,
                    )
                };
                match r {
                    Ok(seq) => {
                        ack(out_tx, Some(seq));
                        self.deliver_pending().await;
                    }
                    Err(e) => send_err(out_tx, &e.to_string()),
                }
            }
        }
    }

    /// Drain the mailboxes of all connected wallets and push their envelopes. Locks the
    /// registry and the service one at a time (never nested) to avoid deadlock.
    async fn deliver_pending(&self) {
        let targets: Vec<(WalletAddress, mpsc::UnboundedSender<ServerFrame>)> = {
            self.registry
                .lock()
                .await
                .iter()
                .map(|(w, s)| (*w, s.clone()))
                .collect()
        };
        let mut svc = self.service.lock().await;
        for (wallet, tx) in targets {
            for env in svc.fetch(&wallet) {
                let _ = tx.send(ServerFrame::Deliver(env));
            }
        }
    }

    /// E-5 WP-3: push an advisory [`ServerFrame::Notify`] to each *connected* recipient
    /// of an accepted Submit, excluding the sender (whose response channel is mid
    /// request/response and who needs no ping about their own message). Best-effort:
    /// disconnected recipients simply miss the ping — the envelope itself still waits
    /// in their mailbox, so nothing is lost but latency. Never ordering-relevant.
    async fn notify_recipients(
        &self,
        group_id: GroupId,
        kind: EnvelopeKind,
        group_seq: u64,
        recipients: &[WalletAddress],
        sender: WalletAddress,
    ) {
        let registry = self.registry.lock().await;
        for r in recipients {
            if *r == sender {
                continue;
            }
            if let Some(tx) = registry.get(r) {
                let _ = tx.send(ServerFrame::Notify {
                    group_id,
                    kind,
                    group_seq,
                });
            }
        }
    }
}

fn ack(tx: &mpsc::UnboundedSender<ServerFrame>, seq: Option<u64>) {
    let _ = tx.send(ServerFrame::Ack { seq });
}
fn send_err(tx: &mpsc::UnboundedSender<ServerFrame>, message: &str) {
    let _ = tx.send(ServerFrame::Error {
        message: message.to_string(),
    });
}

// ─────────────────────────── client ───────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    /// WP-4.6: `connect` fails closed on a remote `ws://` endpoint — and does so BEFORE
    /// dialing, so it resolves instantly even though nothing is listening. (The
    /// `connect_insecure` opt-in bypassing the guard is covered by the `endpoint` policy
    /// tests, which avoid an actual hang-prone dial.)
    #[tokio::test]
    async fn connect_refuses_remote_plaintext_before_dialing() {
        let refused = RelayClient::connect("ws://relay.example.com:8787")
            .await
            .err();
        assert!(
            matches!(refused, Some(WsError::InsecureEndpoint(_))),
            "remote ws:// must be refused"
        );
        // wss:// is permitted by the guard (then fails on the dial, not the policy).
        let dial = RelayClient::connect("wss://127.0.0.1:1").await.err();
        assert!(
            !matches!(dial, Some(WsError::InsecureEndpoint(_))),
            "wss must pass the guard"
        );
    }

    /// FWA-C11-01 **TRIPWIRE (Class-A)** — static guard over this file's own source.
    ///
    /// Every WS dispatch arm that hands a client frame to the delivery service MUST bind
    /// the principal to the connection's authenticated `addr` (`submit_as(addr, …)` /
    /// `onboard(group, addr, …)`), NEVER the trusted private `submit(…)`/un-bound path.
    /// This test fails if a future edit reintroduces an un-bound `service…submit(` or
    /// forwards `Submit`/`PublishKeyPackage` without the session-binding check — so the
    /// FWA-C11-01 sender-spoofing fix cannot silently regress.
    #[test]
    fn tripwire_ws_dispatch_binds_every_client_identity_to_session() {
        let src = include_str!("ws.rs");
        // Isolate the dispatch function body (where frames are handled).
        let dispatch = src
            .split("async fn dispatch(")
            .nth(1)
            .and_then(|s| s.split("\n    async fn deliver_pending").next())
            .expect("dispatch fn present");

        // Class-A: the un-bound private `submit` must NEVER be reached from the WS layer.
        assert!(
            !dispatch.contains(".submit("),
            "TRIPWIRE: WS dispatch reached the un-bound `submit(` — client `sender` must be bound \
             via `submit_as(addr, …)` (FWA-C11-01 regression)"
        );
        // The Submit arm must route through the sender-binding entry point.
        assert!(
            dispatch.contains("submit_as(addr, env, now)"),
            "TRIPWIRE: the Submit arm must call `submit_as(addr, env, now)` to bind the sender"
        );
        // The KeyPackage publication must be checked against the authenticated session.
        assert!(
            dispatch.contains("pubn.wallet != addr"),
            "TRIPWIRE: PublishKeyPackage must reject a wallet != the authenticated session"
        );

        // CM2-B-A004 **TRIPWIRE** — every dispatch arm that touches directory/group
        // state MUST sit behind the `*authed` session guard. Challenge and
        // Authenticate are the ONLY arms allowed to run unauthenticated (they
        // establish the session). This fails if a future edit reintroduces an
        // unauthenticated TakeKeyPackage / RatchetTree / GroupMembers (or any other
        // stateful frame).
        for header in [
            "ClientFrame::PublishKeyPackage",
            "ClientFrame::TakeKeyPackage",
            "ClientFrame::SubmitClaim",
            "ClientFrame::PollClaims",
            "ClientFrame::RegisterGroup",
            "ClientFrame::Onboard",
            "ClientFrame::Submit(",
            "ClientFrame::RatchetTree",
            "ClientFrame::GroupMembers",
            "ClientFrame::Offboard",
        ] {
            // Use the LAST occurrence (the match arm, never the earlier `matches!`
            // pause-list), then bound the slice to this arm's own body — arms are
            // separated by a 12-space-indented `ClientFrame::` on its own line.
            let start = dispatch
                .rfind(header)
                .unwrap_or_else(|| panic!("dispatch arm {header} present"));
            let body = dispatch[start..]
                .split("\n            ClientFrame::")
                .next()
                .unwrap_or("");
            assert!(
                body.contains("*authed"),
                "TRIPWIRE (CM2-B-A004): dispatch arm {header} must be behind the `*authed` \
                 session guard — unauthenticated access to group/directory state"
            );
        }
    }

    /// E-5 WP-3 **schema test (server-blind invariant)** — the advisory Notify frame
    /// carries routing metadata ONLY. We introspect the actual wire encoding (canonical
    /// CBOR → Value) and assert the field set is EXACTLY `{group_id, kind, group_seq}`:
    /// no ciphertext, no body, no content — and no future field can sneak in without
    /// consciously editing this exact-set assertion.
    #[test]
    fn notify_frame_is_metadata_only() {
        let frame = ServerFrame::Notify {
            group_id: GroupId([7; 32]),
            kind: comms_proto::EnvelopeKind::Application,
            group_seq: 42,
        };
        let bytes = canonical::to_vec(&frame).unwrap();
        let value: ciborium::Value = ciborium::from_reader(bytes.as_slice()).unwrap();

        // serde externally-tagged enum → { "Notify": { <fields> } }.
        let outer = value.as_map().expect("enum encodes as a map");
        assert_eq!(outer.len(), 1);
        let (tag, inner) = &outer[0];
        assert_eq!(tag.as_text(), Some("Notify"));
        let fields: Vec<&str> = inner
            .as_map()
            .expect("variant fields encode as a map")
            .iter()
            .map(|(k, _)| k.as_text().unwrap())
            .collect();

        let mut sorted = fields.clone();
        sorted.sort_unstable();
        assert_eq!(
            sorted,
            vec!["group_id", "group_seq", "kind"],
            "Notify must carry EXACTLY group_id/kind/group_seq"
        );
        for forbidden in [
            "ciphertext",
            "body",
            "content",
            "plaintext",
            "payload",
            "text",
            "envelope",
        ] {
            assert!(
                !fields.contains(&forbidden),
                "Notify must never carry `{forbidden}` (server-blind invariant)"
            );
        }
    }
}
