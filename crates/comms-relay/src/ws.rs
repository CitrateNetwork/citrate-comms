//! `ws` — the WebSocket transport for the server-blind relay (COMMS-S1 WP-1.6).
//!
//! [`RelayServer`] wraps a [`DeliveryService`] behind a `tokio-tungstenite` socket and
//! pushes delivered envelopes to connected recipients. [`RelayClient`] is the matching
//! connector. The wire carries CBOR-framed [`ClientFrame`]/[`ServerFrame`] messages;
//! the SIWE handshake runs over the socket on connect. Everything crossing the wire is
//! opaque MLS ciphertext + routing metadata — the relay still reads nothing.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use comms_core::identity::SiweMessage;
use comms_proto::{canonical, Envelope, EnvelopeKind, GroupId, KeyPackagePublication, RoleAssertion, WalletAddress};
use futures_util::{SinkExt, StreamExt};
use serde::{Deserialize, Serialize};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{mpsc, Mutex};
use tokio::task::JoinHandle;
use tokio_tungstenite::tungstenite::Message;

use crate::{DeliveryService, OffboardRequest};

/// Wall-clock millis (the relay daemon is a real process, unlike the deterministic tests).
fn now_ms() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_millis() as u64).unwrap_or(0)
}

// ─────────────────────────── wire frames ───────────────────────────

/// A request from a client to the relay.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum ClientFrame {
    /// Request a fresh single-use nonce (e.g. for a KeyPackage binding attestation).
    Challenge,
    Authenticate { message: SiweMessage, signature: Vec<u8> },
    PublishKeyPackage(KeyPackagePublication),
    TakeKeyPackage { wallet: WalletAddress },
    RegisterGroup { group_id: GroupId },
    Onboard {
        group_id: GroupId,
        joiner: WalletAddress,
        /// `None` if the caller IS the workspace owner; otherwise an owner-signed
        /// grant whose role carries `AddMember` (FWA-C11-03).
        admin_assertion: Option<RoleAssertion>,
        welcome: Envelope,
        ratchet_tree: Vec<u8>,
    },
    Submit(Envelope),
    RatchetTree { group_id: GroupId },
    Offboard {
        group_id: GroupId,
        removed: WalletAddress,
        admin_assertion: Option<RoleAssertion>,
        remove_commit: Envelope,
        ratchet_tree: Vec<u8>,
    },
}

/// A response or server-push to a client.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum ServerFrame {
    Challenge { nonce: String },
    Authenticated { address: WalletAddress },
    KeyPackage(Option<KeyPackagePublication>),
    RatchetTree(Option<Vec<u8>>),
    Ack { seq: Option<u64> },
    Deliver(Envelope),
    /// **E-5 WP-3 — advisory notification ping.** Pushed to each *connected* recipient
    /// (never the sender) when a Submit is accepted, so a native client can raise an OS
    /// notification without waiting to decrypt the envelope. Carries routing-level
    /// metadata ONLY — group id, envelope kind, and the relay-assigned `group_seq`.
    /// **No ciphertext, no body, no content — ever** (server-blind invariant; schema
    /// test `notify_frame_is_metadata_only` below).
    ///
    /// Notify is **advisory and never ordering-relevant**: the per-group total order is
    /// carried exclusively by `group_seq` on delivered [`Envelope`]s (formalized in
    /// `formal/RelayCommitOrder.tla` — that spec is unchanged by this frame). A client
    /// MUST NOT sequence, apply, or reject anything based on a Notify; dropping every
    /// Notify frame loses no correctness, only latency.
    Notify { group_id: GroupId, kind: EnvelopeKind, group_seq: u64 },
    Error { message: String },
}

// ─────────────────────────── server ───────────────────────────

type Registry = Arc<Mutex<HashMap<WalletAddress, mpsc::UnboundedSender<ServerFrame>>>>;

/// A server-blind relay served over WebSocket.
pub struct RelayServer {
    service: Arc<Mutex<DeliveryService>>,
    registry: Registry,
    /// When set (via the admin surface), the relay rejects new mutating operations
    /// (submit/onboard/offboard/register/publish) but keeps serving reads.
    paused: Arc<AtomicBool>,
}

impl RelayServer {
    pub fn new(service: DeliveryService) -> Arc<Self> {
        Arc::new(Self {
            service: Arc::new(Mutex::new(service)),
            registry: Arc::new(Mutex::new(HashMap::new())),
            paused: Arc::new(AtomicBool::new(false)),
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
    pub async fn bind(self: Arc<Self>, addr: &str) -> std::io::Result<(SocketAddr, JoinHandle<()>)> {
        let listener = TcpListener::bind(addr).await?;
        let local = listener.local_addr()?;
        let handle = tokio::spawn(async move {
            while let Ok((stream, _peer)) = listener.accept().await {
                let server = self.clone();
                tokio::spawn(async move {
                    let _ = server.handle_conn(stream).await;
                });
            }
        });
        Ok((local, handle))
    }

    async fn handle_conn(self: Arc<Self>, stream: TcpStream) -> Result<(), WsError> {
        let ws = tokio_tungstenite::accept_async(stream).await.map_err(|e| WsError::Ws(e.to_string()))?;
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
        while let Some(msg) = read.next().await {
            let bytes = match msg {
                Ok(Message::Binary(b)) => b,
                Ok(Message::Close(_)) | Err(_) => break,
                Ok(_) => continue,
            };
            match canonical::from_slice::<ClientFrame>(bytes.as_ref()) {
                Ok(frame) => self.dispatch(frame, &out_tx, &mut authed).await,
                Err(_) => {
                    let _ = out_tx.send(ServerFrame::Error { message: "malformed frame".into() });
                }
            }
        }

        if let Some(w) = authed {
            self.registry.lock().await.remove(&w);
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
                | ClientFrame::RegisterGroup { .. }
                | ClientFrame::Onboard { .. }
                | ClientFrame::Submit(_)
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
                let Some(addr) = *authed else { return send_err(out_tx, "not authenticated") };
                if pubn.wallet != addr {
                    return send_err(out_tx, "key package wallet does not match the authenticated session");
                }
                let r = { self.service.lock().await.publish_key_package(pubn, now) };
                match r {
                    Ok(_) => ack(out_tx, None),
                    Err(e) => send_err(out_tx, &e.to_string()),
                }
            }
            ClientFrame::TakeKeyPackage { wallet } => {
                let kp = { self.service.lock().await.take_key_package(&wallet) };
                let _ = out_tx.send(ServerFrame::KeyPackage(kp));
            }
            ClientFrame::RegisterGroup { group_id } => {
                let Some(addr) = *authed else { return send_err(out_tx, "not authenticated") };
                let r = { self.service.lock().await.register_group(group_id, addr, now) };
                match r {
                    Ok(_) => ack(out_tx, None),
                    Err(e) => send_err(out_tx, &e.to_string()),
                }
            }
            ClientFrame::Onboard { group_id, joiner, admin_assertion, welcome, ratchet_tree } => {
                let Some(addr) = *authed else { return send_err(out_tx, "not authenticated") };
                let r = {
                    self.service.lock().await.onboard(
                        group_id, addr, admin_assertion.as_ref(), joiner, welcome, ratchet_tree, now,
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
                let Some(addr) = *authed else { return send_err(out_tx, "not authenticated") };
                // Routing metadata for the advisory Notify fan-out (E-5 WP-3) — captured
                // before the envelope moves into the service. Metadata only.
                let (group_id, kind, recipients) = (env.group_id, env.kind, env.recipients.clone());
                let r = { self.service.lock().await.submit_as(addr, env, now) };
                match r {
                    Ok(seq) => {
                        ack(out_tx, Some(seq));
                        self.deliver_pending().await;
                        self.notify_recipients(group_id, kind, seq, &recipients, addr).await;
                    }
                    Err(e) => send_err(out_tx, &e.to_string()),
                }
            }
            ClientFrame::RatchetTree { group_id } => {
                let rt = { self.service.lock().await.ratchet_tree(&group_id).map(|s| s.to_vec()) };
                let _ = out_tx.send(ServerFrame::RatchetTree(rt));
            }
            ClientFrame::Offboard { group_id, removed, admin_assertion, remove_commit, ratchet_tree } => {
                let Some(addr) = *authed else { return send_err(out_tx, "not authenticated") };
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
            self.registry.lock().await.iter().map(|(w, s)| (*w, s.clone())).collect()
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
                let _ = tx.send(ServerFrame::Notify { group_id, kind, group_seq });
            }
        }
    }
}

fn ack(tx: &mpsc::UnboundedSender<ServerFrame>, seq: Option<u64>) {
    let _ = tx.send(ServerFrame::Ack { seq });
}
fn send_err(tx: &mpsc::UnboundedSender<ServerFrame>, message: &str) {
    let _ = tx.send(ServerFrame::Error { message: message.to_string() });
}

// ─────────────────────────── client ───────────────────────────

/// A server-pushed advisory notification (the client-side view of
/// [`ServerFrame::Notify`]). Metadata only; see the variant's docs.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NotifyPush {
    pub group_id: GroupId,
    pub kind: EnvelopeKind,
    pub group_seq: u64,
}

/// A connector to a [`RelayServer`]. Request methods serialize one round trip; pushed
/// envelopes arrive via [`RelayClient::next_delivered`] and advisory notification
/// pings via [`RelayClient::next_notify`] (both are routed off the request/response
/// channel, so a push can never be mistaken for an Ack).
pub struct RelayClient {
    out_tx: mpsc::UnboundedSender<ClientFrame>,
    resp_rx: Mutex<mpsc::UnboundedReceiver<ServerFrame>>,
    deliver_rx: Mutex<mpsc::UnboundedReceiver<Envelope>>,
    notify_rx: Mutex<mpsc::UnboundedReceiver<NotifyPush>>,
}

impl RelayClient {
    /// Connect, spawn the read/write tasks, and return the connector plus the relay's
    /// initial SIWE challenge nonce.
    ///
    /// **Connection hardening (WP-4.6):** refuses plaintext `ws://` to a remote host —
    /// only `wss://` (TLS) or loopback `ws://` are allowed. For a trusted private network
    /// where you knowingly want plaintext, use [`RelayClient::connect_insecure`].
    pub async fn connect(url: &str) -> Result<(Self, String), WsError> {
        Self::connect_with_policy(url, false).await
    }

    /// Like [`connect`](Self::connect) but permits plaintext `ws://` to a non-loopback
    /// host (trusted private network / LAN airgap). Use deliberately — metadata and the
    /// SIWE handshake travel in the clear.
    pub async fn connect_insecure(url: &str) -> Result<(Self, String), WsError> {
        Self::connect_with_policy(url, true).await
    }

    async fn connect_with_policy(url: &str, allow_insecure: bool) -> Result<(Self, String), WsError> {
        // Fail closed BEFORE dialing if the endpoint is insecure.
        crate::endpoint::enforce_endpoint_policy(url, allow_insecure)
            .map_err(|e| WsError::InsecureEndpoint(e.to_string()))?;
        let (ws, _resp) = tokio_tungstenite::connect_async(url).await.map_err(|e| WsError::Ws(e.to_string()))?;
        let (mut write, mut read) = ws.split();
        let (out_tx, mut out_rx) = mpsc::unbounded_channel::<ClientFrame>();
        let (resp_tx, resp_rx) = mpsc::unbounded_channel::<ServerFrame>();
        let (deliver_tx, deliver_rx) = mpsc::unbounded_channel::<Envelope>();
        let (notify_tx, notify_rx) = mpsc::unbounded_channel::<NotifyPush>();

        tokio::spawn(async move {
            while let Some(frame) = out_rx.recv().await {
                if let Ok(bytes) = canonical::to_vec(&frame) {
                    if write.send(Message::Binary(bytes)).await.is_err() {
                        break;
                    }
                }
            }
        });
        tokio::spawn(async move {
            while let Some(msg) = read.next().await {
                match msg {
                    Ok(Message::Binary(b)) => {
                        if let Ok(frame) = canonical::from_slice::<ServerFrame>(b.as_ref()) {
                            match frame {
                                ServerFrame::Deliver(env) => {
                                    let _ = deliver_tx.send(env);
                                }
                                // Server pushes ride their own channels — a Notify
                                // arriving mid-request must never displace an Ack.
                                ServerFrame::Notify { group_id, kind, group_seq } => {
                                    let _ = notify_tx.send(NotifyPush { group_id, kind, group_seq });
                                }
                                other => {
                                    let _ = resp_tx.send(other);
                                }
                            }
                        }
                    }
                    Ok(Message::Close(_)) | Err(_) => break,
                    Ok(_) => {}
                }
            }
        });

        let client = Self {
            out_tx,
            resp_rx: Mutex::new(resp_rx),
            deliver_rx: Mutex::new(deliver_rx),
            notify_rx: Mutex::new(notify_rx),
        };
        match client.next_response().await {
            Some(ServerFrame::Challenge { nonce }) => Ok((client, nonce)),
            _ => Err(WsError::Protocol("expected initial challenge")),
        }
    }

    async fn next_response(&self) -> Option<ServerFrame> {
        self.resp_rx.lock().await.recv().await
    }

    /// Request a fresh single-use nonce (for a KeyPackage binding attestation).
    pub async fn challenge(&self) -> Result<String, WsError> {
        match self.request(ClientFrame::Challenge).await? {
            ServerFrame::Challenge { nonce } => Ok(nonce),
            ServerFrame::Error { message } => Err(WsError::Server(message)),
            _ => Err(WsError::Protocol("expected Challenge")),
        }
    }

    async fn request(&self, frame: ClientFrame) -> Result<ServerFrame, WsError> {
        self.out_tx.send(frame).map_err(|_| WsError::Closed)?;
        self.next_response().await.ok_or(WsError::Closed)
    }

    pub async fn authenticate(&self, message: SiweMessage, signature: [u8; 65]) -> Result<WalletAddress, WsError> {
        match self.request(ClientFrame::Authenticate { message, signature: signature.to_vec() }).await? {
            ServerFrame::Authenticated { address } => Ok(address),
            ServerFrame::Error { message } => Err(WsError::Server(message)),
            _ => Err(WsError::Protocol("expected Authenticated")),
        }
    }

    pub async fn publish_key_package(&self, pubn: KeyPackagePublication) -> Result<(), WsError> {
        self.expect_ack(ClientFrame::PublishKeyPackage(pubn)).await.map(|_| ())
    }

    pub async fn take_key_package(&self, wallet: WalletAddress) -> Result<Option<KeyPackagePublication>, WsError> {
        match self.request(ClientFrame::TakeKeyPackage { wallet }).await? {
            ServerFrame::KeyPackage(kp) => Ok(kp),
            ServerFrame::Error { message } => Err(WsError::Server(message)),
            _ => Err(WsError::Protocol("expected KeyPackage")),
        }
    }

    pub async fn register_group(&self, group_id: GroupId) -> Result<(), WsError> {
        self.expect_ack(ClientFrame::RegisterGroup { group_id }).await.map(|_| ())
    }

    pub async fn onboard(
        &self,
        group_id: GroupId,
        joiner: WalletAddress,
        admin_assertion: Option<RoleAssertion>,
        welcome: Envelope,
        ratchet_tree: Vec<u8>,
    ) -> Result<(), WsError> {
        self.expect_ack(ClientFrame::Onboard { group_id, joiner, admin_assertion, welcome, ratchet_tree })
            .await
            .map(|_| ())
    }

    pub async fn submit(&self, envelope: Envelope) -> Result<u64, WsError> {
        match self.expect_ack(ClientFrame::Submit(envelope)).await? {
            Some(seq) => Ok(seq),
            None => Err(WsError::Protocol("submit ack missing seq")),
        }
    }

    pub async fn ratchet_tree(&self, group_id: GroupId) -> Result<Option<Vec<u8>>, WsError> {
        match self.request(ClientFrame::RatchetTree { group_id }).await? {
            ServerFrame::RatchetTree(rt) => Ok(rt),
            ServerFrame::Error { message } => Err(WsError::Server(message)),
            _ => Err(WsError::Protocol("expected RatchetTree")),
        }
    }

    async fn expect_ack(&self, frame: ClientFrame) -> Result<Option<u64>, WsError> {
        match self.request(frame).await? {
            ServerFrame::Ack { seq } => Ok(seq),
            ServerFrame::Error { message } => Err(WsError::Server(message)),
            _ => Err(WsError::Protocol("expected Ack")),
        }
    }

    /// Await the next server-pushed envelope (a fanned-out message for this wallet).
    pub async fn next_delivered(&self) -> Option<Envelope> {
        self.deliver_rx.lock().await.recv().await
    }

    /// Await the next advisory notification ping ([`ServerFrame::Notify`]).
    /// Advisory only — never use it to order or gate envelope processing.
    pub async fn next_notify(&self) -> Option<NotifyPush> {
        self.notify_rx.lock().await.recv().await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// WP-4.6: `connect` fails closed on a remote `ws://` endpoint — and does so BEFORE
    /// dialing, so it resolves instantly even though nothing is listening. (The
    /// `connect_insecure` opt-in bypassing the guard is covered by the `endpoint` policy
    /// tests, which avoid an actual hang-prone dial.)
    #[tokio::test]
    async fn connect_refuses_remote_plaintext_before_dialing() {
        let refused = RelayClient::connect("ws://relay.example.com:8787").await.err();
        assert!(matches!(refused, Some(WsError::InsecureEndpoint(_))), "remote ws:// must be refused");
        // wss:// is permitted by the guard (then fails on the dial, not the policy).
        let dial = RelayClient::connect("wss://127.0.0.1:1").await.err();
        assert!(!matches!(dial, Some(WsError::InsecureEndpoint(_))), "wss must pass the guard");
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
        let fields: Vec<&str> =
            inner.as_map().expect("variant fields encode as a map").iter().map(|(k, _)| k.as_text().unwrap()).collect();

        let mut sorted = fields.clone();
        sorted.sort_unstable();
        assert_eq!(sorted, vec!["group_id", "group_seq", "kind"], "Notify must carry EXACTLY group_id/kind/group_seq");
        for forbidden in ["ciphertext", "body", "content", "plaintext", "payload", "text", "envelope"] {
            assert!(!fields.contains(&forbidden), "Notify must never carry `{forbidden}` (server-blind invariant)");
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum WsError {
    #[error("websocket error: {0}")]
    Ws(String),
    #[error("insecure endpoint refused: {0}")]
    InsecureEndpoint(String),
    #[error("connection closed")]
    Closed,
    #[error("protocol error: {0}")]
    Protocol(&'static str),
    #[error("server error: {0}")]
    Server(String),
}
