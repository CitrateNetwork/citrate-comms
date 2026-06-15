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
use comms_proto::{canonical, Envelope, GroupId, KeyPackagePublication, RoleAssertion, WalletAddress};
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
    Onboard { group_id: GroupId, joiner: WalletAddress, welcome: Envelope, ratchet_tree: Vec<u8> },
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
            ClientFrame::Onboard { group_id, joiner, welcome, ratchet_tree } => {
                let Some(addr) = *authed else { return send_err(out_tx, "not authenticated") };
                let r = { self.service.lock().await.onboard(group_id, addr, joiner, welcome, ratchet_tree, now) };
                match r {
                    Ok(_) => {
                        ack(out_tx, None);
                        self.deliver_pending().await;
                    }
                    Err(e) => send_err(out_tx, &e.to_string()),
                }
            }
            ClientFrame::Submit(env) => {
                let r = { self.service.lock().await.submit(env, now) };
                match r {
                    Ok(seq) => {
                        ack(out_tx, Some(seq));
                        self.deliver_pending().await;
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
}

fn ack(tx: &mpsc::UnboundedSender<ServerFrame>, seq: Option<u64>) {
    let _ = tx.send(ServerFrame::Ack { seq });
}
fn send_err(tx: &mpsc::UnboundedSender<ServerFrame>, message: &str) {
    let _ = tx.send(ServerFrame::Error { message: message.to_string() });
}

// ─────────────────────────── client ───────────────────────────

/// A connector to a [`RelayServer`]. Request methods serialize one round trip; pushed
/// envelopes arrive via [`RelayClient::next_delivered`].
pub struct RelayClient {
    out_tx: mpsc::UnboundedSender<ClientFrame>,
    resp_rx: Mutex<mpsc::UnboundedReceiver<ServerFrame>>,
    deliver_rx: Mutex<mpsc::UnboundedReceiver<Envelope>>,
}

impl RelayClient {
    /// Connect, spawn the read/write tasks, and return the connector plus the relay's
    /// initial SIWE challenge nonce.
    pub async fn connect(url: &str) -> Result<(Self, String), WsError> {
        let (ws, _resp) = tokio_tungstenite::connect_async(url).await.map_err(|e| WsError::Ws(e.to_string()))?;
        let (mut write, mut read) = ws.split();
        let (out_tx, mut out_rx) = mpsc::unbounded_channel::<ClientFrame>();
        let (resp_tx, resp_rx) = mpsc::unbounded_channel::<ServerFrame>();
        let (deliver_tx, deliver_rx) = mpsc::unbounded_channel::<Envelope>();

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

    pub async fn onboard(&self, group_id: GroupId, joiner: WalletAddress, welcome: Envelope, ratchet_tree: Vec<u8>) -> Result<(), WsError> {
        self.expect_ack(ClientFrame::Onboard { group_id, joiner, welcome, ratchet_tree }).await.map(|_| ())
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
}

#[derive(Debug, thiserror::Error)]
pub enum WsError {
    #[error("websocket error: {0}")]
    Ws(String),
    #[error("connection closed")]
    Closed,
    #[error("protocol error: {0}")]
    Protocol(&'static str),
    #[error("server error: {0}")]
    Server(String),
}
