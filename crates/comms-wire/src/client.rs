//! [`RelayClient`] — the connector to a server-blind relay.
//!
//! **Moved verbatim** out of `comms-relay/src/ws.rs`. It was always independent of
//! the server: it speaks the wire frames and nothing else. Living in the same crate
//! as `RelayServer` meant every client linked the relay's storage engine, admin HTTP
//! surface and OS-keyring binding — a client-only consumer (citrate-quorum's Rooms)
//! would have pulled RocksDB, axum and `keyring` into a desktop app to open a socket.
//!
//! The connection-hardening guard travels with it ([`crate::endpoint`]): the refusal
//! of plaintext `ws://` to a remote host is a property of the CLIENT's dial, so it
//! belongs on this side of the split.

use comms_core::identity::SiweMessage;
use comms_proto::{
    canonical, ClaimSubmission, Envelope, EnvelopeKind, GroupId, KeyPackagePublication,
    RoleAssertion, WalletAddress,
};
use futures_util::{SinkExt, StreamExt};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::{mpsc, Mutex};
use tokio::task::JoinHandle;
use tokio_tungstenite::tungstenite::Message;

use crate::frames::{ClientFrame, ServerFrame};

/// Install the rustls `ring` crypto provider exactly once for this process, before any TLS dial.
/// rustls 0.23 no longer auto-selects a provider, and with both `ring` and `aws-lc-rs` present in the
/// tree the ambiguity makes the first `wss://` `connect_async` panic. Called from every connect path.
fn install_tls_provider() {
    use std::sync::Once;
    static ONCE: Once = Once::new();
    ONCE.call_once(|| {
        // Err only means "already installed by someone else" — fine either way.
        let _ = rustls::crypto::ring::default_provider().install_default();
    });
}

/// How often a connected client pings the relay. The ping keeps idle proxies and NATs from dropping
/// a quiet socket, and its answer is how the client knows the link is still there.
pub const KEEPALIVE_INTERVAL: Duration = Duration::from_secs(20);
/// A link that has heard nothing (not even a pong) for this many keepalive intervals is dead.
const KEEPALIVE_MISSES: u32 = 3;

/// What the writer task sends: a protocol frame, or a keepalive ping.
enum Outbound {
    Frame(Box<ClientFrame>),
    Ping,
}

/// The live state of one WebSocket link, shared by the client and its tasks.
struct Link {
    alive: AtomicBool,
    started: Instant,
    /// Milliseconds after `started` when anything last arrived from the relay.
    last_rx_ms: AtomicU64,
}

impl Link {
    fn touch(&self) {
        let ms = self.started.elapsed().as_millis() as u64;
        self.last_rx_ms.store(ms, Ordering::Relaxed);
    }
    fn silent_for(&self) -> Duration {
        let now = self.started.elapsed().as_millis() as u64;
        Duration::from_millis(now.saturating_sub(self.last_rx_ms.load(Ordering::Relaxed)))
    }
    fn kill(&self) {
        self.alive.store(false, Ordering::Relaxed);
    }
}

/// **E-5 WP-3.** The advisory notification push, decoded off its own channel.
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
    out_tx: mpsc::UnboundedSender<Outbound>,
    link: Arc<Link>,
    tasks: Vec<JoinHandle<()>>,
    resp_rx: Mutex<mpsc::UnboundedReceiver<ServerFrame>>,
    deliver_rx: Mutex<mpsc::UnboundedReceiver<(Option<u64>, Envelope)>>,
    /// Arrival numbers of tracked deliveries handed out and not yet acknowledged.
    unacked: Mutex<Vec<u64>>,
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
        Self::connect_with_keepalive(url, false, KEEPALIVE_INTERVAL).await
    }

    /// Like [`connect`](Self::connect) but permits plaintext `ws://` to a non-loopback
    /// host (trusted private network / LAN airgap). Use deliberately — metadata and the
    /// SIWE handshake travel in the clear.
    pub async fn connect_insecure(url: &str) -> Result<(Self, String), WsError> {
        Self::connect_with_keepalive(url, true, KEEPALIVE_INTERVAL).await
    }

    /// Connect with an explicit keepalive interval (`allow_insecure` as in
    /// [`connect_insecure`](Self::connect_insecure)). The client pings every `keepalive` and
    /// counts the link dead after [`KEEPALIVE_MISSES`] silent intervals.
    pub async fn connect_with_keepalive(
        url: &str,
        allow_insecure: bool,
        keepalive: Duration,
    ) -> Result<(Self, String), WsError> {
        // Install the rustls crypto provider ONCE before any TLS dial. rustls 0.23 removed the
        // automatic default provider, and with both `ring` and `aws-lc-rs` in the dependency tree it
        // cannot pick one — so `connect_async` to a wss:// endpoint would PANIC at TLS setup, before
        // the WebSocket handshake, before SIWE login (the relay never sees a connection). This is what
        // made every wss:// group fail to connect. Idempotent (install_default errs if already set).
        install_tls_provider();
        // Fail closed BEFORE dialing if the endpoint is insecure.
        crate::endpoint::enforce_endpoint_policy(url, allow_insecure)
            .map_err(|e| WsError::InsecureEndpoint(e.to_string()))?;
        let (ws, _resp) = tokio_tungstenite::connect_async(url)
            .await
            .map_err(|e| WsError::Ws(e.to_string()))?;
        let (mut write, mut read) = ws.split();
        let (out_tx, mut out_rx) = mpsc::unbounded_channel::<Outbound>();
        let link = Arc::new(Link {
            alive: AtomicBool::new(true),
            started: Instant::now(),
            last_rx_ms: AtomicU64::new(0),
        });
        let (resp_tx, resp_rx) = mpsc::unbounded_channel::<ServerFrame>();
        let (deliver_tx, deliver_rx) = mpsc::unbounded_channel::<(Option<u64>, Envelope)>();
        let (notify_tx, notify_rx) = mpsc::unbounded_channel::<NotifyPush>();

        let wlink = link.clone();
        let writer = tokio::spawn(async move {
            while let Some(out) = out_rx.recv().await {
                let msg = match out {
                    Outbound::Frame(frame) => match canonical::to_vec(&*frame) {
                        Ok(bytes) => Message::Binary(bytes),
                        Err(_) => continue,
                    },
                    Outbound::Ping => Message::Ping(Vec::new()),
                };
                if write.send(msg).await.is_err() {
                    break;
                }
            }
            wlink.kill();
        });
        let rlink = link.clone();
        let reader = tokio::spawn(async move {
            while let Some(msg) = read.next().await {
                rlink.touch();
                match msg {
                    Ok(Message::Binary(b)) => {
                        if let Ok(frame) = canonical::from_slice::<ServerFrame>(b.as_ref()) {
                            match frame {
                                ServerFrame::Deliver(env) => {
                                    let _ = deliver_tx.send((None, env));
                                }
                                ServerFrame::DeliverTracked { arrival, envelope } => {
                                    let _ = deliver_tx.send((Some(arrival), envelope));
                                }
                                // Server pushes ride their own channels — a Notify
                                // arriving mid-request must never displace an Ack.
                                ServerFrame::Notify {
                                    group_id,
                                    kind,
                                    group_seq,
                                } => {
                                    let _ = notify_tx.send(NotifyPush {
                                        group_id,
                                        kind,
                                        group_seq,
                                    });
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
            rlink.kill();
        });
        // Keepalive: ping on a timer; a link silent for KEEPALIVE_MISSES intervals is dead (a
        // half-open TCP socket otherwise looks alive forever).
        let klink = link.clone();
        let ktx = out_tx.clone();
        let keeper = tokio::spawn(async move {
            loop {
                tokio::time::sleep(keepalive).await;
                if !klink.alive.load(Ordering::Relaxed) {
                    break;
                }
                if klink.silent_for() > keepalive * KEEPALIVE_MISSES {
                    klink.kill();
                    break;
                }
                if ktx.send(Outbound::Ping).is_err() {
                    break;
                }
            }
        });

        let client = Self {
            out_tx,
            link,
            tasks: vec![writer, reader, keeper],
            resp_rx: Mutex::new(resp_rx),
            deliver_rx: Mutex::new(deliver_rx),
            unacked: Mutex::new(Vec::new()),
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

    /// Whether the link is up: the socket has not closed or errored, and the relay has answered
    /// within the keepalive window. Cheap (no round trip, nothing sent), so a health probe may ask
    /// it as often as it likes.
    pub fn is_alive(&self) -> bool {
        self.link.alive.load(Ordering::Relaxed)
    }

    /// Mark the link dead, so every later request fails at once with [`WsError::Closed`]. For a
    /// caller that gave up waiting for an answer: the answer may still arrive, and a reused link
    /// would hand it to the next request as that request's reply.
    pub fn mark_dead(&self) {
        self.link.kill();
    }

    fn send_frame(&self, frame: ClientFrame) -> Result<(), WsError> {
        if !self.is_alive() {
            return Err(WsError::Closed);
        }
        self.out_tx
            .send(Outbound::Frame(Box::new(frame)))
            .map_err(|_| WsError::Closed)
    }

    async fn request(&self, frame: ClientFrame) -> Result<ServerFrame, WsError> {
        self.send_frame(frame)?;
        self.next_response().await.ok_or(WsError::Closed)
    }

    pub async fn authenticate(
        &self,
        message: SiweMessage,
        signature: [u8; 65],
    ) -> Result<WalletAddress, WsError> {
        match self
            .request(ClientFrame::Authenticate {
                message,
                signature: signature.to_vec(),
            })
            .await?
        {
            ServerFrame::Authenticated { address } => Ok(address),
            ServerFrame::Error { message } => Err(WsError::Server(message)),
            _ => Err(WsError::Protocol("expected Authenticated")),
        }
    }

    pub async fn publish_key_package(&self, pubn: KeyPackagePublication) -> Result<(), WsError> {
        self.expect_ack(ClientFrame::PublishKeyPackage(pubn))
            .await
            .map(|_| ())
    }

    pub async fn take_key_package(
        &self,
        wallet: WalletAddress,
    ) -> Result<Option<KeyPackagePublication>, WsError> {
        match self.request(ClientFrame::TakeKeyPackage { wallet }).await? {
            ServerFrame::KeyPackage(kp) => Ok(kp),
            ServerFrame::Error { message } => Err(WsError::Server(message)),
            _ => Err(WsError::Protocol("expected KeyPackage")),
        }
    }

    pub async fn register_group(&self, group_id: GroupId) -> Result<(), WsError> {
        self.expect_ack(ClientFrame::RegisterGroup { group_id })
            .await
            .map(|_| ())
    }

    /// CONNECT-S1 — submit a sealed claim to the server-blind claims-inbox (pre-membership).
    pub async fn submit_claim(&self, submission: ClaimSubmission) -> Result<(), WsError> {
        self.expect_ack(ClientFrame::SubmitClaim(submission))
            .await
            .map(|_| ())
    }

    /// CONNECT-S1 — poll the claims-inbox by invite token hash (owner-side); opaque ciphertexts.
    pub async fn poll_claims(&self, token_hash: [u8; 32]) -> Result<Vec<ClaimSubmission>, WsError> {
        match self.request(ClientFrame::PollClaims { token_hash }).await? {
            ServerFrame::Claims(claims) => Ok(claims),
            ServerFrame::Error { message } => Err(WsError::Server(message)),
            _ => Err(WsError::Protocol("expected Claims")),
        }
    }

    pub async fn onboard(
        &self,
        group_id: GroupId,
        joiner: WalletAddress,
        admin_assertion: Option<RoleAssertion>,
        welcome: Envelope,
        ratchet_tree: Vec<u8>,
    ) -> Result<(), WsError> {
        self.expect_ack(ClientFrame::Onboard {
            group_id,
            joiner,
            admin_assertion,
            welcome,
            ratchet_tree,
        })
        .await
        .map(|_| ())
    }

    pub async fn submit(&self, envelope: Envelope) -> Result<u64, WsError> {
        match self.expect_ack(ClientFrame::Submit(envelope)).await? {
            Some(seq) => Ok(seq),
            None => Err(WsError::Protocol("submit ack missing seq")),
        }
    }

    /// Atomic offboard: submit the MLS Remove commit + drop the member's roster/tree at the relay
    /// in one epoch. `admin_assertion` is `None` when the caller is the workspace owner (the relay's
    /// trust anchor). Returns the commit's ordered sequence.
    pub async fn offboard(
        &self,
        group_id: GroupId,
        removed: WalletAddress,
        admin_assertion: Option<RoleAssertion>,
        remove_commit: Envelope,
        ratchet_tree: Vec<u8>,
    ) -> Result<u64, WsError> {
        match self
            .expect_ack(ClientFrame::Offboard {
                group_id,
                removed,
                admin_assertion,
                remove_commit,
                ratchet_tree,
            })
            .await?
        {
            Some(seq) => Ok(seq),
            None => Err(WsError::Protocol("offboard ack missing seq")),
        }
    }

    pub async fn ratchet_tree(&self, group_id: GroupId) -> Result<Option<Vec<u8>>, WsError> {
        match self.request(ClientFrame::RatchetTree { group_id }).await? {
            ServerFrame::RatchetTree(rt) => Ok(rt),
            ServerFrame::Error { message } => Err(WsError::Server(message)),
            _ => Err(WsError::Protocol("expected RatchetTree")),
        }
    }

    /// The group's current member roster (addresses). A joiner uses it to address its messages.
    pub async fn group_members(
        &self,
        group_id: GroupId,
    ) -> Result<Option<Vec<WalletAddress>>, WsError> {
        match self.request(ClientFrame::GroupMembers { group_id }).await? {
            ServerFrame::Members(m) => Ok(m),
            ServerFrame::Error { message } => Err(WsError::Server(message)),
            _ => Err(WsError::Protocol("expected Members")),
        }
    }

    /// `member`'s current grant generation in `group_id` — the generation an owner signs a
    /// delegated grant for (`rbac::sign_group_grant`). `None` if `member` is not a member.
    pub async fn grant_generation(
        &self,
        group_id: GroupId,
        member: WalletAddress,
    ) -> Result<Option<u64>, WsError> {
        match self
            .request(ClientFrame::GrantGeneration { group_id, member })
            .await?
        {
            ServerFrame::GrantGeneration(g) => Ok(g),
            ServerFrame::Error { message } => Err(WsError::Server(message)),
            _ => Err(WsError::Protocol("expected GrantGeneration")),
        }
    }

    /// INVITE-S2 (owner) — publish a single-use, group-bound invite. `group_info` is the
    /// owner's exported public `GroupInfo`; the relay stores it against `token_hash`.
    pub async fn publish_invite(
        &self,
        group_id: GroupId,
        token_hash: [u8; 32],
        group_info: Vec<u8>,
        expires_at: u64,
    ) -> Result<(), WsError> {
        self.expect_ack(ClientFrame::PublishInvite {
            group_id,
            token_hash,
            group_info,
            expires_at,
        })
        .await
        .map(|_| ())
    }

    /// INVITE-S2 (owner) — revoke a previously-published invite (tombstone). With
    /// `report_used`, an invite that was already redeemed is refused with
    /// [`crate::frames::INVITE_ALREADY_USED`] (a relay that predates it acknowledges).
    pub async fn revoke_invite(
        &self,
        token_hash: [u8; 32],
        report_used: bool,
    ) -> Result<(), WsError> {
        self.expect_ack(ClientFrame::RevokeInvite {
            token_hash,
            report_used,
        })
        .await
        .map(|_| ())
    }

    /// INVITE-S2 (joiner) — redeem an invite by its raw token. Returns the relay's typed
    /// [`RedeemInviteResult`] (success carries the public `GroupInfo` + mint epoch; failure
    /// a fail-closed reason). A transport/protocol failure is a [`WsError`].
    pub async fn redeem_invite(
        &self,
        group_id: GroupId,
        token: Vec<u8>,
        key_package: Vec<u8>,
    ) -> Result<crate::frames::RedeemInviteResult, WsError> {
        match self
            .request(ClientFrame::RedeemInvite {
                group_id,
                token,
                key_package,
            })
            .await?
        {
            ServerFrame::RedeemInvite(result) => Ok(result),
            ServerFrame::Error { message } => Err(WsError::Server(message)),
            _ => Err(WsError::Protocol("expected RedeemInvite")),
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
        let (arrival, env) = self.deliver_rx.lock().await.recv().await?;
        if let Some(a) = arrival {
            self.unacked.lock().await.push(a);
        }
        Some(env)
    }

    /// GC-1 review P2: ask the relay to track deliveries for this session. Call it right after
    /// [`connect`](Self::connect) and BEFORE authenticating, so the delivery pass at sign-in
    /// is tracked too. `Ok(false)` from a relay that predates it (the session stays on
    /// untracked delivery).
    pub async fn enable_delivery_acks(&self) -> Result<bool, WsError> {
        self.send_frame(ClientFrame::EnableDeliveryAcks)?;
        match self.next_response().await {
            Some(ServerFrame::Ack { .. }) => Ok(true),
            // A relay that predates tracked delivery cannot decode the frame.
            Some(ServerFrame::Error { .. }) => Ok(false),
            None => Err(WsError::Closed),
            _ => Err(WsError::Protocol("expected Ack")),
        }
    }

    /// Acknowledge every tracked delivery handed out by [`next_delivered`](Self::next_delivered)
    /// so far. Call it only once those envelopes are stored durably.
    pub async fn ack_delivered(&self) -> Result<(), WsError> {
        let arrivals = std::mem::take(&mut *self.unacked.lock().await);
        if arrivals.is_empty() {
            return Ok(());
        }
        self.send_frame(ClientFrame::AckDelivered {
            arrivals: arrivals.clone(),
        })?;
        match self.next_response().await {
            Some(ServerFrame::Ack { .. }) => Ok(()),
            Some(ServerFrame::Error { message }) => {
                // Keep them: the next ack (or the next session's redelivery) covers them.
                self.unacked.lock().await.extend(arrivals);
                Err(WsError::Server(message))
            }
            None => Err(WsError::Closed),
            _ => Err(WsError::Protocol("expected Ack")),
        }
    }

    /// Await the next advisory notification ping ([`ServerFrame::Notify`]).
    /// Advisory only — never use it to order or gate envelope processing.
    pub async fn next_notify(&self) -> Option<NotifyPush> {
        self.notify_rx.lock().await.recv().await
    }
}

impl Drop for RelayClient {
    fn drop(&mut self) {
        self.link.kill();
        for t in &self.tasks {
            t.abort();
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
