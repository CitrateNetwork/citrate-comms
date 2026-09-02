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
use tokio::sync::{mpsc, Mutex};
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

    async fn connect_with_policy(
        url: &str,
        allow_insecure: bool,
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
