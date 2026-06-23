//! Networked session — drives a real MLS client against a **remote** server-blind relay
//! over `wss://` (COMMS-S4). This is what lets two teammates on different machines talk;
//! the in-process [`backend::Workspace`](crate::backend) is the local demo.
//!
//! [`NetSession`] wraps a [`RelayClient`] (the wire) and an [`MlsMember`] (the agent's own
//! group secrets) into the high-level operations the UI calls: `login`, publish a
//! KeyPackage, create or join a channel, send a message, and receive decrypted activity.
//! Every byte the relay sees is ciphertext + routing metadata; plaintext exists only
//! inside this process.

use comms_core::domain::{ChatMessage, Lamport};
use comms_core::identity::{EthWallet, SiweMessage};
use comms_core::mls::{GroupHandle, MlsMember};
use comms_proto::{
    Envelope, EnvelopeKind, EpochId, GroupId, KeyPackagePublication, WalletAddress, CITRATE_CHAIN_ID,
};
use comms_relay::ws::{RelayClient, WsError};

/// One joined channel's MLS state.
struct Channel {
    gid: GroupId,
    group: GroupHandle,
    epoch: u64,
    /// Best-known roster (used to address application messages). Always includes self.
    members: Vec<WalletAddress>,
}

/// A live, authenticated session to a remote relay.
pub struct NetSession {
    domain: String,
    wallet: EthWallet,
    member: MlsMember,
    client: RelayClient,
    channel: Option<Channel>,
}

/// Decrypted activity surfaced to the UI by [`NetSession::recv`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Inbound {
    /// A decrypted application message.
    Message { group: GroupId, sender: WalletAddress, text: String },
    /// A channel system event (e.g. processed a membership Commit).
    System { text: String },
}

/// Install the rustls `ring` crypto provider as the process default exactly once. rustls
/// 0.23 has no built-in default, so any `wss://` dial PANICS without this. Idempotent: a
/// second call (provider already installed) is a no-op.
fn ensure_tls_provider() {
    use std::sync::Once;
    static ONCE: Once = Once::new();
    ONCE.call_once(|| {
        let _ = rustls::crypto::ring::default_provider().install_default();
    });
}

impl NetSession {
    /// Connect to `url` and SIWE-authenticate `wallet` for `domain`. Use `wss://…` across
    /// the internet; loopback `ws://…` is fine locally. `allow_insecure` permits plaintext
    /// `ws://` to a non-loopback host (a trusted private network / LAN airgap).
    ///
    /// `now` MUST be real wall-clock milliseconds (the relay verifies the SIWE expiry
    /// against its own clock); the message is valid for 10 minutes from `now`.
    pub async fn login(
        url: &str,
        domain: &str,
        wallet: EthWallet,
        now: u64,
        allow_insecure: bool,
    ) -> Result<Self, NetError> {
        ensure_tls_provider(); // rustls needs a provider before any wss:// dial
        let (client, nonce) = if allow_insecure {
            RelayClient::connect_insecure(url).await
        } else {
            RelayClient::connect(url).await
        }
        .map_err(NetError::Ws)?;

        let msg = SiweMessage {
            domain: domain.into(),
            address: wallet.address(),
            statement: "Sign in to citrate-comms".into(),
            uri: url.into(),
            version: "1".into(),
            chain_id: CITRATE_CHAIN_ID,
            nonce,
            issued_at_ms: now,
            expiration_ms: now + 600_000,
        };
        let sig = wallet.sign_siwe(&msg);
        let who = client.authenticate(msg, sig).await.map_err(NetError::Ws)?;
        if who != wallet.address() {
            return Err(NetError::AuthMismatch);
        }
        let member = MlsMember::new(&wallet.address().0).map_err(|e| NetError::Mls(e.to_string()))?;
        Ok(Self { domain: domain.into(), wallet, member, client, channel: None })
    }

    pub fn wallet(&self) -> WalletAddress {
        self.wallet.address()
    }
    pub fn in_channel(&self) -> bool {
        self.channel.is_some()
    }
    #[allow(dead_code)]
    pub fn channel_id(&self) -> Option<GroupId> {
        self.channel.as_ref().map(|c| c.gid)
    }

    /// Publish our KeyPackage (with its wallet binding attestation) so a peer can add us.
    pub async fn publish_keypackage(&self) -> Result<(), NetError> {
        let sig_pub = self.member.sig_pubkey();
        let nonce = self.client.challenge().await.map_err(NetError::Ws)?;
        let pubn = KeyPackagePublication {
            wallet: self.wallet.address(),
            key_package: self.member.fresh_key_package().map_err(|e| NetError::Mls(e.to_string()))?,
            mls_sig_pubkey: sig_pub.clone(),
            binding_attestation: self.wallet.sign_binding(&sig_pub, &self.domain, &nonce).to_vec(),
            nonce,
            relay_domain: self.domain.clone(),
        };
        self.client.publish_key_package(pubn).await.map_err(NetError::Ws)
    }

    /// Create a channel and add `peers` (each must have published a KeyPackage). Each add
    /// is its own Commit + Welcome; existing members process the later Commits via
    /// [`recv`](Self::recv). We become the channel owner.
    pub async fn create_channel(&mut self, peers: &[WalletAddress]) -> Result<GroupId, NetError> {
        let mut group = self.member.create_group().map_err(|e| NetError::Mls(e.to_string()))?;
        let gid = GroupId(*blake3::hash(&group.group_id()).as_bytes());
        self.client.register_group(gid).await.map_err(NetError::Ws)?;

        let mut members = vec![self.wallet.address()];
        let mut epoch = group.epoch();
        for &peer in peers {
            let kp = self
                .client
                .take_key_package(peer)
                .await
                .map_err(NetError::Ws)?
                .ok_or(NetError::NoKeyPackage(peer))?;
            let add = group.add(&self.member, &kp.key_package).map_err(|e| NetError::Mls(e.to_string()))?;
            epoch = group.epoch();
            self.client
                .submit(Envelope {
                    group_id: gid,
                    epoch: EpochId(epoch),
                    kind: EnvelopeKind::Commit,
                    sender: self.wallet.address(),
                    recipients: vec![],
                    ciphertext: add.commit,
                    group_seq: None,
                })
                .await
                .map_err(NetError::Ws)?;
            self.client
                .onboard(
                    gid,
                    peer,
                    // We are the channel registrar (workspace owner / trust anchor),
                    // so no owner-signed AddMember grant is required (FWA-C11-03).
                    None,
                    Envelope {
                        group_id: gid,
                        epoch: EpochId(epoch),
                        kind: EnvelopeKind::Welcome,
                        sender: self.wallet.address(),
                        recipients: vec![peer],
                        ciphertext: add.welcome,
                        group_seq: None,
                    },
                    add.ratchet_tree,
                )
                .await
                .map_err(NetError::Ws)?;
            members.push(peer);
        }
        self.channel = Some(Channel { gid, group, epoch, members });
        Ok(gid)
    }

    /// Join the channel a `Welcome` envelope invites us to (fetches the public ratchet
    /// tree from the relay, then joins). The inviter is the envelope's sender; we seed the
    /// roster with them and ourselves (full roster sync is a later refinement).
    pub async fn join_from_welcome(&mut self, env: &Envelope) -> Result<GroupId, NetError> {
        if env.kind != EnvelopeKind::Welcome {
            return Err(NetError::NotInChannel);
        }
        let gid = env.group_id;
        let rt = self
            .client
            .ratchet_tree(gid)
            .await
            .map_err(NetError::Ws)?
            .ok_or(NetError::NoRatchetTree)?;
        let group = self.member.join(&env.ciphertext, &rt).map_err(|e| NetError::Mls(e.to_string()))?;
        let epoch = group.epoch();
        let members = vec![self.wallet.address(), env.sender];
        self.channel = Some(Channel { gid, group, epoch, members });
        Ok(gid)
    }

    /// Block until a Welcome is pushed, then join it (convenience over
    /// [`join_from_welcome`](Self::join_from_welcome); the driver polls instead). Used by tests.
    #[allow(dead_code)]
    pub async fn join_next_channel(&mut self) -> Result<GroupId, NetError> {
        loop {
            let env = self.client.next_delivered().await.ok_or(NetError::Closed)?;
            if env.kind == EnvelopeKind::Welcome {
                return self.join_from_welcome(&env).await;
            }
        }
    }

    /// Encrypt `body` and submit it to the channel. Returns the relay sequence number.
    pub async fn send_text(&mut self, body: &str) -> Result<u64, NetError> {
        let ch = self.channel.as_mut().ok_or(NetError::NotInChannel)?;
        let payload = ChatMessage {
            thread_id: None,
            parent_id: None,
            body: body.into(),
            sent: Lamport { counter: 0, actor: self.wallet.address() },
        }
        .encode()
        .map_err(|e| NetError::Codec(e.to_string()))?;
        let ct = ch.group.send(&self.member, &payload).map_err(|e| NetError::Mls(e.to_string()))?;
        let recipients: Vec<WalletAddress> =
            ch.members.iter().copied().filter(|a| *a != self.wallet.address()).collect();
        self.client
            .submit(Envelope {
                group_id: ch.gid,
                epoch: EpochId(ch.epoch),
                kind: EnvelopeKind::Application,
                sender: self.wallet.address(),
                recipients,
                ciphertext: ct,
                group_seq: None,
            })
            .await
            .map_err(NetError::Ws)
    }

    /// Await the next raw envelope pushed by the relay (borrows `&self` only, so a driver
    /// loop can `select`/poll it without holding a `&mut self` borrow). Returns `None` on
    /// a closed connection. The bytes are still ciphertext — feed it to [`apply`](Self::apply).
    pub async fn next_envelope(&self) -> Option<Envelope> {
        self.client.next_delivered().await
    }

    /// Apply a delivered envelope to our MLS state: decrypt application messages, process
    /// membership Commits (advancing our epoch). Returns `Ok(None)` for envelopes not for
    /// our channel or that produce no user-visible event. Synchronous (no `await`), so it
    /// composes with [`next_envelope`](Self::next_envelope) in a poll loop.
    pub fn apply(&mut self, env: Envelope) -> Result<Option<Inbound>, NetError> {
        let ch = self.channel.as_mut().ok_or(NetError::NotInChannel)?;
        if env.group_id != ch.gid {
            return Ok(None);
        }
        match env.kind {
            EnvelopeKind::Application => {
                let pt = ch.group.receive(&self.member, &env.ciphertext).map_err(|e| NetError::Mls(e.to_string()))?;
                let msg = ChatMessage::decode(&pt).map_err(|e| NetError::Codec(e.to_string()))?;
                Ok(Some(Inbound::Message { group: ch.gid, sender: env.sender, text: msg.body }))
            }
            EnvelopeKind::Commit => {
                ch.group.process_commit(&self.member, &env.ciphertext).map_err(|e| NetError::Mls(e.to_string()))?;
                ch.epoch = ch.group.epoch();
                if !ch.members.contains(&env.sender) {
                    ch.members.push(env.sender);
                }
                Ok(Some(Inbound::System { text: "channel membership changed".into() }))
            }
            _ => Ok(None),
        }
    }

    /// Await the next decrypted inbound event for our channel (a convenience that loops
    /// [`next_envelope`](Self::next_envelope) + [`apply`](Self::apply)). The driver uses
    /// the split form; this is exercised by tests.
    #[allow(dead_code)]
    pub async fn recv(&mut self) -> Result<Inbound, NetError> {
        loop {
            let env = self.next_envelope().await.ok_or(NetError::Closed)?;
            if let Some(inb) = self.apply(env)? {
                return Ok(inb);
            }
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum NetError {
    #[error("relay/transport error: {0}")]
    Ws(#[source] WsError),
    #[error("relay authenticated a different address than we signed with")]
    AuthMismatch,
    #[error("no KeyPackage published for {0:?} — ask them to come online first")]
    NoKeyPackage(WalletAddress),
    #[error("relay has no ratchet tree for the channel we were welcomed to")]
    NoRatchetTree,
    #[error("not in a channel yet")]
    NotInChannel,
    #[error("connection closed")]
    Closed,
    #[error("mls error: {0}")]
    Mls(String),
    #[error("codec error: {0}")]
    Codec(String),
}

#[cfg(test)]
mod tests {
    use super::*;
    use comms_relay::ws::RelayServer;
    use comms_relay::DeliveryService;

    /// LIVE readiness gate — connects to the deployed relay over real `wss://`, runs the
    /// SIWE login, and publishes a KeyPackage. Proves the production relay accepts our
    /// handshake before two teammates rely on it. Ignored by default (needs the relay up
    /// + network); run manually:
    ///   cargo test -p comms-client --bin citrate-comms live_relay_handshake -- --ignored --nocapture
    #[tokio::test]
    #[ignore = "live: needs the deployed relay running + outbound wss"]
    async fn live_relay_handshake() {
        const URL: &str = "wss://comms.citrate.ai";
        const DOMAIN: &str = "comms.citrate.ai";
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64;
        let wallet = EthWallet::generate();
        let me = wallet.address().to_hex();
        let session = NetSession::login(URL, DOMAIN, wallet, now, false)
            .await
            .unwrap_or_else(|e| panic!("LIVE login to {URL} failed: {e} (is the relay up? `systemctl status comms-relay`)"));
        session
            .publish_keypackage()
            .await
            .unwrap_or_else(|e| panic!("LIVE publish_keypackage failed: {e}"));
        eprintln!("LIVE relay OK — {URL} accepted SIWE login + KeyPackage for {me}");
    }

    /// LIVE end-to-end — two independent clients over real `wss://` create a channel, join,
    /// and exchange an MLS-encrypted message through the deployed relay. The definitive
    /// "ready for real cross-machine data" proof. Ignored by default; run:
    ///   cargo test -p comms-client --bin citrate-comms live_relay_two_party_chat -- --ignored --nocapture
    #[tokio::test]
    #[ignore = "live: full two-party exchange against the deployed relay"]
    async fn live_relay_two_party_chat() {
        const URL: &str = "wss://comms.citrate.ai";
        const DOMAIN: &str = "comms.citrate.ai";
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64;
        let alice_w = EthWallet::generate();
        let bob_w = EthWallet::generate();
        let alice_addr = alice_w.address();
        let bob_addr = bob_w.address();

        // Both sign in to the live relay over TLS.
        let mut alice = NetSession::login(URL, DOMAIN, alice_w, now, false).await.expect("alice live login");
        let mut bob = NetSession::login(URL, DOMAIN, bob_w, now, false).await.expect("bob live login");

        // Bob comes online; Alice creates a channel and invites him.
        bob.publish_keypackage().await.expect("bob publish kp");
        let gid = alice.create_channel(&[bob_addr]).await.expect("alice create channel");
        let joined = bob.join_next_channel().await.expect("bob join channel");
        assert_eq!(joined, gid, "bob joined the channel alice created");

        // Alice → Bob, decrypted on the far side through the live relay.
        alice.send_text("live cross-machine hello ✅").await.expect("alice send");
        match bob.recv().await.expect("bob recv") {
            Inbound::Message { sender, text, .. } => {
                assert_eq!(sender, alice_addr, "sender is alice");
                assert!(text.contains("live cross-machine"), "decrypted text: {text}");
            }
            other => panic!("expected a message, got {other:?}"),
        }
        eprintln!("LIVE two-party OK — channel create/join/message over {URL}");
    }

    /// Two NetSessions on a loopback RelayServer chat end to end through the high-level
    /// API — the same flow two teammates run across the internet, minus the TLS hop.
    #[tokio::test]
    async fn two_sessions_chat_over_the_wire() {
        const DOMAIN: &str = "relay.citrate.ai";
        let alice_w = EthWallet::generate(); // workspace owner
        let bob_w = EthWallet::generate();
        let alice_addr = alice_w.address();
        let bob_addr = bob_w.address();
        let service = DeliveryService::new(DOMAIN, alice_addr, 0).unwrap();
        let server = RelayServer::new(service);
        let (addr, _accept) = server.bind("127.0.0.1:0").await.unwrap();
        let url = format!("ws://{addr}");

        // The relay checks SIWE expiry against its real wall-clock, so `now` must be real.
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64;
        let mut alice = NetSession::login(&url, DOMAIN, alice_w, now, false).await.unwrap();
        let mut bob = NetSession::login(&url, DOMAIN, bob_w, now, false).await.unwrap();

        // Bob comes online and publishes his KeyPackage; Alice creates the channel.
        bob.publish_keypackage().await.unwrap();
        let gid = alice.create_channel(&[bob_addr]).await.unwrap();

        // Bob joins from the pushed Welcome.
        let joined = bob.join_next_channel().await.unwrap();
        assert_eq!(joined, gid);
        assert!(alice.in_channel() && bob.in_channel());

        // Alice → Bob, and Bob → Alice, decrypted through the API.
        alice.send_text("hey, can you see this across the wire?").await.unwrap();
        match bob.recv().await.unwrap() {
            Inbound::Message { sender, text, .. } => {
                assert_eq!(sender, alice_addr);
                assert!(text.contains("across the wire"));
            }
            other => panic!("expected a message, got {other:?}"),
        }
        bob.send_text("loud and clear ✅").await.unwrap();
        match alice.recv().await.unwrap() {
            Inbound::Message { sender, text, .. } => {
                assert_eq!(sender, bob_addr);
                assert!(text.contains("loud and clear"));
            }
            other => panic!("expected a message, got {other:?}"),
        }
    }
}
