//! `comms-session` — a member's live session against a server-blind relay.
//!
//! [`NetSession`] wraps a [`RelayClient`] (the wire) and an [`MlsMember`] (this
//! member's own group secrets) into the operations an application calls: log in,
//! publish a KeyPackage, create or join a channel, send a message, receive decrypted
//! activity. Every byte the relay sees is ciphertext plus routing metadata; plaintext
//! exists only inside this process.
//!
//! **Moved out of `comms-client`** (where it was `src/net.rs`) so that it can be used
//! without a UI toolkit. The logic is unchanged; the tests came with it.
//!
//! ## The one API change: the caller keeps its key
//!
//! `login` used to take an [`EthWallet`] — a struct that owns a secp256k1 secret key —
//! because the only caller had one. That is a hard requirement to meet for an
//! application whose whole design says the private key never leaves an OS-keyring
//! vault and every signature passes a human approval (citrate-quorum: "no agent,
//! sidecar, daemon, or remote service ever holds a key or signs").
//!
//! So the session now asks for a [`SiweSigner`]: something that can produce the two
//! signatures a session needs — the SIWE login, and the attestation binding this
//! member's MLS public key to the wallet identity. [`EthWallet`] implements it (so
//! `comms-client` is unchanged), and an application that holds its key behind a
//! ceremony implements it by routing those two calls through the ceremony.
//!
//! Two signatures, not two per message: MLS group operations sign with the member's
//! own MLS credential key, which is generated here and never leaves the process. A
//! human approval per chat message would be absurd; a human approval per *session*
//! is exactly right, because "connect this machine to the relay as me" is the act
//! that deserves one.

use comms_core::domain::{ChatMessage, Lamport};
use comms_core::identity::{EthWallet, SiweMessage};
use comms_core::mls::{GroupHandle, MlsMember};
use comms_proto::{
    Envelope, EnvelopeKind, EpochId, GroupId, KeyPackagePublication, WalletAddress,
    CITRATE_CHAIN_ID,
};
use comms_wire::client::{RelayClient, WsError};

/// What a session needs from whoever owns the wallet identity.
///
/// Deliberately narrow: two signatures and an address, both one-off per session. It
/// is an `async` trait in spirit but written with a boxed future so the crate stays
/// free of proc-macro dependencies — an implementation that signs through a
/// human-in-the-loop ceremony genuinely needs to await a human.
pub trait SiweSigner: Send + Sync {
    /// The wallet address these signatures will recover to. The session checks the
    /// relay agrees before trusting the connection.
    fn address(&self) -> WalletAddress;

    /// Sign the SIWE login message (EIP-191 `personal_sign`, 65-byte r‖s‖v).
    fn sign_siwe(&self, message: &SiweMessage) -> Result<[u8; 65], SignerError>;

    /// Sign the binding attestation that ties this member's MLS signature public key
    /// to the wallet identity, for `relay_domain`, against a relay-issued `nonce`.
    ///
    /// This is what stops anyone else publishing a KeyPackage in your name: the relay
    /// verifies the recovered signer matches the claimed wallet
    /// (`identity::verify_binding_attestation`).
    fn sign_binding(
        &self,
        mls_sig_pubkey: &[u8],
        relay_domain: &str,
        nonce: &str,
    ) -> Result<[u8; 65], SignerError>;
}

/// Why a signer could not produce a signature. Carries a message, never key material.
#[derive(Debug, thiserror::Error)]
#[error("{0}")]
pub struct SignerError(pub String);

impl SignerError {
    pub fn new(msg: impl Into<String>) -> Self {
        Self(msg.into())
    }
}

/// The obvious implementation: a wallet that holds its own secret key. This is what
/// `comms-client` uses, and it is why extracting the trait changed no behaviour there.
impl SiweSigner for EthWallet {
    fn address(&self) -> WalletAddress {
        EthWallet::address(self)
    }
    fn sign_siwe(&self, message: &SiweMessage) -> Result<[u8; 65], SignerError> {
        Ok(EthWallet::sign_siwe(self, message))
    }
    fn sign_binding(
        &self,
        mls_sig_pubkey: &[u8],
        relay_domain: &str,
        nonce: &str,
    ) -> Result<[u8; 65], SignerError> {
        Ok(EthWallet::sign_binding(
            self,
            mls_sig_pubkey,
            relay_domain,
            nonce,
        ))
    }
}

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
    /// Whoever owns the wallet identity, when the caller has one that can sign on
    /// demand. `None` when signatures come from a human — see [`PendingLogin`].
    /// Either way the session never sees a secret key.
    signer: Option<Box<dyn SiweSigner>>,
    /// This member's own MLS credential + group secrets. Generated in-process and
    /// never sent anywhere: MLS signatures do not go through the signer.
    member: MlsMember,
    client: RelayClient,
    channel: Option<Channel>,
    address: WalletAddress,
}

/// Decrypted activity surfaced to the UI by [`NetSession::recv`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Inbound {
    /// A decrypted application message.
    Message {
        group: GroupId,
        sender: WalletAddress,
        text: String,
    },
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
        signer: Box<dyn SiweSigner>,
        now: u64,
        allow_insecure: bool,
    ) -> Result<Self, NetError> {
        let pending = Self::begin(url, domain, signer.address(), now, allow_insecure).await?;
        let sig = signer
            .sign_siwe(pending.message())
            .map_err(NetError::Signer)?;
        pending.complete(sig, Some(signer)).await
    }

    /// **Phase 1 of a human-in-the-loop login.** Connect, take the relay's challenge
    /// nonce, and build the SIWE message — signing nothing.
    ///
    /// [`login`](Self::login) is the whole handshake for a caller that owns its key.
    /// A caller whose signature comes from a *human* cannot use it: the nonce only
    /// exists after the socket is open, so the message to be signed cannot be known
    /// in advance, and a synchronous [`SiweSigner`] cannot wait for someone to click
    /// Approve. This pair splits the handshake either side of that wait — the
    /// connection stays open, holding the nonce, while a person decides.
    ///
    /// `address` is who the caller claims to be; [`PendingLogin::complete`] refuses
    /// the session if the relay recovers anyone else from the signature.
    pub async fn begin(
        url: &str,
        domain: &str,
        address: WalletAddress,
        now: u64,
        allow_insecure: bool,
    ) -> Result<PendingLogin, NetError> {
        ensure_tls_provider(); // rustls needs a provider before any wss:// dial
        let (client, nonce) = if allow_insecure {
            RelayClient::connect_insecure(url).await
        } else {
            RelayClient::connect(url).await
        }
        .map_err(NetError::Ws)?;

        let message = SiweMessage {
            domain: domain.into(),
            address,
            statement: "Sign in to citrate-comms".into(),
            uri: url.into(),
            version: "1".into(),
            chain_id: CITRATE_CHAIN_ID,
            nonce,
            issued_at_ms: now,
            expiration_ms: now + 600_000,
        };
        Ok(PendingLogin {
            client,
            message,
            domain: domain.into(),
            address,
        })
    }

    pub fn wallet(&self) -> WalletAddress {
        self.address
    }

    /// This member's MLS signature public key — the value the binding attestation
    /// commits to, and the handle a roster uses to tell two seats apart.
    pub fn mls_sig_pubkey(&self) -> Vec<u8> {
        self.member.sig_pubkey()
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
            wallet: self.address,
            key_package: self
                .member
                .fresh_key_package()
                .map_err(|e| NetError::Mls(e.to_string()))?,
            mls_sig_pubkey: sig_pub.clone(),
            binding_attestation: self
                .signer
                .as_ref()
                .ok_or(NetError::NoSigner)?
                .sign_binding(&sig_pub, &self.domain, &nonce)
                .map_err(NetError::Signer)?
                .to_vec(),
            nonce,
            relay_domain: self.domain.clone(),
        };
        self.client
            .publish_key_package(pubn)
            .await
            .map_err(NetError::Ws)
    }

    /// **Phase 1 of a human-signed KeyPackage publication.** Takes the relay's
    /// single-use nonce and builds everything except the attestation.
    ///
    /// The attestation is what stops anyone else publishing a KeyPackage in your
    /// name, so it is signed by the wallet identity — which, for a human, means a
    /// second approval. Same reason as [`NetSession::begin`]: the nonce does not
    /// exist until we ask, and a person cannot be awaited synchronously.
    pub async fn keypackage_intent(&self) -> Result<KeyPackageIntent, NetError> {
        let nonce = self.client.challenge().await.map_err(NetError::Ws)?;
        Ok(KeyPackageIntent {
            mls_sig_pubkey: self.member.sig_pubkey(),
            relay_domain: self.domain.clone(),
            nonce,
            key_package: self
                .member
                .fresh_key_package()
                .map_err(|e| NetError::Mls(e.to_string()))?,
        })
    }

    /// **Phase 2.** Publish the KeyPackage with a wallet signature over the intent's
    /// `(mls_sig_pubkey, relay_domain, nonce)`.
    pub async fn publish_signed(
        &self,
        intent: KeyPackageIntent,
        attestation: [u8; 65],
    ) -> Result<(), NetError> {
        let pubn = KeyPackagePublication {
            wallet: self.address,
            key_package: intent.key_package,
            mls_sig_pubkey: intent.mls_sig_pubkey,
            binding_attestation: attestation.to_vec(),
            nonce: intent.nonce,
            relay_domain: intent.relay_domain,
        };
        self.client
            .publish_key_package(pubn)
            .await
            .map_err(NetError::Ws)
    }

    /// Create a channel and add `peers` (each must have published a KeyPackage). Each add
    /// is its own Commit + Welcome; existing members process the later Commits via
    /// [`recv`](Self::recv). We become the channel owner.
    pub async fn create_channel(&mut self, peers: &[WalletAddress]) -> Result<GroupId, NetError> {
        let mut group = self
            .member
            .create_group()
            .map_err(|e| NetError::Mls(e.to_string()))?;
        let gid = GroupId(*blake3::hash(&group.group_id()).as_bytes());
        self.client
            .register_group(gid)
            .await
            .map_err(NetError::Ws)?;

        let mut members = vec![self.address];
        let mut epoch = group.epoch();
        for &peer in peers {
            let kp = self
                .client
                .take_key_package(peer)
                .await
                .map_err(NetError::Ws)?
                .ok_or(NetError::NoKeyPackage(peer))?;
            let add = group
                .add(&self.member, &kp.key_package)
                .map_err(|e| NetError::Mls(e.to_string()))?;
            epoch = group.epoch();
            self.client
                .submit(Envelope {
                    group_id: gid,
                    epoch: EpochId(epoch),
                    kind: EnvelopeKind::Commit,
                    sender: self.address,
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
                        sender: self.address,
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
        self.channel = Some(Channel {
            gid,
            group,
            epoch,
            members,
        });
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
        let group = self
            .member
            .join(&env.ciphertext, &rt)
            .map_err(|e| NetError::Mls(e.to_string()))?;
        let epoch = group.epoch();
        let members = vec![self.address, env.sender];
        self.channel = Some(Channel {
            gid,
            group,
            epoch,
            members,
        });
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
            sent: Lamport {
                counter: 0,
                actor: self.address,
            },
        }
        .encode()
        .map_err(|e| NetError::Codec(e.to_string()))?;
        let ct = ch
            .group
            .send(&self.member, &payload)
            .map_err(|e| NetError::Mls(e.to_string()))?;
        let recipients: Vec<WalletAddress> = ch
            .members
            .iter()
            .copied()
            .filter(|a| *a != self.address)
            .collect();
        self.client
            .submit(Envelope {
                group_id: ch.gid,
                epoch: EpochId(ch.epoch),
                kind: EnvelopeKind::Application,
                sender: self.address,
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
                let pt = ch
                    .group
                    .receive(&self.member, &env.ciphertext)
                    .map_err(|e| NetError::Mls(e.to_string()))?;
                let msg = ChatMessage::decode(&pt).map_err(|e| NetError::Codec(e.to_string()))?;
                Ok(Some(Inbound::Message {
                    group: ch.gid,
                    sender: env.sender,
                    text: msg.body,
                }))
            }
            EnvelopeKind::Commit => {
                ch.group
                    .process_commit(&self.member, &env.ciphertext)
                    .map_err(|e| NetError::Mls(e.to_string()))?;
                ch.epoch = ch.group.epoch();
                if !ch.members.contains(&env.sender) {
                    ch.members.push(env.sender);
                }
                Ok(Some(Inbound::System {
                    text: "channel membership changed".into(),
                }))
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

/// A connected-but-unauthenticated session, waiting for a signature over
/// [`message`](Self::message). Holding one keeps the socket — and therefore the
/// relay's single-use nonce — alive while a human decides.
pub struct PendingLogin {
    client: RelayClient,
    message: SiweMessage,
    domain: String,
    address: WalletAddress,
}

impl PendingLogin {
    /// Exactly what must be signed. Show this to the human; do not reconstruct it.
    pub fn message(&self) -> &SiweMessage {
        &self.message
    }

    /// The address the session will claim.
    pub fn address(&self) -> WalletAddress {
        self.address
    }

    /// **Phase 2.** Complete the handshake with a signature over [`message`](Self::message).
    ///
    /// `signer` is optional and is used only for *later* signatures (the KeyPackage
    /// binding attestation via [`NetSession::publish_keypackage`]). A caller whose
    /// signatures come from a human passes `None` and uses the two-phase
    /// [`NetSession::keypackage_intent`] / [`NetSession::publish_signed`] pair
    /// instead — nothing in this crate will then ever hold its key.
    pub async fn complete(
        self,
        signature: [u8; 65],
        signer: Option<Box<dyn SiweSigner>>,
    ) -> Result<NetSession, NetError> {
        let who = self
            .client
            .authenticate(self.message, signature)
            .await
            .map_err(NetError::Ws)?;
        // The relay recovered a different address than we believe we are. Either the
        // signer is wrong about its own identity or something re-signed in the middle;
        // both are reasons to refuse the session, not to continue under a name we
        // cannot substantiate.
        if who != self.address {
            return Err(NetError::AuthMismatch);
        }
        let member = MlsMember::new(&self.address.0).map_err(|e| NetError::Mls(e.to_string()))?;
        Ok(NetSession {
            domain: self.domain,
            signer,
            member,
            client: self.client,
            channel: None,
            address: self.address,
        })
    }
}

/// What a KeyPackage publication needs signed, when the signature comes from a human.
///
/// The relay-issued `nonce` is single-use, so this cannot be rebuilt later: the
/// intent holds it while the human decides.
pub struct KeyPackageIntent {
    /// This member's MLS signature public key — the value being bound to the wallet.
    pub mls_sig_pubkey: Vec<u8>,
    pub relay_domain: String,
    pub nonce: String,
    key_package: Vec<u8>,
}

#[derive(Debug, thiserror::Error)]
pub enum NetError {
    #[error("relay/transport error: {0}")]
    Ws(#[source] WsError),
    #[error("could not obtain a signature: {0}")]
    Signer(#[source] SignerError),
    #[error("this session holds no signer — use keypackage_intent/publish_signed")]
    NoSigner,
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
    ///   cargo test -p comms-session live_relay_handshake -- --ignored --nocapture
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
        let session = NetSession::login(URL, DOMAIN, Box::new(wallet), now, false)
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
    ///   cargo test -p comms-session live_relay_two_party_chat -- --ignored --nocapture
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
        let mut alice = NetSession::login(URL, DOMAIN, Box::new(alice_w), now, false)
            .await
            .expect("alice live login");
        let mut bob = NetSession::login(URL, DOMAIN, Box::new(bob_w), now, false)
            .await
            .expect("bob live login");

        // Bob comes online; Alice creates a channel and invites him.
        bob.publish_keypackage().await.expect("bob publish kp");
        let gid = alice
            .create_channel(&[bob_addr])
            .await
            .expect("alice create channel");
        let joined = bob.join_next_channel().await.expect("bob join channel");
        assert_eq!(joined, gid, "bob joined the channel alice created");

        // Alice → Bob, decrypted on the far side through the live relay.
        alice
            .send_text("live cross-machine hello ✅")
            .await
            .expect("alice send");
        match bob.recv().await.expect("bob recv") {
            Inbound::Message { sender, text, .. } => {
                assert_eq!(sender, alice_addr, "sender is alice");
                assert!(
                    text.contains("live cross-machine"),
                    "decrypted text: {text}"
                );
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
        let mut alice = NetSession::login(&url, DOMAIN, Box::new(alice_w), now, false)
            .await
            .unwrap();
        let mut bob = NetSession::login(&url, DOMAIN, Box::new(bob_w), now, false)
            .await
            .unwrap();

        // Bob comes online and publishes his KeyPackage; Alice creates the channel.
        bob.publish_keypackage().await.unwrap();
        let gid = alice.create_channel(&[bob_addr]).await.unwrap();

        // Bob joins from the pushed Welcome.
        let joined = bob.join_next_channel().await.unwrap();
        assert_eq!(joined, gid);
        assert!(alice.in_channel() && bob.in_channel());

        // Alice → Bob, and Bob → Alice, decrypted through the API.
        alice
            .send_text("hey, can you see this across the wire?")
            .await
            .unwrap();
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

#[cfg(test)]
mod two_phase_tests {
    use super::*;
    use comms_relay::ws::RelayServer;
    use comms_relay::DeliveryService;

    fn now_ms() -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0)
    }

    /// The human-in-the-loop path: connect, look at what must be signed, sign it
    /// somewhere else entirely, then complete. This is the shape citrate-quorum
    /// needs — between `begin` and `complete` sits a signature ceremony and a
    /// person, and the session never holds the key.
    #[tokio::test]
    async fn a_session_completes_from_a_signature_produced_elsewhere() {
        const DOMAIN: &str = "relay.citrate.ai";
        let owner = EthWallet::generate();
        let service = DeliveryService::new(DOMAIN, owner.address(), 0).unwrap();
        let server = RelayServer::new(service);
        let (addr, _accept) = server.bind("127.0.0.1:0").await.unwrap();
        let url = format!("ws://{addr}");

        // The "vault": a key the session is never given.
        let vault = EthWallet::generate();

        let pending = NetSession::begin(&url, DOMAIN, vault.address(), now_ms(), false)
            .await
            .expect("phase 1");
        // What a human would be shown, verbatim — not reconstructed.
        assert_eq!(pending.message().address, vault.address());
        assert_eq!(pending.message().domain, DOMAIN);
        assert!(
            !pending.message().nonce.is_empty(),
            "the relay's challenge is bound in"
        );

        let signature = vault.sign_siwe(pending.message()); // ← the ceremony, in real life
        let session = pending.complete(signature, None).await.expect("phase 2");
        assert_eq!(session.wallet(), vault.address());

        // And the KeyPackage half, same shape.
        let intent = session.keypackage_intent().await.expect("kp intent");
        assert_eq!(intent.mls_sig_pubkey, session.mls_sig_pubkey());
        let attestation =
            vault.sign_binding(&intent.mls_sig_pubkey, &intent.relay_domain, &intent.nonce);
        session
            .publish_signed(intent, attestation)
            .await
            .expect("publish");
    }

    /// A signature by the wrong key must not yield a session under the claimed
    /// address — the relay recovers the actual signer, and we refuse the mismatch
    /// rather than continuing under a name we cannot substantiate.
    #[tokio::test]
    async fn a_signature_from_another_key_is_refused() {
        const DOMAIN: &str = "relay.citrate.ai";
        let owner = EthWallet::generate();
        let service = DeliveryService::new(DOMAIN, owner.address(), 0).unwrap();
        let server = RelayServer::new(service);
        let (addr, _accept) = server.bind("127.0.0.1:0").await.unwrap();
        let url = format!("ws://{addr}");

        let claimed = EthWallet::generate();
        let impostor = EthWallet::generate();
        let pending = NetSession::begin(&url, DOMAIN, claimed.address(), now_ms(), false)
            .await
            .unwrap();
        let forged = impostor.sign_siwe(pending.message());
        // The relay itself rejects the mismatch (the SIWE message names `claimed`
        // while the signature recovers `impostor`), so this fails at the wire. The
        // `AuthMismatch` arm is the belt to that braces: it also fails if a relay
        // were ever to authenticate someone other than who we claimed.
        assert!(pending.complete(forged, None).await.is_err());
    }

    /// A session with no signer must not silently skip the attestation.
    #[tokio::test]
    async fn publish_keypackage_without_a_signer_fails_loudly() {
        const DOMAIN: &str = "relay.citrate.ai";
        let owner = EthWallet::generate();
        let service = DeliveryService::new(DOMAIN, owner.address(), 0).unwrap();
        let server = RelayServer::new(service);
        let (addr, _accept) = server.bind("127.0.0.1:0").await.unwrap();
        let url = format!("ws://{addr}");

        let vault = EthWallet::generate();
        let pending = NetSession::begin(&url, DOMAIN, vault.address(), now_ms(), false)
            .await
            .unwrap();
        let sig = vault.sign_siwe(pending.message());
        let session = pending.complete(sig, None).await.unwrap();
        match session.publish_keypackage().await {
            Err(NetError::NoSigner) => {}
            other => panic!("expected NoSigner, got {other:?}"),
        }
    }
}
