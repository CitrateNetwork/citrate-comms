//! The `Relay` seam — the daemon's dependency on a server-blind relay, abstracted so it can run
//! against an **in-process** [`DeliveryService`] (single node, today) or a **networked** relay over
//! `ws://` (cross-node — CX-S3.2 "shared relay + WS clients"; the `WsRelay` impl lands next).
//!
//! Sync by design: the daemon is sync, so the trait is sync and the WS impl bridges to the async
//! `comms-wire::RelayClient` internally (a tokio runtime + `block_on`). Errors collapse to `String`
//! (the daemon already surfaces relay failures as strings).

use comms_core::identity::SiweMessage;
use comms_proto::{ClaimSubmission, Envelope, GroupId, KeyPackagePublication, WalletAddress};
use comms_relay::{DeliveryService, OffboardRequest};

/// A down link's state, reported to the app (`relayStatus`).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct LinkStatus {
    /// Seconds until the next redial (0 = due now or in progress). Set whenever the link is down.
    pub retry_in_secs: Option<u64>,
    /// Why the last redial, sign-in or KeyPackage republish failed.
    pub last_error: Option<String>,
    /// Failed redials in a row since the link was last fully up.
    pub failures: u32,
}

/// Signs a SIWE message with the member's comms key.
pub type SiweSigner = std::sync::Arc<dyn Fn(&SiweMessage) -> [u8; 65] + Send + Sync>;

/// What a networked relay needs to sign in again on its own after a redial: the SIWE domain, the
/// member address, and a signer for the SIWE message. The signer holds the member's comms key in
/// this process only; nothing crosses to the relay but the signature.
#[derive(Clone)]
pub struct SessionSigner {
    pub domain: String,
    pub address: WalletAddress,
    pub sign: SiweSigner,
}

/// The SIWE message a member signs to open a relay session (startup and every redial).
pub fn siwe_message(domain: &str, address: WalletAddress, nonce: String, now: u64) -> SiweMessage {
    SiweMessage {
        domain: domain.into(),
        address,
        statement: "Sign in to citrate-comms".into(),
        uri: format!("wss://{domain}"),
        version: "1".into(),
        chain_id: comms_proto::CITRATE_CHAIN_ID,
        nonce,
        issued_at_ms: now,
        expiration_ms: now + 600_000,
    }
}

/// A server-blind relay the daemon talks to. Every op the [`crate::MemberDaemon`] needs; the owner
/// is the offboard trust anchor, so no admin assertion crosses this seam.
pub trait Relay: Send {
    /// A fresh single-use nonce from the relay. A failure is an error, never an empty nonce.
    fn issue_challenge(&mut self, now: u64) -> Result<String, String>;
    fn authenticate(&mut self, msg: &SiweMessage, sig: &[u8; 65], now: u64) -> Result<(), String>;
    fn publish_key_package(&mut self, pubn: KeyPackagePublication, now: u64) -> Result<(), String>;
    fn take_key_package(
        &mut self,
        wallet: &WalletAddress,
    ) -> Result<Option<KeyPackagePublication>, String>;
    /// CONNECT-S1 — submit a sealed claim to the relay's server-blind claims-inbox (pre-membership).
    fn submit_claim(
        &mut self,
        submitter: WalletAddress,
        submission: ClaimSubmission,
    ) -> Result<(), String>;
    /// CONNECT-S1 — poll the relay's claims-inbox by invite token hash (owner-side).
    fn poll_claims(
        &mut self,
        poller: WalletAddress,
        token_hash: [u8; 32],
    ) -> Result<Vec<ClaimSubmission>, String>;
    fn register_group(
        &mut self,
        gid: GroupId,
        owner: WalletAddress,
        now: u64,
    ) -> Result<(), String>;
    fn submit_as(&mut self, sender: WalletAddress, env: Envelope, now: u64) -> Result<u64, String>;
    #[allow(clippy::too_many_arguments)]
    fn onboard(
        &mut self,
        gid: GroupId,
        admin: WalletAddress,
        joiner: WalletAddress,
        welcome: Envelope,
        ratchet_tree: Vec<u8>,
        now: u64,
    ) -> Result<(), String>;
    fn fetch(&mut self, wallet: &WalletAddress) -> Vec<Envelope>;
    /// INVITE-S2 (owner) — publish a single-use, group-bound invite: the relay stores
    /// `token_hash -> group_info` (public group state) so a token-holder can self-admit by
    /// external commit while the owner is offline.
    fn publish_invite(
        &mut self,
        inviter: WalletAddress,
        gid: GroupId,
        token_hash: [u8; 32],
        group_info: Vec<u8>,
        expires_at: u64,
    ) -> Result<(), String>;
    /// INVITE-S2 (owner) — revoke a previously-published invite (tombstone). With
    /// `report_used`, an already-redeemed invite comes back as the relay's
    /// `INVITE_ALREADY_USED` error, passed through unchanged.
    fn revoke_invite(
        &mut self,
        caller: WalletAddress,
        token_hash: [u8; 32],
        report_used: bool,
    ) -> Result<(), String>;
    /// INVITE-S2 (joiner) — redeem an invite by its raw token. Returns
    /// `(group_info, mint_epoch)` on success; a fail-closed reason string otherwise.
    fn redeem_invite(
        &mut self,
        joiner: WalletAddress,
        gid: GroupId,
        token: Vec<u8>,
        key_package: Vec<u8>,
        now: u64,
    ) -> Result<(Vec<u8>, u64), String>;
    /// Flag-A — whether this relay's link is currently usable. The in-process relay is always
    /// local-up; a networked [`WsRelay`] reports its LIVE connection state so the daemon (and the app
    /// above it) can surface a relay DROP instead of a false "healthy" while every relayed op fails.
    /// Default `true` so in-process impls need no change; must be cheap + bounded (a health probe).
    fn is_connected(&self) -> bool {
        true
    }
    /// Give a networked relay what it needs to sign in again by itself after a redial. In-process
    /// relays ignore it.
    fn set_session_signer(&mut self, _signer: SessionSigner) {}
    /// True once after a networked relay redialed and signed in on its own: the caller republishes
    /// this member's KeyPackage, then calls [`Self::session_ready`] (or [`Self::mark_down`]).
    fn take_fresh_session(&mut self) -> bool {
        false
    }
    /// The fresh session is fully up (signed in and the KeyPackage republished): the backoff starts
    /// again from its minimum.
    fn session_ready(&mut self) {}
    /// Count the current link as down (the KeyPackage republish on a fresh session failed): it is
    /// retired and the next redial waits on the (still growing) backoff.
    fn mark_down(&mut self, _why: &str) {}
    /// The link's state while it is down: when it next redials and why the last try failed.
    fn link_status(&self) -> LinkStatus {
        LinkStatus::default()
    }
    /// GC-1 review P2: tell the relay that everything [`fetch`](Self::fetch) returned so far is
    /// stored durably, so it may delete those mailbox rows. Until then the relay keeps them and
    /// sends them again on the next session. In-process relays have nothing to acknowledge.
    fn ack_delivered(&mut self) -> Result<(), String> {
        Ok(())
    }
    /// The public ratchet tree a joiner needs to process its Welcome.
    fn ratchet_tree(&mut self, gid: GroupId) -> Result<Option<Vec<u8>>, String>;
    /// The group's current member roster (addresses) — a joiner needs it to address messages.
    fn group_members(&mut self, gid: GroupId) -> Result<Option<Vec<WalletAddress>>, String>;
    #[allow(clippy::too_many_arguments)]
    fn offboard(
        &mut self,
        gid: GroupId,
        admin: WalletAddress,
        removed: WalletAddress,
        remove_commit: Envelope,
        ratchet_tree: Vec<u8>,
        now: u64,
    ) -> Result<u64, String>;
}

/// The in-process relay (single-node): delegates straight to a [`DeliveryService`].
pub struct InProcessRelay(pub DeliveryService);

impl InProcessRelay {
    /// Open a fresh in-process relay owned by `owner`.
    pub fn new(domain: &str, owner: WalletAddress) -> Result<Self, String> {
        Ok(InProcessRelay(
            DeliveryService::new(domain, owner, 0).map_err(|e| e.to_string())?,
        ))
    }
}

impl Relay for InProcessRelay {
    fn issue_challenge(&mut self, now: u64) -> Result<String, String> {
        Ok(self.0.issue_challenge(now))
    }
    fn authenticate(&mut self, msg: &SiweMessage, sig: &[u8; 65], now: u64) -> Result<(), String> {
        self.0
            .authenticate(msg, sig, now)
            .map(|_| ())
            .map_err(|e| e.to_string())
    }
    fn publish_key_package(&mut self, pubn: KeyPackagePublication, now: u64) -> Result<(), String> {
        self.0
            .publish_key_package(pubn, now)
            .map(|_| ())
            .map_err(|e| e.to_string())
    }
    fn take_key_package(
        &mut self,
        wallet: &WalletAddress,
    ) -> Result<Option<KeyPackagePublication>, String> {
        Ok(self.0.take_key_package(wallet))
    }
    fn submit_claim(
        &mut self,
        submitter: WalletAddress,
        submission: ClaimSubmission,
    ) -> Result<(), String> {
        self.0
            .submit_claim(&submitter, submission)
            .map_err(|e| e.to_string())
    }
    fn poll_claims(
        &mut self,
        poller: WalletAddress,
        token_hash: [u8; 32],
    ) -> Result<Vec<ClaimSubmission>, String> {
        self.0
            .poll_claims(&poller, &token_hash)
            .map_err(|e| e.to_string())
    }
    fn register_group(
        &mut self,
        gid: GroupId,
        owner: WalletAddress,
        now: u64,
    ) -> Result<(), String> {
        self.0
            .register_group(gid, owner, now)
            .map_err(|e| e.to_string())
    }
    fn submit_as(&mut self, sender: WalletAddress, env: Envelope, now: u64) -> Result<u64, String> {
        self.0
            .submit_as(sender, env, now)
            .map_err(|e| e.to_string())
    }
    fn onboard(
        &mut self,
        gid: GroupId,
        admin: WalletAddress,
        joiner: WalletAddress,
        welcome: Envelope,
        ratchet_tree: Vec<u8>,
        now: u64,
    ) -> Result<(), String> {
        self.0
            .onboard(gid, admin, None, joiner, welcome, ratchet_tree, now)
            .map_err(|e| e.to_string())
    }
    fn fetch(&mut self, wallet: &WalletAddress) -> Vec<Envelope> {
        // On a store error the relay leaves the mailbox intact, so the next poll retries
        // and nothing is lost; this poll simply returns nothing.
        self.0.fetch(wallet).unwrap_or_else(|e| {
            eprintln!("member-daemon: relay fetch failed, will retry: {e}");
            Vec::new()
        })
    }
    fn publish_invite(
        &mut self,
        inviter: WalletAddress,
        gid: GroupId,
        token_hash: [u8; 32],
        group_info: Vec<u8>,
        expires_at: u64,
    ) -> Result<(), String> {
        self.0
            .publish_invite(inviter, gid, token_hash, group_info, expires_at)
            .map_err(|e| e.to_string())
    }
    fn revoke_invite(
        &mut self,
        caller: WalletAddress,
        token_hash: [u8; 32],
        report_used: bool,
    ) -> Result<(), String> {
        self.0
            .revoke_invite(caller, token_hash, report_used)
            .map_err(|e| e.to_string())
    }
    fn redeem_invite(
        &mut self,
        joiner: WalletAddress,
        gid: GroupId,
        token: Vec<u8>,
        key_package: Vec<u8>,
        now: u64,
    ) -> Result<(Vec<u8>, u64), String> {
        self.0
            .redeem_invite(joiner, gid, &token, &key_package, now)
            .map_err(|e| e.to_string())
    }
    fn ratchet_tree(&mut self, gid: GroupId) -> Result<Option<Vec<u8>>, String> {
        Ok(self.0.ratchet_tree(&gid).map(|s| s.to_vec()))
    }
    fn group_members(&mut self, gid: GroupId) -> Result<Option<Vec<WalletAddress>>, String> {
        Ok(self.0.group_members(&gid))
    }
    fn offboard(
        &mut self,
        gid: GroupId,
        admin: WalletAddress,
        removed: WalletAddress,
        remove_commit: Envelope,
        ratchet_tree: Vec<u8>,
        now: u64,
    ) -> Result<u64, String> {
        self.0
            .offboard(
                OffboardRequest {
                    group_id: gid,
                    admin,
                    admin_assertion: None,
                    removed,
                    remove_commit,
                    ratchet_tree,
                },
                now,
            )
            .map_err(|e| e.to_string())
    }
}

// ---------------------------------------------------------------------------
// WsRelay — the networked relay (a comms-wire WS client), for cross-node groups.
// ---------------------------------------------------------------------------

use comms_wire::RelayClient;
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, Instant};
use tokio::runtime::Runtime;
use tokio::task::JoinHandle;

/// Timing for a [`WsRelay`]. [`Default`] is production; tests shorten it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WsTiming {
    /// How often the client pings the relay (a link silent for 3 intervals is dead).
    pub keepalive: Duration,
    /// Backoff ceiling after the first failed redial; doubles per failure up to `reconnect_max`.
    pub reconnect_min: Duration,
    /// Largest backoff ceiling.
    pub reconnect_max: Duration,
    /// A dial (TCP + TLS + WebSocket + delivery opt-in) not done by now has failed.
    pub connect_timeout: Duration,
    /// A relay op with no answer by now has failed and its link is retired. Below citrate-core's
    /// 5 s IPC timeout, so a half-open socket never stalls the daemon longer than Core waits.
    pub op_timeout: Duration,
    /// How often the background supervisor checks the link.
    pub supervise_tick: Duration,
}

impl Default for WsTiming {
    fn default() -> Self {
        WsTiming {
            keepalive: comms_wire::client::KEEPALIVE_INTERVAL,
            reconnect_min: Duration::from_secs(1),
            reconnect_max: Duration::from_secs(60),
            connect_timeout: Duration::from_secs(4),
            op_timeout: Duration::from_secs(3),
            supervise_tick: Duration::from_millis(100),
        }
    }
}

/// A full-jitter wait: uniform in `[0, ceiling]` from the random `r`. Spreads a fleet-wide redial
/// (a relay restart, a forced update) instead of every client knocking at the same instant.
pub fn jittered(ceiling: Duration, r: u64) -> Duration {
    let ms = ceiling.as_millis() as u64;
    Duration::from_millis(r % ms.saturating_add(1))
}

fn random_u64() -> Option<u64> {
    let mut b = [0u8; 8];
    getrandom::getrandom(&mut b).ok()?;
    Some(u64::from_le_bytes(b))
}

/// The link state, shared by the sync op path and the background supervisor.
struct Shared {
    /// The signed-in link ops use. `None` (or a dead client) while down.
    client: Option<Arc<RelayClient>>,
    /// Installed by the supervisor; the daemon has not republished its KeyPackage on it yet.
    fresh: bool,
    /// Backoff ceiling for the next failure. Reset only once a session is fully up.
    delay: Duration,
    next_dial: Option<Instant>,
    failures: u32,
    last_error: Option<String>,
}

impl Shared {
    fn alive(&self) -> bool {
        self.client.as_ref().is_some_and(|c| c.is_alive())
    }

    /// A failure: wait a jittered time under the current ceiling, then double the ceiling.
    fn back_off(&mut self, why: String, timing: &WsTiming) {
        let wait = match random_u64() {
            Some(r) => jittered(self.delay, r),
            None => self.delay,
        };
        self.next_dial = Some(Instant::now() + wait);
        self.delay = (self.delay * 2).min(timing.reconnect_max);
        self.failures = self.failures.saturating_add(1);
        self.last_error = Some(why);
    }
}

fn lock(m: &Mutex<Shared>) -> MutexGuard<'_, Shared> {
    m.lock().unwrap_or_else(|e| e.into_inner())
}

/// A networked, server-blind relay: a `comms-wire::RelayClient` over `ws://`, wrapped so the SYNC
/// daemon can drive it (a dedicated tokio runtime + `block_on`). This is the CX-S3.2 shared-relay,
/// WS-clients transport — two members on two nodes point their daemons at the same relay. Security
/// is UNCHANGED: E2E MLS + SIWE/wallet binding; the relay only ever sees ciphertext.
///
/// A background supervisor (on this relay's runtime) redials a dropped link with full-jitter
/// exponential backoff and signs in again with the [`SessionSigner`], so no request ever waits on a
/// redial: ops on a down link fail at once, and `relayStatus` answers from the current state. The
/// daemon republishes its KeyPackage on the next op ([`Relay::take_fresh_session`]); only then does
/// the backoff start again from its minimum.
pub struct WsRelay {
    rt: Runtime,
    shared: Arc<Mutex<Shared>>,
    signer: Arc<Mutex<Option<SessionSigner>>>,
    timing: WsTiming,
    supervisor: JoinHandle<()>,
}

impl WsRelay {
    /// Connect to a relay at `url` (the client's connection hardening enforces `wss://` off
    /// loopback). Blocks until connected.
    pub fn connect(url: &str) -> Result<Self, String> {
        Self::build(url, false, WsTiming::default())
    }
    /// Connect permitting plaintext `ws://` (loopback/dev/tests only).
    pub fn connect_insecure(url: &str) -> Result<Self, String> {
        Self::build(url, true, WsTiming::default())
    }
    /// [`Self::connect_insecure`] with explicit timing (tests).
    pub fn connect_insecure_with(url: &str, timing: WsTiming) -> Result<Self, String> {
        Self::build(url, true, timing)
    }
    fn build(url: &str, insecure: bool, timing: WsTiming) -> Result<Self, String> {
        let rt = Runtime::new().map_err(|e| e.to_string())?;
        let client = rt.block_on(dial(url, insecure, timing))?;
        let shared = Arc::new(Mutex::new(Shared {
            client: Some(Arc::new(client)),
            fresh: false,
            delay: timing.reconnect_min,
            next_dial: None,
            failures: 0,
            last_error: None,
        }));
        let signer: Arc<Mutex<Option<SessionSigner>>> = Arc::new(Mutex::new(None));
        let supervisor = rt.spawn(supervise(
            shared.clone(),
            signer.clone(),
            url.to_string(),
            insecure,
            timing,
        ));
        Ok(WsRelay {
            rt,
            shared,
            signer,
            timing,
            supervisor,
        })
    }

    /// The live link, or why there is none (ops fail at once on a down link; they never redial).
    fn client(&self) -> Result<Arc<RelayClient>, String> {
        let s = lock(&self.shared);
        match &s.client {
            Some(c) if c.is_alive() => Ok(c.clone()),
            _ => Err(match &s.last_error {
                Some(e) => format!("the relay link is down and redialing ({e})"),
                None => "the relay link is down and redialing".to_string(),
            }),
        }
    }

    /// Run one relay op on the live link, bounded by `op_timeout`. A timeout or a closed socket
    /// retires the link, so a late answer is never read as the reply to the next request; the
    /// supervisor then redials.
    fn call<T, Fut>(&self, op: impl FnOnce(Arc<RelayClient>) -> Fut) -> Result<T, String>
    where
        Fut: std::future::Future<Output = Result<T, comms_wire::WsError>>,
    {
        let c = self.client()?;
        let fut = op(c.clone());
        let limit = self.timing.op_timeout;
        match self
            .rt
            .block_on(async move { tokio::time::timeout(limit, fut).await })
        {
            Ok(Ok(v)) => Ok(v),
            Ok(Err(e)) => {
                if matches!(e, comms_wire::WsError::Closed) {
                    c.mark_dead();
                }
                Err(e.to_string())
            }
            Err(_) => {
                c.mark_dead();
                Err(format!(
                    "the relay did not answer within {} ms; reconnecting",
                    limit.as_millis()
                ))
            }
        }
    }
}

impl Drop for WsRelay {
    fn drop(&mut self) {
        self.supervisor.abort();
    }
}

/// Dial `url` and opt in to tracked delivery, bounded by `connect_timeout`.
async fn dial(url: &str, insecure: bool, timing: WsTiming) -> Result<RelayClient, String> {
    let fut = async {
        let (c, _nonce) =
            RelayClient::connect_with_keepalive(url, insecure, timing.keepalive).await?;
        // GC-1 review P2: tracked delivery, opted in before sign-in. A relay that
        // predates it answers false and the session stays on untracked delivery.
        c.enable_delivery_acks().await?;
        Ok::<_, comms_wire::WsError>(c)
    };
    match tokio::time::timeout(timing.connect_timeout, fut).await {
        Ok(r) => r.map_err(|e| e.to_string()),
        Err(_) => Err(format!(
            "could not reach the relay within {} ms",
            timing.connect_timeout.as_millis()
        )),
    }
}

/// Dial, then sign in with `signer` (if one is set), bounded by the op timeout.
async fn dial_and_sign_in(
    url: &str,
    insecure: bool,
    timing: WsTiming,
    signer: Option<SessionSigner>,
) -> Result<RelayClient, String> {
    let c = dial(url, insecure, timing).await?;
    if let Some(sg) = signer {
        let sign_in = async {
            let nonce = c.challenge().await.map_err(|e| e.to_string())?;
            let msg = siwe_message(&sg.domain, sg.address, nonce, wall_ms());
            let sig = (sg.sign)(&msg);
            c.authenticate(msg, sig).await.map_err(|e| e.to_string())
        };
        match tokio::time::timeout(timing.op_timeout, sign_in).await {
            Ok(Ok(_)) => {}
            Ok(Err(e)) => return Err(format!("sign-in after reconnect failed: {e}")),
            Err(_) => return Err("sign-in after reconnect timed out".to_string()),
        }
    }
    Ok(c)
}

/// The background supervisor: whenever the link is down and the backoff is due, redial and sign
/// in. The backoff ceiling is NOT reset here; it is reset by [`Relay::session_ready`] once the
/// daemon has republished its KeyPackage, so a relay that accepts the socket but refuses the
/// sign-in keeps backing off instead of being redialed every second.
async fn supervise(
    shared: Arc<Mutex<Shared>>,
    signer: Arc<Mutex<Option<SessionSigner>>>,
    url: String,
    insecure: bool,
    timing: WsTiming,
) {
    loop {
        tokio::time::sleep(timing.supervise_tick).await;
        let due = {
            let s = lock(&shared);
            !s.alive() && s.next_dial.is_none_or(|t| Instant::now() >= t)
        };
        if !due {
            continue;
        }
        let sg = signer.lock().unwrap_or_else(|e| e.into_inner()).clone();
        let result = dial_and_sign_in(&url, insecure, timing, sg).await;
        let mut s = lock(&shared);
        match result {
            Ok(c) => {
                if let Some(old) = s.client.replace(Arc::new(c)) {
                    old.mark_dead();
                }
                s.fresh = true;
                s.next_dial = None;
                eprintln!("comms-member-daemon: relay redialed and signed in");
            }
            Err(e) => {
                eprintln!("comms-member-daemon: relay redial failed: {e}");
                s.back_off(e, &timing);
            }
        }
    }
}

/// Wall-clock milliseconds since the Unix epoch (0 if the clock is before it).
fn wall_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

impl Relay for WsRelay {
    fn ack_delivered(&mut self) -> Result<(), String> {
        self.call(|c| async move { c.ack_delivered().await })
    }
    fn is_connected(&self) -> bool {
        // Flag-A — the live link state, with no round trip: the socket is open, signed in, and the
        // relay answered within the keepalive window. It used to send a `Challenge` per probe, and
        // the relay caps challenges per connection (CM2-B-B009), so after ~29 probes every probe
        // and every sign-in nonce failed on a healthy socket.
        lock(&self.shared).alive()
    }
    fn set_session_signer(&mut self, signer: SessionSigner) {
        *self.signer.lock().unwrap_or_else(|e| e.into_inner()) = Some(signer);
    }
    fn take_fresh_session(&mut self) -> bool {
        let mut s = lock(&self.shared);
        std::mem::take(&mut s.fresh) && s.alive()
    }
    fn session_ready(&mut self) {
        let mut s = lock(&self.shared);
        s.delay = self.timing.reconnect_min;
        s.failures = 0;
        s.last_error = None;
    }
    fn mark_down(&mut self, why: &str) {
        let mut s = lock(&self.shared);
        if let Some(c) = s.client.take() {
            c.mark_dead();
        }
        s.fresh = false;
        s.back_off(why.to_string(), &self.timing);
    }
    fn link_status(&self) -> LinkStatus {
        let s = lock(&self.shared);
        if s.alive() {
            return LinkStatus::default();
        }
        LinkStatus {
            retry_in_secs: Some(
                s.next_dial
                    .map(|t| t.saturating_duration_since(Instant::now()).as_secs())
                    .unwrap_or(0),
            ),
            last_error: s.last_error.clone(),
            failures: s.failures,
        }
    }
    fn issue_challenge(&mut self, _now: u64) -> Result<String, String> {
        self.call(|c| async move { c.challenge().await })
    }
    fn authenticate(&mut self, msg: &SiweMessage, sig: &[u8; 65], _now: u64) -> Result<(), String> {
        let (msg, sig) = (msg.clone(), *sig);
        self.call(move |c| async move { c.authenticate(msg, sig).await })
            .map(|_| ())
    }
    fn publish_key_package(
        &mut self,
        pubn: KeyPackagePublication,
        _now: u64,
    ) -> Result<(), String> {
        self.call(move |c| async move { c.publish_key_package(pubn).await })
    }
    fn take_key_package(
        &mut self,
        wallet: &WalletAddress,
    ) -> Result<Option<KeyPackagePublication>, String> {
        let wallet = *wallet;
        self.call(move |c| async move { c.take_key_package(wallet).await })
    }
    fn submit_claim(
        &mut self,
        _submitter: WalletAddress,
        submission: ClaimSubmission,
    ) -> Result<(), String> {
        self.call(move |c| async move { c.submit_claim(submission).await })
    }
    fn poll_claims(
        &mut self,
        _poller: WalletAddress,
        token_hash: [u8; 32],
    ) -> Result<Vec<ClaimSubmission>, String> {
        self.call(move |c| async move { c.poll_claims(token_hash).await })
    }
    fn register_group(
        &mut self,
        gid: GroupId,
        _owner: WalletAddress,
        _now: u64,
    ) -> Result<(), String> {
        self.call(move |c| async move { c.register_group(gid).await })
    }
    fn submit_as(
        &mut self,
        _sender: WalletAddress,
        env: Envelope,
        _now: u64,
    ) -> Result<u64, String> {
        self.call(move |c| async move { c.submit(env).await })
    }
    fn onboard(
        &mut self,
        gid: GroupId,
        _admin: WalletAddress,
        joiner: WalletAddress,
        welcome: Envelope,
        ratchet_tree: Vec<u8>,
        _now: u64,
    ) -> Result<(), String> {
        self.call(move |c| async move { c.onboard(gid, joiner, None, welcome, ratchet_tree).await })
    }
    fn publish_invite(
        &mut self,
        _inviter: WalletAddress,
        gid: GroupId,
        token_hash: [u8; 32],
        group_info: Vec<u8>,
        expires_at: u64,
    ) -> Result<(), String> {
        // The relay binds the inviter to the authenticated WS session, so `_inviter` is
        // not sent — the session principal is authoritative (FWA-C11-01 pattern).
        self.call(move |c| async move {
            c.publish_invite(gid, token_hash, group_info, expires_at)
                .await
        })
    }
    fn revoke_invite(
        &mut self,
        _caller: WalletAddress,
        token_hash: [u8; 32],
        report_used: bool,
    ) -> Result<(), String> {
        self.call(move |c| async move { c.revoke_invite(token_hash, report_used).await })
    }
    fn redeem_invite(
        &mut self,
        _joiner: WalletAddress,
        gid: GroupId,
        token: Vec<u8>,
        key_package: Vec<u8>,
        _now: u64,
    ) -> Result<(Vec<u8>, u64), String> {
        use comms_wire::frames::RedeemInviteResult;
        match self.call(move |c| async move { c.redeem_invite(gid, token, key_package).await })? {
            RedeemInviteResult::Ok { group_info, epoch } => Ok((group_info, epoch)),
            RedeemInviteResult::Err(reason) => Err(reason.as_str().to_string()),
        }
    }
    fn fetch(&mut self, _wallet: &WalletAddress) -> Vec<Envelope> {
        // Drain what the relay has PUSHED to this session (the WS client only receives its own
        // envelopes). Bounded per-item timeout so an empty mailbox returns promptly. A down link
        // has nothing to drain; the relay sends unacknowledged mail again at the next sign-in.
        let Ok(c) = self.client() else {
            return Vec::new();
        };
        self.rt.block_on(async move {
            let mut out = Vec::new();
            while let Ok(Some(env)) =
                tokio::time::timeout(Duration::from_millis(20), c.next_delivered()).await
            {
                out.push(env);
            }
            out
        })
    }
    fn ratchet_tree(&mut self, gid: GroupId) -> Result<Option<Vec<u8>>, String> {
        self.call(move |c| async move { c.ratchet_tree(gid).await })
    }
    fn group_members(&mut self, gid: GroupId) -> Result<Option<Vec<WalletAddress>>, String> {
        self.call(move |c| async move { c.group_members(gid).await })
    }
    fn offboard(
        &mut self,
        gid: GroupId,
        _admin: WalletAddress,
        removed: WalletAddress,
        remove_commit: Envelope,
        ratchet_tree: Vec<u8>,
        _now: u64,
    ) -> Result<u64, String> {
        self.call(move |c| async move {
            c.offboard(gid, removed, None, remove_commit, ratchet_tree)
                .await
        })
    }
}

#[cfg(test)]
mod ws_tests {
    include!("ws_tests.rs");
}
