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

/// The answer of [`Relay::reconnect`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Reconnect {
    /// The link is up; nothing was done.
    Up,
    /// A new link was dialed; the caller must sign in on it.
    Reconnected,
    /// The link is down and the next redial is not due yet.
    Waiting,
    /// A redial was tried now and failed (the reason).
    Failed(String),
}

/// A down link's state, reported to the app (`relayStatus`).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct LinkStatus {
    /// Seconds until the next redial, when one is scheduled.
    pub retry_in_secs: Option<u64>,
    /// Why the last redial or sign-in failed.
    pub last_error: Option<String>,
}

/// A server-blind relay the daemon talks to. Every op the [`crate::MemberDaemon`] needs; the owner
/// is the offboard trust anchor, so no admin assertion crosses this seam.
pub trait Relay: Send {
    fn issue_challenge(&mut self, now: u64) -> String;
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
    /// Bring a dropped link back. In-process relays are always up ([`Reconnect::Up`]). A
    /// networked relay redials on a backoff schedule; after [`Reconnect::Reconnected`] the caller
    /// must sign in again (the new socket has no session).
    fn reconnect(&mut self) -> Reconnect {
        Reconnect::Up
    }
    /// Count the link as down (a sign-in on a fresh link failed), so the next [`Self::reconnect`]
    /// redials on the backoff schedule instead of reusing it.
    fn mark_down(&mut self, _why: &str) {}
    /// What the link is doing while it is down: when it next redials, and why the last try failed.
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
    fn issue_challenge(&mut self, now: u64) -> String {
        self.0.issue_challenge(now)
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
use std::time::{Duration, Instant};
use tokio::runtime::Runtime;

/// First wait before redialing a dropped relay link; doubles per failure up to [`RECONNECT_MAX`].
const RECONNECT_MIN: Duration = Duration::from_secs(1);
/// Longest wait between redials.
const RECONNECT_MAX: Duration = Duration::from_secs(60);
/// A dial that has not connected by now has failed. Kept under citrate-core's 5 s IPC timeout,
/// since a redial runs inside the request that found the link down.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(4);
/// A relay op with no answer by now has failed, and its link is retired: the late answer would
/// otherwise be read as the reply to the next request.
const OP_TIMEOUT: Duration = Duration::from_secs(30);

/// A networked, server-blind relay: a `comms-wire::RelayClient` over `ws://`, wrapped so the SYNC
/// daemon can drive it (a dedicated tokio runtime + `block_on`). This is the CX-S3.2 shared-relay,
/// WS-clients transport — two members on two nodes point their daemons at the same relay. Security
/// is UNCHANGED: E2E MLS + SIWE/wallet binding; the relay only ever sees ciphertext.
///
/// A dropped link is redialed by [`Relay::reconnect`] with exponential backoff
/// ([`RECONNECT_MIN`]..[`RECONNECT_MAX`]); the client pings the relay every `keepalive` so an idle
/// link stays open and a dead one is noticed.
pub struct WsRelay {
    rt: Runtime,
    client: RelayClient,
    url: String,
    insecure: bool,
    keepalive: Duration,
    delay: Duration,
    next_dial: Option<Instant>,
    last_error: Option<String>,
}

impl WsRelay {
    /// Connect to a relay at `url` (the client's connection hardening enforces `wss://` off
    /// loopback). Blocks until connected.
    pub fn connect(url: &str) -> Result<Self, String> {
        Self::build(url, false, comms_wire::client::KEEPALIVE_INTERVAL)
    }
    /// Connect permitting plaintext `ws://` (loopback/dev/tests only).
    pub fn connect_insecure(url: &str) -> Result<Self, String> {
        Self::build(url, true, comms_wire::client::KEEPALIVE_INTERVAL)
    }
    /// [`Self::connect_insecure`] with an explicit keepalive interval (tests).
    pub fn connect_insecure_with_keepalive(url: &str, keepalive: Duration) -> Result<Self, String> {
        Self::build(url, true, keepalive)
    }
    fn build(url: &str, insecure: bool, keepalive: Duration) -> Result<Self, String> {
        let rt = Runtime::new().map_err(|e| e.to_string())?;
        let client = dial(&rt, url, insecure, keepalive)?;
        Ok(WsRelay {
            rt,
            client,
            url: url.to_string(),
            insecure,
            keepalive,
            delay: RECONNECT_MIN,
            next_dial: None,
            last_error: None,
        })
    }

    /// Schedule the next redial after a failure, doubling the wait.
    fn back_off(&mut self, why: String) {
        self.next_dial = Some(Instant::now() + self.delay);
        self.delay = (self.delay * 2).min(RECONNECT_MAX);
        self.last_error = Some(why);
    }

    /// Run one relay op, bounded by [`OP_TIMEOUT`]. A timeout or a closed socket retires the link
    /// (the next request redials instead of reading a stale answer).
    fn call<T>(
        &self,
        fut: impl std::future::Future<Output = Result<T, comms_wire::WsError>>,
    ) -> Result<T, String> {
        // The timer is built inside the runtime (a `Sleep` made outside it panics).
        match self
            .rt
            .block_on(async { tokio::time::timeout(OP_TIMEOUT, fut).await })
        {
            Ok(Ok(v)) => Ok(v),
            Ok(Err(e)) => {
                if matches!(e, comms_wire::WsError::Closed) {
                    self.client.mark_dead();
                }
                Err(e.to_string())
            }
            Err(_) => {
                self.client.mark_dead();
                Err(format!(
                    "the relay did not answer within {}s; reconnecting",
                    OP_TIMEOUT.as_secs()
                ))
            }
        }
    }
}

/// Dial `url`, opt in to tracked delivery, and return the client (bounded by [`CONNECT_TIMEOUT`]).
fn dial(
    rt: &Runtime,
    url: &str,
    insecure: bool,
    keepalive: Duration,
) -> Result<RelayClient, String> {
    let url = url.to_string();
    rt.block_on(async move {
        let fut = async {
            let (c, nonce) = RelayClient::connect_with_keepalive(&url, insecure, keepalive).await?;
            // GC-1 review P2: tracked delivery, opted in before sign-in. A relay that
            // predates it answers false and the session stays on untracked delivery.
            c.enable_delivery_acks().await?;
            Ok::<_, comms_wire::WsError>((c, nonce))
        };
        match tokio::time::timeout(CONNECT_TIMEOUT, fut).await {
            Ok(r) => r.map(|(c, _relay_key)| c).map_err(|e| e.to_string()),
            Err(_) => Err(format!(
                "could not reach the relay within {}s",
                CONNECT_TIMEOUT.as_secs()
            )),
        }
    })
}

impl Relay for WsRelay {
    fn ack_delivered(&mut self) -> Result<(), String> {
        self.call(self.client.ack_delivered())
    }
    fn is_connected(&self) -> bool {
        // Flag-A — the live link state, with no round trip: the socket is open and the relay
        // answered within the keepalive window. It used to send a `Challenge` per probe, and the
        // relay caps challenges per connection (CM2-B-B009), so after ~31 probes every probe and
        // every sign-in nonce failed on a healthy socket.
        self.client.is_alive()
    }
    fn reconnect(&mut self) -> Reconnect {
        if self.client.is_alive() {
            return Reconnect::Up;
        }
        if self.next_dial.is_some_and(|t| Instant::now() < t) {
            return Reconnect::Waiting;
        }
        match dial(&self.rt, &self.url, self.insecure, self.keepalive) {
            Ok(c) => {
                self.client = c;
                self.delay = RECONNECT_MIN;
                self.next_dial = None;
                self.last_error = None;
                Reconnect::Reconnected
            }
            Err(e) => {
                self.back_off(e.clone());
                Reconnect::Failed(e)
            }
        }
    }
    fn mark_down(&mut self, why: &str) {
        self.client.mark_dead();
        self.back_off(why.to_string());
    }
    fn link_status(&self) -> LinkStatus {
        LinkStatus {
            retry_in_secs: self
                .next_dial
                .map(|t| t.saturating_duration_since(Instant::now()).as_secs()),
            last_error: self.last_error.clone(),
        }
    }
    fn issue_challenge(&mut self, _now: u64) -> String {
        // A failure here surfaces at authenticate/publish (which then fail loudly).
        self.call(self.client.challenge()).unwrap_or_default()
    }
    fn authenticate(&mut self, msg: &SiweMessage, sig: &[u8; 65], _now: u64) -> Result<(), String> {
        self.call(self.client.authenticate(msg.clone(), *sig))
            .map(|_| ())
    }
    fn publish_key_package(
        &mut self,
        pubn: KeyPackagePublication,
        _now: u64,
    ) -> Result<(), String> {
        self.call(self.client.publish_key_package(pubn))
    }
    fn take_key_package(
        &mut self,
        wallet: &WalletAddress,
    ) -> Result<Option<KeyPackagePublication>, String> {
        self.call(self.client.take_key_package(*wallet))
    }
    fn submit_claim(
        &mut self,
        _submitter: WalletAddress,
        submission: ClaimSubmission,
    ) -> Result<(), String> {
        self.call(self.client.submit_claim(submission))
    }
    fn poll_claims(
        &mut self,
        _poller: WalletAddress,
        token_hash: [u8; 32],
    ) -> Result<Vec<ClaimSubmission>, String> {
        self.call(self.client.poll_claims(token_hash))
    }
    fn register_group(
        &mut self,
        gid: GroupId,
        _owner: WalletAddress,
        _now: u64,
    ) -> Result<(), String> {
        self.call(self.client.register_group(gid))
    }
    fn submit_as(
        &mut self,
        _sender: WalletAddress,
        env: Envelope,
        _now: u64,
    ) -> Result<u64, String> {
        self.call(self.client.submit(env))
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
        self.call(
            self.client
                .onboard(gid, joiner, None, welcome, ratchet_tree),
        )
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
        self.call(
            self.client
                .publish_invite(gid, token_hash, group_info, expires_at),
        )
    }
    fn revoke_invite(
        &mut self,
        _caller: WalletAddress,
        token_hash: [u8; 32],
        report_used: bool,
    ) -> Result<(), String> {
        self.call(self.client.revoke_invite(token_hash, report_used))
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
        match self.call(self.client.redeem_invite(gid, token, key_package))? {
            RedeemInviteResult::Ok { group_info, epoch } => Ok((group_info, epoch)),
            RedeemInviteResult::Err(reason) => Err(reason.as_str().to_string()),
        }
    }
    fn fetch(&mut self, _wallet: &WalletAddress) -> Vec<Envelope> {
        // Drain what the relay has PUSHED to this session (the WS client only receives its own
        // envelopes). Bounded per-item timeout so an empty mailbox returns promptly.
        self.rt.block_on(async {
            let mut out = Vec::new();
            while let Ok(Some(env)) = tokio::time::timeout(
                std::time::Duration::from_millis(20),
                self.client.next_delivered(),
            )
            .await
            {
                out.push(env);
            }
            out
        })
    }
    fn ratchet_tree(&mut self, gid: GroupId) -> Result<Option<Vec<u8>>, String> {
        self.call(self.client.ratchet_tree(gid))
    }
    fn group_members(&mut self, gid: GroupId) -> Result<Option<Vec<WalletAddress>>, String> {
        self.call(self.client.group_members(gid))
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
        self.call(
            self.client
                .offboard(gid, removed, None, remove_commit, ratchet_tree),
        )
    }
}

#[cfg(test)]
mod ws_tests {
    include!("ws_tests.rs");
}
