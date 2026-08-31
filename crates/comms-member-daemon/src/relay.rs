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
        self.0.fetch(wallet)
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
use tokio::runtime::Runtime;

/// A networked, server-blind relay: a `comms-wire::RelayClient` over `ws://`, wrapped so the SYNC
/// daemon can drive it (a dedicated tokio runtime + `block_on`). This is the CX-S3.2 shared-relay,
/// WS-clients transport — two members on two nodes point their daemons at the same relay. Security
/// is UNCHANGED: E2E MLS + SIWE/wallet binding; the relay only ever sees ciphertext.
pub struct WsRelay {
    rt: Runtime,
    client: RelayClient,
}

impl WsRelay {
    /// Connect to a relay at `url` (the client's connection hardening enforces `wss://` off
    /// loopback). Blocks until connected.
    pub fn connect(url: &str) -> Result<Self, String> {
        Self::build(url, false)
    }
    /// Connect permitting plaintext `ws://` (loopback/dev/tests only).
    pub fn connect_insecure(url: &str) -> Result<Self, String> {
        Self::build(url, true)
    }
    fn build(url: &str, insecure: bool) -> Result<Self, String> {
        let rt = Runtime::new().map_err(|e| e.to_string())?;
        let url = url.to_string();
        let client = rt
            .block_on(async move {
                if insecure {
                    RelayClient::connect_insecure(&url).await
                } else {
                    RelayClient::connect(&url).await
                }
            })
            .map(|(c, _relay_key)| c)
            .map_err(|e| e.to_string())?;
        Ok(WsRelay { rt, client })
    }
}

impl Relay for WsRelay {
    fn issue_challenge(&mut self, _now: u64) -> String {
        // A WS challenge failure surfaces at authenticate (which will then fail loudly).
        self.rt
            .block_on(self.client.challenge())
            .unwrap_or_default()
    }
    fn authenticate(&mut self, msg: &SiweMessage, sig: &[u8; 65], _now: u64) -> Result<(), String> {
        self.rt
            .block_on(self.client.authenticate(msg.clone(), *sig))
            .map(|_| ())
            .map_err(|e| e.to_string())
    }
    fn publish_key_package(
        &mut self,
        pubn: KeyPackagePublication,
        _now: u64,
    ) -> Result<(), String> {
        self.rt
            .block_on(self.client.publish_key_package(pubn))
            .map_err(|e| e.to_string())
    }
    fn take_key_package(
        &mut self,
        wallet: &WalletAddress,
    ) -> Result<Option<KeyPackagePublication>, String> {
        self.rt
            .block_on(self.client.take_key_package(*wallet))
            .map_err(|e| e.to_string())
    }
    fn submit_claim(
        &mut self,
        _submitter: WalletAddress,
        submission: ClaimSubmission,
    ) -> Result<(), String> {
        self.rt
            .block_on(self.client.submit_claim(submission))
            .map_err(|e| e.to_string())
    }
    fn poll_claims(
        &mut self,
        _poller: WalletAddress,
        token_hash: [u8; 32],
    ) -> Result<Vec<ClaimSubmission>, String> {
        self.rt
            .block_on(self.client.poll_claims(token_hash))
            .map_err(|e| e.to_string())
    }
    fn register_group(
        &mut self,
        gid: GroupId,
        _owner: WalletAddress,
        _now: u64,
    ) -> Result<(), String> {
        self.rt
            .block_on(self.client.register_group(gid))
            .map_err(|e| e.to_string())
    }
    fn submit_as(
        &mut self,
        _sender: WalletAddress,
        env: Envelope,
        _now: u64,
    ) -> Result<u64, String> {
        self.rt
            .block_on(self.client.submit(env))
            .map_err(|e| e.to_string())
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
        self.rt
            .block_on(
                self.client
                    .onboard(gid, joiner, None, welcome, ratchet_tree),
            )
            .map_err(|e| e.to_string())
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
        self.rt
            .block_on(self.client.ratchet_tree(gid))
            .map_err(|e| e.to_string())
    }
    fn group_members(&mut self, gid: GroupId) -> Result<Option<Vec<WalletAddress>>, String> {
        self.rt
            .block_on(self.client.group_members(gid))
            .map_err(|e| e.to_string())
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
        self.rt
            .block_on(
                self.client
                    .offboard(gid, removed, None, remove_commit, ratchet_tree),
            )
            .map_err(|e| e.to_string())
    }
}

#[cfg(test)]
mod ws_tests {
    include!("ws_tests.rs");
}
