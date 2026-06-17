//! Networked driver (COMMS-S4 WP-4.10) — bridges the async [`NetSession`](crate::net)
//! to Slint's single-threaded event loop so two teammates on different machines can chat.
//!
//! Slint owns the main thread; the relay client is async. So we run the `NetSession` on a
//! dedicated background thread with a current-thread tokio runtime. The UI thread sends
//! [`UiCmd`]s down an `mpsc` channel; the driver pushes updates back to the UI with
//! [`slint::invoke_from_event_loop`] via a `Weak<AppWindow>`. Plaintext lives only on this
//! process's heap — the wire and the relay see ciphertext.
//!
//! Configuration (env), networked mode is enabled iff `CITRATE_COMMS_RELAY` is set:
//!   CITRATE_COMMS_RELAY           relay URL — `wss://comms.example.com` (or loopback `ws://…`)
//!   CITRATE_COMMS_DOMAIN          SIWE domain bound at login (must match the relay's domain)
//!   CITRATE_COMMS_PEER            if set (`0x…`): CREATE a channel and invite this peer;
//!                                 if unset: JOIN the next channel we're welcomed to
//!   CITRATE_COMMS_WALLET_ACCOUNT  OS-keyring account for our durable wallet (default below)
//!   CITRATE_COMMS_ALLOW_INSECURE_WS  permit plaintext ws:// to a non-loopback host (LAN)

use std::sync::mpsc::{Receiver, Sender, TryRecvError};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use comms_core::identity::EthWallet;
use comms_proto::WalletAddress;
use slint::{Color, ComponentHandle, ModelRc, SharedString, VecModel, Weak};

use crate::net::{Inbound, NetSession};
use crate::{AppWindow, Msg};

/// A command from the UI thread to the networked session.
pub enum UiCmd {
    Send(String),
    /// Create a channel and invite a peer by their `0x…` wallet address.
    CreateChannel(String),
}

/// Default production relay — the app talks to this out of the box (override with
/// `CITRATE_COMMS_RELAY`). Clean launch is networked; the in-process demo is opt-in.
pub const DEFAULT_RELAY: &str = "wss://comms.citrate.ai";
pub const DEFAULT_DOMAIN: &str = "comms.citrate.ai";

/// Networked mode is the default. The in-process demo (seeded fixtures) is opt-in via
/// `CITRATE_COMMS_DEMO=1`.
pub fn is_enabled() -> bool {
    std::env::var("CITRATE_COMMS_DEMO").is_err()
}

/// Spawn the background session thread. Returns the command sender the UI uses to post
/// messages. Call once, after the user signs in.
pub fn start(app: &AppWindow) -> Sender<UiCmd> {
    let (cmd_tx, cmd_rx) = std::sync::mpsc::channel::<UiCmd>();
    let weak = app.as_weak();
    let cfg = Cfg::from_env();
    std::thread::Builder::new()
        .name("comms-net".into())
        .spawn(move || match tokio::runtime::Builder::new_current_thread().enable_all().build() {
            Ok(rt) => rt.block_on(run(weak, cfg, cmd_rx)),
            Err(e) => eprintln!("citrate-comms: could not start network runtime: {e}"),
        })
        .ok();
    cmd_tx
}

struct Cfg {
    url: String,
    domain: String,
    peer: Option<String>,
    wallet_account: String,
    allow_insecure: bool,
}

impl Cfg {
    fn from_env() -> Self {
        Self {
            url: std::env::var("CITRATE_COMMS_RELAY").unwrap_or_else(|_| DEFAULT_RELAY.into()),
            domain: std::env::var("CITRATE_COMMS_DOMAIN").unwrap_or_else(|_| DEFAULT_DOMAIN.into()),
            peer: std::env::var("CITRATE_COMMS_PEER").ok().filter(|s| !s.is_empty()),
            wallet_account: std::env::var("CITRATE_COMMS_WALLET_ACCOUNT")
                .unwrap_or_else(|_| "client:default:wallet".into()),
            allow_insecure: std::env::var("CITRATE_COMMS_ALLOW_INSECURE_WS").is_ok(),
        }
    }

    /// Short label for the header pill (`host` of the relay URL).
    fn endpoint_label(&self) -> String {
        self.url
            .split_once("://")
            .map(|(_, rest)| rest.split(['/', '?']).next().unwrap_or(rest).to_string())
            .unwrap_or_else(|| self.url.clone())
    }
}

/// The driver: connect → login → publish KeyPackage → create/join a channel → pump
/// messages until the connection or the UI goes away.
async fn run(weak: Weak<AppWindow>, cfg: Cfg, cmd_rx: Receiver<UiCmd>) {
    let mut log: Vec<Line> = Vec::new();
    let endpoint = cfg.endpoint_label();
    status(&weak, "connecting…", &endpoint, false);

    let wallet = load_wallet(&cfg.wallet_account);
    let mut session = match NetSession::login(&cfg.url, &cfg.domain, wallet, now_ms(), cfg.allow_insecure).await {
        Ok(s) => s,
        Err(e) => {
            system(&weak, &mut log, &format!("Could not connect to {}: {e}", cfg.url));
            status(&weak, "offline", &endpoint, false);
            return;
        }
    };
    let me_hex = session.wallet().to_hex();
    if let Err(e) = session.publish_keypackage().await {
        system(&weak, &mut log, &format!("Could not publish your key: {e}"));
        status(&weak, "offline", &endpoint, false);
        return;
    }
    eprintln!("citrate-comms: signed in as {me_hex} on {}", cfg.url);
    status(&weak, "live", &endpoint, true);
    system(&weak, &mut log, &format!("Signed in. Your address: {me_hex}"));
    system(&weak, &mut log, "Share it with a teammate, then use Invite to start a channel — or wait to be invited.");

    // Convenience: if a peer was pre-set via env (CLI / airgap), create the channel now.
    if let Some(peer_hex) = cfg.peer.clone() {
        create_channel(&weak, &mut log, &mut session, &peer_hex).await;
    }

    // Pump: drain UI commands, then await the next delivery with a short timeout so we
    // loop back to check commands. (No select! — keeps the &self await and &mut self
    // mutation strictly sequential.)
    loop {
        loop {
            match cmd_rx.try_recv() {
                Ok(UiCmd::Send(text)) => {
                    if !session.in_channel() {
                        system(&weak, &mut log, "Create or join a channel first (Invite a teammate by their 0x address).");
                    } else {
                        match session.send_text(&text).await {
                            Ok(_) => push(&weak, &mut log, Line::mine(&me_hex, &text)),
                            Err(e) => system(&weak, &mut log, &format!("Send failed: {e}")),
                        }
                    }
                }
                Ok(UiCmd::CreateChannel(addr)) => {
                    create_channel(&weak, &mut log, &mut session, &addr).await;
                }
                Err(TryRecvError::Empty) => break,
                Err(TryRecvError::Disconnected) => return, // UI gone
            }
        }
        match tokio::time::timeout(Duration::from_millis(80), session.next_envelope()).await {
            Ok(Some(env)) => {
                // A Welcome pushed to us means a teammate invited us — auto-join.
                if env.kind == comms_proto::EnvelopeKind::Welcome && !session.in_channel() {
                    match session.join_from_welcome(&env).await {
                        Ok(_) => system(&weak, &mut log, "Joined the channel ✅"),
                        Err(e) => system(&weak, &mut log, &format!("Join failed: {e}")),
                    }
                    continue;
                }
                match session.apply(env) {
                    Ok(Some(Inbound::Message { sender, text, .. })) => {
                        push(&weak, &mut log, Line::peer(&sender.to_hex(), &text))
                    }
                    Ok(Some(Inbound::System { text })) => system(&weak, &mut log, &text),
                    Ok(None) => {}
                    Err(e) => system(&weak, &mut log, &format!("Receive error: {e}")),
                }
            }
            Ok(None) => {
                status(&weak, "disconnected", &endpoint, false);
                return;
            }
            Err(_) => {} // timeout tick — re-check commands
        }
    }
}

/// Create a channel and invite `addr` (a `0x…` wallet). The peer must have signed in
/// already (so their KeyPackage is published). Reports progress to the UI.
async fn create_channel(weak: &Weak<AppWindow>, log: &mut Vec<Line>, session: &mut NetSession, addr: &str) {
    let addr = addr.trim();
    let peer = match WalletAddress::from_hex(addr) {
        Ok(p) => p,
        Err(_) => {
            system(weak, log, &format!("\"{addr}\" is not a valid 0x wallet address."));
            return;
        }
    };
    if session.in_channel() {
        system(weak, log, "Already in a channel (one channel per session for now).");
        return;
    }
    system(weak, log, &format!("Inviting {addr} to a new channel…"));
    match session.create_channel(&[peer]).await {
        Ok(_) => system(weak, log, "Channel created — they'll join automatically when they're online."),
        Err(e) => system(weak, log, &format!("Couldn't invite them (are they signed in yet?): {e}")),
    }
}

/// A durable, keyring-backed wallet identity (stable across restarts). Falls back to an
/// ephemeral wallet if the keyring is unavailable — never panics (Rule 8).
fn load_wallet(account: &str) -> EthWallet {
    match comms_relay::keyvault::load_or_create_master_key("citrate-comms", account) {
        Ok(secret) => EthWallet::from_secret_key(&secret).unwrap_or_else(|_| EthWallet::generate()),
        Err(_) => EthWallet::generate(),
    }
}

fn now_ms() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_millis() as u64).unwrap_or(0)
}

// ───────────────────────────── UI rendering ─────────────────────────────

/// One rendered chat line.
#[derive(Clone)]
struct Line {
    author: String,
    text: String,
    system: bool,
    mine: bool,
}

impl Line {
    fn mine(addr_hex: &str, text: &str) -> Self {
        Self { author: addr_hex.into(), text: text.into(), system: false, mine: true }
    }
    fn peer(addr_hex: &str, text: &str) -> Self {
        Self { author: addr_hex.into(), text: text.into(), system: false, mine: false }
    }
    fn sys(text: &str) -> Self {
        Self { author: String::new(), text: text.into(), system: true, mine: false }
    }
}

fn system(weak: &Weak<AppWindow>, log: &mut Vec<Line>, text: &str) {
    push(weak, log, Line::sys(text));
}

fn push(weak: &Weak<AppWindow>, log: &mut Vec<Line>, line: Line) {
    log.push(line);
    render(weak, log);
}

/// Rebuild the message model on the UI thread from the accumulated log.
fn render(weak: &Weak<AppWindow>, log: &[Line]) {
    let snapshot = log.to_vec();
    let weak = weak.clone();
    let _ = slint::invoke_from_event_loop(move || {
        if let Some(app) = weak.upgrade() {
            let rows: Vec<Msg> = snapshot.iter().map(line_to_msg).collect();
            app.set_ws_messages(ModelRc::new(VecModel::from(rows)));
        }
    });
}

fn status(weak: &Weak<AppWindow>, label: &str, endpoint: &str, ok: bool) {
    let (weak, label, endpoint) = (weak.clone(), label.to_string(), endpoint.to_string());
    let _ = slint::invoke_from_event_loop(move || {
        if let Some(app) = weak.upgrade() {
            app.set_relay_status(label.into());
            app.set_relay_endpoint(endpoint.into());
            app.set_relay_ok(ok);
        }
    });
}

fn line_to_msg(l: &Line) -> Msg {
    let (author, initials, tint) = if l.system {
        ("citrate-comms".to_string(), "··".to_string(), (140, 140, 140))
    } else {
        (short_addr(&l.author), initials_of(&l.author), tint_for(&l.author))
    };
    Msg {
        author: author.into(),
        initials: initials.into(),
        tint: Color::from_rgb_u8(tint.0, tint.1, tint.2),
        role: if l.mine { "you".into() } else { SharedString::new() },
        ts: SharedString::new(),
        text: l.text.as_str().into(),
        is_agent: false,
        system: l.system,
        boundary: false,
        has_link: false,
        link_kind: SharedString::new(),
        link_name: SharedString::new(),
        link_id: SharedString::new(),
        state: SharedString::new(),
    }
}

/// `0x1f2e…9ad9` from a full hex address.
fn short_addr(hex: &str) -> String {
    let h = hex.strip_prefix("0x").unwrap_or(hex);
    if h.len() >= 8 {
        format!("0x{}…{}", &h[..4], &h[h.len() - 4..])
    } else {
        hex.to_string()
    }
}

fn initials_of(hex: &str) -> String {
    let h = hex.strip_prefix("0x").unwrap_or(hex);
    h.get(..2).unwrap_or("0x").to_uppercase()
}

/// A stable brand-ish tint derived from the address bytes.
fn tint_for(hex: &str) -> (u8, u8, u8) {
    let bytes = blake3::hash(hex.as_bytes());
    let b = bytes.as_bytes();
    // Bias toward the brand's muted, dark-on-paper palette.
    (40 + (b[0] >> 1), 50 + (b[1] >> 1), 20 + (b[2] >> 2))
}
