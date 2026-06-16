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
}

/// Whether networked mode is configured (the relay URL is set).
pub fn is_enabled() -> bool {
    std::env::var("CITRATE_COMMS_RELAY").is_ok()
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
            url: std::env::var("CITRATE_COMMS_RELAY").unwrap_or_default(),
            domain: std::env::var("CITRATE_COMMS_DOMAIN").unwrap_or_else(|_| "relay.citrate.ai".into()),
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
    system(&weak, &mut log, &format!("Signed in. Your address (share with your teammate): {me_hex}"));

    // Establish the channel: invite a peer, or wait to be invited.
    if let Some(peer_hex) = &cfg.peer {
        match WalletAddress::from_hex(peer_hex) {
            Ok(peer) => {
                system(&weak, &mut log, &format!("Inviting {peer_hex} to a new channel…"));
                if let Err(e) = session.create_channel(&[peer]).await {
                    system(&weak, &mut log, &format!("Couldn't invite them (have them sign in first): {e}"));
                    status(&weak, "offline", &endpoint, false);
                    return;
                }
                system(&weak, &mut log, "Channel created — waiting for them to join.");
            }
            Err(_) => {
                system(&weak, &mut log, "CITRATE_COMMS_PEER is not a valid 0x address.");
                status(&weak, "offline", &endpoint, false);
                return;
            }
        }
    } else {
        system(&weak, &mut log, "Waiting to be invited to a channel…");
        if let Err(e) = session.join_next_channel().await {
            system(&weak, &mut log, &format!("Join failed: {e}"));
            status(&weak, "offline", &endpoint, false);
            return;
        }
        system(&weak, &mut log, "Joined the channel ✅");
    }
    if session.in_channel() {
        if let Some(gid) = session.channel_id() {
            eprintln!("citrate-comms: live on channel {}", hex::encode(&gid.0[..6]));
        }
    }
    status(&weak, "live", &endpoint, true);

    // Pump: drain UI commands, then await the next delivery with a short timeout so we
    // loop back to check commands. (No select! — keeps the &self await and &mut self
    // mutation strictly sequential.)
    loop {
        loop {
            match cmd_rx.try_recv() {
                Ok(UiCmd::Send(text)) => match session.send_text(&text).await {
                    Ok(_) => push(&weak, &mut log, Line::mine(&me_hex, &text)),
                    Err(e) => system(&weak, &mut log, &format!("Send failed: {e}")),
                },
                Err(TryRecvError::Empty) => break,
                Err(TryRecvError::Disconnected) => return, // UI gone
            }
        }
        match tokio::time::timeout(Duration::from_millis(80), session.next_envelope()).await {
            Ok(Some(env)) => match session.apply(env) {
                Ok(Some(Inbound::Message { sender, text, .. })) => {
                    push(&weak, &mut log, Line::peer(&sender.to_hex(), &text))
                }
                Ok(Some(Inbound::System { text })) => system(&weak, &mut log, &text),
                Ok(None) => {}
                Err(e) => system(&weak, &mut log, &format!("Receive error: {e}")),
            },
            Ok(None) => {
                status(&weak, "disconnected", &endpoint, false);
                return;
            }
            Err(_) => {} // timeout tick — re-check commands
        }
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
