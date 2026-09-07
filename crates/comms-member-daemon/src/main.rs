//! citrate-comms member daemon — the binary.
//!
//! The member-client sidecar citrate-core Commons spawns. It runs a wallet-owned MLS member + an
//! in-process server-blind relay, and serves a loopback UDS JSON IPC. All config is via ENV (the
//! bearer token comes as a FILE PATH, never inline — argv/env leak to `ps`):
//!
//!   CITRATE_MEMBER_SOCKET      UDS path to bind (required)
//!   CITRATE_MEMBER_BEARER_FILE path to the 0600 bearer-token file the client wrote (required)
//!   CITRATE_MEMBER_SEED_FILE   path to a 0600 file holding the 32-byte hex secret key (PREFERRED —
//!                              the seed never crosses env/argv, which leak to `ps`; citrate-core
//!                              seals a scoped secp256k1 comms key in the OS keyring and writes it
//!                              here at spawn). Falls back to CITRATE_MEMBER_SEED if unset.
//!   CITRATE_MEMBER_SEED        32-byte hex secret key inline (back-compat / tests only — a STABLE
//!                              identity across restarts). Prefer CITRATE_MEMBER_SEED_FILE.
//!   CITRATE_MEMBER_DOMAIN      relay domain (default relay.citrate.internal)

use std::env;
use std::error::Error;
use std::fs;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use comms_core::identity::EthWallet;
use comms_member_daemon::relay::{Relay, WsRelay};
use comms_member_daemon::{server, MemberDaemon};
use zeroize::Zeroizing;

fn required(key: &str) -> Result<String, String> {
    env::var(key).map_err(|_| format!("{key} is required"))
}

fn main() -> Result<(), Box<dyn Error>> {
    let socket = PathBuf::from(required("CITRATE_MEMBER_SOCKET")?);
    let bearer_file = required("CITRATE_MEMBER_BEARER_FILE")?;
    let bearer = fs::read_to_string(&bearer_file)
        .map_err(|e| format!("reading bearer file {bearer_file}: {e}"))?
        .trim()
        .to_string();
    if bearer.is_empty() {
        return Err("bearer file is empty (fail closed)".into());
    }
    let domain = env::var("CITRATE_MEMBER_DOMAIN").unwrap_or_else(|_| "relay.citrate.internal".into());

    // Seed: prefer a 0600 FILE (the secret never crosses env/argv, which leak to `ps`), mirroring
    // the bearer. Fall back to the inline CITRATE_MEMBER_SEED for back-compat / tests.
    //
    // Every copy of the secret key material is held in `Zeroizing` so it is wiped from
    // memory on drop rather than left resident for the daemon's lifetime (CM2-B-A009):
    // the hex text, the decoded bytes, and the fixed 32-byte array.
    let seed_hex = Zeroizing::new(
        match env::var("CITRATE_MEMBER_SEED_FILE")
            .ok()
            .filter(|p| !p.is_empty())
        {
            Some(path) => {
                fs::read_to_string(&path).map_err(|e| format!("reading seed file {path}: {e}"))?
            }
            None => required("CITRATE_MEMBER_SEED")?,
        },
    );
    let seed_trimmed = seed_hex.trim();
    if seed_trimmed.is_empty() {
        return Err("seed is empty (fail closed)".into());
    }
    let seed_bytes = Zeroizing::new(hex::decode(seed_trimmed).map_err(|_| "seed must be hex")?);
    let seed: Zeroizing<[u8; 32]> = Zeroizing::new(
        seed_bytes
            .as_slice()
            .try_into()
            .map_err(|_| "seed must be 32 bytes")?,
    );
    let wallet = EthWallet::from_secret_key(&seed).map_err(|e| format!("bad seed: {e}"))?;

    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(1);

    // Relay transport: a shared networked relay (CITRATE_MEMBER_RELAY_URL, ws://|wss://) for
    // cross-node groups, else a local in-process relay (single node).
    let daemon = match env::var("CITRATE_MEMBER_RELAY_URL").ok().filter(|u| !u.is_empty()) {
        Some(url) => {
            let ws: Box<dyn Relay> = Box::new(WsRelay::connect(&url).map_err(|e| format!("relay {url}: {e}"))?);
            MemberDaemon::new_with_relay(wallet, ws, domain, now)?
        }
        None => MemberDaemon::new(wallet, domain, now)?,
    };
    eprintln!(
        "comms-member-daemon: owner {} serving on {}",
        hex::encode(daemon.owner().0),
        socket.display()
    );
    server::serve(daemon, &socket, &bearer)?;
    Ok(())
}
