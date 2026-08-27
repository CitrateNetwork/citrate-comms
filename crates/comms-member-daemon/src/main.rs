//! citrate-comms member daemon — the binary.
//!
//! The member-client sidecar citrate-core Commons spawns. It runs a wallet-owned MLS member + an
//! in-process server-blind relay, and serves a loopback UDS JSON IPC. All config is via ENV (the
//! bearer token comes as a FILE PATH, never inline — argv/env leak to `ps`):
//!
//!   CITRATE_MEMBER_SOCKET      UDS path to bind (required)
//!   CITRATE_MEMBER_BEARER_FILE path to the 0600 bearer-token file the client wrote (required)
//!   CITRATE_MEMBER_SEED        32-byte hex secret key for the owner wallet (required — a STABLE
//!                              identity across restarts; citrate-core derives it from custody)
//!   CITRATE_MEMBER_DOMAIN      relay domain (default relay.citrate.internal)

use std::env;
use std::error::Error;
use std::fs;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use comms_core::identity::EthWallet;
use comms_member_daemon::{server, MemberDaemon};

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

    let seed_hex = required("CITRATE_MEMBER_SEED")?;
    let seed_bytes = hex::decode(seed_hex.trim()).map_err(|_| "CITRATE_MEMBER_SEED must be hex")?;
    let seed: [u8; 32] = seed_bytes
        .try_into()
        .map_err(|_| "CITRATE_MEMBER_SEED must be 32 bytes")?;
    let wallet = EthWallet::from_secret_key(&seed).map_err(|e| format!("bad seed: {e}"))?;

    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(1);

    let daemon = MemberDaemon::new(wallet, domain, now)?;
    eprintln!(
        "comms-member-daemon: owner {} serving on {}",
        hex::encode(daemon.owner().0),
        socket.display()
    );
    server::serve(daemon, &socket, &bearer)?;
    Ok(())
}
