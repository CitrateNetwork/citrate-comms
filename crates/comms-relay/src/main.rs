//! `comms-relay` daemon — the self-hostable, server-blind relay binary.
//!
//! Opens an encrypted RocksDB store and serves the WebSocket transport. Binds to
//! loopback by default (on-prem / air-gap posture); override deliberately. It stores
//! and forwards ciphertext + routing metadata only — it never reads message plaintext.
//!
//! Configuration (env):
//!   CITRATE_COMMS_DOMAIN      logical relay domain bound in the SIWE handshake (default relay.citrate.ai)
//!   CITRATE_COMMS_BIND        listen address (default 127.0.0.1:8787 — loopback)
//!   CITRATE_COMMS_DATA        RocksDB store path (default ./data)
//!   CITRATE_COMMS_OWNER       workspace owner wallet, 0x + 40 hex (RBAC trust anchor) [required]
//!   CITRATE_COMMS_MASTER_KEY  at-rest master key, 64 hex (32 bytes) [required]
//!
//! The master key is read from the environment for now; wrapping it with the chain's
//! PQ-hybrid HybridKEM and unsealing from the OS keyring is the next hardening step
//! (PLANSET/07).

use std::env;
use std::time::{SystemTime, UNIX_EPOCH};

use comms_proto::WalletAddress;
use comms_relay::ws::RelayServer;
use comms_relay::DeliveryService;

fn now_ms() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_millis() as u64).unwrap_or(0)
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let domain = env::var("CITRATE_COMMS_DOMAIN").unwrap_or_else(|_| "relay.citrate.ai".into());
    let bind = env::var("CITRATE_COMMS_BIND").unwrap_or_else(|_| "127.0.0.1:8787".into());
    let data = env::var("CITRATE_COMMS_DATA").unwrap_or_else(|_| "./data".into());

    let owner_hex = env::var("CITRATE_COMMS_OWNER")
        .map_err(|_| "set CITRATE_COMMS_OWNER=0x<40 hex> (the workspace owner wallet)")?;
    let owner = WalletAddress::from_hex(&owner_hex).map_err(|_| "CITRATE_COMMS_OWNER must be a 20-byte hex address")?;

    let master_hex = env::var("CITRATE_COMMS_MASTER_KEY")
        .map_err(|_| "set CITRATE_COMMS_MASTER_KEY=<64 hex> (the 32-byte at-rest master key)")?;
    let master_vec = hex::decode(master_hex.trim_start_matches("0x")).map_err(|_| "master key must be hex")?;
    let master: [u8; 32] = master_vec.as_slice().try_into().map_err(|_| "master key must be 32 bytes (64 hex)")?;

    let service = DeliveryService::open(&data, domain.clone(), owner, master, now_ms())?;
    let server = RelayServer::new(service);
    let (addr, accept) = server.bind(&bind).await?;

    eprintln!("citrate-comms relay — serving {domain} on ws://{addr}");
    eprintln!("  owner (RBAC anchor): {}", owner.to_hex());
    eprintln!("  store: {data} (RocksDB + AES-256-GCM at rest)");
    eprintln!("  server-blind: stores ciphertext + routing metadata only; never reads plaintext");
    if !addr.ip().is_loopback() {
        eprintln!("  WARNING: bound to a non-loopback address — ensure TLS termination + access control");
    }

    accept.await?;
    Ok(())
}
