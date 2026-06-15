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
//!   CITRATE_COMMS_MASTER_KEY  at-rest master key, 64 hex (32 bytes) [optional override]
//!
//! The at-rest master key is taken from `CITRATE_COMMS_MASTER_KEY` when set (explicit /
//! air-gap / CI key management); otherwise it is loaded from the OS keyring, generating
//! one on first run (`keyvault`). Wrapping it with the chain's PQ-hybrid HybridKEM before
//! it touches the keystore is the next hardening step (PLANSET/07).

use std::env;
use std::time::{SystemTime, UNIX_EPOCH};

use comms_proto::WalletAddress;
use comms_relay::admin::serve_admin;
use comms_relay::keyvault;
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

    // At-rest master key: explicit env override, else the OS keyring (create on first run).
    let (master, key_source) = match env::var("CITRATE_COMMS_MASTER_KEY") {
        Ok(hex_key) => {
            let v = hex::decode(hex_key.trim_start_matches("0x")).map_err(|_| "master key must be hex")?;
            let arr: [u8; 32] = v.as_slice().try_into().map_err(|_| "master key must be 32 bytes (64 hex)")?;
            (arr, "environment (explicit)".to_string())
        }
        Err(_) => {
            let key = keyvault::load_or_create_master_key(keyvault::KEYRING_SERVICE, keyvault::KEYRING_ACCOUNT)?;
            (key, format!("OS keyring ({}/{})", keyvault::KEYRING_SERVICE, keyvault::KEYRING_ACCOUNT))
        }
    };

    let service = DeliveryService::open(&data, domain.clone(), owner, master, now_ms())?;
    let server = RelayServer::new(service);
    let (addr, accept) = server.clone().bind(&bind).await?;

    // Bearer-gated, loopback-only admin surface.
    let admin_bind = env::var("CITRATE_COMMS_ADMIN_BIND").unwrap_or_else(|_| "127.0.0.1:8788".into());
    let mut tok = [0u8; 32];
    getrandom::getrandom(&mut tok).map_err(|_| "failed to generate admin token")?;
    let admin_token = hex::encode(tok);
    let (admin_addr, _admin) = serve_admin(server.clone(), &admin_bind, admin_token.clone()).await?;

    eprintln!("citrate-comms relay — serving {domain} on ws://{addr}");
    eprintln!("  owner (RBAC anchor): {}", owner.to_hex());
    eprintln!("  store: {data} (RocksDB + AES-256-GCM at rest)");
    eprintln!("  master key: {key_source}");
    eprintln!("  server-blind: stores ciphertext + routing metadata only; never reads plaintext");
    eprintln!("  admin: http://{admin_addr} (loopback-only)  GET /health|/status  POST /pause|/resume");
    eprintln!("  admin bearer token: {admin_token}");
    if !addr.ip().is_loopback() {
        eprintln!("  WARNING: bound to a non-loopback address — ensure TLS termination + access control");
    }

    accept.await?;
    Ok(())
}
