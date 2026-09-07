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
//! one on first run (`keyvault`). Wrapping it with the chain's `HybridKEM` (X25519 +
//! ML-KEM-768) before it touches the keystore is a roadmap item — NOT yet implemented
//! (PLANSET/07); the at-rest key is currently used directly with AES-256-GCM-SIV.

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

/// Non-reversible fingerprint of the admin bearer token for log correlation.
///
/// FWA-C11-07: the raw token must never reach stderr/journald. We emit a short
/// SHA-256 prefix (12 hex chars = 48 bits, enough to correlate an instance, far
/// too little to recover the 256-bit token) plus the token byte-length, clearly
/// labeled as a fingerprint so it is never mistaken for the secret itself.
fn redact_token(token: &str) -> String {
    use sha2::{Digest, Sha256};
    let digest = Sha256::digest(token.as_bytes());
    let fp = hex::encode(&digest[..6]); // 12 hex chars
    format!("sha256:{fp}… len={}", token.len())
}

/// Write the admin bearer token to `path` with owner-only (0600) permissions.
///
/// This is the sanctioned channel for tooling that needs the real token, instead
/// of scraping it from logs. The file is created/truncated and chmod'd 0600 on
/// unix before the secret is written.
fn write_token_file(path: &str, token: &str) -> std::io::Result<()> {
    use std::io::Write;
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    let mut f = opts.open(path)?;
    f.write_all(token.as_bytes())?;
    f.flush()
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
    // Held in a `Zeroizing` wrapper so the decoded key is wiped from memory on drop
    // rather than left resident for the process lifetime (CM2-B-A009).
    let (master, key_source): (zeroize::Zeroizing<[u8; 32]>, String) =
        match env::var("CITRATE_COMMS_MASTER_KEY") {
            Ok(hex_key) => {
                let v = zeroize::Zeroizing::new(
                    hex::decode(hex_key.trim_start_matches("0x"))
                        .map_err(|_| "master key must be hex")?,
                );
                let arr: [u8; 32] = v
                    .as_slice()
                    .try_into()
                    .map_err(|_| "master key must be 32 bytes (64 hex)")?;
                (
                    zeroize::Zeroizing::new(arr),
                    "environment (explicit)".to_string(),
                )
            }
            Err(_) => {
                let key = keyvault::load_or_create_master_key(
                    keyvault::KEYRING_SERVICE,
                    keyvault::KEYRING_ACCOUNT,
                )?;
                (
                    key,
                    format!(
                        "OS keyring ({}/{})",
                        keyvault::KEYRING_SERVICE,
                        keyvault::KEYRING_ACCOUNT
                    ),
                )
            }
        };

    let service = DeliveryService::open(&data, domain.clone(), owner, *master, now_ms())?;
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
    // FWA-C11-07: never print the admin bearer token in cleartext — a journald/log
    // reader would gain admin-surface control. Log only a redacted fingerprint so
    // operators can correlate the running instance; the real token is exported via
    // the CITRATE_COMMS_ADMIN_TOKEN_FILE path below for tooling that needs it.
    eprintln!("  admin auth: bearer enabled (token fp {})", redact_token(&admin_token));
    match env::var("CITRATE_COMMS_ADMIN_TOKEN_FILE") {
        Ok(path) => match write_token_file(&path, &admin_token) {
            Ok(()) => eprintln!("  admin token written to {path} (0600)"),
            Err(e) => eprintln!("  WARNING: failed to write admin token file {path}: {e}"),
        },
        Err(_) => eprintln!(
            "  admin token: set CITRATE_COMMS_ADMIN_TOKEN_FILE=<path> to export it (0600); not logged"
        ),
    }
    if !addr.ip().is_loopback() {
        eprintln!("  WARNING: bound to a non-loopback address — ensure TLS termination + access control");
    }

    accept.await?;
    Ok(())
}

#[cfg(test)]
mod fwa_c11_07 {
    use super::{redact_token, write_token_file};

    /// A realistic admin token: 32 random bytes hex-encoded (64 chars), exactly as
    /// generated in `main`.
    const SAMPLE_TOKEN: &str =
        "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

    /// Regression for FWA-C11-07: the redacted fingerprint must NOT contain the raw
    /// token, must be clearly labeled, and must not be reversible to the token.
    #[test]
    fn redacted_fingerprint_does_not_leak_token() {
        let fp = redact_token(SAMPLE_TOKEN);
        assert!(!fp.contains(SAMPLE_TOKEN), "redacted log leaked the full token: {fp}");
        // No long run of the token's hex should survive (guard against partial leak).
        assert!(!fp.contains(&SAMPLE_TOKEN[..16]), "redacted log leaked a token prefix: {fp}");
        assert!(fp.starts_with("sha256:"), "fingerprint must be clearly labeled: {fp}");
        // The fingerprint is a 12-hex SHA-256 prefix — far too short to recover 256 bits.
        assert!(fp.contains("len=64"));
    }

    /// Distinct tokens yield distinct fingerprints (so operators can still correlate).
    #[test]
    fn fingerprint_is_token_specific() {
        let a = redact_token(SAMPLE_TOKEN);
        let b = redact_token("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
        assert_ne!(a, b);
    }

    /// The sanctioned token-export channel writes the secret to a file, not the log,
    /// with owner-only permissions on unix.
    #[test]
    fn token_file_is_written_with_0600() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("admin.token");
        let path_str = path.to_str().unwrap();
        write_token_file(path_str, SAMPLE_TOKEN).unwrap();
        let got = std::fs::read_to_string(&path).unwrap();
        assert_eq!(got, SAMPLE_TOKEN);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o600, "token file must be 0600, got {mode:o}");
        }
    }
}
