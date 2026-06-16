//! `sign-manifest` — attach (or verify) an Ed25519 signature on a release manifest
//! (COMMS-S4 WP-4.7). The signing key is read from `RELEASE_SIGNING_KEY_HEX` (64 hex =
//! 32-byte Ed25519 seed); soft-key signing marks a bundle pre-production. The HSM swap-in
//! keeps the same wire form — see `docs/audit/HSM_SEAM.md`.
//!
//! Usage:
//!   RELEASE_SIGNING_KEY_HEX=<64hex> sign-manifest --input m.toml --out m.toml
//!   sign-manifest --verify --input m.toml

use std::process::ExitCode;

use comms_release::Manifest;
use ed25519_dalek::SigningKey;

fn main() -> ExitCode {
    match run() {
        Ok(msg) => {
            eprintln!("{msg}");
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("sign-manifest: {e}");
            ExitCode::FAILURE
        }
    }
}

fn run() -> Result<String, String> {
    let mut input = None;
    let mut out = None;
    let mut verify = false;

    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--input" => input = args.next(),
            "--out" => out = args.next(),
            "--verify" => verify = true,
            other => return Err(format!("unknown argument: {other}")),
        }
    }
    let input = input.ok_or("--input is required")?;
    let toml = std::fs::read_to_string(&input).map_err(|e| e.to_string())?;
    let mut manifest = Manifest::from_toml(&toml).map_err(|e| e.to_string())?;

    if verify {
        let vk = manifest.verify().map_err(|e| e.to_string())?;
        return Ok(format!("signature OK — signed by {}", hex::encode(vk.to_bytes())));
    }

    let key_hex = std::env::var("RELEASE_SIGNING_KEY_HEX")
        .map_err(|_| "RELEASE_SIGNING_KEY_HEX not set (64 hex = 32-byte Ed25519 seed)")?;
    let seed: [u8; 32] = hex::decode(key_hex.trim())
        .map_err(|_| "RELEASE_SIGNING_KEY_HEX must be hex")?
        .as_slice()
        .try_into()
        .map_err(|_| "RELEASE_SIGNING_KEY_HEX must be 32 bytes (64 hex)")?;
    let key = SigningKey::from_bytes(&seed);
    manifest.sign(&key).map_err(|e| e.to_string())?;
    // Sanity: the signature we just wrote verifies.
    manifest.verify().map_err(|e| format!("self-verify failed: {e}"))?;

    let out = out.unwrap_or(input);
    std::fs::write(&out, manifest.to_toml().map_err(|e| e.to_string())?).map_err(|e| e.to_string())?;
    Ok(format!("signed {out} with {}", hex::encode(key.verifying_key().to_bytes())))
}
