//! `keyvault` — the at-rest master key, backed by the OS keyring (COMMS-S1).
//!
//! The relay's RocksDB column families are encrypted with AES-256-GCM under a 32-byte
//! master key (see `comms-core::store`). This module persists that key in the platform
//! keystore — macOS Keychain, Windows Credential Manager, or the Linux Secret Service —
//! generating one on first run, so the operator never has to manage key bytes by hand.
//!
//! Mirrors the `citrate-studio` `KeyringTokenStore` pattern. The deeper hardening step —
//! wrapping the stored key with the chain's PQ-hybrid `HybridKEM` (Kyber-768 + X25519)
//! before it touches the keystore — slots in at [`master_key_for`] without changing the
//! daemon's call site.

use keyring::Entry;

/// Keyring service + account the relay stores its master key under.
pub const KEYRING_SERVICE: &str = "citrate-comms";
pub const KEYRING_ACCOUNT: &str = "relay-master-key";

/// Load the master key from the OS keyring, generating + storing one on first run.
pub fn load_or_create_master_key(service: &str, account: &str) -> Result<[u8; 32], KeyvaultError> {
    let entry = Entry::new(service, account).map_err(|e| KeyvaultError::Keyring(e.to_string()))?;
    master_key_for(&entry)
}

/// Get-or-create against a specific keyring entry (the testable core).
fn master_key_for(entry: &Entry) -> Result<[u8; 32], KeyvaultError> {
    match entry.get_secret() {
        Ok(bytes) => bytes.as_slice().try_into().map_err(|_| KeyvaultError::BadLength),
        Err(keyring::Error::NoEntry) => {
            let mut key = [0u8; 32];
            getrandom::getrandom(&mut key).map_err(|_| KeyvaultError::Rng)?;
            entry.set_secret(&key).map_err(|e| KeyvaultError::Keyring(e.to_string()))?;
            Ok(key)
        }
        Err(e) => Err(KeyvaultError::Keyring(e.to_string())),
    }
}

#[derive(Debug, thiserror::Error)]
pub enum KeyvaultError {
    #[error("keyring error: {0}")]
    Keyring(String),
    #[error("stored master key is not 32 bytes")]
    BadLength,
    #[error("rng failure generating master key")]
    Rng,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn master_key_is_generated_once_then_reused() {
        // Use the in-memory mock keystore (no real OS keychain access in tests).
        keyring::set_default_credential_builder(keyring::mock::default_credential_builder());
        let entry = Entry::new("citrate-comms-test", "master-key-roundtrip").unwrap();

        let first = master_key_for(&entry).unwrap();
        let second = master_key_for(&entry).unwrap();
        assert_eq!(first, second, "the key generated on first run is reused thereafter");
        assert_ne!(first, [0u8; 32], "the generated key is not all-zero");
    }
}
