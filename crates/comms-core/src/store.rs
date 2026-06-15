//! `store` — RocksDB persistence with AES-256-GCM column-family encryption (feature `store`).
//!
//! Matches the chain's at-rest grade (`citrate-chain/core/storage`): RocksDB 0.22 with
//! AES-256-GCM and **mandatory AAD** (the column-family name). Each column family has its
//! own data key derived from a master key via BLAKE3's keyed KDF; values are stored as
//! `nonce(12) ‖ ciphertext+tag`.
//!
//! The master key is supplied by the caller (in production, wrapped by the chain's
//! PQ-hybrid `HybridKEM` — Kyber-768 + X25519 — and unsealed from the OS keyring; that
//! key-management wrap is the next hardening step, `PLANSET/07`). This module gives the
//! relay a durable, encrypted, replayable store so it survives restart (R10).

use aes_gcm::aead::{Aead, Payload};
use aes_gcm::{Aes256Gcm, Key, KeyInit, Nonce};
use rocksdb::{ColumnFamilyDescriptor, IteratorMode, Options, DB};
use std::path::Path;

/// Column families the relay persists (ciphertext + metadata only — never plaintext).
pub const CF_ENVELOPES: &str = "envelopes"; // group_id(32) ‖ seq(8 BE) -> Envelope
pub const CF_KEYPACKAGES: &str = "keypackages"; // wallet(20) ‖ idx(8 BE) -> KeyPackagePublication
pub const CF_AUDIT: &str = "audit"; // seq(8 BE) -> AuditRecord
pub const CF_MEMBERSHIP: &str = "membership"; // group_id(32) -> GroupSnapshot
pub const CF_META: &str = "meta"; // small key/value (owner, domain, …)

const CFS: [&str; 5] = [CF_ENVELOPES, CF_KEYPACKAGES, CF_AUDIT, CF_MEMBERSHIP, CF_META];

/// Decrypted `(key, value)` pairs returned by [`EncryptedStore::scan`].
pub type KvPairs = Vec<(Vec<u8>, Vec<u8>)>;

/// An encrypted RocksDB store. Cheap to clone keys; the DB handle is owned.
pub struct EncryptedStore {
    db: DB,
    master: [u8; 32],
}

impl EncryptedStore {
    /// Open (creating if absent) an encrypted store at `path` with the given master key.
    pub fn open(path: impl AsRef<Path>, master: [u8; 32]) -> Result<Self, StoreError> {
        let mut opts = Options::default();
        opts.create_if_missing(true);
        opts.create_missing_column_families(true);
        let cfs = CFS
            .iter()
            .map(|n| ColumnFamilyDescriptor::new(*n, Options::default()))
            .collect::<Vec<_>>();
        let db = DB::open_cf_descriptors(&opts, path, cfs).map_err(|e| StoreError::Db(e.to_string()))?;
        Ok(Self { db, master })
    }

    fn cipher(&self, cf: &str) -> Aes256Gcm {
        // Per-CF data key: domain-separated keyed KDF over the master key.
        let cf_key = blake3::derive_key(&format!("citrate-comms/store/cf/v1:{cf}"), &self.master);
        Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&cf_key))
    }

    /// Encrypt + store `plaintext` under `key` in column family `cf` (AAD = cf name).
    pub fn put(&self, cf: &str, key: &[u8], plaintext: &[u8]) -> Result<(), StoreError> {
        let handle = self.db.cf_handle(cf).ok_or(StoreError::NoCf)?;
        let mut nonce = [0u8; 12];
        getrandom::getrandom(&mut nonce).map_err(|_| StoreError::Rng)?;
        let ct = self
            .cipher(cf)
            .encrypt(Nonce::from_slice(&nonce), Payload { msg: plaintext, aad: cf.as_bytes() })
            .map_err(|_| StoreError::Crypto)?;
        let mut val = Vec::with_capacity(12 + ct.len());
        val.extend_from_slice(&nonce);
        val.extend_from_slice(&ct);
        self.db.put_cf(handle, key, val).map_err(|e| StoreError::Db(e.to_string()))
    }

    /// Fetch + decrypt the value under `key` in `cf`.
    pub fn get(&self, cf: &str, key: &[u8]) -> Result<Option<Vec<u8>>, StoreError> {
        let handle = self.db.cf_handle(cf).ok_or(StoreError::NoCf)?;
        match self.db.get_cf(handle, key).map_err(|e| StoreError::Db(e.to_string()))? {
            None => Ok(None),
            Some(v) => Ok(Some(self.decrypt(cf, &v)?)),
        }
    }

    /// Scan a whole column family in key order, decrypting each value.
    pub fn scan(&self, cf: &str) -> Result<KvPairs, StoreError> {
        let handle = self.db.cf_handle(cf).ok_or(StoreError::NoCf)?;
        let mut out = Vec::new();
        for item in self.db.iterator_cf(handle, IteratorMode::Start) {
            let (k, v) = item.map_err(|e| StoreError::Db(e.to_string()))?;
            out.push((k.to_vec(), self.decrypt(cf, &v)?));
        }
        Ok(out)
    }

    fn decrypt(&self, cf: &str, raw: &[u8]) -> Result<Vec<u8>, StoreError> {
        if raw.len() < 12 {
            return Err(StoreError::Corrupt);
        }
        let (nonce, ct) = raw.split_at(12);
        self.cipher(cf)
            .decrypt(Nonce::from_slice(nonce), Payload { msg: ct, aad: cf.as_bytes() })
            .map_err(|_| StoreError::Crypto)
    }
}

/// Big-endian compound key helper: `prefix ‖ index`.
pub fn seq_key(prefix: &[u8], index: u64) -> Vec<u8> {
    let mut k = Vec::with_capacity(prefix.len() + 8);
    k.extend_from_slice(prefix);
    k.extend_from_slice(&index.to_be_bytes());
    k
}

#[derive(Debug, thiserror::Error)]
pub enum StoreError {
    #[error("rocksdb error: {0}")]
    Db(String),
    #[error("unknown column family")]
    NoCf,
    #[error("rng failure")]
    Rng,
    #[error("aead encrypt/decrypt failed (wrong key or tampered)")]
    Crypto,
    #[error("stored value is corrupt (too short)")]
    Corrupt,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp() -> std::path::PathBuf {
        let mut rnd = [0u8; 8];
        getrandom::getrandom(&mut rnd).unwrap();
        std::env::temp_dir().join(format!("comms-store-test-{}", hex::encode(rnd)))
    }

    #[test]
    fn put_get_scan_and_persist_across_reopen() {
        let path = tmp();
        let master = [7u8; 32];
        {
            let s = EncryptedStore::open(&path, master).unwrap();
            s.put(CF_AUDIT, &0u64.to_be_bytes(), b"genesis").unwrap();
            s.put(CF_AUDIT, &1u64.to_be_bytes(), b"record-1").unwrap();
            s.put(CF_META, b"owner", b"0xabc").unwrap();
            assert_eq!(s.get(CF_META, b"owner").unwrap().unwrap(), b"0xabc");
            let scanned = s.scan(CF_AUDIT).unwrap();
            assert_eq!(scanned.len(), 2);
            assert_eq!(scanned[0].1, b"genesis"); // key-ordered
            assert_eq!(scanned[1].1, b"record-1");
        }
        // Reopen — data survives, still decryptable with the same master key.
        {
            let s = EncryptedStore::open(&path, master).unwrap();
            assert_eq!(s.get(CF_META, b"owner").unwrap().unwrap(), b"0xabc");
            assert_eq!(s.scan(CF_AUDIT).unwrap().len(), 2);
        }
        // Wrong master key cannot decrypt (AEAD auth fails).
        {
            let s = EncryptedStore::open(&path, [9u8; 32]).unwrap();
            assert!(matches!(s.get(CF_META, b"owner"), Err(StoreError::Crypto)));
        }
        std::fs::remove_dir_all(&path).ok();
    }

    #[test]
    fn on_disk_bytes_are_not_plaintext() {
        let path = tmp();
        let s = EncryptedStore::open(&path, [3u8; 32]).unwrap();
        let secret = b"OWNER-0xdeadbeef-do-not-leak";
        s.put(CF_META, b"k", secret).unwrap();
        drop(s);
        // Grep the raw SST/log files — the plaintext must not appear on disk.
        let mut found = false;
        for entry in walk(&path) {
            if let Ok(bytes) = std::fs::read(&entry) {
                if bytes.windows(secret.len()).any(|w| w == secret) {
                    found = true;
                }
            }
        }
        assert!(!found, "plaintext leaked to disk");
        std::fs::remove_dir_all(&path).ok();
    }

    fn walk(dir: &std::path::Path) -> Vec<std::path::PathBuf> {
        let mut out = Vec::new();
        if let Ok(rd) = std::fs::read_dir(dir) {
            for e in rd.flatten() {
                let p = e.path();
                if p.is_dir() {
                    out.extend(walk(&p));
                } else {
                    out.push(p);
                }
            }
        }
        out
    }
}
