//! `store` — RocksDB persistence with AES-256-GCM-SIV column-family encryption (feature `store`).
//!
//! Matches the chain's at-rest grade (`citrate-chain/core/storage`): RocksDB 0.22 with
//! a **nonce-misuse-resistant** AEAD (AES-256-GCM-SIV, RFC 8452) and **mandatory AAD**
//! (the column-family name). Each column family has its own data key derived from a master
//! key via BLAKE3's keyed KDF; values are stored as `nonce(12) ‖ ciphertext+tag`.
//!
//! **Why SIV (FWA-C11-04):** the per-CF key is long-lived and `put` draws a fresh random
//! 96-bit nonce per write. Under plain AES-GCM a birthday-bound nonce collision (~2^32
//! writes for ~2^-33 collision, NIST SP 800-38D) would be catastrophic — a single reuse
//! leaks the keystream XOR and the GHASH authentication key. AES-GCM-SIV is built for
//! exactly this: a nonce reuse degrades only to *revealing whether two (nonce, AAD,
//! plaintext) triples were identical* — no keystream or auth-key disclosure. We keep the
//! random nonce (so distinct writes stay unlinkable) but are now safe even at relay scale.
//!
//! The master key is supplied by the caller (in production, wrapped by the chain's
//! `HybridKEM` key-management layer and unsealed from the OS keyring; that wrap is a
//! documented roadmap item, `PLANSET/07`, and is NOT yet implemented). This module gives
//! the relay a durable, encrypted, replayable store so it survives restart (R10).

use aes_gcm_siv::aead::{Aead, Payload};
use aes_gcm_siv::{Aes256GcmSiv, Key, KeyInit, Nonce};
use rocksdb::{ColumnFamilyDescriptor, IteratorMode, Options, DB};
use std::path::Path;
use zeroize::Zeroizing;

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
    /// The 32-byte master key. Held in `Zeroizing` so it is wiped when the store drops —
    /// no master key lingers in a freed allocation (`PLANSET/07` §2.2).
    master: Zeroizing<[u8; 32]>,
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
        Ok(Self { db, master: Zeroizing::new(master) })
    }

    fn cipher(&self, cf: &str) -> Aes256GcmSiv {
        // Per-CF data key: domain-separated keyed KDF over the master key. The derived key
        // is `Zeroizing` so it is wiped once the cipher has copied it in — the only place
        // the per-CF key exists in our memory is this short-lived buffer.
        // v2 = AES-256-GCM-SIV (v1 was plain AES-256-GCM). Bumping the KDF domain on the
        // algorithm change keeps the per-CF key bound to the suite that produced it.
        let cf_key = Zeroizing::new(blake3::derive_key(
            &format!("citrate-comms/store/cf/v2:{cf}"),
            self.master.as_ref(),
        ));
        Aes256GcmSiv::new(Key::<Aes256GcmSiv>::from_slice(cf_key.as_ref()))
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

    /// FWA-C11-04 (MED) red test — **nonce-misuse resistance** of the at-rest AEAD.
    ///
    /// The store draws a random 96-bit nonce per `put` under a long-lived per-CF key, so
    /// at relay scale a nonce *will eventually* repeat (birthday bound). This test forces
    /// the worst case — the SAME nonce on two DIFFERENT equal-length plaintexts — and
    /// asserts the catastrophic GCM failure mode does NOT occur:
    ///
    /// Under plain AES-GCM both ciphertexts share the keystream `E_k(nonce‖ctr)`, so
    /// `ct1 XOR ct2 == pt1 XOR pt2` — the attacker recovers the plaintext XOR (and the
    /// GHASH key). Under AES-256-GCM-SIV the synthetic IV is derived from the plaintext,
    /// so the two keystreams differ and that identity fails. We assert it fails.
    ///
    /// Before the GCM→GCM-SIV swap this test FAILED (the XOR identity held). After it, it
    /// passes — proving the at-rest layer is nonce-misuse-resistant.
    #[test]
    fn at_rest_aead_is_nonce_misuse_resistant() {
        use aes_gcm_siv::aead::{Aead, Payload};
        use aes_gcm_siv::{Aes256GcmSiv, Key, KeyInit, Nonce};

        let key_bytes = blake3::derive_key("citrate-comms/store/cf/v2:test", &[42u8; 32]);
        let cipher = Aes256GcmSiv::new(Key::<Aes256GcmSiv>::from_slice(&key_bytes));
        let nonce = Nonce::from_slice(&[9u8; 12]); // FORCE a reused nonce
        let aad = b"audit";

        let pt1 = b"PLAINTEXT-ONE-secret-deal-with-Acme--";
        let pt2 = b"PLAINTEXT-TWO-other-secret-message-XY";
        assert_eq!(pt1.len(), pt2.len(), "equal length to expose the keystream-XOR identity");

        let ct1 = cipher.encrypt(nonce, Payload { msg: pt1, aad }).unwrap();
        let ct2 = cipher.encrypt(nonce, Payload { msg: pt2, aad }).unwrap();

        // Strip the trailing 16-byte tag; compare just the ciphertext bodies.
        let body1 = &ct1[..pt1.len()];
        let body2 = &ct2[..pt2.len()];

        let ct_xor: Vec<u8> = body1.iter().zip(body2).map(|(a, b)| a ^ b).collect();
        let pt_xor: Vec<u8> = pt1.iter().zip(pt2).map(|(a, b)| a ^ b).collect();

        // The GCM catastrophe: ct1^ct2 == pt1^pt2 (keystream cancels). MUST NOT hold.
        assert_ne!(ct_xor, pt_xor, "nonce reuse must not leak the plaintext XOR (GCM-SIV resists misuse)");

        // Distinct plaintexts under a reused nonce still produce distinct ciphertexts and
        // each decrypts correctly.
        assert_ne!(body1, body2);
        assert_eq!(cipher.decrypt(nonce, Payload { msg: &ct1, aad }).unwrap(), pt1);
        assert_eq!(cipher.decrypt(nonce, Payload { msg: &ct2, aad }).unwrap(), pt2);
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
