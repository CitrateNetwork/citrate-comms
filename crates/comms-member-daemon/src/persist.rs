//! Durable MLS + group-registry persistence for the member daemon (issue #3).
//!
//! The daemon holds every MLS secret and its group registry in RAM and re-inits
//! empty on each launch, so `list_groups` returns nothing after a restart. This
//! module snapshots both — the `MlsMember` provider keystore (all MLS secrets) and
//! the RAM group registry — to a single **encrypted** file under a state directory,
//! and rehydrates them on startup so groups survive a full restart with NO re-create.
//!
//! ## Security
//!
//! * **Never plaintext.** The whole snapshot is sealed with AES-256-GCM-SIV
//!   (RFC 8452, nonce-misuse-resistant), a fresh random 96-bit nonce prepended to
//!   the ciphertext, and a mandatory AAD (a version/context string) that binds the
//!   blob to this format and rejects cross-context reuse.
//! * **Key.** 32 bytes derived from the daemon's identity seed via
//!   `blake3::derive_key` under a fixed context string, kept `Zeroizing`. The seed is
//!   the sole identity anchor (it already survives restarts); the state key is a pure
//!   function of it, so no new long-term secret is introduced.
//! * **Fail-closed.** A present-but-undecryptable/corrupt state file is a hard error
//!   at startup (wrong seed, truncation, tamper) — the daemon must NOT silently start
//!   empty and lose the operator's groups.
//! * **Pure Rust.** AES-GCM-SIV + BLAKE3 + getrandom + ciborium only — no RocksDB,
//!   no C deps — so the daemon keeps cross-compiling to `x86_64-pc-windows-*`.
//!
//! This does not alter the CM2-B-A009 zeroization residual: the live OpenMLS heap
//! copies are still not wiped on drop. Persistence only adds an *encrypted-at-rest*
//! copy; the snapshot bytes are held in `Zeroizing` buffers while in this process.

use std::fs;
use std::io::Write as _;
use std::path::{Path, PathBuf};

use aes_gcm_siv::aead::{Aead, Payload};
use aes_gcm_siv::{Aes256GcmSiv, Key, KeyInit, Nonce};
use comms_proto::{GroupId, Role, WalletAddress};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

/// State file basename inside the state directory.
pub const STATE_FILE_NAME: &str = "mls-state.bin";

/// KDF context that binds the state key to this exact use of the seed.
const KDF_CONTEXT: &str = "citrate-comms daemon mls-state v1";

/// Mandatory AEAD associated data — a version/context tag. Present on every seal and
/// required on every open, so a blob from another context/version fails to decrypt.
const AEAD_AAD: &[u8] = b"citrate-comms daemon mls-state v1";

/// On-disk format version (the plaintext record's own tag, distinct from the AAD).
const STATE_VERSION: u32 = 1;

/// AES-256-GCM-SIV nonce length (96-bit).
const NONCE_LEN: usize = 12;

#[derive(Debug, thiserror::Error)]
pub enum PersistError {
    #[error("state i/o error: {0}")]
    Io(String),
    #[error("state encode error: {0}")]
    Encode(String),
    #[error("state decode error: {0}")]
    Decode(String),
    #[error("rng failure")]
    Rng,
    #[error("state file could not be decrypted (wrong seed or tampered/corrupt file)")]
    Crypto,
    #[error("state file is corrupt (truncated)")]
    Corrupt,
    #[error("state file belongs to a different identity than the seed")]
    IdentityMismatch,
}

/// A group member as persisted (mirror of the daemon's in-RAM `MemberInfo`), so
/// roles and the wallet→leaf signature mapping survive a restart intact.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PersistedMember {
    pub wallet: WalletAddress,
    pub sig_pubkey: Vec<u8>,
    pub role: Role,
}

/// One group as persisted: the daemon's public [`GroupId`], the raw MLS group id
/// needed to reload the OpenMLS group from the rehydrated keystore, the friendly
/// name, the current epoch, and the full roster.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PersistedGroup {
    pub id: GroupId,
    pub mls_group_id: Vec<u8>,
    pub name: String,
    pub epoch: u64,
    pub members: Vec<PersistedMember>,
}

/// The full daemon snapshot: MLS secrets + group registry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StateFile {
    pub version: u32,
    /// The owner wallet-address bytes — checked against the seed-derived wallet on
    /// load so a state file cannot be paired with the wrong identity.
    pub identity: Vec<u8>,
    /// The MLS signature public key, used to re-read the signer from the keystore.
    pub sig_pubkey: Vec<u8>,
    /// The `MlsMember` provider keystore snapshot (all MLS secrets).
    pub mls_snapshot: Vec<u8>,
    /// The group registry.
    pub groups: Vec<PersistedGroup>,
}

impl StateFile {
    pub fn new(
        identity: Vec<u8>,
        sig_pubkey: Vec<u8>,
        mls_snapshot: Vec<u8>,
        groups: Vec<PersistedGroup>,
    ) -> Self {
        Self {
            version: STATE_VERSION,
            identity,
            sig_pubkey,
            mls_snapshot,
            groups,
        }
    }
}

/// Derive the 32-byte state key from the identity seed. Pure function of the seed,
/// domain-separated by [`KDF_CONTEXT`]; kept `Zeroizing`.
pub fn derive_state_key(seed: &[u8]) -> Zeroizing<[u8; 32]> {
    Zeroizing::new(blake3::derive_key(KDF_CONTEXT, seed))
}

/// The state file path inside `dir`.
pub fn state_file_path(dir: &Path) -> PathBuf {
    dir.join(STATE_FILE_NAME)
}

fn cipher(key: &[u8; 32]) -> Aes256GcmSiv {
    Aes256GcmSiv::new(Key::<Aes256GcmSiv>::from_slice(key))
}

/// Seal `plaintext` → `nonce ‖ ciphertext` under `key` with the mandatory AAD.
fn seal(key: &[u8; 32], plaintext: &[u8]) -> Result<Vec<u8>, PersistError> {
    let mut nonce = [0u8; NONCE_LEN];
    getrandom::getrandom(&mut nonce).map_err(|_| PersistError::Rng)?;
    let ct = cipher(key)
        .encrypt(
            Nonce::from_slice(&nonce),
            Payload {
                msg: plaintext,
                aad: AEAD_AAD,
            },
        )
        .map_err(|_| PersistError::Crypto)?;
    let mut out = Vec::with_capacity(NONCE_LEN + ct.len());
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&ct);
    Ok(out)
}

/// Open a `nonce ‖ ciphertext` blob. Fails closed on any auth failure.
fn open(key: &[u8; 32], blob: &[u8]) -> Result<Zeroizing<Vec<u8>>, PersistError> {
    if blob.len() < NONCE_LEN {
        return Err(PersistError::Corrupt);
    }
    let (nonce, ct) = blob.split_at(NONCE_LEN);
    let pt = cipher(key)
        .decrypt(
            Nonce::from_slice(nonce),
            Payload {
                msg: ct,
                aad: AEAD_AAD,
            },
        )
        .map_err(|_| PersistError::Crypto)?;
    Ok(Zeroizing::new(pt))
}

/// Create the state directory if absent (0700 on unix).
pub fn ensure_state_dir(dir: &Path) -> Result<(), PersistError> {
    if dir.exists() {
        return Ok(());
    }
    fs::create_dir_all(dir)
        .map_err(|e| PersistError::Io(format!("create {}: {e}", dir.display())))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(dir, fs::Permissions::from_mode(0o700))
            .map_err(|e| PersistError::Io(format!("chmod 0700 {}: {e}", dir.display())))?;
    }
    Ok(())
}

/// Encrypt `state` and write it atomically to `dir/mls-state.bin` (temp file in the
/// same directory + rename; 0600 on unix). The plaintext CBOR is held only in a
/// `Zeroizing` buffer.
pub fn write_state(dir: &Path, key: &[u8; 32], state: &StateFile) -> Result<(), PersistError> {
    ensure_state_dir(dir)?;
    let mut plaintext = Zeroizing::new(Vec::new());
    ciborium::into_writer(state, &mut *plaintext)
        .map_err(|e| PersistError::Encode(e.to_string()))?;
    let sealed = seal(key, &plaintext)?;

    let final_path = state_file_path(dir);
    let mut nonce = [0u8; 8];
    getrandom::getrandom(&mut nonce).map_err(|_| PersistError::Rng)?;
    let tmp_path = dir.join(format!("{STATE_FILE_NAME}.tmp.{}", hex::encode(nonce)));

    // Write + fsync the temp file, then atomically rename over the target.
    {
        let mut f = fs::File::create(&tmp_path)
            .map_err(|e| PersistError::Io(format!("create tmp {}: {e}", tmp_path.display())))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            f.set_permissions(fs::Permissions::from_mode(0o600))
                .map_err(|e| PersistError::Io(format!("chmod 0600 tmp: {e}")))?;
        }
        f.write_all(&sealed)
            .map_err(|e| PersistError::Io(format!("write tmp: {e}")))?;
        f.sync_all()
            .map_err(|e| PersistError::Io(format!("fsync tmp: {e}")))?;
    }
    fs::rename(&tmp_path, &final_path).map_err(|e| {
        // Best-effort cleanup of the temp file on a failed rename.
        let _ = fs::remove_file(&tmp_path);
        PersistError::Io(format!("rename into place: {e}"))
    })?;
    Ok(())
}

/// Load + decrypt the state file if present. `Ok(None)` means "no state file — first
/// run" (behave as today, empty). `Ok(Some(_))` is a fully verified snapshot. Any
/// present-but-bad file is an `Err` (fail closed — never a silent empty start).
///
/// `expected_identity` is the seed-derived wallet-address bytes; a mismatch is a hard
/// error so a state file cannot be silently paired with a different seed.
pub fn load_state(
    dir: &Path,
    key: &[u8; 32],
    expected_identity: &[u8],
) -> Result<Option<StateFile>, PersistError> {
    let path = state_file_path(dir);
    let blob = match fs::read(&path) {
        Ok(b) => b,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(PersistError::Io(format!("read {}: {e}", path.display()))),
    };
    let plaintext = open(key, &blob)?;
    let state: StateFile =
        ciborium::from_reader(&plaintext[..]).map_err(|e| PersistError::Decode(e.to_string()))?;
    if state.version != STATE_VERSION {
        return Err(PersistError::Decode(format!(
            "unsupported state version {} (expected {STATE_VERSION})",
            state.version
        )));
    }
    if state.identity != expected_identity {
        return Err(PersistError::IdentityMismatch);
    }
    Ok(Some(state))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp_dir() -> PathBuf {
        let mut rnd = [0u8; 8];
        getrandom::getrandom(&mut rnd).unwrap();
        std::env::temp_dir().join(format!("comms-persist-test-{}", hex::encode(rnd)))
    }

    fn sample(identity: &[u8]) -> StateFile {
        StateFile::new(
            identity.to_vec(),
            vec![1, 2, 3, 4],
            vec![9, 9, 9],
            vec![PersistedGroup {
                id: GroupId([7u8; 32]),
                mls_group_id: vec![1, 2, 3],
                name: "deals".into(),
                epoch: 2,
                members: vec![PersistedMember {
                    wallet: WalletAddress([0xabu8; 20]),
                    sig_pubkey: vec![5, 6],
                    role: Role::Owner,
                }],
            }],
        )
    }

    #[test]
    fn roundtrips_through_disk() {
        let dir = tmp_dir();
        let key = derive_state_key(b"seed-material-A");
        let st = sample(&[0xab; 20]);
        write_state(&dir, &key, &st).expect("write");

        let got = load_state(&dir, &key, &[0xab; 20])
            .expect("load ok")
            .expect("present");
        assert_eq!(got.groups.len(), 1);
        assert_eq!(got.groups[0].name, "deals");
        assert_eq!(got.groups[0].epoch, 2);
        assert_eq!(got.groups[0].members[0].role, Role::Owner);
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn absent_file_is_none() {
        let dir = tmp_dir();
        let key = derive_state_key(b"seed");
        assert!(load_state(&dir, &key, &[0u8; 20]).expect("ok").is_none());
    }

    #[test]
    fn wrong_seed_fails_closed() {
        let dir = tmp_dir();
        let key = derive_state_key(b"correct-seed");
        write_state(&dir, &key, &sample(&[0xab; 20])).expect("write");

        let wrong = derive_state_key(b"attacker-seed");
        let err = load_state(&dir, &wrong, &[0xab; 20]).expect_err("must fail closed");
        assert!(matches!(err, PersistError::Crypto), "got {err:?}");
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn corrupt_file_fails_closed() {
        let dir = tmp_dir();
        let key = derive_state_key(b"seed");
        write_state(&dir, &key, &sample(&[0xab; 20])).expect("write");
        // Flip a byte in the ciphertext body (past the nonce).
        let path = state_file_path(&dir);
        let mut bytes = std::fs::read(&path).unwrap();
        let idx = bytes.len() - 1;
        bytes[idx] ^= 0xff;
        std::fs::write(&path, &bytes).unwrap();

        let err = load_state(&dir, &key, &[0xab; 20]).expect_err("must fail closed");
        assert!(matches!(err, PersistError::Crypto), "got {err:?}");
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn identity_mismatch_fails_closed() {
        let dir = tmp_dir();
        let key = derive_state_key(b"seed");
        write_state(&dir, &key, &sample(&[0xab; 20])).expect("write");
        let err = load_state(&dir, &key, &[0xcd; 20]).expect_err("must reject foreign identity");
        assert!(matches!(err, PersistError::IdentityMismatch), "got {err:?}");
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn on_disk_bytes_are_not_plaintext() {
        let dir = tmp_dir();
        let key = derive_state_key(b"seed");
        // A recognizable marker inside the group name.
        let mut st = sample(&[0xab; 20]);
        st.groups[0].name = "SECRET-GROUP-NAME-marker".into();
        write_state(&dir, &key, &st).expect("write");
        let raw = std::fs::read(state_file_path(&dir)).unwrap();
        assert!(
            !raw.windows(b"SECRET-GROUP-NAME-marker".len())
                .any(|w| w == b"SECRET-GROUP-NAME-marker"),
            "group name must not appear in cleartext on disk"
        );
        std::fs::remove_dir_all(&dir).ok();
    }
}
