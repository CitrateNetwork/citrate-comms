//! `identity` — the SIWE login handshake and the wallet→MLS binding attestation.
//!
//! Reuses the security properties of `citrate-identity/src/siwe.ts` (`verifySiweLogin`):
//! a single-use nonce (replay defence), chain binding to 40204, domain binding
//! (anti-phishing), expiry, low-S ECDSA (anti-malleability), and secp256k1 address
//! recovery. The durable identity is the recovered wallet address.
//!
//! The handshake carries a structured [`SiweMessage`]; both client and relay derive the
//! signed bytes through the *same* [`SiweMessage::to_signing_string`], so the signature is
//! over the exact EIP-4361 field set. (Byte-exact interop with viem's text parser is an
//! S1 item — the security-relevant fields are all bound here.)
//!
//! `identity` holds NO MLS secrets and is compiled into the relay too: every function
//! here is public-key verification or client-side signing — the relay only verifies.

use comms_proto::{KeyPackagePublication, WalletAddress, CITRATE_CHAIN_ID};
use k256::ecdsa::{RecoveryId, Signature, SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha3::{Digest, Keccak256};
use std::collections::HashMap;

const ATTEST_DOMAIN: &[u8] = b"citrate-comms/binding-attestation/v1";

// ───────────────────────────── nonce store ─────────────────────────────

/// Single-use nonce directory (the relay's replay defence). Mirrors the
/// `NonceStore` contract in `siwe.ts`: `issue` once, `consume` once.
pub trait NonceStore {
    fn issue(&mut self, nonce: String, issued_at_ms: u64);
    /// Remove the nonce; returns true iff it was present (i.e. not already used).
    fn consume(&mut self, nonce: &str) -> bool;
}

/// In-memory nonce store (dev / single-relay). A Redis-backed store lands in S1.
#[derive(Default)]
pub struct InMemoryNonceStore {
    nonces: HashMap<String, u64>,
}

impl InMemoryNonceStore {
    /// A nonce older than this can no longer complete a SIWE login (verification also
    /// enforces the message's own expiration), so it is safe to evict. Bounds the
    /// store against an unauthenticated peer looping `Challenge` (CIT-COMMS-005).
    const NONCE_TTL_MS: u64 = 10 * 60 * 1000; // 10 minutes

    pub fn new() -> Self {
        Self::default()
    }
    /// Issue a fresh random nonce (32 bytes hex) and record it.
    pub fn fresh(&mut self, issued_at_ms: u64) -> String {
        let mut bytes = [0u8; 32];
        rand_core::OsRng.fill_bytes(&mut bytes);
        let nonce = hex::encode(bytes);
        self.issue(nonce.clone(), issued_at_ms);
        nonce
    }
}

impl NonceStore for InMemoryNonceStore {
    fn issue(&mut self, nonce: String, issued_at_ms: u64) {
        // CIT-COMMS-005: evict expired nonces before inserting, so the store cannot be
        // inflated without bound by looping the pre-auth `Challenge` frame. Insert-only
        // was a memory-exhaustion vector on the single-droplet relay.
        self.nonces
            .retain(|_, &mut issued| issued_at_ms.saturating_sub(issued) < Self::NONCE_TTL_MS);
        self.nonces.insert(nonce, issued_at_ms);
    }
    fn consume(&mut self, nonce: &str) -> bool {
        self.nonces.remove(nonce).is_some()
    }
}

use rand_core::RngCore;

// ───────────────────────────── SIWE message ─────────────────────────────

/// EIP-4361 field set carried over the WS handshake.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SiweMessage {
    pub domain: String,
    pub address: WalletAddress,
    pub statement: String,
    pub uri: String,
    pub version: String,
    pub chain_id: u64,
    pub nonce: String,
    pub issued_at_ms: u64,
    pub expiration_ms: u64,
}

impl SiweMessage {
    /// The canonical signing string (EIP-4361 shaped). Both parties derive the
    /// signed bytes from exactly this function.
    pub fn to_signing_string(&self) -> String {
        format!(
            "{domain} wants you to sign in with your Ethereum account:\n{addr}\n\n{stmt}\n\n\
             URI: {uri}\nVersion: {ver}\nChain ID: {chain}\nNonce: {nonce}\n\
             Issued At: {iat}\nExpiration Time: {exp}",
            domain = self.domain,
            addr = self.address.to_hex(),
            stmt = self.statement,
            uri = self.uri,
            ver = self.version,
            chain = self.chain_id,
            nonce = self.nonce,
            iat = self.issued_at_ms,
            exp = self.expiration_ms,
        )
    }
}

/// The outcome of a verified login: the durable wallet identity.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct VerifiedLogin {
    pub address: WalletAddress,
}

/// Verify a SIWE login against the relay's expectations. On success the nonce is
/// consumed (so a replay fails), and the recovered address is returned.
pub fn verify_siwe_login(
    message: &SiweMessage,
    signature: &[u8; 65],
    expected_domain: &str,
    now_ms: u64,
    nonces: &mut dyn NonceStore,
) -> Result<VerifiedLogin, IdentityError> {
    // 1. Replay defence: the nonce must be live and is consumed up-front.
    if !nonces.consume(&message.nonce) {
        return Err(IdentityError::NonceUnknownOrUsed);
    }
    // 2. Chain binding (anti cross-chain replay).
    if message.chain_id != CITRATE_CHAIN_ID {
        return Err(IdentityError::WrongChain { expected: CITRATE_CHAIN_ID, found: message.chain_id });
    }
    // 3. Domain binding (anti-phishing).
    if message.domain != expected_domain {
        return Err(IdentityError::DomainMismatch);
    }
    // 4. Expiry.
    if now_ms >= message.expiration_ms {
        return Err(IdentityError::Expired);
    }
    // 5. Recover the signer over the EIP-191 personal-sign hash and bind to `address`.
    let digest = eth_personal_hash(message.to_signing_string().as_bytes());
    let recovered = recover_address(&digest, signature)?;
    if recovered != message.address {
        return Err(IdentityError::AddressMismatch);
    }
    Ok(VerifiedLogin { address: recovered })
}

// ──────────────────────── wallet → MLS binding attestation ────────────────────────

/// The 32-byte digest a wallet signs to bind an MLS signature key to itself
/// (`PLANSET/02` §2 step 6). Domain-separated; covers the relay domain + nonce so
/// the attestation cannot be replayed to a different relay or session.
pub fn binding_digest(
    wallet: &WalletAddress,
    mls_sig_pubkey: &[u8],
    relay_domain: &str,
    nonce: &str,
) -> [u8; 32] {
    let mut h = blake3::Hasher::new();
    h.update(ATTEST_DOMAIN);
    h.update(&wallet.0);
    h.update(mls_sig_pubkey);
    h.update(relay_domain.as_bytes());
    h.update(nonce.as_bytes());
    *h.finalize().as_bytes()
}

/// Verify that a published KeyPackage really belongs to the claimed wallet.
/// This is what defeats KeyPackage spoofing (R3) — the relay runs it before
/// admitting a KeyPackage to its directory. Public-key crypto over public data:
/// no plaintext is ever exposed.
pub fn verify_binding_attestation(pubn: &KeyPackagePublication) -> Result<(), IdentityError> {
    let sig: &[u8; 65] = pubn
        .binding_attestation
        .as_slice()
        .try_into()
        .map_err(|_| IdentityError::BadSignatureLength)?;
    let digest = binding_digest(&pubn.wallet, &pubn.mls_sig_pubkey, &pubn.relay_domain, &pubn.nonce);
    let recovered = recover_address(&digest, sig)?;
    if recovered != pubn.wallet {
        return Err(IdentityError::AddressMismatch);
    }
    Ok(())
}

// ───────────────────────────── secp256k1 helpers ─────────────────────────────

/// keccak256("\x19Ethereum Signed Message:\n" + len + msg) — the EIP-191 hash.
fn eth_personal_hash(msg: &[u8]) -> [u8; 32] {
    let mut k = Keccak256::new();
    k.update(b"\x19Ethereum Signed Message:\n");
    k.update(msg.len().to_string().as_bytes());
    k.update(msg);
    k.finalize().into()
}

fn keccak256(bytes: &[u8]) -> [u8; 32] {
    let mut k = Keccak256::new();
    k.update(bytes);
    k.finalize().into()
}

fn address_from_verifying_key(vk: &VerifyingKey) -> WalletAddress {
    let point = vk.to_encoded_point(false); // 0x04 || X(32) || Y(32)
    let hash = keccak256(&point.as_bytes()[1..]); // hash X||Y
    let mut addr = [0u8; 20];
    addr.copy_from_slice(&hash[12..]);
    WalletAddress(addr)
}

/// Recover the signing wallet address from a 32-byte digest + a 65-byte
/// `r‖s‖v` signature. Enforces low-S (rejects malleable high-S signatures).
fn recover_address(digest: &[u8; 32], signature: &[u8; 65]) -> Result<WalletAddress, IdentityError> {
    let sig = Signature::from_slice(&signature[..64]).map_err(|_| IdentityError::BadSignature)?;
    // Low-S enforcement: if normalize_s() returns Some, the signature was high-S → reject.
    if sig.normalize_s().is_some() {
        return Err(IdentityError::HighS);
    }
    let v = signature[64];
    let rec = v.checked_sub(27).unwrap_or(v); // accept eth {27,28} or raw {0,1}
    let rec_id = RecoveryId::from_byte(rec).ok_or(IdentityError::BadRecoveryId)?;
    let vk = VerifyingKey::recover_from_prehash(digest, &sig, rec_id)
        .map_err(|_| IdentityError::RecoveryFailed)?;
    Ok(address_from_verifying_key(&vk))
}

// ───────────────────────────── client-side wallet ─────────────────────────────

/// A secp256k1 wallet — used by clients (and tests) to produce the SIWE signature
/// and the binding attestation. The relay never holds one; it only verifies.
pub struct EthWallet {
    signing_key: SigningKey,
    address: WalletAddress,
}

impl EthWallet {
    /// Generate a fresh random wallet.
    pub fn generate() -> Self {
        let signing_key = SigningKey::random(&mut rand_core::OsRng);
        let address = address_from_verifying_key(signing_key.verifying_key());
        Self { signing_key, address }
    }

    /// Restore a wallet from its 32-byte secp256k1 secret (e.g. unsealed from the OS
    /// keyring), giving a stable identity across restarts.
    pub fn from_secret_key(secret: &[u8; 32]) -> Result<Self, IdentityError> {
        let signing_key = SigningKey::from_slice(secret).map_err(|_| IdentityError::BadKey)?;
        let address = address_from_verifying_key(signing_key.verifying_key());
        Ok(Self { signing_key, address })
    }

    /// Export the 32-byte secret for sealing in the OS keyring. Handle with care.
    ///
    /// Returned inside [`Zeroizing`](zeroize::Zeroizing) so the caller's copy is wiped
    /// from memory on drop rather than left resident (CM2-B-A009).
    pub fn secret_bytes(&self) -> zeroize::Zeroizing<[u8; 32]> {
        let mut out = zeroize::Zeroizing::new([0u8; 32]);
        out.copy_from_slice(&self.signing_key.to_bytes());
        out
    }

    pub fn address(&self) -> WalletAddress {
        self.address
    }

    fn sign_digest(&self, digest: &[u8; 32]) -> [u8; 65] {
        // k256 produces low-S normalized recoverable signatures.
        let (sig, rec_id): (Signature, RecoveryId) = self
            .signing_key
            .sign_prehash_recoverable(digest)
            .expect("prehash sign");
        let mut out = [0u8; 65];
        out[..64].copy_from_slice(&sig.to_bytes());
        out[64] = rec_id.to_byte();
        out
    }

    /// Sign a SIWE message (EIP-191 personal-sign).
    pub fn sign_siwe(&self, message: &SiweMessage) -> [u8; 65] {
        let digest = eth_personal_hash(message.to_signing_string().as_bytes());
        self.sign_digest(&digest)
    }

    /// Produce the wallet binding attestation for an MLS signature public key.
    pub fn sign_binding(&self, mls_sig_pubkey: &[u8], relay_domain: &str, nonce: &str) -> [u8; 65] {
        let digest = binding_digest(&self.address, mls_sig_pubkey, relay_domain, nonce);
        self.sign_digest(&digest)
    }

    /// Sign an arbitrary domain-separated blob (used for signed `RoleAssertion`s).
    /// The signed digest is `BLAKE3(domain ‖ blob)`.
    pub fn sign_blob(&self, domain: &[u8], blob: &[u8]) -> [u8; 65] {
        self.sign_digest(&blob_digest(domain, blob))
    }
}

/// Domain-separated digest used by [`EthWallet::sign_blob`] / [`recover_blob_signer`].
fn blob_digest(domain: &[u8], blob: &[u8]) -> [u8; 32] {
    let mut h = blake3::Hasher::new();
    h.update(domain);
    h.update(blob);
    *h.finalize().as_bytes()
}

/// Recover the wallet that signed a domain-separated blob (public-key verification).
pub fn recover_blob_signer(
    domain: &[u8],
    blob: &[u8],
    signature: &[u8; 65],
) -> Result<WalletAddress, IdentityError> {
    recover_address(&blob_digest(domain, blob), signature)
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum IdentityError {
    #[error("nonce unknown or already used (replay)")]
    NonceUnknownOrUsed,
    #[error("wrong chain id: expected {expected}, found {found}")]
    WrongChain { expected: u64, found: u64 },
    #[error("domain mismatch (possible phishing)")]
    DomainMismatch,
    #[error("SIWE message expired")]
    Expired,
    #[error("recovered address does not match claimed address")]
    AddressMismatch,
    #[error("malleable high-S signature rejected")]
    HighS,
    #[error("malformed signature")]
    BadSignature,
    #[error("invalid secret key")]
    BadKey,
    #[error("signature must be 65 bytes (r||s||v)")]
    BadSignatureLength,
    #[error("bad recovery id")]
    BadRecoveryId,
    #[error("public-key recovery failed")]
    RecoveryFailed,
    #[error("canonical encode failed: {0}")]
    Encode(String),
}

#[cfg(test)]
mod tests {
    use super::*;

    /// CIT-COMMS-005: the nonce store must evict entries older than the TTL, so an
    /// unauthenticated peer looping `Challenge` cannot grow it without bound.
    #[test]
    fn stale_nonces_are_evicted_on_issue() {
        let mut store = InMemoryNonceStore::new();
        // A batch of never-consumed challenge nonces at t=0.
        for _ in 0..100 {
            let _ = store.fresh(0);
        }
        assert_eq!(store.nonces.len(), 100);
        // A fresh issue well past the TTL prunes all of them (leaving only the new one).
        let _ = store.fresh(InMemoryNonceStore::NONCE_TTL_MS + 1);
        assert_eq!(store.nonces.len(), 1, "stale nonces were not evicted");
    }

    fn msg(domain: &str, addr: WalletAddress, nonce: &str, chain: u64, exp: u64) -> SiweMessage {
        SiweMessage {
            domain: domain.into(),
            address: addr,
            statement: "Sign in to citrate-comms".into(),
            uri: format!("wss://{domain}"),
            version: "1".into(),
            chain_id: chain,
            nonce: nonce.into(),
            issued_at_ms: 1_000,
            expiration_ms: exp,
        }
    }

    /// WP-4.3 (`PLANSET/07` §2.3) — every secp256k1 verify path rejects malleable high-S
    /// signatures. We take a valid low-S signature, flip `s → N - s` (its high-S twin) and
    /// the recovery parity (a textbook malleability transform), and assert the shared
    /// recovery helper refuses it. SIWE, the binding attestation, and RoleAssertions all
    /// route through this helper, so one guard covers them all.
    #[test]
    fn high_s_signatures_are_rejected() {
        // secp256k1 group order N, big-endian.
        const N: [u8; 32] = [
            0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
            0xFE, 0xBA, 0xAE, 0xDC, 0xE6, 0xAF, 0x48, 0xA0, 0x3B, 0xBF, 0xD2, 0x5E, 0x8C, 0xD0, 0x36,
            0x41, 0x41,
        ];
        // Big-endian `a - b` for a >= b.
        fn sub_be(a: &[u8; 32], b: &[u8; 32]) -> [u8; 32] {
            let mut out = [0u8; 32];
            let mut borrow = 0i16;
            for i in (0..32).rev() {
                let mut d = a[i] as i16 - b[i] as i16 - borrow;
                if d < 0 {
                    d += 256;
                    borrow = 1;
                } else {
                    borrow = 0;
                }
                out[i] = d as u8;
            }
            out
        }

        let domain = b"citrate-comms/test";
        let blob = b"authorize the agent";
        let wallet = EthWallet::generate();
        let low = wallet.sign_blob(domain, blob);
        // Sanity: the honest low-S signature verifies.
        assert_eq!(recover_blob_signer(domain, blob, &low).unwrap(), wallet.address());

        // Forge its high-S malleable twin: s' = N - s, flip recovery parity.
        let mut s = [0u8; 32];
        s.copy_from_slice(&low[32..64]);
        let high_s = sub_be(&N, &s);
        let mut tampered = low;
        tampered[32..64].copy_from_slice(&high_s);
        tampered[64] ^= 1;

        assert_eq!(
            recover_blob_signer(domain, blob, &tampered),
            Err(IdentityError::HighS),
            "high-S signature must be rejected at the door"
        );
    }

    #[test]
    fn valid_login_recovers_wallet() {
        let mut nonces = InMemoryNonceStore::new();
        let nonce = nonces.fresh(1_000);
        let wallet = EthWallet::generate();
        let m = msg("relay.citrate.ai", wallet.address(), &nonce, CITRATE_CHAIN_ID, 1_000_000);
        let sig = wallet.sign_siwe(&m);
        let v = verify_siwe_login(&m, &sig, "relay.citrate.ai", 5_000, &mut nonces).unwrap();
        assert_eq!(v.address, wallet.address());
    }

    #[test]
    fn nonce_replay_is_rejected() {
        let mut nonces = InMemoryNonceStore::new();
        let nonce = nonces.fresh(1_000);
        let wallet = EthWallet::generate();
        let m = msg("relay.citrate.ai", wallet.address(), &nonce, CITRATE_CHAIN_ID, 1_000_000);
        let sig = wallet.sign_siwe(&m);
        verify_siwe_login(&m, &sig, "relay.citrate.ai", 5_000, &mut nonces).unwrap();
        // Second use of the same nonce must fail.
        let err = verify_siwe_login(&m, &sig, "relay.citrate.ai", 5_000, &mut nonces).unwrap_err();
        assert_eq!(err, IdentityError::NonceUnknownOrUsed);
    }

    #[test]
    fn wrong_chain_is_rejected() {
        let mut nonces = InMemoryNonceStore::new();
        let nonce = nonces.fresh(1_000);
        let wallet = EthWallet::generate();
        let m = msg("relay.citrate.ai", wallet.address(), &nonce, 1, 1_000_000); // chain 1, not 40204
        let sig = wallet.sign_siwe(&m);
        let err = verify_siwe_login(&m, &sig, "relay.citrate.ai", 5_000, &mut nonces).unwrap_err();
        assert_eq!(err, IdentityError::WrongChain { expected: CITRATE_CHAIN_ID, found: 1 });
    }

    #[test]
    fn wrong_domain_is_rejected() {
        let mut nonces = InMemoryNonceStore::new();
        let nonce = nonces.fresh(1_000);
        let wallet = EthWallet::generate();
        let m = msg("evil.example", wallet.address(), &nonce, CITRATE_CHAIN_ID, 1_000_000);
        let sig = wallet.sign_siwe(&m);
        let err = verify_siwe_login(&m, &sig, "relay.citrate.ai", 5_000, &mut nonces).unwrap_err();
        assert_eq!(err, IdentityError::DomainMismatch);
    }

    #[test]
    fn expired_message_is_rejected() {
        let mut nonces = InMemoryNonceStore::new();
        let nonce = nonces.fresh(1_000);
        let wallet = EthWallet::generate();
        let m = msg("relay.citrate.ai", wallet.address(), &nonce, CITRATE_CHAIN_ID, 2_000);
        let sig = wallet.sign_siwe(&m);
        let err = verify_siwe_login(&m, &sig, "relay.citrate.ai", 5_000, &mut nonces).unwrap_err();
        assert_eq!(err, IdentityError::Expired);
    }

    #[test]
    fn forged_signature_for_other_wallet_is_rejected() {
        let mut nonces = InMemoryNonceStore::new();
        let nonce = nonces.fresh(1_000);
        let victim = EthWallet::generate();
        let attacker = EthWallet::generate();
        // Attacker claims the victim's address but signs with its own key.
        let m = msg("relay.citrate.ai", victim.address(), &nonce, CITRATE_CHAIN_ID, 1_000_000);
        let sig = attacker.sign_siwe(&m);
        let err = verify_siwe_login(&m, &sig, "relay.citrate.ai", 5_000, &mut nonces).unwrap_err();
        assert_eq!(err, IdentityError::AddressMismatch);
    }

    #[test]
    fn binding_attestation_roundtrip_and_spoof_rejected() {
        let wallet = EthWallet::generate();
        let mls_pub = vec![0xaa; 32];
        let sig = wallet.sign_binding(&mls_pub, "relay.citrate.ai", "nonce123");
        let good = KeyPackagePublication {
            wallet: wallet.address(),
            key_package: vec![1, 2, 3],
            mls_sig_pubkey: mls_pub.clone(),
            binding_attestation: sig.to_vec(),
            nonce: "nonce123".into(),
            relay_domain: "relay.citrate.ai".into(),
        };
        verify_binding_attestation(&good).unwrap();

        // Spoof: attacker claims the victim's wallet for an MLS key it controls.
        let attacker = EthWallet::generate();
        let spoof_sig = attacker.sign_binding(&mls_pub, "relay.citrate.ai", "nonce123");
        let spoof = KeyPackagePublication {
            wallet: wallet.address(), // claims victim
            binding_attestation: spoof_sig.to_vec(),
            ..good
        };
        assert_eq!(verify_binding_attestation(&spoof).unwrap_err(), IdentityError::AddressMismatch);
    }
}
