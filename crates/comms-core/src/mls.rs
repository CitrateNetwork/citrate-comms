//! `mls` — the OpenMLS group engine (feature `mls`).
//!
//! This is the ONLY module that holds MLS group secrets. The relay depends on
//! `comms-core` with `default-features = false`, so this module is not compiled
//! into the relay at all — the server-blind invariant, enforced by the build graph
//! (`PLANSET/02_ARCHITECTURE.md` §1).
//!
//! Ciphersuite: see [`CIPHERSUITE`]. The planset originally named a non-existent
//! suite (`MLS_256_DHKEMX25519_AES256GCM_SHA512_Ed25519`); RFC 9420 has no X25519
//! suite at the 256-bit AEAD level, so we use the strongest *X25519 + Ed25519*
//! standard suite (matching the chain's curve choices) and keep the AES-256-GCM
//! "chain grade" at the at-rest storage layer. See `PLANSET/00` + `02` (reconciled).
//!
//! ## Zeroization residual (CM2-B-A009) — accepted, documented
//!
//! The MLS key schedule — the Ed25519 signing key ([`SignatureKeyPair`]) and every
//! epoch/exporter/encryption secret and HPKE private key held inside the
//! [`OpenMlsRustCrypto`] in-memory provider — is owned by OpenMLS and its crypto
//! provider. Those upstream types do NOT implement `Zeroize`/`ZeroizeOnDrop` and
//! expose no hook to wipe their heap on drop, so this module cannot zeroize them
//! without a bespoke storage provider. This is an **accepted residual**: the
//! wallet-key hops the workspace controls directly ARE wiped (the member daemon's
//! seed, `keyvault`'s master key, `EthWallet::secret_bytes`, and the encrypted
//! store's master + derived keys all use `Zeroizing`). A zeroizing OpenMLS storage
//! provider is the roadmap fix (`PLANSET/07`). `reach=local` — this matters only to
//! an attacker who can already read this process's memory.

use openmls::prelude::*;
use openmls_basic_credential::SignatureKeyPair;
use openmls_rust_crypto::OpenMlsRustCrypto;
use tls_codec::{Deserialize as _, Serialize as _};

/// The live transport ciphersuite: X25519 KEM · AES-128-GCM · SHA-256 · Ed25519.
/// Strongest standard MLS suite over the chain's X25519/Ed25519 curves — fully
/// **classical**. There is NO post-quantum protection of message content today:
/// no ML-KEM/Kyber is present in the build. A future ratified X25519+ML-KEM-768
/// hybrid MLS suite is roadmap-only (the envelope reserves a `ciphersuite_id` so
/// groups can migrate epoch-by-epoch when one exists). Do NOT describe the live
/// transport as post-quantum.
pub const CIPHERSUITE: Ciphersuite = Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519;

/// A member's MLS keys + credential + its own crypto provider (keystore).
pub struct MlsMember {
    provider: OpenMlsRustCrypto,
    signer: SignatureKeyPair,
    credential_with_key: CredentialWithKey,
}

/// What `add` produces: the messages the relay must route (opaque to it).
pub struct AddOutput {
    /// MLS Commit — fanned out to existing members.
    pub commit: Vec<u8>,
    /// MLS Welcome — routed to the new joiner.
    pub welcome: Vec<u8>,
    /// The ratchet tree the joiner needs (sent alongside the Welcome).
    pub ratchet_tree: Vec<u8>,
}

/// What `remove` produces: the Commit removing a member (no Welcome). Applying it
/// rotates the group secret so the removed member loses access to future epochs.
pub struct RemoveOutput {
    /// MLS Commit — fanned out to the REMAINING members.
    pub commit: Vec<u8>,
    /// The new public ratchet tree at the post-removal epoch.
    pub ratchet_tree: Vec<u8>,
}

impl MlsMember {
    /// Create a member with the given credential identity bytes (for citrate-comms
    /// this is the canonical CBOR of `{ wallet_address, mls_sig_pubkey }`).
    pub fn new(identity: &[u8]) -> Result<Self, MlsError> {
        let provider = OpenMlsRustCrypto::default();
        let signer = SignatureKeyPair::new(CIPHERSUITE.signature_algorithm())
            .map_err(|e| MlsError::Crypto(format!("signer gen: {e:?}")))?;
        signer
            .store(provider.storage())
            .map_err(|e| MlsError::Crypto(format!("signer store: {e:?}")))?;
        let credential = BasicCredential::new(identity.to_vec());
        let credential_with_key = CredentialWithKey {
            credential: credential.into(),
            signature_key: signer.public().into(),
        };
        Ok(Self {
            provider,
            signer,
            credential_with_key,
        })
    }

    /// The MLS signature public key — bound to the wallet by the attestation.
    pub fn sig_pubkey(&self) -> Vec<u8> {
        self.signer.public().to_vec()
    }

    /// Build a fresh single-use KeyPackage; private parts are kept in this
    /// member's keystore so it can later join from the Welcome. Returns the
    /// TLS-serialized public KeyPackage to publish to the relay directory.
    pub fn fresh_key_package(&self) -> Result<Vec<u8>, MlsError> {
        let bundle = KeyPackage::builder()
            .build(
                CIPHERSUITE,
                &self.provider,
                &self.signer,
                self.credential_with_key.clone(),
            )
            .map_err(|e| MlsError::Crypto(format!("key package build: {e:?}")))?;
        bundle
            .key_package()
            .tls_serialize_detached()
            .map_err(|e| MlsError::Codec(format!("kp serialize: {e:?}")))
    }

    /// Create a new MLS group (the creator becomes its first member).
    pub fn create_group(&self) -> Result<GroupHandle, MlsError> {
        let group = MlsGroup::new(
            &self.provider,
            &self.signer,
            &MlsGroupCreateConfig::default(),
            self.credential_with_key.clone(),
        )
        .map_err(|e| MlsError::Group(format!("create: {e:?}")))?;
        Ok(GroupHandle { group })
    }

    /// Join a group from a Welcome + ratchet tree (the onboarding path).
    pub fn join(
        &self,
        welcome_bytes: &[u8],
        ratchet_tree_bytes: &[u8],
    ) -> Result<GroupHandle, MlsError> {
        let msg = MlsMessageIn::tls_deserialize_exact(welcome_bytes)
            .map_err(|e| MlsError::Codec(format!("welcome deser: {e:?}")))?;
        let welcome = match msg.extract() {
            MlsMessageBodyIn::Welcome(w) => w,
            other => return Err(MlsError::Group(format!("expected Welcome, got {other:?}"))),
        };
        let ratchet_tree = RatchetTreeIn::tls_deserialize_exact(ratchet_tree_bytes)
            .map_err(|e| MlsError::Codec(format!("ratchet tree deser: {e:?}")))?;
        let staged = StagedWelcome::new_from_welcome(
            &self.provider,
            &MlsGroupJoinConfig::default(),
            welcome,
            Some(ratchet_tree),
        )
        .map_err(|e| MlsError::Group(format!("staged welcome: {e:?}")))?;
        let group = staged
            .into_group(&self.provider)
            .map_err(|e| MlsError::Group(format!("into_group: {e:?}")))?;
        Ok(GroupHandle { group })
    }
}

/// A decrypted application message plus the authenticated MLS sender identity.
///
/// `sender_identity` comes from the MLS credential that signed the message
/// (`ProcessedMessage::credential()`), which OpenMLS verifies during
/// `process_message`. It is the ONLY trustworthy attribution: the relay-controlled
/// `Envelope.sender` routing field can name anyone (finding CM2-B-A002), so callers
/// MUST attribute from this value — recover it with
/// [`WalletAddress::from_identity`](comms_proto::WalletAddress::from_identity).
pub struct ReceivedMessage {
    /// The authenticated sender's credential identity (the 20 wallet-address bytes).
    pub sender_identity: Vec<u8>,
    /// The decrypted application plaintext.
    pub plaintext: Vec<u8>,
}

/// A member's view of one MLS group. Holds epoch secrets — never leaves the client.
pub struct GroupHandle {
    group: MlsGroup,
}

/// Extract the BasicCredential identity bytes from an authenticated MLS credential.
/// For citrate-comms this is the member's 20-byte wallet address.
fn basic_credential_identity(credential: &Credential) -> Result<Vec<u8>, MlsError> {
    let basic = BasicCredential::try_from(credential.clone())
        .map_err(|e| MlsError::Group(format!("non-basic credential: {e:?}")))?;
    Ok(basic.identity().to_vec())
}

impl GroupHandle {
    pub fn group_id(&self) -> Vec<u8> {
        self.group.group_id().as_slice().to_vec()
    }

    pub fn epoch(&self) -> u64 {
        self.group.epoch().as_u64()
    }

    /// Add a member by their published KeyPackage. Returns the Commit + Welcome +
    /// ratchet tree the relay routes. The caller (an admin) merges the commit so
    /// its own view advances to the new epoch.
    pub fn add(
        &mut self,
        owner: &MlsMember,
        joiner_key_package: &[u8],
    ) -> Result<AddOutput, MlsError> {
        let kp_in = KeyPackageIn::tls_deserialize_exact(joiner_key_package)
            .map_err(|e| MlsError::Codec(format!("kp deser: {e:?}")))?;
        let kp = kp_in
            .validate(owner.provider.crypto(), ProtocolVersion::Mls10)
            .map_err(|e| MlsError::Group(format!("kp validate: {e:?}")))?;
        let (commit, welcome, _group_info) = self
            .group
            .add_members(&owner.provider, &owner.signer, &[kp])
            .map_err(|e| MlsError::Group(format!("add_members: {e:?}")))?;
        self.group
            .merge_pending_commit(&owner.provider)
            .map_err(|e| MlsError::Group(format!("merge commit: {e:?}")))?;
        let commit = commit
            .tls_serialize_detached()
            .map_err(|e| MlsError::Codec(format!("commit serialize: {e:?}")))?;
        let welcome = welcome
            .tls_serialize_detached()
            .map_err(|e| MlsError::Codec(format!("welcome serialize: {e:?}")))?;
        let ratchet_tree = self
            .group
            .export_ratchet_tree()
            .tls_serialize_detached()
            .map_err(|e| MlsError::Codec(format!("ratchet tree serialize: {e:?}")))?;
        Ok(AddOutput {
            commit,
            welcome,
            ratchet_tree,
        })
    }

    /// Add SEVERAL members in ONE Commit. Returns a single Commit + Welcome +
    /// ratchet tree covering all of them.
    ///
    /// This is not an optimisation, it is the correct shape, and calling
    /// [`add`](Self::add) in a loop is subtly wrong: each add produces its own
    /// epoch, its own Welcome and its own ratchet tree, while the relay keeps ONE
    /// tree per group. The second joiner then fetches a tree from a later epoch
    /// than its Welcome and fails validation with `TreeHashMismatch` — so a room
    /// with three or more members could never be joined. Found by citrate-quorum's
    /// QRM-S3 exit gate (two humans + two agents), which is the first thing in the
    /// federation to put four members in one group; every test before it added
    /// exactly one peer, which is the one case the loop gets right.
    ///
    /// An empty `joiners` list is an error rather than a no-op commit: committing
    /// nothing still burns an epoch, and a caller asking to add nobody has a bug.
    pub fn add_many(
        &mut self,
        owner: &MlsMember,
        joiner_key_packages: &[Vec<u8>],
    ) -> Result<AddOutput, MlsError> {
        if joiner_key_packages.is_empty() {
            return Err(MlsError::Group("add_many: no joiners".into()));
        }
        let mut kps = Vec::with_capacity(joiner_key_packages.len());
        for bytes in joiner_key_packages {
            let kp_in = KeyPackageIn::tls_deserialize_exact(bytes.as_slice())
                .map_err(|e| MlsError::Codec(format!("kp deser: {e:?}")))?;
            kps.push(
                kp_in
                    .validate(owner.provider.crypto(), ProtocolVersion::Mls10)
                    .map_err(|e| MlsError::Group(format!("kp validate: {e:?}")))?,
            );
        }
        let (commit, welcome, _group_info) = self
            .group
            .add_members(&owner.provider, &owner.signer, &kps)
            .map_err(|e| MlsError::Group(format!("add_members: {e:?}")))?;
        self.group
            .merge_pending_commit(&owner.provider)
            .map_err(|e| MlsError::Group(format!("merge commit: {e:?}")))?;
        let commit = commit
            .tls_serialize_detached()
            .map_err(|e| MlsError::Codec(format!("commit serialize: {e:?}")))?;
        let welcome = welcome
            .tls_serialize_detached()
            .map_err(|e| MlsError::Codec(format!("welcome serialize: {e:?}")))?;
        let ratchet_tree = self
            .group
            .export_ratchet_tree()
            .tls_serialize_detached()
            .map_err(|e| MlsError::Codec(format!("ratchet tree serialize: {e:?}")))?;
        Ok(AddOutput {
            commit,
            welcome,
            ratchet_tree,
        })
    }

    /// The authenticated credential identities (20-byte wallet addresses) of every
    /// current group member, taken from the MLS ratchet tree — NOT from any
    /// relay-supplied routing metadata. The correct source for a client's roster
    /// after a membership change (finding CM2-B-A002): a hostile relay cannot inject
    /// a phantom wallet, because every entry here is an authenticated MLS credential.
    pub fn member_identities(&self) -> Vec<Vec<u8>> {
        self.group
            .members()
            .filter_map(|m| basic_credential_identity(&m.credential).ok())
            .collect()
    }

    /// Find a member's leaf index by their MLS signature public key (the value
    /// bound to their wallet by the attestation). Returns `None` if not a member.
    pub fn member_index_by_sig(&self, sig_pubkey: &[u8]) -> Option<u32> {
        self.group
            .members()
            .find(|m| m.signature_key.as_slice() == sig_pubkey)
            .map(|m| m.index.u32())
    }

    /// Remove a member by leaf index (offboarding). Produces a Commit with a path
    /// update — the new epoch secret is unknown to the removed member, so from the
    /// next epoch forward they cannot decrypt. The admin merges the commit so its
    /// own view advances.
    pub fn remove(&mut self, admin: &MlsMember, leaf_index: u32) -> Result<RemoveOutput, MlsError> {
        let (commit, _welcome, _group_info) = self
            .group
            .remove_members(
                &admin.provider,
                &admin.signer,
                &[LeafNodeIndex::new(leaf_index)],
            )
            .map_err(|e| MlsError::Group(format!("remove_members: {e:?}")))?;
        self.group
            .merge_pending_commit(&admin.provider)
            .map_err(|e| MlsError::Group(format!("merge remove commit: {e:?}")))?;
        let commit = commit
            .tls_serialize_detached()
            .map_err(|e| MlsError::Codec(format!("remove commit serialize: {e:?}")))?;
        let ratchet_tree = self
            .group
            .export_ratchet_tree()
            .tls_serialize_detached()
            .map_err(|e| MlsError::Codec(format!("ratchet tree serialize: {e:?}")))?;
        Ok(RemoveOutput {
            commit,
            ratchet_tree,
        })
    }

    /// Apply an incoming Commit (a membership/epoch change from another member).
    pub fn process_commit(
        &mut self,
        member: &MlsMember,
        commit_bytes: &[u8],
    ) -> Result<(), MlsError> {
        let processed = self.process(member, commit_bytes)?;
        match processed.into_content() {
            ProcessedMessageContent::StagedCommitMessage(staged) => {
                self.group
                    .merge_staged_commit(&member.provider, *staged)
                    .map_err(|e| MlsError::Group(format!("merge staged: {e:?}")))?;
                Ok(())
            }
            other => Err(MlsError::Group(format!(
                "expected Commit, got {}",
                content_kind(&other)
            ))),
        }
    }

    /// Encrypt an application message. Returns opaque ciphertext bytes.
    pub fn send(&mut self, member: &MlsMember, plaintext: &[u8]) -> Result<Vec<u8>, MlsError> {
        let out = self
            .group
            .create_message(&member.provider, &member.signer, plaintext)
            .map_err(|e| MlsError::Group(format!("create_message: {e:?}")))?;
        out.tls_serialize_detached()
            .map_err(|e| MlsError::Codec(format!("app serialize: {e:?}")))
    }

    /// Decrypt an incoming application message. Returns the plaintext together with
    /// the *authenticated* sender identity (the MLS credential OpenMLS verified), so
    /// callers never attribute from the relay-controlled `Envelope.sender`
    /// (finding CM2-B-A002).
    pub fn receive(
        &mut self,
        member: &MlsMember,
        ciphertext: &[u8],
    ) -> Result<ReceivedMessage, MlsError> {
        let processed = self.process(member, ciphertext)?;
        // Capture the authenticated sender identity BEFORE consuming the message.
        let sender_identity = basic_credential_identity(processed.credential())?;
        match processed.into_content() {
            ProcessedMessageContent::ApplicationMessage(app) => Ok(ReceivedMessage {
                sender_identity,
                plaintext: app.into_bytes(),
            }),
            other => Err(MlsError::Group(format!(
                "expected Application, got {}",
                content_kind(&other)
            ))),
        }
    }

    fn process(&mut self, member: &MlsMember, bytes: &[u8]) -> Result<ProcessedMessage, MlsError> {
        let msg = MlsMessageIn::tls_deserialize_exact(bytes)
            .map_err(|e| MlsError::Codec(format!("msg deser: {e:?}")))?;
        let protocol = msg
            .try_into_protocol_message()
            .map_err(|e| MlsError::Group(format!("not a protocol message: {e:?}")))?;
        self.group
            .process_message(&member.provider, protocol)
            .map_err(|e| MlsError::Group(format!("process_message: {e:?}")))
    }
}

/// Client-side gate that a KeyPackage handed back by the (untrusted) relay
/// genuinely belongs to the wallet we intend to admit — the security boundary for
/// KeyPackage substitution (finding `CM2-B-A001`).
///
/// RFC 9420 §3 treats the Delivery Service (here, the relay) as untrusted, and
/// `01_SCOPE.md` §2 names the relay operator an in-scope attacker for this
/// server-blind asset. The relay's own `publish_key_package` attestation check
/// therefore runs *inside the component it must defend against*: it is a courtesy
/// pre-filter only. THIS function — run by the client that is about to add the
/// member — is the authority. Three independent bindings must all hold, or a
/// hostile relay substitutes its own KeyPackage, is admitted as a full MLS member,
/// and decrypts the group:
///
/// 1. **Roster binding** — the publication claims the wallet we asked to add. A
///    relay that hands back its *own* validly-attested KeyPackage is caught here.
/// 2. **Wallet→MLS attestation** — the claimed wallet's secp256k1 key signed the
///    binding over `mls_sig_pubkey`. A relay that mints an MLS key in the victim's
///    name is caught here: it does not hold the victim's wallet secret.
/// 3. **KeyPackage↔attestation consistency** — the signature key and credential
///    identity actually inside the TLS-serialized KeyPackage equal the attested
///    `mls_sig_pubkey` and wallet. A relay that keeps a genuine attestation but
///    swaps the KeyPackage bytes under it is caught here.
///
/// Refuses on any mismatch. Public-key verification over public data only — no
/// group secret is touched, so this is safe to run before any MLS state change.
pub fn verify_incoming_key_package(
    pubn: &comms_proto::KeyPackagePublication,
    expected_wallet: &comms_proto::WalletAddress,
) -> Result<(), MlsError> {
    // (1) Roster binding: the relay must return the wallet we asked for.
    if pubn.wallet != *expected_wallet {
        return Err(MlsError::Binding(format!(
            "relay returned a KeyPackage for {} but {} was requested",
            hex::encode(pubn.wallet.0),
            hex::encode(expected_wallet.0),
        )));
    }
    // (2) Wallet→MLS binding attestation. The client is the authority here; the
    //     relay running the identical check cannot defend against the relay itself.
    crate::identity::verify_binding_attestation(pubn)
        .map_err(|e| MlsError::Binding(format!("binding attestation failed: {e}")))?;
    // (3) The KeyPackage bytes must actually carry the attested signature key and
    //     wallet identity, or a relay could keep a real attestation and swap the
    //     package under it.
    let provider = OpenMlsRustCrypto::default();
    let kp_in = KeyPackageIn::tls_deserialize_exact(pubn.key_package.as_slice())
        .map_err(|e| MlsError::Codec(format!("kp deser: {e:?}")))?;
    let kp = kp_in
        .validate(provider.crypto(), ProtocolVersion::Mls10)
        .map_err(|e| MlsError::Group(format!("kp validate: {e:?}")))?;
    let leaf = kp.leaf_node();
    if leaf.signature_key().as_slice() != pubn.mls_sig_pubkey.as_slice() {
        return Err(MlsError::Binding(
            "KeyPackage signature key does not match the attested mls_sig_pubkey".into(),
        ));
    }
    let credential = BasicCredential::try_from(leaf.credential().clone())
        .map_err(|e| MlsError::Binding(format!("non-basic credential: {e:?}")))?;
    if credential.identity() != expected_wallet.0 {
        return Err(MlsError::Binding(
            "KeyPackage credential identity does not match the claimed wallet".into(),
        ));
    }
    Ok(())
}

fn content_kind(c: &ProcessedMessageContent) -> &'static str {
    match c {
        ProcessedMessageContent::ApplicationMessage(_) => "Application",
        ProcessedMessageContent::ProposalMessage(_) => "Proposal",
        ProcessedMessageContent::ExternalJoinProposalMessage(_) => "ExternalJoinProposal",
        ProcessedMessageContent::StagedCommitMessage(_) => "StagedCommit",
    }
}

#[derive(Debug, thiserror::Error)]
pub enum MlsError {
    #[error("mls crypto error: {0}")]
    Crypto(String),
    #[error("mls codec error: {0}")]
    Codec(String),
    #[error("mls group error: {0}")]
    Group(String),
    #[error("keypackage binding rejected: {0}")]
    Binding(String),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn provider_supports_our_ciphersuite() {
        let provider = OpenMlsRustCrypto::default();
        let supported = provider.crypto().supported_ciphersuites();
        // Document what the RustCrypto provider actually offers (informs the
        // ciphersuite reconciliation in PLANSET/00 + 02).
        println!("supported ciphersuites: {supported:?}");
        assert!(
            supported.contains(&CIPHERSUITE),
            "provider must support {CIPHERSUITE:?}"
        );
    }

    // ── CM2-B-A001 tripwire: the CLIENT is the authority on KeyPackage binding ──
    //
    // A hostile relay is the in-scope attacker for this server-blind asset (RFC 9420
    // §3). The relay's own `publish_key_package` attestation check is inside the
    // component it must defend against, so it is not the boundary. These tests pin
    // that `verify_incoming_key_package` — run client-side before a member is
    // admitted — accepts a genuine member and rejects every relay substitution.

    use crate::identity::EthWallet;
    use comms_proto::KeyPackagePublication;

    const RELAY_DOMAIN: &str = "relay.citrate.ai";
    const NONCE: &str = "nonce-abc";

    /// Build the KeyPackage publication a genuine `wallet` would publish: a fresh
    /// MLS KeyPackage whose credential identity is the wallet address, plus the
    /// wallet's secp256k1 attestation over that MLS signature key.
    fn genuine_publication(wallet: &EthWallet) -> KeyPackagePublication {
        let member = MlsMember::new(&wallet.address().0).unwrap();
        let key_package = member.fresh_key_package().unwrap();
        let mls_sig_pubkey = member.sig_pubkey();
        let binding = wallet
            .sign_binding(&mls_sig_pubkey, RELAY_DOMAIN, NONCE)
            .to_vec();
        KeyPackagePublication {
            wallet: wallet.address(),
            key_package,
            mls_sig_pubkey,
            binding_attestation: binding,
            nonce: NONCE.into(),
            relay_domain: RELAY_DOMAIN.into(),
        }
    }

    #[test]
    fn genuine_member_is_accepted_client_side() {
        let bob = EthWallet::generate();
        let pubn = genuine_publication(&bob);
        // GREEN: the honest member the client asked for is admitted.
        verify_incoming_key_package(&pubn, &bob.address())
            .expect("a genuine member's KeyPackage must be accepted");
    }

    #[test]
    fn relay_substituted_keypackage_is_rejected_client_side() {
        // Alice wants to add Bob. The relay (attacker) instead mints its OWN MLS
        // key but labels the publication with Bob's wallet — the executed A001 PoC.
        // The relay cannot forge Bob's secp256k1 attestation, so the client rejects.
        let bob = EthWallet::generate();
        let relay = EthWallet::generate();
        let relay_member = MlsMember::new(&bob.address().0).unwrap(); // relay controls this key
        let forged = KeyPackagePublication {
            wallet: bob.address(), // claims to be Bob
            key_package: relay_member.fresh_key_package().unwrap(),
            mls_sig_pubkey: relay_member.sig_pubkey(),
            // Relay can only sign with ITS key — recovers to relay, not Bob.
            binding_attestation: relay
                .sign_binding(&relay_member.sig_pubkey(), RELAY_DOMAIN, NONCE)
                .to_vec(),
            nonce: NONCE.into(),
            relay_domain: RELAY_DOMAIN.into(),
        };
        let err = verify_incoming_key_package(&forged, &bob.address())
            .expect_err("a KeyPackage the claimed wallet never attested must be rejected");
        assert!(matches!(err, MlsError::Binding(_)), "got {err:?}");
    }

    #[test]
    fn relays_own_validly_attested_keypackage_is_rejected_for_the_wrong_wallet() {
        // The relay returns its OWN fully valid publication (valid attestation) when
        // Alice asked for Bob. Attestation verifies, but the roster binding does not.
        let bob = EthWallet::generate();
        let relay = EthWallet::generate();
        let relay_pubn = genuine_publication(&relay);
        let err = verify_incoming_key_package(&relay_pubn, &bob.address())
            .expect_err("a KeyPackage for a different wallet than requested must be rejected");
        assert!(matches!(err, MlsError::Binding(_)), "got {err:?}");
    }

    #[test]
    fn swapped_keypackage_under_a_genuine_attestation_is_rejected() {
        // The relay keeps Bob's genuine attestation but swaps the KeyPackage bytes
        // (and mls_sig_pubkey field) for a different member it controls. The
        // KeyPackage↔attestation consistency check catches the swap.
        let bob = EthWallet::generate();
        let genuine = genuine_publication(&bob);
        let other = MlsMember::new(&bob.address().0).unwrap();
        let swapped = KeyPackagePublication {
            // Keep Bob's wallet, his real mls_sig_pubkey, and his real attestation
            // (steps 1 & 2 pass) — only the KeyPackage bytes are swapped for a
            // package carrying a DIFFERENT signature key. Step 3 must catch it.
            key_package: other.fresh_key_package().unwrap(),
            ..genuine
        };
        let err = verify_incoming_key_package(&swapped, &bob.address())
            .expect_err("a KeyPackage whose key differs from the attested one must be rejected");
        assert!(matches!(err, MlsError::Binding(_)), "got {err:?}");
    }

    /// RED witness for CM2-B-A001. Demonstrates the exact PoC primitive: the raw
    /// MLS add path the client used *before* this fix accepts a relay-substituted
    /// KeyPackage, the relay-controlled member joins from the Welcome and reads
    /// Alice's plaintext — and then that the new client gate refuses the very same
    /// publication. Kept as a permanent witness of why the gate must run.
    #[test]
    fn red_witness_forged_keypackage_joins_and_reads_then_gate_rejects() {
        let alice_wallet = EthWallet::generate();
        let bob = EthWallet::generate();
        let relay = EthWallet::generate();

        // Relay mints an MLS key it controls, but labels the publication as Bob.
        let relay_member = MlsMember::new(&bob.address().0).unwrap();
        let forged = KeyPackagePublication {
            wallet: bob.address(),
            key_package: relay_member.fresh_key_package().unwrap(),
            mls_sig_pubkey: relay_member.sig_pubkey(),
            binding_attestation: relay
                .sign_binding(&relay_member.sig_pubkey(), RELAY_DOMAIN, NONCE)
                .to_vec(),
            nonce: NONCE.into(),
            relay_domain: RELAY_DOMAIN.into(),
        };

        // RED: the pre-fix path (add straight from the relay's bytes) accepts it.
        let alice = MlsMember::new(&alice_wallet.address().0).unwrap();
        let mut alice_group = alice.create_group().unwrap();
        let add = alice_group
            .add_many(&alice, &[forged.key_package.clone()])
            .expect("raw MLS add accepts the forged KeyPackage — the A001 primitive");
        let mut relay_group = relay_member.join(&add.welcome, &add.ratchet_tree).unwrap();
        let secret = b"acquisition price is 240M, do not forward";
        let ct = alice_group.send(&alice, secret).unwrap();
        let read = relay_group.receive(&relay_member, &ct).unwrap();
        assert_eq!(
            read.plaintext, secret,
            "RED CONFIRMED: without the client gate the relay reads plaintext"
        );

        // GREEN: the client gate refuses the identical publication, so it never
        // reaches `add_many`.
        let err = verify_incoming_key_package(&forged, &bob.address())
            .expect_err("GREEN: the client gate must reject the forged KeyPackage");
        assert!(matches!(err, MlsError::Binding(_)), "got {err:?}");
    }

    #[test]
    fn two_member_group_exchanges_a_message() {
        let alice = MlsMember::new(b"alice-identity").unwrap();
        let bob = MlsMember::new(b"bob-identity").unwrap();

        let bob_kp = bob.fresh_key_package().unwrap();
        let mut alice_group = alice.create_group().unwrap();
        assert_eq!(alice_group.epoch(), 0);

        let add = alice_group.add(&alice, &bob_kp).unwrap();
        assert_eq!(
            alice_group.epoch(),
            1,
            "epoch advances by exactly 1 after the add commit"
        );

        let mut bob_group = bob.join(&add.welcome, &add.ratchet_tree).unwrap();
        assert_eq!(bob_group.group_id(), alice_group.group_id());
        assert_eq!(bob_group.epoch(), 1);

        // Alice → Bob.
        let ciphertext = alice_group.send(&alice, b"hello from alice").unwrap();
        assert_ne!(
            &ciphertext, b"hello from alice",
            "wire bytes are ciphertext, not plaintext"
        );
        let received = bob_group.receive(&bob, &ciphertext).unwrap();
        assert_eq!(received.plaintext, b"hello from alice");
        // The authenticated sender identity is Alice's wallet credential, recovered
        // from the MLS message itself (not any routing metadata) — CM2-B-A002.
        assert_eq!(
            received.sender_identity, b"alice-identity",
            "sender attributed from the authenticated MLS credential"
        );

        // Bob → Alice (bidirectional).
        let ct2 = bob_group.send(&bob, b"hi alice").unwrap();
        let back = alice_group.receive(&alice, &ct2).unwrap();
        assert_eq!(back.plaintext, b"hi alice");
        assert_eq!(back.sender_identity, b"bob-identity");
    }
}
