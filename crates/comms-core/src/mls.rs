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

use openmls::prelude::*;
use openmls_basic_credential::SignatureKeyPair;
use openmls_rust_crypto::OpenMlsRustCrypto;
use tls_codec::{Deserialize as _, Serialize as _};

/// The live transport ciphersuite: X25519 KEM · AES-128-GCM · SHA-256 · Ed25519.
/// Strongest standard MLS suite over the chain's X25519/Ed25519 curves. The
/// 256-bit-AEAD roadmap is the future ratified X25519+Kyber768 PQ-hybrid suite
/// (the envelope reserves a `ciphersuite_id` for the migration).
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
        Ok(Self { provider, signer, credential_with_key })
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
            .build(CIPHERSUITE, &self.provider, &self.signer, self.credential_with_key.clone())
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
    pub fn join(&self, welcome_bytes: &[u8], ratchet_tree_bytes: &[u8]) -> Result<GroupHandle, MlsError> {
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

/// A member's view of one MLS group. Holds epoch secrets — never leaves the client.
pub struct GroupHandle {
    group: MlsGroup,
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
    pub fn add(&mut self, owner: &MlsMember, joiner_key_package: &[u8]) -> Result<AddOutput, MlsError> {
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
        Ok(AddOutput { commit, welcome, ratchet_tree })
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
            .remove_members(&admin.provider, &admin.signer, &[LeafNodeIndex::new(leaf_index)])
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
        Ok(RemoveOutput { commit, ratchet_tree })
    }

    /// Apply an incoming Commit (a membership/epoch change from another member).
    pub fn process_commit(&mut self, member: &MlsMember, commit_bytes: &[u8]) -> Result<(), MlsError> {
        let processed = self.process(member, commit_bytes)?;
        match processed.into_content() {
            ProcessedMessageContent::StagedCommitMessage(staged) => {
                self.group
                    .merge_staged_commit(&member.provider, *staged)
                    .map_err(|e| MlsError::Group(format!("merge staged: {e:?}")))?;
                Ok(())
            }
            other => Err(MlsError::Group(format!("expected Commit, got {}", content_kind(&other)))),
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

    /// Decrypt an incoming application message. Returns the plaintext.
    pub fn receive(&mut self, member: &MlsMember, ciphertext: &[u8]) -> Result<Vec<u8>, MlsError> {
        let processed = self.process(member, ciphertext)?;
        match processed.into_content() {
            ProcessedMessageContent::ApplicationMessage(app) => Ok(app.into_bytes()),
            other => Err(MlsError::Group(format!("expected Application, got {}", content_kind(&other)))),
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
        assert!(supported.contains(&CIPHERSUITE), "provider must support {CIPHERSUITE:?}");
    }

    #[test]
    fn two_member_group_exchanges_a_message() {
        let alice = MlsMember::new(b"alice-identity").unwrap();
        let bob = MlsMember::new(b"bob-identity").unwrap();

        let bob_kp = bob.fresh_key_package().unwrap();
        let mut alice_group = alice.create_group().unwrap();
        assert_eq!(alice_group.epoch(), 0);

        let add = alice_group.add(&alice, &bob_kp).unwrap();
        assert_eq!(alice_group.epoch(), 1, "epoch advances by exactly 1 after the add commit");

        let mut bob_group = bob.join(&add.welcome, &add.ratchet_tree).unwrap();
        assert_eq!(bob_group.group_id(), alice_group.group_id());
        assert_eq!(bob_group.epoch(), 1);

        // Alice → Bob.
        let ciphertext = alice_group.send(&alice, b"hello from alice").unwrap();
        assert_ne!(&ciphertext, b"hello from alice", "wire bytes are ciphertext, not plaintext");
        let plaintext = bob_group.receive(&bob, &ciphertext).unwrap();
        assert_eq!(plaintext, b"hello from alice");

        // Bob → Alice (bidirectional).
        let ct2 = bob_group.send(&bob, b"hi alice").unwrap();
        assert_eq!(alice_group.receive(&alice, &ct2).unwrap(), b"hi alice");
    }
}
