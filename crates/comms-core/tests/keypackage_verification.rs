//! `verify_incoming_key_package` runs several independent checks. These tests target
//! the two that the rest of the suite reaches only together with another check, so
//! each one is pinned on its own.

#![cfg(feature = "mls")]

use comms_core::identity::EthWallet;
use comms_core::mls::{verify_incoming_key_package, MlsError, MlsMember};
use comms_proto::KeyPackagePublication;

const DOMAIN: &str = "relay.citrate.ai";
const NONCE: &str = "nonce-kp-verify";

/// A publication whose KeyPackage credential names `identity`, attested by `attester`.
fn publication(attester: &EthWallet, identity: &[u8]) -> KeyPackagePublication {
    let member = MlsMember::new(identity).unwrap();
    KeyPackagePublication {
        wallet: attester.address(),
        key_package: member.fresh_key_package().unwrap(),
        mls_sig_pubkey: member.sig_pubkey(),
        binding_attestation: attester
            .sign_binding(&member.sig_pubkey(), DOMAIN, NONCE)
            .to_vec(),
        nonce: NONCE.into(),
        relay_domain: DOMAIN.into(),
    }
}

fn binding_message(err: MlsError) -> String {
    match err {
        MlsError::Binding(m) => m,
        other => panic!("expected a binding rejection, got {other:?}"),
    }
}

/// Another wallet's fully consistent publication is refused because it is not for
/// the wallet that was requested, and it is that check that refuses it.
#[test]
fn a_consistent_publication_for_another_wallet_is_refused_as_the_wrong_wallet() {
    let bob = EthWallet::generate();
    let carol = EthWallet::generate();
    let carols = publication(&carol, &carol.address().0);
    verify_incoming_key_package(&carols, &carol.address()).expect("control: valid for its own wallet");

    let msg = binding_message(verify_incoming_key_package(&carols, &bob.address()).unwrap_err());
    assert!(
        msg.contains("was requested"),
        "the requested-wallet check must be what rejects this, got: {msg}"
    );
}

/// The wallet attested the MLS signature key, but the KeyPackage credential inside
/// names a different identity. The credential-identity check refuses it.
#[test]
fn a_keypackage_whose_credential_names_another_identity_is_refused() {
    let bob = EthWallet::generate();
    let carol = EthWallet::generate();
    // Bob's wallet attests a key whose MLS credential identity is Carol's address.
    let mismatched = publication(&bob, &carol.address().0);
    let msg = binding_message(verify_incoming_key_package(&mismatched, &bob.address()).unwrap_err());
    assert!(
        msg.contains("credential identity"),
        "the credential-identity check must be what rejects this, got: {msg}"
    );

    // Control: the same construction with Bob's own identity is accepted.
    let ok = publication(&bob, &bob.address().0);
    verify_incoming_key_package(&ok, &bob.address()).unwrap();
}
