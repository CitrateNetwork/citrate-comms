//! Persisted MLS keystore compatibility across OpenMLS releases.
//!
//! The member daemon persists `MlsMember::snapshot_storage()` (OpenMLS's own
//! serialized storage entities) and rehydrates it with `MlsMember::restore` +
//! `load_group` after a restart. An OpenMLS upgrade that changes that storage format
//! would strand every existing group. The committed fixture below was written by an
//! OLDER OpenMLS release (see `FIXTURE_WRITER`); these tests load it with the
//! release currently in `Cargo.lock` and prove the groups are still fully usable:
//! a message in flight across the upgrade decrypts, both sides keep talking, a
//! membership change commits and is merged, and replays / corrupt blobs fail closed.
//!
//! Regenerating the fixture is a deliberate act (it must be done on the OLD release,
//! before a bump): `COMMS_MLS_FIXTURE_OUT=<path> cargo test -p comms-core --test
//! mls_keystore_compat -- --ignored write_fixture`.
#![cfg(feature = "mls")]

use comms_core::mls::{MlsError, MlsMember};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

/// The OpenMLS release that wrote the committed fixture.
const FIXTURE_WRITER: &str = "openmls 0.8.1";
const FIXTURE_FILE: &str = "mls_keystore_openmls_0_8_1.cbor";

const ALICE: &[u8] = b"alice-identity";
const BOB: &[u8] = b"bob-identity";
const IN_FLIGHT: &[u8] = b"sent before the upgrade, read after it";

#[derive(Serialize, Deserialize)]
struct Fixture {
    writer: String,
    group_id: Vec<u8>,
    epoch: u64,
    alice_sig: Vec<u8>,
    alice_snapshot: Vec<u8>,
    bob_sig: Vec<u8>,
    bob_snapshot: Vec<u8>,
    /// Alice → Bob application message produced AFTER Bob's snapshot was taken, so
    /// Bob's persisted secret-tree state must decrypt it on the new release.
    in_flight: Vec<u8>,
}

fn fixture_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures")
        .join(FIXTURE_FILE)
}

fn load_fixture() -> Fixture {
    let path = fixture_path();
    let bytes = std::fs::read(&path).unwrap_or_default();
    assert!(
        !bytes.is_empty(),
        "persisted-keystore fixture missing or empty: {}",
        path.display()
    );
    let fx: Fixture = ciborium::from_reader(bytes.as_slice()).expect("fixture decodes");
    assert_eq!(fx.writer, FIXTURE_WRITER, "fixture writer label");
    fx
}

fn restore(identity: &[u8], sig: &[u8], snapshot: &[u8]) -> MlsMember {
    match MlsMember::restore(identity, sig, snapshot) {
        Ok(m) => m,
        Err(e) => panic!("restore of a keystore persisted by {FIXTURE_WRITER} failed: {e:?}"),
    }
}

#[test]
fn keystore_persisted_by_older_openmls_reloads_and_stays_usable() {
    let fx = load_fixture();

    let alice = restore(ALICE, &fx.alice_sig, &fx.alice_snapshot);
    let bob = restore(BOB, &fx.bob_sig, &fx.bob_snapshot);
    let mut alice_g = alice.load_group(&fx.group_id).expect("alice reloads group");
    let mut bob_g = bob.load_group(&fx.group_id).expect("bob reloads group");
    assert_eq!(alice_g.group_id(), fx.group_id);
    assert_eq!(bob_g.group_id(), fx.group_id);
    assert_eq!(alice_g.epoch(), fx.epoch);
    assert_eq!(bob_g.epoch(), fx.epoch);

    let roster: Vec<Vec<u8>> = bob_g
        .authenticated_members()
        .into_iter()
        .map(|(id, _)| id)
        .collect();
    assert!(roster.iter().any(|id| id == ALICE), "roster has alice");
    assert!(roster.iter().any(|id| id == BOB), "roster has bob");

    // A message encrypted by the old release decrypts from Bob's persisted ratchet.
    let got = bob_g.receive(&bob, &fx.in_flight).expect("in-flight message decrypts");
    assert_eq!(got.plaintext, IN_FLIGHT);
    assert_eq!(got.sender_identity, ALICE);

    // Adversarial: the same ciphertext must not decrypt twice (ratchet consumed).
    assert!(
        bob_g.receive(&bob, &fx.in_flight).is_err(),
        "a replayed ciphertext must be rejected after the upgrade"
    );

    // Both directions keep working on the reloaded state.
    let ct = alice_g.send(&alice, b"post-upgrade a->b").unwrap();
    assert_eq!(bob_g.receive(&bob, &ct).unwrap().plaintext, b"post-upgrade a->b");
    let ct = bob_g.send(&bob, b"post-upgrade b->a").unwrap();
    let back = alice_g.receive(&alice, &ct).unwrap();
    assert_eq!(back.plaintext, b"post-upgrade b->a");
    assert_eq!(back.sender_identity, BOB);

    // A membership change commits from the reloaded epoch secrets and the other
    // reloaded member merges it; all three then share the new epoch.
    let carol = MlsMember::new(b"carol-identity").unwrap();
    let add = alice_g
        .add(&alice, &carol.fresh_key_package().unwrap())
        .expect("add from reloaded state");
    bob_g.process_commit(&bob, &add.commit).expect("bob merges commit");
    let mut carol_g = carol.join(&add.welcome, &add.ratchet_tree).expect("carol joins");
    assert_eq!(alice_g.epoch(), fx.epoch + 1);
    assert_eq!(bob_g.epoch(), fx.epoch + 1);
    assert_eq!(carol_g.epoch(), fx.epoch + 1);
    let ct = alice_g.send(&alice, b"epoch after upgrade").unwrap();
    assert_eq!(bob_g.receive(&bob, &ct).unwrap().plaintext, b"epoch after upgrade");
    assert_eq!(carol_g.receive(&carol, &ct).unwrap().plaintext, b"epoch after upgrade");
}

#[test]
fn persisted_keystore_cannot_be_restored_under_another_members_signer() {
    let fx = load_fixture();
    // Bob's keystore does not hold Alice's signer: fail closed, never a half-member.
    match MlsMember::restore(ALICE, &fx.alice_sig, &fx.bob_snapshot) {
        Err(MlsError::Crypto(_)) => {}
        Ok(_) => panic!("a foreign keystore must not restore"),
        Err(other) => panic!("expected Crypto error, got {other:?}"),
    }
}

#[test]
fn truncated_persisted_keystore_fails_closed() {
    let fx = load_fixture();
    let cut = &fx.alice_snapshot[..fx.alice_snapshot.len() / 2];
    match MlsMember::restore(ALICE, &fx.alice_sig, cut) {
        Err(MlsError::Codec(_)) => {}
        Ok(_) => panic!("a truncated keystore must not restore"),
        Err(other) => panic!("expected Codec error, got {other:?}"),
    }
}

/// Writes the fixture. Run ONLY on the release named in `FIXTURE_WRITER`, before a
/// bump; writes solely to the explicit `COMMS_MLS_FIXTURE_OUT` path.
#[test]
#[ignore = "fixture generator; run manually on the old OpenMLS release"]
fn write_fixture() {
    let out = std::env::var("COMMS_MLS_FIXTURE_OUT").expect("set COMMS_MLS_FIXTURE_OUT");

    let alice = MlsMember::new(ALICE).unwrap();
    let bob = MlsMember::new(BOB).unwrap();
    let mut alice_g = alice.create_group().unwrap();
    let add = alice_g.add(&alice, &bob.fresh_key_package().unwrap()).unwrap();
    let mut bob_g = bob.join(&add.welcome, &add.ratchet_tree).unwrap();
    // Advance both secret trees before persisting.
    let ct = alice_g.send(&alice, b"warm-up a->b").unwrap();
    bob_g.receive(&bob, &ct).unwrap();
    let ct = bob_g.send(&bob, b"warm-up b->a").unwrap();
    alice_g.receive(&alice, &ct).unwrap();

    let bob_snapshot = bob.snapshot_storage().unwrap();
    let in_flight = alice_g.send(&alice, IN_FLIGHT).unwrap();
    let alice_snapshot = alice.snapshot_storage().unwrap();

    let fx = Fixture {
        writer: FIXTURE_WRITER.into(),
        group_id: alice_g.group_id(),
        epoch: alice_g.epoch(),
        alice_sig: alice.sig_pubkey(),
        alice_snapshot,
        bob_sig: bob.sig_pubkey(),
        bob_snapshot,
        in_flight,
    };
    let mut buf = Vec::new();
    ciborium::into_writer(&fx, &mut buf).unwrap();
    std::fs::write(&out, buf).unwrap();
}
