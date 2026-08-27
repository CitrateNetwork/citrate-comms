// comms-member-daemon — increment 1 tests. Real MLS: no fixtures, no stubs.
//
// The round-trip proves the whole path end-to-end: the owner creates a group, adds a second
// member (real MLS commit + welcome), that member joins and sends an ENCRYPTED message through the
// in-process relay, and the owner drains its mailbox and DECRYPTS it. If the crypto or the relay
// wiring were wrong, the plaintext would not come back.

use super::*;

#[test]
fn owner_creates_group_and_lists_it() {
    let mut d = MemberDaemon::new(EthWallet::generate(), "relay.test", 1000).expect("daemon up");
    let gid = d.create_group("deals").expect("create");
    let groups = d.list_groups();
    assert_eq!(groups.len(), 1);
    assert_eq!(groups[0].0, gid);
    assert_eq!(groups[0].1, "deals");
}

#[test]
fn owner_adds_a_member_who_sends_a_message_the_owner_decrypts() {
    let domain = "relay.test";
    let mut owner = MemberDaemon::new(EthWallet::generate(), domain, 1000).expect("owner up");
    let gid = owner.create_group("deals").expect("create");

    // A second member comes up: wallet + MLS identity, and publishes a key package + logs in to
    // the SAME relay (the owner's in-process relay) so the owner can add them.
    let bob_w = EthWallet::generate();
    let bob_m = MlsMember::new(&bob_w.address().0).expect("bob mls");
    {
        let relay = owner.relay_mut();
        login(relay, &bob_w, domain, 2000).expect("bob login");
        publish_kp(relay, &bob_w, &bob_m, domain, 2001).expect("bob kp");
    }

    // The owner adds bob — real MLS commit + welcome.
    let add = owner.add_member(gid, bob_w.address()).expect("add bob");
    assert_eq!(add.member, bob_w.address());

    // Bob joins from the welcome material and sends an encrypted message to the group.
    let mut bob_g = bob_m
        .join(&add.welcome, &add.ratchet_tree)
        .map(|g| g)
        .expect("bob joins");
    let ct = bob_g.send(&bob_m, b"hello owner").expect("bob encrypts");
    let owner_addr = owner.owner();
    owner
        .relay_mut()
        .submit_as(
            bob_w.address(),
            Envelope {
                group_id: gid,
                epoch: EpochId(1),
                kind: EnvelopeKind::Application,
                sender: bob_w.address(),
                recipients: vec![owner_addr],
                ciphertext: ct,
                group_seq: None,
            },
            3000,
        )
        .expect("bob submits");

    // The owner drains + decrypts — the plaintext must come back through real MLS.
    let msgs = owner.poll_messages(gid).expect("owner polls");
    assert_eq!(msgs.len(), 1, "got {msgs:?}");
    assert_eq!(msgs[0].body, "hello owner");
    assert_eq!(msgs[0].sender, bob_w.address());
    assert_eq!(msgs[0].group, gid);
}

#[test]
fn add_member_without_a_published_key_package_is_an_honest_error() {
    let mut owner = MemberDaemon::new(EthWallet::generate(), "relay.test", 1000).expect("owner up");
    let gid = owner.create_group("deals").expect("create");
    let stranger = EthWallet::generate().address();
    let r = owner.add_member(gid, stranger);
    assert!(matches!(r, Err(DaemonError::NoKeyPackage(_))), "got {r:?}");
}
