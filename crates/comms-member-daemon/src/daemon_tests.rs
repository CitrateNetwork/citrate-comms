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

/// Publish `member_w`'s key package to the owner's relay and add them to `gid` (real MLS).
fn onboard_member(owner: &mut MemberDaemon, domain: &str, gid: GroupId, member_w: &EthWallet) {
    let m = MlsMember::new(&member_w.address().0).expect("member mls");
    {
        let relay = owner.relay_mut();
        login(relay, member_w, domain, 2000).expect("member login");
        publish_kp(relay, member_w, &m, domain, 2001).expect("member kp");
    }
    owner.add_member(gid, member_w.address()).expect("add member");
}

/// The effective role of `who` in a roster listing, if present.
fn role_in(roster: &[(WalletAddress, Role)], who: WalletAddress) -> Option<Role> {
    roster.iter().find(|(a, _)| *a == who).map(|(_, r)| *r)
}

#[test]
fn roster_reflects_add_and_offboard_with_effective_roles() {
    let domain = "relay.test";
    let mut owner = MemberDaemon::new(EthWallet::generate(), domain, 1000).expect("owner up");
    let owner_addr = owner.owner();
    let gid = owner.create_group("deals").expect("create");
    // Fresh group: just the owner, as Owner.
    assert_eq!(owner.roster(gid).unwrap(), vec![(owner_addr, Role::Owner)]);

    let bob = EthWallet::generate();
    onboard_member(&mut owner, domain, gid, &bob);
    // A freshly-added member defaults to Member.
    assert_eq!(role_in(&owner.roster(gid).unwrap(), bob.address()), Some(Role::Member));

    // Offboard bob — real MLS remove + relay atomic offboard; roster returns to just the owner.
    owner.offboard(gid, bob.address()).expect("offboard");
    assert_eq!(owner.roster(gid).unwrap(), vec![(owner_addr, Role::Owner)]);
    // A second offboard of a non-member is an honest error, never a panic.
    assert!(matches!(
        owner.offboard(gid, bob.address()),
        Err(DaemonError::NoMember(_))
    ));
}

#[test]
fn assign_role_applies_an_owner_signed_grant_and_rejects_a_forgery() {
    let domain = "relay.test";
    // The daemon VERIFIES ONLY (Rule 3): the OWNER signs the grant (here, up front — the ceremony
    // does this in prod); the daemon never signs. Sign with scope=None so it can be minted before
    // the group id exists.
    let owner_w = EthWallet::generate();
    let bob = EthWallet::generate();
    let grant =
        rbac::sign_role_assertion(&owner_w, Role::Owner, bob.address(), Role::Admin, None, None)
            .expect("owner signs grant");
    // A forgery: an attacker signs but claims the owner as issuer.
    let attacker = EthWallet::generate();
    let mut forged =
        rbac::sign_role_assertion(&attacker, Role::Owner, bob.address(), Role::Admin, None, None)
            .expect("attacker signs");
    forged.issuer = owner_w.address();

    let mut owner = MemberDaemon::new(owner_w, domain, 1000).expect("owner up");
    let gid = owner.create_group("deals").expect("create");
    onboard_member(&mut owner, domain, gid, &bob);

    // The forgery is rejected (signature doesn't recover to the claimed issuer); role unchanged.
    assert!(matches!(owner.assign_role(gid, &forged), Err(DaemonError::Rbac(_))));
    assert_eq!(role_in(&owner.roster(gid).unwrap(), bob.address()), Some(Role::Member));

    // The genuine owner-signed grant applies.
    owner.assign_role(gid, &grant).expect("assign admin");
    assert_eq!(role_in(&owner.roster(gid).unwrap(), bob.address()), Some(Role::Admin));
}

#[test]
fn revoke_role_demotes_via_a_signed_assertion() {
    let domain = "relay.test";
    let owner_w = EthWallet::generate();
    let bob = EthWallet::generate();
    let grant =
        rbac::sign_role_assertion(&owner_w, Role::Owner, bob.address(), Role::Admin, None, None)
            .expect("grant");
    let demote =
        rbac::sign_role_assertion(&owner_w, Role::Owner, bob.address(), Role::Member, None, None)
            .expect("demote");

    let mut owner = MemberDaemon::new(owner_w, domain, 1000).expect("owner up");
    let gid = owner.create_group("deals").expect("create");
    onboard_member(&mut owner, domain, gid, &bob);
    owner.assign_role(gid, &grant).expect("assign");
    assert_eq!(role_in(&owner.roster(gid).unwrap(), bob.address()), Some(Role::Admin));

    owner.revoke_role(gid, &demote).expect("revoke");
    assert_eq!(role_in(&owner.roster(gid).unwrap(), bob.address()), Some(Role::Member));
}

#[test]
fn add_member_without_a_published_key_package_is_an_honest_error() {
    let mut owner = MemberDaemon::new(EthWallet::generate(), "relay.test", 1000).expect("owner up");
    let gid = owner.create_group("deals").expect("create");
    let stranger = EthWallet::generate().address();
    let r = owner.add_member(gid, stranger);
    assert!(matches!(r, Err(DaemonError::NoKeyPackage(_))), "got {r:?}");
}

// ── Issue #3: durable MLS + group persistence across a full daemon restart ──

#[test]
fn groups_survive_a_full_restart_and_stay_usable() {
    let domain = "relay.test";
    let tmp = tempfile::tempdir().expect("tmp dir");
    let state_dir = tmp.path().join("state");

    // A STABLE identity: the seed is the anchor across restarts.
    let wallet = EthWallet::generate();
    let seed = wallet.secret_bytes();
    let owner_addr = wallet.address();

    // ── Boot 1: create a group and add bob (real MLS commit → epoch 1), then drop. ──
    let (gid, epoch_before);
    {
        let mut owner =
            MemberDaemon::new_persistent(wallet, domain, 1000, state_dir.clone(), &seed)
                .expect("owner boot 1");
        gid = owner.create_group("deals").expect("create");
        let bob = EthWallet::generate();
        onboard_member(&mut owner, domain, gid, &bob);
        epoch_before = owner.mls_epoch(gid).expect("epoch");
        assert_eq!(epoch_before, 1, "one add ⇒ MLS epoch 1");
        assert_eq!(owner.list_groups().len(), 1);
        assert_eq!(role_in(&owner.roster(gid).unwrap(), bob.address()), Some(Role::Member));
    } // daemon (and its ephemeral in-process relay) dropped — a full shutdown.

    // The encrypted state file was written.
    assert!(
        state_dir.join(crate::persist::STATE_FILE_NAME).exists(),
        "state file must be written"
    );

    // ── Boot 2: a FRESH daemon (new process, new in-process relay), same seed + dir. ──
    let wallet2 = EthWallet::from_secret_key(&seed).expect("re-derive wallet");
    assert_eq!(wallet2.address(), owner_addr);
    // A SUCCESSFUL boot is itself a signer-liveness proof: `build` re-publishes a fresh
    // KeyPackage, which the RESTORED signer must sign and the restored provider must build.
    let owner2 = MemberDaemon::new_persistent(wallet2, domain, 9000, state_dir.clone(), &seed)
        .expect("owner boot 2 (restart)");

    // (1) The group came back WITHOUT any re-create — the primary bug in #3.
    let groups = owner2.list_groups();
    assert_eq!(groups.len(), 1, "groups must survive the restart, got {groups:?}");
    assert_eq!(groups[0].0, gid);
    assert_eq!(groups[0].1, "deals");

    // (2) The daemon roster (bob included, roles preserved) survived.
    let roster = owner2.roster(gid).expect("roster");
    assert_eq!(role_in(&roster, owner_addr), Some(Role::Owner));
    assert_eq!(roster.len(), 2, "owner + bob must be restored, got {roster:?}");

    // (3) The reloaded OpenMLS group is real and at the SAME epoch — proof the epoch
    //     secrets deserialized, not just the registry counter (`MlsGroup::load` worked).
    assert_eq!(
        owner2.mls_epoch(gid).expect("epoch after restart"),
        epoch_before,
        "the restored MLS group must be at the pre-restart epoch"
    );

    // (4) It persists again across a SECOND restart (idempotent rehydrate → re-persist).
    drop(owner2);
    let wallet3 = EthWallet::from_secret_key(&seed).expect("re-derive");
    let owner3 = MemberDaemon::new_persistent(wallet3, domain, 20000, state_dir.clone(), &seed)
        .expect("owner boot 3");
    assert_eq!(owner3.roster(gid).expect("roster").len(), 2);
    assert_eq!(owner3.mls_epoch(gid).expect("epoch"), epoch_before);
}

#[test]
fn restart_with_the_wrong_seed_fails_closed() {
    let domain = "relay.test";
    let tmp = tempfile::tempdir().expect("tmp dir");
    let state_dir = tmp.path().join("state");

    let wallet = EthWallet::generate();
    let seed = wallet.secret_bytes();
    {
        let mut owner =
            MemberDaemon::new_persistent(wallet, domain, 1000, state_dir.clone(), &seed)
                .expect("owner boot 1");
        owner.create_group("deals").expect("create");
    }

    // A DIFFERENT identity pointed at the same state dir must NOT silently start empty:
    // the AEAD key is derived from the seed, so decryption fails and the daemon errors.
    let attacker = EthWallet::generate();
    let bad_seed = attacker.secret_bytes();
    let r = MemberDaemon::new_persistent(attacker, domain, 5000, state_dir.clone(), &bad_seed);
    assert!(
        matches!(r, Err(DaemonError::Persist(_))),
        "a wrong-seed restart must fail closed, got {:?}",
        r.as_ref().map(|_| "Ok")
    );
}

#[test]
fn relay_status_op_reports_connected_for_the_in_process_relay() {
    // Flag-A — the health query maps straight to Relay::is_connected. The in-process relay is always
    // local-up, so a fresh daemon answers relayStatus{connected:true}. (A networked WsRelay overrides
    // is_connected with a live challenge round-trip; a dropped link answers connected:false.)
    let mut d = MemberDaemon::new(EthWallet::generate(), "relay.test", 1000).expect("daemon up");
    assert!(d.relay_connected(), "in-process relay is always connected");
    match crate::ipc::handle_request(&mut d, crate::ipc::Request::RelayStatus) {
        crate::ipc::Response::RelayStatus { connected } => assert!(connected),
        other => panic!("expected RelayStatus, got {other:?}"),
    }
}
