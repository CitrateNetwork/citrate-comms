//! Delegated grants follow the holder's membership, and membership ops act on one group.
//!
//! - Offboarding a member from a group ends every grant they held there: adding them
//!   back as a plain member does not bring an old, unexpired grant back to life. A new
//!   grant issued for their current generation works.
//! - Offboarding a group's creator ends their creator authority in that group.
//! - `onboard` / `offboard` refuse an envelope whose `group_id` is not the request's.
//! - A refused envelope leaves the roster exactly as it was.

use comms_core::identity::{EthWallet, SiweMessage};
use comms_core::rbac;
use comms_proto::{
    Envelope, EnvelopeKind, EpochId, GroupId, Role, RoleAssertion, WalletAddress, CITRATE_CHAIN_ID,
};
use comms_relay::{DeliveryService, OffboardRequest};

const DOMAIN: &str = "relay.citrate.ai";
const GID_A: GroupId = GroupId([0xA1; 32]);
const GID_B: GroupId = GroupId([0xB2; 32]);
const T: u64 = 1_000_000;
const EXP: u64 = T + 3_600_000;

fn login(relay: &mut DeliveryService, wallet: &EthWallet) {
    let nonce = relay.issue_challenge(T);
    let msg = SiweMessage {
        domain: DOMAIN.into(),
        address: wallet.address(),
        statement: "Sign in to citrate-comms".into(),
        uri: format!("wss://{DOMAIN}"),
        version: "1".into(),
        chain_id: CITRATE_CHAIN_ID,
        nonce,
        issued_at_ms: T,
        expiration_ms: T + 600_000,
    };
    let sig = wallet.sign_siwe(&msg);
    relay.authenticate(&msg, &sig, T).unwrap();
}

fn env(
    gid: GroupId,
    sender: WalletAddress,
    kind: EnvelopeKind,
    epoch: u64,
    ct: &[u8],
    to: &[WalletAddress],
) -> Envelope {
    Envelope {
        group_id: gid,
        epoch: EpochId(epoch),
        kind,
        sender,
        recipients: to.to_vec(),
        ciphertext: ct.to_vec(),
        group_seq: None,
    }
}

/// The owner creates A; carol creates B. dave is a plain member of A and of B; erin is a
/// plain member of B. Every wallet holds a session.
struct World {
    relay: DeliveryService,
    owner: EthWallet,
    carol: EthWallet,
    dave: EthWallet,
    erin: EthWallet,
}

fn populate(relay: &mut DeliveryService) -> (EthWallet, EthWallet, EthWallet) {
    let carol = EthWallet::generate();
    let dave = EthWallet::generate();
    let erin = EthWallet::generate();
    for w in [&carol, &dave, &erin] {
        login(relay, w);
    }
    let owner = relay.owner();
    relay.register_group(GID_A, owner, T).unwrap();
    relay.register_group(GID_B, carol.address(), T).unwrap();
    onboard_ok(relay, GID_A, owner, dave.address(), None);
    onboard_ok(relay, GID_B, carol.address(), dave.address(), None);
    onboard_ok(relay, GID_B, carol.address(), erin.address(), None);
    (carol, dave, erin)
}

fn world() -> World {
    let owner = EthWallet::generate();
    let mut relay = DeliveryService::new(DOMAIN, owner.address(), 0).unwrap();
    login(&mut relay, &owner);
    let (carol, dave, erin) = populate(&mut relay);
    World {
        relay,
        owner,
        carol,
        dave,
        erin,
    }
}

fn onboard(
    relay: &mut DeliveryService,
    gid: GroupId,
    admin: WalletAddress,
    joiner: WalletAddress,
    grant: Option<&RoleAssertion>,
) -> Result<(), comms_relay::RelayError> {
    relay.onboard(
        gid,
        admin,
        grant,
        joiner,
        env(gid, admin, EnvelopeKind::Welcome, 0, b"welcome", &[joiner]),
        b"tree".to_vec(),
        T,
    )
}

fn onboard_ok(
    relay: &mut DeliveryService,
    gid: GroupId,
    admin: WalletAddress,
    joiner: WalletAddress,
    grant: Option<&RoleAssertion>,
) {
    onboard(relay, gid, admin, joiner, grant).unwrap();
}

/// The group's current epoch, read from the accepted Commits in its log.
fn epoch(relay: &DeliveryService, gid: GroupId) -> u64 {
    relay
        .group_log(&gid)
        .unwrap()
        .iter()
        .filter(|e| e.kind == EnvelopeKind::Commit)
        .map(|e| e.epoch.0)
        .max()
        .unwrap_or(0)
}

fn offboard(
    relay: &mut DeliveryService,
    gid: GroupId,
    admin: WalletAddress,
    removed: WalletAddress,
    grant: Option<&RoleAssertion>,
) -> Result<u64, comms_relay::RelayError> {
    let next = epoch(relay, gid) + 1;
    relay.offboard(
        OffboardRequest {
            group_id: gid,
            admin,
            admin_assertion: grant,
            removed,
            remove_commit: env(gid, admin, EnvelopeKind::Commit, next, b"remove", &[]),
            ratchet_tree: b"tree-after-remove".to_vec(),
        },
        T,
    )
}

fn members(relay: &DeliveryService, gid: GroupId) -> Vec<WalletAddress> {
    relay.group_members(&gid).unwrap_or_default()
}

fn log_len(relay: &DeliveryService, gid: GroupId) -> usize {
    relay.group_log(&gid).map(|l| l.len()).unwrap_or(0)
}

/// An owner-signed Admin grant for dave in group A, as issued before any offboard.
fn dave_admin_grant_a(w: &World) -> RoleAssertion {
    rbac::sign_role_assertion(
        &w.owner,
        Role::Owner,
        w.dave.address(),
        Role::Admin,
        Some(GID_A),
        Some(EXP),
    )
    .unwrap()
}

/// The owner offboards dave from A, then adds him back as a plain member. dave logs in
/// again (offboarding ended his session).
fn offboard_then_readd_dave(w: &mut World) {
    let (owner, dave) = (w.owner.address(), w.dave.address());
    offboard(&mut w.relay, GID_A, owner, dave, None).unwrap();
    assert!(!members(&w.relay, GID_A).contains(&dave));
    onboard_ok(&mut w.relay, GID_A, owner, dave, None);
    login(&mut w.relay, &w.dave);
}

// ─────────────────────── offboarding ends a delegate's grants ───────────────────────

#[test]
fn readded_delegate_old_grant_is_refused() {
    let mut w = world();
    let old = dave_admin_grant_a(&w);
    let dave = w.dave.address();

    // While dave holds the grant it works: he onboards x into A.
    let x = EthWallet::generate().address();
    onboard_ok(&mut w.relay, GID_A, dave, x, Some(&old));

    offboard_then_readd_dave(&mut w);

    // The pre-offboard grant no longer authorizes onboarding...
    let y = EthWallet::generate().address();
    let r = onboard(&mut w.relay, GID_A, dave, y, Some(&old));
    assert!(
        r.is_err(),
        "a grant issued before the holder was offboarded must not authorize onboarding \
         after they are added back, got {r:?}"
    );
    assert!(!members(&w.relay, GID_A).contains(&y));

    // ...or offboarding.
    let r = offboard(&mut w.relay, GID_A, dave, x, Some(&old));
    assert!(
        r.is_err(),
        "a grant issued before the holder was offboarded must not authorize offboarding \
         after they are added back, got {r:?}"
    );
    assert!(members(&w.relay, GID_A).contains(&x));
}

#[test]
fn readded_delegate_needs_a_grant_for_the_current_generation() {
    let mut w = world();
    let dave = w.dave.address();
    assert_eq!(w.relay.grant_generation(&GID_A, &dave), Some(0));

    offboard_then_readd_dave(&mut w);
    assert_eq!(
        w.relay.grant_generation(&GID_A, &dave),
        Some(1),
        "offboarding must advance the member's grant generation in that group"
    );

    // A grant pre-signed for a later generation is refused (exact match only).
    let future = rbac::sign_group_grant(
        &w.owner,
        Role::Owner,
        dave,
        Role::Admin,
        GID_A,
        2,
        Some(EXP),
    )
    .unwrap();
    let y = EthWallet::generate().address();
    assert!(onboard(&mut w.relay, GID_A, dave, y, Some(&future)).is_err());
    assert!(!members(&w.relay, GID_A).contains(&y));

    // A new grant for the current generation works.
    let fresh = rbac::sign_group_grant(
        &w.owner,
        Role::Owner,
        dave,
        Role::Admin,
        GID_A,
        1,
        Some(EXP),
    )
    .unwrap();
    onboard_ok(&mut w.relay, GID_A, dave, y, Some(&fresh));
    assert!(members(&w.relay, GID_A).contains(&y));
}

#[test]
fn offboard_from_one_group_leaves_grants_in_another_group_alone() {
    let mut w = world();
    let grant_a = dave_admin_grant_a(&w);
    let (carol, dave) = (w.carol.address(), w.dave.address());

    offboard(&mut w.relay, GID_B, carol, dave, None).unwrap();
    login(&mut w.relay, &w.dave);
    assert_eq!(w.relay.grant_generation(&GID_A, &dave), Some(0));
    assert_eq!(w.relay.grant_generation(&GID_B, &dave), None);

    let x = EthWallet::generate().address();
    onboard_ok(&mut w.relay, GID_A, dave, x, Some(&grant_a));
}

#[test]
fn offboarded_grant_stays_dead_across_restart() {
    let dir = tempfile::tempdir().unwrap();
    let owner = EthWallet::generate();
    let key = [7u8; 32];
    let (dave, old) = {
        let mut relay = DeliveryService::open(dir.path(), DOMAIN, owner.address(), key, 0).unwrap();
        login(&mut relay, &owner);
        let (_carol, dave, _erin) = populate(&mut relay);
        let old = rbac::sign_role_assertion(
            &owner,
            Role::Owner,
            dave.address(),
            Role::Admin,
            Some(GID_A),
            Some(EXP),
        )
        .unwrap();
        offboard(&mut relay, GID_A, owner.address(), dave.address(), None).unwrap();
        onboard_ok(&mut relay, GID_A, owner.address(), dave.address(), None);
        (dave, old)
    };

    let mut relay = DeliveryService::open(dir.path(), DOMAIN, owner.address(), key, 0).unwrap();
    login(&mut relay, &dave);
    assert_eq!(relay.grant_generation(&GID_A, &dave.address()), Some(1));
    let y = EthWallet::generate().address();
    let r = onboard(&mut relay, GID_A, dave.address(), y, Some(&old));
    assert!(
        r.is_err(),
        "a pre-offboard grant must stay refused after a relay restart, got {r:?}"
    );
    assert!(!members(&relay, GID_A).contains(&y));
}

#[test]
fn readded_creator_has_no_creator_authority() {
    let mut w = world();
    let (owner, carol) = (w.owner.address(), w.carol.address());
    // The owner joins B so it can offboard and re-add carol there.
    onboard_ok(&mut w.relay, GID_B, carol, owner, None);
    offboard(&mut w.relay, GID_B, owner, carol, None).unwrap();
    onboard_ok(&mut w.relay, GID_B, owner, carol, None);
    login(&mut w.relay, &w.carol);

    let z = EthWallet::generate().address();
    let r = onboard(&mut w.relay, GID_B, carol, z, None);
    assert!(
        r.is_err(),
        "an offboarded creator added back as a plain member must not keep creator authority, \
         got {r:?}"
    );
    assert!(!members(&w.relay, GID_B).contains(&z));
    let erin = w.erin.address();
    assert!(offboard(&mut w.relay, GID_B, carol, erin, None).is_err());
    assert!(members(&w.relay, GID_B).contains(&erin));
}

// ─────────────────────── the envelope belongs to the request's group ───────────────────────

#[test]
fn onboard_refuses_a_welcome_for_another_group() {
    let mut w = world();
    let grant_a = dave_admin_grant_a(&w);
    let (dave, erin) = (w.dave.address(), w.erin.address());
    let (a_before, b_before) = (members(&w.relay, GID_A), members(&w.relay, GID_B));
    let b_log = log_len(&w.relay, GID_B);

    // Authorized in A, but the Welcome is addressed to B (where erin already is).
    let r = w.relay.onboard(
        GID_A,
        dave,
        Some(&grant_a),
        erin,
        env(GID_B, dave, EnvelopeKind::Welcome, 0, b"w-cross", &[erin]),
        b"tree".to_vec(),
        T,
    );
    assert!(
        r.is_err(),
        "onboard for A must refuse a Welcome whose group is B, got {r:?}"
    );
    assert_eq!(
        log_len(&w.relay, GID_B),
        b_log,
        "nothing may land in B's log"
    );
    assert_eq!(
        members(&w.relay, GID_A),
        a_before,
        "A's roster is unchanged"
    );
    assert_eq!(
        members(&w.relay, GID_B),
        b_before,
        "B's roster is unchanged"
    );

    // Same, with a joiner who is in neither group (the Welcome is then refused by B).
    let j = EthWallet::generate().address();
    let owner = w.owner.address();
    let r = w.relay.onboard(
        GID_A,
        owner,
        None,
        j,
        env(GID_B, owner, EnvelopeKind::Welcome, 0, b"w-cross-2", &[j]),
        b"tree".to_vec(),
        T,
    );
    assert!(r.is_err(), "got {r:?}");
    assert_eq!(
        members(&w.relay, GID_A),
        a_before,
        "A's roster is unchanged"
    );
    assert_eq!(log_len(&w.relay, GID_B), b_log);
}

#[test]
fn offboard_refuses_a_commit_for_another_group() {
    let mut w = world();
    let grant_a = dave_admin_grant_a(&w);
    let (owner, dave) = (w.owner.address(), w.dave.address());
    let x = EthWallet::generate().address();
    onboard_ok(&mut w.relay, GID_A, owner, x, None);
    let (a_before, b_before) = (members(&w.relay, GID_A), members(&w.relay, GID_B));
    let (b_log, b_epoch) = (log_len(&w.relay, GID_B), epoch(&w.relay, GID_B));

    // Authorized to remove x from A, but the Remove commit is for B's next epoch.
    let r = w.relay.offboard(
        OffboardRequest {
            group_id: GID_A,
            admin: dave,
            admin_assertion: Some(&grant_a),
            removed: x,
            remove_commit: env(
                GID_B,
                dave,
                EnvelopeKind::Commit,
                b_epoch + 1,
                b"rm-cross",
                &[],
            ),
            ratchet_tree: b"tree-after".to_vec(),
        },
        T,
    );
    assert!(
        r.is_err(),
        "offboard for A must refuse a Commit whose group is B, got {r:?}"
    );
    assert_eq!(members(&w.relay, GID_A), a_before, "x stays in A");
    assert_eq!(members(&w.relay, GID_B), b_before);
    assert_eq!(
        log_len(&w.relay, GID_B),
        b_log,
        "nothing may land in B's log"
    );
    assert_eq!(epoch(&w.relay, GID_B), b_epoch, "B's epoch is unchanged");
}

// ─────────────────────── a refused envelope leaves the roster unchanged ───────────────────────

#[test]
fn failed_welcome_submit_leaves_the_roster_unchanged() {
    let mut w = world();
    let owner = w.owner.address();
    let before = members(&w.relay, GID_A);

    // (1) The Welcome names a sender other than the acting admin: refused at submit.
    let j = EthWallet::generate().address();
    let r = w.relay.onboard(
        GID_A,
        owner,
        None,
        j,
        env(
            GID_A,
            w.dave.address(),
            EnvelopeKind::Welcome,
            0,
            b"w",
            &[j],
        ),
        b"tree-new".to_vec(),
        T,
    );
    assert!(r.is_err(), "got {r:?}");
    assert_eq!(
        members(&w.relay, GID_A),
        before,
        "a refused Welcome must not leave the joiner in the roster"
    );

    // (2) An oversized Welcome: refused at submit.
    let k = EthWallet::generate().address();
    let big = vec![0u8; 4 * 1024 * 1024 + 1];
    let r = w.relay.onboard(
        GID_A,
        owner,
        None,
        k,
        env(GID_A, owner, EnvelopeKind::Welcome, 0, &big, &[k]),
        b"tree-new".to_vec(),
        T,
    );
    assert!(r.is_err(), "got {r:?}");
    assert_eq!(members(&w.relay, GID_A), before);

    // (3) Re-onboarding an existing member with a refused Welcome keeps them a member.
    let dave = w.dave.address();
    let r = w.relay.onboard(
        GID_A,
        owner,
        None,
        dave,
        env(GID_A, owner, EnvelopeKind::Welcome, 0, &big, &[dave]),
        b"tree-new".to_vec(),
        T,
    );
    assert!(r.is_err(), "got {r:?}");
    assert_eq!(members(&w.relay, GID_A), before);
    assert_eq!(w.relay.ratchet_tree(&GID_A), Some(&b"tree"[..]));
}

#[test]
fn failed_welcome_submit_is_not_persisted_by_a_later_write() {
    let dir = tempfile::tempdir().unwrap();
    let owner = EthWallet::generate();
    let key = [9u8; 32];
    let j = EthWallet::generate().address();
    {
        let mut relay = DeliveryService::open(dir.path(), DOMAIN, owner.address(), key, 0).unwrap();
        login(&mut relay, &owner);
        relay.register_group(GID_A, owner.address(), T).unwrap();
        let o = owner.address();
        let big = vec![0u8; 4 * 1024 * 1024 + 1];
        assert!(relay
            .onboard(
                GID_A,
                o,
                None,
                j,
                env(GID_A, o, EnvelopeKind::Welcome, 0, &big, &[j]),
                b"t".to_vec(),
                T,
            )
            .is_err());
        // A later, unrelated successful write persists the group snapshot.
        relay
            .submit_as(
                o,
                env(GID_A, o, EnvelopeKind::Application, 0, b"hi", &[]),
                T,
            )
            .unwrap();
    }
    let relay = DeliveryService::open(dir.path(), DOMAIN, owner.address(), key, 0).unwrap();
    assert!(
        !members(&relay, GID_A).contains(&j),
        "a refused onboard must not reach the durable roster"
    );
}

#[test]
fn membership_ops_refuse_the_wrong_envelope_kind() {
    let mut w = world();
    let owner = w.owner.address();
    let before = members(&w.relay, GID_A);
    let (log, ep) = (log_len(&w.relay, GID_A), epoch(&w.relay, GID_A));

    // An onboard carrying a Commit (which would advance the epoch) instead of a Welcome.
    let j = EthWallet::generate().address();
    let r = w.relay.onboard(
        GID_A,
        owner,
        None,
        j,
        env(
            GID_A,
            owner,
            EnvelopeKind::Commit,
            ep + 1,
            b"not-a-welcome",
            &[j],
        ),
        b"tree-new".to_vec(),
        T,
    );
    assert!(r.is_err(), "got {r:?}");
    assert_eq!(members(&w.relay, GID_A), before);
    assert_eq!(
        (log_len(&w.relay, GID_A), epoch(&w.relay, GID_A)),
        (log, ep)
    );

    // An offboard carrying an application message instead of a Remove commit.
    let dave = w.dave.address();
    let r = w.relay.offboard(
        OffboardRequest {
            group_id: GID_A,
            admin: owner,
            admin_assertion: None,
            removed: dave,
            remove_commit: env(GID_A, owner, EnvelopeKind::Application, ep, b"msg", &[]),
            ratchet_tree: b"tree-after".to_vec(),
        },
        T,
    );
    assert!(r.is_err(), "got {r:?}");
    assert_eq!(members(&w.relay, GID_A), before);
    assert_eq!(log_len(&w.relay, GID_A), log);
}

// ─────────────────────── the generation over the wire ───────────────────────

#[tokio::test]
async fn grant_generation_is_served_to_members_only() {
    use comms_relay::ws::{RelayClient, RelayServer};

    async fn ws_login(c: &RelayClient, nonce: String, wallet: &EthWallet) {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64;
        let msg = SiweMessage {
            domain: DOMAIN.into(),
            address: wallet.address(),
            statement: "Sign in to citrate-comms".into(),
            uri: format!("wss://{DOMAIN}"),
            version: "1".into(),
            chain_id: CITRATE_CHAIN_ID,
            nonce,
            issued_at_ms: now,
            expiration_ms: now + 600_000,
        };
        let sig = wallet.sign_siwe(&msg);
        c.authenticate(msg, sig).await.unwrap();
    }

    let owner = EthWallet::generate();
    let dave = EthWallet::generate();
    let stranger = EthWallet::generate();
    let server = RelayServer::new(DeliveryService::new(DOMAIN, owner.address(), 0).unwrap());
    let (addr, _h) = server.clone().bind("127.0.0.1:0").await.unwrap();
    let url = format!("ws://{addr}");
    let (owner_c, n) = RelayClient::connect(&url).await.unwrap();
    ws_login(&owner_c, n, &owner).await;
    let (dave_c, n) = RelayClient::connect(&url).await.unwrap();
    ws_login(&dave_c, n, &dave).await;
    let (stranger_c, n) = RelayClient::connect(&url).await.unwrap();
    ws_login(&stranger_c, n, &stranger).await;

    let (o, d) = (owner.address(), dave.address());
    owner_c.register_group(GID_A).await.unwrap();
    let welcome = |ct: &[u8]| env(GID_A, o, EnvelopeKind::Welcome, 0, ct, &[d]);
    owner_c
        .onboard(GID_A, d, None, welcome(b"w1"), b"t".to_vec())
        .await
        .unwrap();
    assert_eq!(owner_c.grant_generation(GID_A, d).await.unwrap(), Some(0));
    owner_c
        .offboard(
            GID_A,
            d,
            None,
            env(GID_A, o, EnvelopeKind::Commit, 1, b"rm", &[]),
            b"t2".to_vec(),
        )
        .await
        .unwrap();
    assert_eq!(owner_c.grant_generation(GID_A, d).await.unwrap(), None);
    owner_c
        .onboard(GID_A, d, None, welcome(b"w2"), b"t3".to_vec())
        .await
        .unwrap();
    assert_eq!(owner_c.grant_generation(GID_A, d).await.unwrap(), Some(1));
    // A non-member may not read a group's membership metadata.
    assert!(stranger_c.grant_generation(GID_A, d).await.is_err());
    drop(dave_c);
}

// ───────────────────────────── tripwire ─────────────────────────────

/// Structural problems in relay production code (`lib.rs` before its test module):
/// - a member may leave a roster only through `end_membership`, which also advances
///   their grant generation (so no grant outlives the membership it was issued for);
/// - `onboard` and `offboard` must check their envelope with `require_op_envelope`
///   before submitting it.
fn membership_tripwire(src: &str) -> Vec<String> {
    let prod = src.split("\n#[cfg(test)]").next().unwrap_or(src);
    let mut out = Vec::new();
    let removes = prod.matches("members.remove(").count();
    let helper = prod
        .split("fn end_membership(")
        .nth(1)
        .and_then(|b| b.split("\n    }").next())
        .unwrap_or("");
    if removes != 1 || !helper.contains("members.remove(") {
        out.push(format!(
            "`members.remove(` must appear exactly once, inside `end_membership` (found {removes})"
        ));
    }
    if !helper.contains("grant_generations") {
        out.push("`end_membership` must advance the grant generation".into());
    }
    for op in ["pub fn onboard(", "pub fn offboard("] {
        let body = prod
            .split(op)
            .nth(1)
            .and_then(|b| b.split("\n    pub fn ").next())
            .unwrap_or("");
        let check = body.find("require_op_envelope(");
        let submit = body.find("self.submit_as(admin");
        match (check, submit) {
            (Some(c), Some(s)) if c < s => {}
            _ => out.push(format!(
                "`{op}` must call `require_op_envelope` before `submit_as`"
            )),
        }
    }
    out
}

#[test]
fn tripwire_membership_ends_grants_and_ops_check_their_envelope() {
    let v = membership_tripwire(include_str!("../src/lib.rs"));
    assert!(v.is_empty(), "TRIPWIRE: {v:#?}");
}

#[test]
fn tripwire_membership_negative_control() {
    let good = "\
    fn end_membership(&mut self, m: &W) {
        self.members.remove(m);
        self.grant_generations.entry(*m);
    }
    pub fn onboard(&mut self) {
        require_op_envelope(&w, g, K)?;
        self.submit_as(admin, w, n)?;
    }
    pub fn offboard(&mut self) {
        require_op_envelope(&c, g, K)?;
        self.submit_as(admin, c, n)?;
    }
";
    assert!(membership_tripwire(good).is_empty());
    // A second roster removal that bypasses the generation bump.
    let extra = good.replace(
        "pub fn offboard(&mut self) {",
        "pub fn offboard(&mut self) {\n        state.members.remove(&x);",
    );
    assert_eq!(membership_tripwire(&extra).len(), 1);
    // The helper stops advancing the generation.
    let no_bump = good.replace("self.grant_generations.entry(*m);", "");
    assert_eq!(membership_tripwire(&no_bump).len(), 1);
    // An op that submits before checking its envelope, or never checks it.
    let late = good.replace(
        "        require_op_envelope(&w, g, K)?;\n        self.submit_as(admin, w, n)?;",
        "        self.submit_as(admin, w, n)?;\n        require_op_envelope(&w, g, K)?;",
    );
    assert_eq!(membership_tripwire(&late).len(), 1);
    let none = good.replace("        require_op_envelope(&c, g, K)?;\n", "");
    assert_eq!(membership_tripwire(&none).len(), 1);
}
