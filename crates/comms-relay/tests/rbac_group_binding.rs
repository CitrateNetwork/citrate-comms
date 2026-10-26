//! Role grants are bound to the group they are evaluated for.
//!
//! Driven through the real WebSocket entry point (`RelayServer` + `RelayClient`): a
//! delegated grant authorizes a membership operation (onboard / offboard) only in the
//! group named by the grant's signed `scope`. A grant for another group, a grant with
//! no group, a grant whose group was edited after signing, and a grant whose holder was
//! removed from the group are all refused, and the roster is left unchanged.

use comms_core::identity::{EthWallet, SiweMessage};
use comms_core::rbac;
use comms_proto::{
    Envelope, EnvelopeKind, EpochId, GroupId, Role, RoleAssertion, WalletAddress, CITRATE_CHAIN_ID,
};
use comms_relay::ws::{RelayClient, RelayServer};
use comms_relay::DeliveryService;

const DOMAIN: &str = "relay.citrate.ai";

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64
}

async fn login(client: &RelayClient, nonce: String, wallet: &EthWallet) -> WalletAddress {
    let now = now_ms();
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
    client.authenticate(msg, sig).await.unwrap()
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

const GID_A: GroupId = GroupId([0xA1; 32]);
const GID_B: GroupId = GroupId([0xB2; 32]);

/// Two groups on one relay. The workspace owner creates A; `carol` creates B. `dave` is
/// an admin delegate who is an ordinary member of BOTH groups; `erin` is an ordinary
/// member of B. Nobody but the owner and carol holds creator authority anywhere.
struct World {
    owner: EthWallet,
    dave: EthWallet,
    erin: EthWallet,
    owner_c: RelayClient,
    carol_c: RelayClient,
    dave_c: RelayClient,
    url: String,
}

async fn world() -> World {
    let owner = EthWallet::generate();
    let carol = EthWallet::generate();
    let dave = EthWallet::generate();
    let erin = EthWallet::generate();
    let service = DeliveryService::new(DOMAIN, owner.address(), 0).unwrap();
    let server = RelayServer::new(service);
    let (addr, _h) = server.clone().bind("127.0.0.1:0").await.unwrap();
    let url = format!("ws://{addr}");

    let (owner_c, n) = RelayClient::connect(&url).await.unwrap();
    login(&owner_c, n, &owner).await;
    let (carol_c, n) = RelayClient::connect(&url).await.unwrap();
    login(&carol_c, n, &carol).await;
    let (dave_c, n) = RelayClient::connect(&url).await.unwrap();
    login(&dave_c, n, &dave).await;
    let (erin_c, n) = RelayClient::connect(&url).await.unwrap();
    login(&erin_c, n, &erin).await;

    owner_c.register_group(GID_A).await.unwrap();
    carol_c.register_group(GID_B).await.unwrap();
    owner_c
        .onboard(
            GID_A,
            dave.address(),
            None,
            env(
                GID_A,
                owner.address(),
                EnvelopeKind::Welcome,
                0,
                b"wa",
                &[dave.address()],
            ),
            b"rt-a".to_vec(),
        )
        .await
        .unwrap();
    for (who, ct) in [
        (dave.address(), &b"wb-d"[..]),
        (erin.address(), &b"wb-e"[..]),
    ] {
        carol_c
            .onboard(
                GID_B,
                who,
                None,
                env(GID_B, carol.address(), EnvelopeKind::Welcome, 0, ct, &[who]),
                b"rt-b".to_vec(),
            )
            .await
            .unwrap();
    }
    drop(erin_c);
    World {
        owner,
        dave,
        erin,
        owner_c,
        carol_c,
        dave_c,
        url,
    }
}

fn admin_grant(w: &World, scope: Option<GroupId>) -> RoleAssertion {
    rbac::sign_role_assertion(
        &w.owner,
        Role::Owner,
        w.dave.address(),
        Role::Admin,
        scope,
        Some(now_ms() + 3_600_000),
    )
    .unwrap()
}

async fn members(c: &RelayClient, gid: GroupId) -> Vec<WalletAddress> {
    c.group_members(gid).await.unwrap().unwrap_or_default()
}

/// Dave tries to onboard a fresh wallet into group B with `grant`. Returns the result.
async fn dave_onboards_into_b(w: &World, grant: RoleAssertion) -> Result<(), String> {
    let joiner = EthWallet::generate();
    let r = w
        .dave_c
        .onboard(
            GID_B,
            joiner.address(),
            Some(grant),
            env(
                GID_B,
                w.dave.address(),
                EnvelopeKind::Welcome,
                0,
                b"w-x",
                &[joiner.address()],
            ),
            b"rt-overwritten".to_vec(),
        )
        .await;
    let roster = members(&w.carol_c, GID_B).await;
    if r.is_err() {
        assert!(
            !roster.contains(&joiner.address()),
            "a refused onboard must leave the roster unchanged"
        );
        assert_eq!(
            w.carol_c.ratchet_tree(GID_B).await.unwrap().as_deref(),
            Some(&b"rt-b"[..]),
            "a refused onboard must not overwrite the stored ratchet tree"
        );
    }
    r.map_err(|e| e.to_string())
}

/// Dave tries to offboard erin from group B with `grant`.
async fn dave_offboards_erin_from_b(w: &World, grant: RoleAssertion) -> Result<u64, String> {
    let r = w
        .dave_c
        .offboard(
            GID_B,
            w.erin.address(),
            Some(grant),
            env(GID_B, w.dave.address(), EnvelopeKind::Commit, 1, b"rm", &[]),
            b"rt-rm".to_vec(),
        )
        .await;
    if r.is_err() {
        assert!(
            members(&w.carol_c, GID_B).await.contains(&w.erin.address()),
            "a refused offboard must leave the member in the roster"
        );
    }
    r.map_err(|e| e.to_string())
}

#[tokio::test]
async fn grant_for_group_a_does_not_authorize_onboard_into_group_b() {
    let w = world().await;
    let grant_a = admin_grant(&w, Some(GID_A));
    let r = dave_onboards_into_b(&w, grant_a).await;
    assert!(
        r.is_err(),
        "a grant scoped to group A must not authorize onboarding into group B"
    );
}

#[tokio::test]
async fn grant_for_group_a_does_not_authorize_offboard_in_group_b() {
    let w = world().await;
    let grant_a = admin_grant(&w, Some(GID_A));
    let r = dave_offboards_erin_from_b(&w, grant_a).await;
    assert!(
        r.is_err(),
        "a grant scoped to group A must not authorize offboarding in group B"
    );
}

#[tokio::test]
async fn grant_with_no_group_is_refused_for_membership_ops() {
    let w = world().await;
    let unscoped = admin_grant(&w, None);
    assert!(
        dave_onboards_into_b(&w, unscoped.clone()).await.is_err(),
        "a grant with no group must not authorize onboarding (fail closed)"
    );
    assert!(
        dave_offboards_erin_from_b(&w, unscoped).await.is_err(),
        "a grant with no group must not authorize offboarding (fail closed)"
    );
}

#[tokio::test]
async fn grant_whose_group_was_edited_after_signing_is_refused() {
    let w = world().await;
    // Signed for A, then the scope field rewritten to B to match the request.
    let mut forged = admin_grant(&w, Some(GID_A));
    forged.scope = Some(GID_B);
    assert!(dave_onboards_into_b(&w, forged.clone()).await.is_err());
    assert!(dave_offboards_erin_from_b(&w, forged).await.is_err());
}

#[tokio::test]
async fn grant_for_the_same_group_still_authorizes_both_ops() {
    let w = world().await;
    let grant_b = admin_grant(&w, Some(GID_B));
    dave_onboards_into_b(&w, grant_b.clone())
        .await
        .expect("a grant scoped to group B authorizes onboarding into B");
    dave_offboards_erin_from_b(&w, grant_b)
        .await
        .expect("a grant scoped to group B authorizes offboarding in B");
    assert!(!members(&w.carol_c, GID_B).await.contains(&w.erin.address()));
}

#[tokio::test]
async fn revoked_grant_is_refused() {
    let w = world().await;
    // (1) An expired grant for the right group is refused.
    let expired = rbac::sign_role_assertion(
        &w.owner,
        Role::Owner,
        w.dave.address(),
        Role::Admin,
        Some(GID_B),
        Some(now_ms().saturating_sub(1)),
    )
    .unwrap();
    assert!(dave_onboards_into_b(&w, expired.clone()).await.is_err());
    assert!(dave_offboards_erin_from_b(&w, expired).await.is_err());

    // (2) Revocation by removal: the owner holds group A; dave's A-scoped grant works in
    // A until the owner offboards him from A. After that, even a fresh session holding
    // the still-unexpired grant cannot act in A.
    let grant_a = admin_grant(&w, Some(GID_A));
    w.owner_c
        .offboard(
            GID_A,
            w.dave.address(),
            None,
            env(
                GID_A,
                w.owner.address(),
                EnvelopeKind::Commit,
                1,
                b"rm-d",
                &[],
            ),
            b"rt-a2".to_vec(),
        )
        .await
        .unwrap();
    let (dave_c2, n) = RelayClient::connect(&w.url).await.unwrap();
    login(&dave_c2, n, &w.dave).await;
    let joiner = EthWallet::generate();
    let r = dave_c2
        .onboard(
            GID_A,
            joiner.address(),
            Some(grant_a),
            env(
                GID_A,
                w.dave.address(),
                EnvelopeKind::Welcome,
                1,
                b"w-after",
                &[joiner.address()],
            ),
            b"rt-a3".to_vec(),
        )
        .await;
    assert!(
        r.is_err(),
        "a removed delegate's grant must not authorize onboarding"
    );
    assert!(!members(&w.owner_c, GID_A).await.contains(&joiner.address()));
}

// ───────────────────────────── tripwire ─────────────────────────────

/// Grant-verification calls in relay production code that are NOT bound to a group.
/// Every grant check must go through `verify_grant_for_group(…, group_id, …)`; the
/// unbound `verify_grant_chain` / `verify_role_assertion` must not be called directly.
fn unbound_grant_checks(file: &str, src: &str) -> Vec<String> {
    // Production code only: everything before the file's `#[cfg(test)]` module.
    let prod = src.split("\n#[cfg(test)]").next().unwrap_or(src);
    let mut out = Vec::new();
    for banned in ["verify_grant_chain(", "verify_role_assertion("] {
        if prod.contains(banned) {
            out.push(format!("{file}: calls unbound `{banned}`"));
        }
    }
    for (i, _) in prod.match_indices("verify_grant_for_group(") {
        let rest = &prod[i + "verify_grant_for_group(".len()..];
        let args = rest.split(')').next().unwrap_or("");
        if !args.contains("group_id") {
            out.push(format!(
                "{file}: `verify_grant_for_group({args})` does not pass the group id"
            ));
        }
    }
    out
}

#[test]
fn tripwire_every_relay_grant_check_is_bound_to_its_group() {
    let sources = [
        ("lib.rs", include_str!("../src/lib.rs")),
        ("ws.rs", include_str!("../src/ws.rs")),
        ("admin.rs", include_str!("../src/admin.rs")),
        ("main.rs", include_str!("../src/main.rs")),
        ("keyvault.rs", include_str!("../src/keyvault.rs")),
    ];
    let violations: Vec<String> = sources
        .iter()
        .flat_map(|(f, s)| unbound_grant_checks(f, s))
        .collect();
    assert!(
        violations.is_empty(),
        "TRIPWIRE: relay grant checks must be bound to the group they act on: {violations:#?}"
    );
    // The membership ops must actually reach the bound check (not merely avoid the
    // unbound one by skipping verification altogether).
    let lib = include_str!("../src/lib.rs");
    let prod = lib.split("\n#[cfg(test)]").next().unwrap();
    assert!(
        prod.contains("rbac::verify_grant_for_group(a, admin, self.owner, group_id, now_ms)"),
        "TRIPWIRE: the membership RBAC gate must call the group-bound grant check"
    );
    assert_eq!(
        prod.matches("self.authorize_membership_op(").count(),
        2,
        "TRIPWIRE: onboard and offboard must both go through `authorize_membership_op`"
    );
}

/// Negative control: the scanner flags each regression shape it exists to catch.
#[test]
fn tripwire_negative_control() {
    let unbound = "fn f() { rbac::verify_grant_chain(a, admin, self.owner, now_ms)?; }";
    assert_eq!(unbound_grant_checks("x.rs", unbound).len(), 1);
    let sig_only = "fn f() { rbac::verify_role_assertion(a, now_ms)?; }";
    assert_eq!(unbound_grant_checks("x.rs", sig_only).len(), 1);
    let wrong_arg =
        "fn f() { rbac::verify_grant_for_group(a, admin, self.owner, other, now_ms)?; }";
    assert_eq!(unbound_grant_checks("x.rs", wrong_arg).len(), 1);
    let ok = "fn f() { rbac::verify_grant_for_group(a, admin, self.owner, group_id, now_ms)?; }";
    assert!(unbound_grant_checks("x.rs", ok).is_empty());
    // Test-module calls are out of scope.
    let in_tests = "fn f() {}\n#[cfg(test)]\nmod t { fn g() { verify_grant_chain(x); } }";
    assert!(unbound_grant_checks("x.rs", in_tests).is_empty());
}
