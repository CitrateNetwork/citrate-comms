//! `rbac` — roles → capabilities, and signed [`RoleAssertion`]s.
//!
//! Roles map to capability sets (`PLANSET/02_ARCHITECTURE.md` §4). A `RoleAssertion`
//! is a grant signed by an owner/admin **wallet** (secp256k1, low-S), verifiable by
//! every client and by the blind relay (public-key over public data — no plaintext
//! exposure). Capability checks are evaluated client-side; the relay additionally
//! verifies an actor's assertion before admitting a membership-mutating op.
//!
//! Offboarding revokes the role and future crypto access **atomically** — both ride
//! one MLS Commit (`crate::mls` Remove) recorded as a single audited event.

use crate::identity::{self, EthWallet, IdentityError};
use comms_proto::{canonical, GroupId, Role, RoleAssertion, WalletAddress};
use serde::Serialize;

const ASSERTION_DOMAIN: &[u8] = b"citrate-comms/role-assertion/v1";

/// A discrete permission. The role→capability matrix lives in [`can`].
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Capability {
    ReadChannel,
    PostMessage,
    CreateThread,
    CreateChannel,
    AddMember,
    RemoveMember,
    AddAgent,
    RemoveAgent,
    AssignRole,
    ManageWorkspace,
    CreateRecord, // CRM / PM entities
}

/// Does `role` hold `cap`? The authoritative capability matrix (`PLANSET/02` §4).
pub fn can(role: Role, cap: Capability) -> bool {
    use Capability::*;
    use Role::*;
    match role {
        Owner => true, // everything
        Admin => matches!(
            cap,
            ReadChannel
                | PostMessage
                | CreateThread
                | CreateChannel
                | AddMember
                | RemoveMember
                | AddAgent
                | RemoveAgent
                | AssignRole
                | CreateRecord
        ),
        Member => matches!(cap, ReadChannel | PostMessage | CreateThread | CreateRecord),
        // Partner: scoped read/post only (scope enforced separately at the channel level).
        Partner => matches!(cap, ReadChannel | PostMessage),
        Guest => matches!(cap, ReadChannel),
        // Agent: read + post in channels it is a member of; NO membership-mutating caps.
        Agent => matches!(cap, ReadChannel | PostMessage),
    }
}

/// May an issuer holding `issuer_role` grant `target_role`? Prevents privilege
/// escalation: an Admin cannot mint Owners or other Admins.
pub fn can_grant(issuer_role: Role, target_role: Role) -> bool {
    match issuer_role {
        Role::Owner => true,
        Role::Admin => matches!(
            target_role,
            Role::Member | Role::Partner | Role::Guest | Role::Agent
        ),
        _ => false,
    }
}

/// The exact bytes a `RoleAssertion` signature covers (everything but the signature).
#[derive(Serialize)]
struct AssertionCore {
    subject: WalletAddress,
    role: Role,
    scope: Option<GroupId>,
    not_after: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    generation: Option<u64>,
    issuer: WalletAddress,
}

fn assertion_blob(a: &AssertionCore) -> Result<Vec<u8>, RbacError> {
    canonical::to_vec(a).map_err(|e| RbacError::Encode(e.to_string()))
}

/// Issue a signed role grant. Fails if the issuer's role can't assign roles or
/// can't grant the requested role (anti-escalation).
pub fn sign_role_assertion(
    issuer_wallet: &EthWallet,
    issuer_role: Role,
    subject: WalletAddress,
    role: Role,
    scope: Option<GroupId>,
    not_after_ms: Option<u64>,
) -> Result<RoleAssertion, RbacError> {
    sign_assertion(
        issuer_wallet,
        issuer_role,
        subject,
        role,
        scope,
        not_after_ms,
        None,
    )
}

/// Issue a grant **for one group at the subject's current grant generation** there
/// (the relay's `grant_generation`). Offboarding a member from a group advances their
/// generation, so a grant issued before the offboard no longer authorizes anything in
/// that group, even after the member is added back.
pub fn sign_group_grant(
    issuer_wallet: &EthWallet,
    issuer_role: Role,
    subject: WalletAddress,
    role: Role,
    group_id: GroupId,
    generation: u64,
    not_after_ms: Option<u64>,
) -> Result<RoleAssertion, RbacError> {
    sign_assertion(
        issuer_wallet,
        issuer_role,
        subject,
        role,
        Some(group_id),
        not_after_ms,
        // Generation 0 is encoded as absent, byte-identical to a grant without the field.
        (generation != 0).then_some(generation),
    )
}

fn sign_assertion(
    issuer_wallet: &EthWallet,
    issuer_role: Role,
    subject: WalletAddress,
    role: Role,
    scope: Option<GroupId>,
    not_after: Option<u64>,
    generation: Option<u64>,
) -> Result<RoleAssertion, RbacError> {
    if !can(issuer_role, Capability::AssignRole) {
        return Err(RbacError::NotAuthorized);
    }
    if !can_grant(issuer_role, role) {
        return Err(RbacError::CannotGrant {
            issuer: issuer_role,
            target: role,
        });
    }
    let issuer = issuer_wallet.address();
    let blob = assertion_blob(&AssertionCore {
        subject,
        role,
        scope,
        not_after,
        generation,
        issuer,
    })?;
    let sig = issuer_wallet.sign_blob(ASSERTION_DOMAIN, &blob);
    Ok(RoleAssertion {
        subject,
        role,
        scope,
        not_after,
        generation,
        issuer,
        signature: sig.to_vec(),
    })
}

/// Verify a role grant's signature and expiry. Returns the issuer on success.
/// (Whether the issuer was *entitled* to grant is checked separately by the
/// relay/client against the workspace owner — see [`verify_grant_chain`].)
pub fn verify_role_assertion(a: &RoleAssertion, now_ms: u64) -> Result<WalletAddress, RbacError> {
    if let Some(exp) = a.not_after {
        if now_ms >= exp {
            return Err(RbacError::Expired);
        }
    }
    let sig: &[u8; 65] = a
        .signature
        .as_slice()
        .try_into()
        .map_err(|_| RbacError::BadSignatureLength)?;
    let blob = assertion_blob(&AssertionCore {
        subject: a.subject,
        role: a.role,
        scope: a.scope,
        not_after: a.not_after,
        generation: a.generation,
        issuer: a.issuer,
    })?;
    let signer =
        identity::recover_blob_signer(ASSERTION_DOMAIN, &blob, sig).map_err(RbacError::Identity)?;
    if signer != a.issuer {
        return Err(RbacError::SignerMismatch);
    }
    Ok(signer)
}

/// Verify a one-hop grant chain: the assertion is validly signed, unexpired, names
/// the expected `subject`, and was issued by `workspace_owner` who is entitled to
/// grant that role. This is what the relay runs before admitting a membership op.
pub fn verify_grant_chain(
    a: &RoleAssertion,
    subject: WalletAddress,
    workspace_owner: WalletAddress,
    now_ms: u64,
) -> Result<(), RbacError> {
    let signer = verify_role_assertion(a, now_ms)?;
    if a.subject != subject {
        return Err(RbacError::SubjectMismatch);
    }
    if signer != workspace_owner {
        return Err(RbacError::UntrustedIssuer);
    }
    // The owner can grant any role; this is the trust anchor.
    if !can_grant(Role::Owner, a.role) {
        return Err(RbacError::CannotGrant {
            issuer: Role::Owner,
            target: a.role,
        });
    }
    Ok(())
}

/// [`verify_grant_chain`] **bound to one group and one membership**: the grant must
/// also carry a signed `scope` equal to `group_id`, the group the caller is about to act
/// in, and a signed `generation` equal to `generation`, the subject's current grant
/// generation there (absent == 0). Fails closed: a grant with no scope (`None`), a scope
/// naming any other group, or a grant issued for an earlier (or later) generation is
/// refused. Offboarding advances a member's generation, so every grant they held in the
/// group ends with the membership, and re-adding them does not revive it. Every
/// group-level permission check (the relay's membership-mutating ops) goes through this.
pub fn verify_grant_for_group(
    a: &RoleAssertion,
    subject: WalletAddress,
    workspace_owner: WalletAddress,
    group_id: GroupId,
    generation: u64,
    now_ms: u64,
) -> Result<(), RbacError> {
    verify_grant_chain(a, subject, workspace_owner, now_ms)?;
    match a.scope {
        None => return Err(RbacError::MissingScope),
        Some(scope) if scope != group_id => return Err(RbacError::ScopeMismatch),
        Some(_) => {}
    }
    if a.generation.unwrap_or(0) != generation {
        return Err(RbacError::StaleGeneration);
    }
    Ok(())
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum RbacError {
    #[error("issuer role is not allowed to assign roles")]
    NotAuthorized,
    #[error("{issuer:?} cannot grant {target:?} (anti-escalation)")]
    CannotGrant { issuer: Role, target: Role },
    #[error("role assertion expired")]
    Expired,
    #[error("recovered signer does not match the issuer")]
    SignerMismatch,
    #[error("assertion subject does not match the expected subject")]
    SubjectMismatch,
    #[error("assertion issuer is not the trusted workspace owner")]
    UntrustedIssuer,
    #[error("assertion carries no group scope; a group-bound check requires one")]
    MissingScope,
    #[error("assertion scope does not match the group being acted on")]
    ScopeMismatch,
    #[error("assertion was issued for another membership generation of its subject")]
    StaleGeneration,
    #[error("signature must be 65 bytes")]
    BadSignatureLength,
    #[error("canonical encode failed: {0}")]
    Encode(String),
    #[error("identity error: {0}")]
    Identity(IdentityError),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn capability_matrix() {
        assert!(can(Role::Owner, Capability::ManageWorkspace));
        assert!(can(Role::Admin, Capability::RemoveMember));
        assert!(!can(Role::Member, Capability::RemoveMember));
        assert!(can(Role::Member, Capability::PostMessage));
        assert!(can(Role::Partner, Capability::ReadChannel));
        assert!(!can(Role::Partner, Capability::CreateChannel));
        assert!(can(Role::Guest, Capability::ReadChannel));
        assert!(!can(Role::Guest, Capability::PostMessage));
        // The agent guardrail: read + post, but never membership mutation.
        assert!(can(Role::Agent, Capability::PostMessage));
        assert!(!can(Role::Agent, Capability::AddMember));
        assert!(!can(Role::Agent, Capability::RemoveMember));
        assert!(!can(Role::Agent, Capability::AssignRole));
    }

    #[test]
    fn anti_escalation_on_grant() {
        assert!(can_grant(Role::Owner, Role::Admin));
        assert!(can_grant(Role::Admin, Role::Member));
        assert!(!can_grant(Role::Admin, Role::Admin)); // admin can't mint admins
        assert!(!can_grant(Role::Admin, Role::Owner));
        assert!(!can_grant(Role::Member, Role::Member));
    }

    #[test]
    fn sign_and_verify_role_assertion() {
        let owner = EthWallet::generate();
        let alice = EthWallet::generate();
        let a = sign_role_assertion(
            &owner,
            Role::Owner,
            alice.address(),
            Role::Admin,
            None,
            None,
        )
        .unwrap();
        let signer = verify_role_assertion(&a, 1_000).unwrap();
        assert_eq!(signer, owner.address());
        verify_grant_chain(&a, alice.address(), owner.address(), 1_000).unwrap();
    }

    #[test]
    fn admin_cannot_sign_admin_grant() {
        let admin = EthWallet::generate();
        let bob = EthWallet::generate();
        let err = sign_role_assertion(&admin, Role::Admin, bob.address(), Role::Admin, None, None)
            .unwrap_err();
        assert_eq!(
            err,
            RbacError::CannotGrant {
                issuer: Role::Admin,
                target: Role::Admin
            }
        );
        // But an admin CAN grant Member.
        sign_role_assertion(&admin, Role::Admin, bob.address(), Role::Member, None, None).unwrap();
    }

    #[test]
    fn expired_assertion_rejected() {
        let owner = EthWallet::generate();
        let alice = EthWallet::generate();
        let a = sign_role_assertion(
            &owner,
            Role::Owner,
            alice.address(),
            Role::Partner,
            None,
            Some(2_000),
        )
        .unwrap();
        assert_eq!(
            verify_role_assertion(&a, 5_000).unwrap_err(),
            RbacError::Expired
        );
        verify_role_assertion(&a, 1_000).unwrap(); // still valid before expiry
    }

    #[test]
    fn grant_is_bound_to_its_group() {
        let owner = EthWallet::generate();
        let alice = EthWallet::generate();
        let (ga, gb) = (GroupId([1; 32]), GroupId([2; 32]));
        let grant = |scope| {
            sign_role_assertion(
                &owner,
                Role::Owner,
                alice.address(),
                Role::Admin,
                scope,
                None,
            )
            .unwrap()
        };
        let (o, s) = (owner.address(), alice.address());
        // Same group: accepted.
        verify_grant_for_group(&grant(Some(ga)), s, o, ga, 0, 1_000).unwrap();
        // Another group: refused.
        assert_eq!(
            verify_grant_for_group(&grant(Some(ga)), s, o, gb, 0, 1_000).unwrap_err(),
            RbacError::ScopeMismatch
        );
        // No group: refused (fail closed).
        assert_eq!(
            verify_grant_for_group(&grant(None), s, o, ga, 0, 1_000).unwrap_err(),
            RbacError::MissingScope
        );
        // Scope rewritten after signing to match the target group: the signature no
        // longer covers it.
        let mut edited = grant(Some(ga));
        edited.scope = Some(gb);
        assert_eq!(
            verify_grant_for_group(&edited, s, o, gb, 0, 1_000).unwrap_err(),
            RbacError::SignerMismatch
        );
        // The chain checks still run first: expired and wrong-subject grants are refused.
        let expiring =
            sign_role_assertion(&owner, Role::Owner, s, Role::Admin, Some(ga), Some(500)).unwrap();
        assert_eq!(
            verify_grant_for_group(&expiring, s, o, ga, 0, 1_000).unwrap_err(),
            RbacError::Expired
        );
        assert_eq!(
            verify_grant_for_group(&grant(Some(ga)), o, o, ga, 0, 1_000).unwrap_err(),
            RbacError::SubjectMismatch
        );
    }

    #[test]
    fn grant_is_bound_to_its_generation() {
        let owner = EthWallet::generate();
        let alice = EthWallet::generate();
        let ga = GroupId([1; 32]);
        let (o, s) = (owner.address(), alice.address());
        let at = |generation| {
            sign_group_grant(&owner, Role::Owner, s, Role::Admin, ga, generation, None).unwrap()
        };
        verify_grant_for_group(&at(0), s, o, ga, 0, 1_000).unwrap();
        verify_grant_for_group(&at(3), s, o, ga, 3, 1_000).unwrap();
        // Older and newer generations are both refused (exact match).
        assert_eq!(
            verify_grant_for_group(&at(0), s, o, ga, 1, 1_000).unwrap_err(),
            RbacError::StaleGeneration
        );
        assert_eq!(
            verify_grant_for_group(&at(2), s, o, ga, 1, 1_000).unwrap_err(),
            RbacError::StaleGeneration
        );
        // The generation is signed: editing it after signing breaks the signature.
        let mut edited = at(0);
        edited.generation = Some(1);
        assert_eq!(
            verify_grant_for_group(&edited, s, o, ga, 1, 1_000).unwrap_err(),
            RbacError::SignerMismatch
        );
        // Generation 0 is encoded as absent: identical to a grant without the field.
        assert_eq!(
            at(0),
            sign_role_assertion(&owner, Role::Owner, s, Role::Admin, Some(ga), None).unwrap()
        );
    }

    /// Grants signed before `generation` existed keep their exact signed bytes: a
    /// generation-0 grant encodes byte-for-byte like the five-field legacy core.
    #[test]
    fn generation_zero_keeps_the_legacy_signed_bytes() {
        #[derive(Serialize)]
        struct LegacyCore {
            subject: WalletAddress,
            role: Role,
            scope: Option<GroupId>,
            not_after: Option<u64>,
            issuer: WalletAddress,
        }
        let (subject, issuer) = (WalletAddress([1; 20]), WalletAddress([2; 20]));
        let legacy = canonical::to_vec(&LegacyCore {
            subject,
            role: Role::Admin,
            scope: Some(GroupId([3; 32])),
            not_after: Some(9),
            issuer,
        })
        .unwrap();
        let now = assertion_blob(&AssertionCore {
            subject,
            role: Role::Admin,
            scope: Some(GroupId([3; 32])),
            not_after: Some(9),
            generation: None,
            issuer,
        })
        .unwrap();
        assert_eq!(legacy, now);
        // A legacy wire grant (no `generation` key) still decodes.
        let wire = RoleAssertion {
            subject,
            role: Role::Admin,
            scope: None,
            not_after: None,
            generation: None,
            issuer,
            signature: vec![0; 65],
        };
        let bytes = canonical::to_vec(&wire).unwrap();
        let back: RoleAssertion = canonical::from_slice(&bytes).unwrap();
        assert_eq!(back, wire);
    }

    #[test]
    fn forged_assertion_rejected() {
        let owner = EthWallet::generate();
        let attacker = EthWallet::generate();
        let victim = EthWallet::generate();
        // Attacker forges an admin grant for itself but signs with its own key while
        // claiming the owner as issuer.
        let mut a = sign_role_assertion(
            &attacker,
            Role::Owner,
            attacker.address(),
            Role::Admin,
            None,
            None,
        )
        .unwrap();
        a.issuer = owner.address(); // lie about the issuer
        assert_eq!(
            verify_role_assertion(&a, 1_000).unwrap_err(),
            RbacError::SignerMismatch
        );
        // And the grant chain rejects an issuer that isn't the workspace owner.
        let real = sign_role_assertion(
            &attacker,
            Role::Owner,
            victim.address(),
            Role::Admin,
            None,
            None,
        )
        .unwrap();
        assert_eq!(
            verify_grant_chain(&real, victim.address(), owner.address(), 1_000).unwrap_err(),
            RbacError::UntrustedIssuer
        );
    }
}
