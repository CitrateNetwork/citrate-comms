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
            ReadChannel | PostMessage | CreateThread | CreateChannel
                | AddMember | RemoveMember | AddAgent | RemoveAgent | AssignRole | CreateRecord
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
    issuer: WalletAddress,
}

fn assertion_blob(
    subject: WalletAddress,
    role: Role,
    scope: Option<GroupId>,
    not_after: Option<u64>,
    issuer: WalletAddress,
) -> Result<Vec<u8>, RbacError> {
    canonical::to_vec(&AssertionCore { subject, role, scope, not_after, issuer })
        .map_err(|e| RbacError::Encode(e.to_string()))
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
    if !can(issuer_role, Capability::AssignRole) {
        return Err(RbacError::NotAuthorized);
    }
    if !can_grant(issuer_role, role) {
        return Err(RbacError::CannotGrant { issuer: issuer_role, target: role });
    }
    let issuer = issuer_wallet.address();
    let blob = assertion_blob(subject, role, scope, not_after_ms, issuer)?;
    let sig = issuer_wallet.sign_blob(ASSERTION_DOMAIN, &blob);
    Ok(RoleAssertion { subject, role, scope, not_after: not_after_ms, issuer, signature: sig.to_vec() })
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
    let sig: &[u8; 65] = a.signature.as_slice().try_into().map_err(|_| RbacError::BadSignatureLength)?;
    let blob = assertion_blob(a.subject, a.role, a.scope, a.not_after, a.issuer)?;
    let signer = identity::recover_blob_signer(ASSERTION_DOMAIN, &blob, sig).map_err(RbacError::Identity)?;
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
        return Err(RbacError::CannotGrant { issuer: Role::Owner, target: a.role });
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
        let a = sign_role_assertion(&owner, Role::Owner, alice.address(), Role::Admin, None, None).unwrap();
        let signer = verify_role_assertion(&a, 1_000).unwrap();
        assert_eq!(signer, owner.address());
        verify_grant_chain(&a, alice.address(), owner.address(), 1_000).unwrap();
    }

    #[test]
    fn admin_cannot_sign_admin_grant() {
        let admin = EthWallet::generate();
        let bob = EthWallet::generate();
        let err = sign_role_assertion(&admin, Role::Admin, bob.address(), Role::Admin, None, None).unwrap_err();
        assert_eq!(err, RbacError::CannotGrant { issuer: Role::Admin, target: Role::Admin });
        // But an admin CAN grant Member.
        sign_role_assertion(&admin, Role::Admin, bob.address(), Role::Member, None, None).unwrap();
    }

    #[test]
    fn expired_assertion_rejected() {
        let owner = EthWallet::generate();
        let alice = EthWallet::generate();
        let a = sign_role_assertion(&owner, Role::Owner, alice.address(), Role::Partner, None, Some(2_000)).unwrap();
        assert_eq!(verify_role_assertion(&a, 5_000).unwrap_err(), RbacError::Expired);
        verify_role_assertion(&a, 1_000).unwrap(); // still valid before expiry
    }

    #[test]
    fn forged_assertion_rejected() {
        let owner = EthWallet::generate();
        let attacker = EthWallet::generate();
        let victim = EthWallet::generate();
        // Attacker forges an admin grant for itself but signs with its own key while
        // claiming the owner as issuer.
        let mut a = sign_role_assertion(&attacker, Role::Owner, attacker.address(), Role::Admin, None, None).unwrap();
        a.issuer = owner.address(); // lie about the issuer
        assert_eq!(verify_role_assertion(&a, 1_000).unwrap_err(), RbacError::SignerMismatch);
        // And the grant chain rejects an issuer that isn't the workspace owner.
        let real = sign_role_assertion(&attacker, Role::Owner, victim.address(), Role::Admin, None, None).unwrap();
        assert_eq!(
            verify_grant_chain(&real, victim.address(), owner.address(), 1_000).unwrap_err(),
            RbacError::UntrustedIssuer
        );
    }
}
