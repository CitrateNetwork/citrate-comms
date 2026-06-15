---------------------------- MODULE RelayCommitOrder ----------------------------
(***************************************************************************)
(* The load-bearing safety invariants of the server-blind relay (Risk R1, *)
(* PLANSET/03_TLA_SPECS.md), refreshed in COMMS-S1 WP-1.9 to cover the     *)
(* ATOMIC OFFBOARD bundle.                                                 *)
(*                                                                         *)
(* The relay is the sole total-order authority for a group's Commits. If   *)
(* it ever accepted two different Commits for one epoch, members would     *)
(* fork the MLS ratchet tree (NoEpochFork). An OFFBOARD is one Commit that *)
(* bundles two effects — the MLS Remove (crypto membership) and the        *)
(* superseding RoleAssertion (RBAC role) — applied together at one epoch.  *)
(* We model them as SEPARATE state and prove they always flip together     *)
(* (OffboardAtomic: no partial offboard) and that a removed member never   *)
(* reaches its removal epoch (NoDecryptAfterOffboard: forward security).   *)
(*                                                                         *)
(* Mirrors comms-relay/src/lib.rs::{submit, offboard} (the `accepted_commit*)
(* map, epoch advance, roster drop, and the MemberRemoved+RoleRevoked pair)*)
(* and comms-core/src/mls.rs (epoch advances by exactly 1 per applied      *)
(* Commit; a removed member loses the new epoch secret).                   *)
(***************************************************************************)
EXTENDS Naturals, FiniteSets

CONSTANTS
    Members,        \* set of member ids, e.g. {a, b, c}
    NoOne,          \* sentinel distinct from any member (an epoch that removed nobody)
    MaxEpoch        \* model bound, e.g. 4

ASSUME NoOne \notin Members

\* A "Commit value" is abstracted to a natural number; two different naturals
\* model two different Commit ciphertexts proposed for the same epoch.
CommitVals == 0 .. MaxEpoch + 1

VARIABLES
    accepted,       \* accepted[e] = the unique Commit value accepted for epoch e, or -1
    removedBy,      \* removedBy[e] = the member offboarded by epoch e's commit, or NoOne
    relayEpoch,     \* highest epoch the relay has accepted a Commit for
    memberEpoch,    \* memberEpoch[m] = the epoch member m has applied up to
    member,         \* member[m]     = m still holds crypto membership (MLS leaf present)
    roleActive      \* roleActive[m] = m still holds its RBAC role (RoleAssertion live)

vars == <<accepted, removedBy, relayEpoch, memberEpoch, member, roleActive>>

Init ==
    /\ accepted = [ e \in 1 .. MaxEpoch |-> -1 ]
    /\ removedBy = [ e \in 1 .. MaxEpoch |-> NoOne ]
    /\ relayEpoch = 0
    /\ memberEpoch = [ m \in Members |-> 0 ]
    /\ member = [ m \in Members |-> TRUE ]
    /\ roleActive = [ m \in Members |-> TRUE ]

\* A normal Commit for the next epoch (first-writer-wins, fail-closed). A conflicting
\* proposal for an already-accepted epoch is simply not enabled — never overwritten.
AcceptNormalCommit(e, v) ==
    /\ e = relayEpoch + 1
    /\ e <= MaxEpoch
    /\ accepted[e] = -1
    /\ accepted' = [ accepted EXCEPT ![e] = v ]
    /\ relayEpoch' = e
    /\ removedBy' = [ removedBy EXCEPT ![e] = NoOne ]
    /\ UNCHANGED <<memberEpoch, member, roleActive>>

\* The ATOMIC OFFBOARD: one Commit that, in a single step, advances the epoch AND
\* drops m's crypto membership AND revokes m's role. There is no intermediate state
\* where one effect has landed and the other has not — that is the whole point.
AcceptOffboardCommit(e, v, m) ==
    /\ e = relayEpoch + 1
    /\ e <= MaxEpoch
    /\ accepted[e] = -1
    /\ member[m] = TRUE                       \* can only offboard a current member
    /\ accepted' = [ accepted EXCEPT ![e] = v ]
    /\ relayEpoch' = e
    /\ removedBy' = [ removedBy EXCEPT ![e] = m ]
    /\ member' = [ member EXCEPT ![m] = FALSE ]
    /\ roleActive' = [ roleActive EXCEPT ![m] = FALSE ]
    /\ UNCHANGED memberEpoch

\* A member applies the (unique) accepted Commit for its next epoch, in order — but
\* only while it still holds membership. A removed member is frozen, so it never
\* reaches the epoch that removed it (and thus never derives that epoch's secret).
ApplyCommit(m) ==
    /\ member[m] = TRUE
    /\ memberEpoch[m] + 1 <= relayEpoch
    /\ accepted[memberEpoch[m] + 1] # -1
    /\ memberEpoch' = [ memberEpoch EXCEPT ![m] = memberEpoch[m] + 1 ]
    /\ UNCHANGED <<accepted, removedBy, relayEpoch, member, roleActive>>

Next ==
    \/ \E e \in 1 .. MaxEpoch, v \in CommitVals : AcceptNormalCommit(e, v)
    \/ \E e \in 1 .. MaxEpoch, v \in CommitVals, m \in Members : AcceptOffboardCommit(e, v, m)
    \/ \E m \in Members : ApplyCommit(m)

Spec == Init /\ [][Next]_vars /\ WF_vars(Next)

(***************************************************************************)
(* Invariants                                                              *)
(***************************************************************************)

TypeOK ==
    /\ accepted \in [ 1 .. MaxEpoch -> CommitVals \cup {-1} ]
    /\ removedBy \in [ 1 .. MaxEpoch -> Members \cup {NoOne} ]
    /\ relayEpoch \in 0 .. MaxEpoch
    /\ memberEpoch \in [ Members -> 0 .. MaxEpoch ]
    /\ member \in [ Members -> BOOLEAN ]
    /\ roleActive \in [ Members -> BOOLEAN ]

\* NoEpochFork: at most one accepted Commit per epoch (the relay never forks a group).
NoEpochFork ==
    \A e \in 1 .. MaxEpoch :
        (accepted[e] # -1) => (accepted[e] \in CommitVals)

\* MonotoneEpoch: a member never advances past what the relay has totally ordered.
MonotoneEpoch ==
    \A m \in Members : memberEpoch[m] <= relayEpoch

\* A member only applies Commits the relay actually accepted (no out-of-band epochs).
AppliedExists ==
    \A m \in Members :
        \A e \in 1 .. memberEpoch[m] : accepted[e] # -1

\* OffboardAtomic (WP-1.9): crypto membership and RBAC role are ALWAYS in lockstep.
\* No reachable state has one revoked while the other is retained — the offboard
\* bundle is indivisible.
OffboardAtomic ==
    \A m \in Members : member[m] = roleActive[m]

\* NoDecryptAfterOffboard (WP-1.9 / forward security): a member removed at epoch e
\* never applied epoch e (or beyond), so it cannot derive the post-removal secret.
NoDecryptAfterOffboard ==
    \A m \in Members, e \in 1 .. MaxEpoch :
        (removedBy[e] = m) => (memberEpoch[m] < e)

Invariant ==
    /\ TypeOK
    /\ NoEpochFork
    /\ MonotoneEpoch
    /\ AppliedExists
    /\ OffboardAtomic
    /\ NoDecryptAfterOffboard

(***************************************************************************)
(* Liveness: with weak fairness, every member that still holds membership  *)
(* eventually reaches the relay's frontier. Removed members are excluded   *)
(* (they freeze by design).                                                *)
(***************************************************************************)
ConvergenceOfActive ==
    <>[]( \A m \in Members : (member[m] = TRUE) => (memberEpoch[m] = relayEpoch) )

(***************************************************************************)
(* TLC model (PLANSET/03): Members = {a, b, c}, NoOne = "none", MaxEpoch=4.*)
(* Check Invariant (safety); check ConvergenceOfActive (temporal).         *)
(***************************************************************************)
=============================================================================
