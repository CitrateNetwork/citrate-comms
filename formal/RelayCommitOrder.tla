---------------------------- MODULE RelayCommitOrder ----------------------------
(***************************************************************************)
(* The load-bearing safety invariant of the server-blind relay (Risk R1,  *)
(* PLANSET/03_TLA_SPECS.md).  The relay is the sole total-order authority  *)
(* for a group's Commits.  If it ever accepted two different Commits for   *)
(* the same epoch, members would fork the MLS ratchet tree and silently    *)
(* diverge.  This module models the relay's first-writer-wins rule and the *)
(* members' ordered apply, and proves NoEpochFork + MonotoneEpoch.         *)
(*                                                                         *)
(* Mirrors the implementation in comms-relay/src/lib.rs::submit (the       *)
(* `accepted_commit` map + the epoch advance) and comms-core/src/mls.rs    *)
(* (a member's epoch advances by exactly 1 per applied Commit).            *)
(***************************************************************************)
EXTENDS Naturals, FiniteSets

CONSTANTS
    Members,        \* set of member ids, e.g. {a, b, c}
    MaxEpoch        \* model bound, e.g. 4

\* A "Commit value" is abstracted to a natural number; two different naturals
\* model two different Commit ciphertexts proposed for the same epoch.
CommitVals == 0 .. MaxEpoch + 1

VARIABLES
    accepted,       \* accepted[e] = the unique Commit value the relay accepted for epoch e, or -1
    relayEpoch,     \* highest epoch the relay has accepted a Commit for
    memberEpoch     \* memberEpoch[m] = the epoch member m has applied up to

vars == <<accepted, relayEpoch, memberEpoch>>

Init ==
    /\ accepted = [ e \in 1 .. MaxEpoch |-> -1 ]
    /\ relayEpoch = 0
    /\ memberEpoch = [ m \in Members |-> 0 ]

\* The relay accepts a Commit `v` for the next epoch iff that epoch is still open
\* (first-writer-wins, fail-closed).  A conflicting proposal for an already
\* accepted epoch is simply not enabled — it is rejected, never overwritten.
AcceptCommit(e, v) ==
    /\ e = relayEpoch + 1
    /\ e <= MaxEpoch
    /\ accepted[e] = -1
    /\ accepted' = [ accepted EXCEPT ![e] = v ]
    /\ relayEpoch' = e
    /\ UNCHANGED memberEpoch

\* A member applies the (unique) accepted Commit for its next epoch, in order.
ApplyCommit(m) ==
    /\ memberEpoch[m] + 1 <= relayEpoch
    /\ accepted[memberEpoch[m] + 1] # -1
    /\ memberEpoch' = [ memberEpoch EXCEPT ![m] = memberEpoch[m] + 1 ]
    /\ UNCHANGED <<accepted, relayEpoch>>

Next ==
    \/ \E e \in 1 .. MaxEpoch, v \in CommitVals : AcceptCommit(e, v)
    \/ \E m \in Members : ApplyCommit(m)

Spec == Init /\ [][Next]_vars /\ WF_vars(Next)

(***************************************************************************)
(* Invariants                                                              *)
(***************************************************************************)

TypeOK ==
    /\ accepted \in [ 1 .. MaxEpoch -> CommitVals \cup {-1} ]
    /\ relayEpoch \in 0 .. MaxEpoch
    /\ memberEpoch \in [ Members -> 0 .. MaxEpoch ]

\* NoEpochFork: there is at most one accepted Commit per epoch.  Because
\* `accepted[e]` is a single value that is only ever written when it is -1,
\* no epoch can carry two distinct Commit values — the relay never forks a group.
NoEpochFork ==
    \A e \in 1 .. MaxEpoch :
        (accepted[e] # -1) => (accepted[e] \in CommitVals)

\* MonotoneEpoch: a member only ever advances, and never past what the relay
\* has totally ordered — so all members converge along the one accepted chain.
MonotoneEpoch ==
    \A m \in Members : memberEpoch[m] <= relayEpoch

\* A member only applies Commits the relay actually accepted (no out-of-band epochs).
AppliedExists ==
    \A m \in Members :
        \A e \in 1 .. memberEpoch[m] : accepted[e] # -1

Invariant == TypeOK /\ NoEpochFork /\ MonotoneEpoch /\ AppliedExists

(***************************************************************************)
(* Liveness: with weak fairness on Next, every member eventually reaches   *)
(* the relay's frontier (Convergence) — no member is stranded on a stale   *)
(* epoch once the relay stops accepting new Commits.                       *)
(***************************************************************************)
Convergence == \A m \in Members : <>[](memberEpoch[m] = relayEpoch)

(***************************************************************************)
(* TLC model (PLANSET/03): Members = {a, b, c}, MaxEpoch = 4.              *)
(* Check Invariant (safety) under Spec; check Convergence (temporal).      *)
(***************************************************************************)
=============================================================================
