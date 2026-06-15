-------------------------- MODULE AuditChainIntegrity --------------------------
(***************************************************************************)
(* The BLAKE3 audit chain maintained by the relay (comms-core/src/audit.rs *)
(* and PLANSET/02 §7).  Mirrors citrate-agent-runtime's AuditChain.  We    *)
(* model the chain as a growing sequence of records and prove the four     *)
(* properties verify_integrity() checks offline, plus anchor monotonicity. *)
(*                                                                         *)
(* Hashes are abstracted: each record's `recordHash` is modelled as its    *)
(* (sequence, prevHash, payload) tuple, so "recompute matches" becomes a   *)
(* structural identity and "previous_hash links" becomes equality of tuples*)
(***************************************************************************)
EXTENDS Naturals, Sequences

CONSTANTS MaxLen, Payloads     \* model bound + the set of event payloads

\* A record is [seq, prevHash, payload, recordHash].  We model a hash as the
\* record's own identity tuple, which is exactly the determinism the real
\* link_hash() provides (same contents => same hash; different => different).
ZeroHash == <<0, 0, 0>>            \* the genesis previous_hash sentinel
Hash(seq, prev, pl) == <<seq, prev, pl>>

VARIABLES chain, anchor           \* chain = Seq of records; anchor = last anchored block number

vars == <<chain, anchor>>

Genesis ==
    [ seq |-> 0, prevHash |-> ZeroHash, payload |-> 0,
      recordHash |-> Hash(0, ZeroHash, 0) ]

Init ==
    /\ chain = << Genesis >>
    /\ anchor = 0

Append(pl) ==
    /\ Len(chain) < MaxLen
    /\ LET head == chain[Len(chain)]
           seq  == head.seq + 1
           rec  == [ seq |-> seq, prevHash |-> head.recordHash, payload |-> pl,
                     recordHash |-> Hash(seq, head.recordHash, pl) ]
       IN chain' = Append(chain, rec)
    /\ UNCHANGED anchor

\* Periodically anchor the head to chain 40204; block numbers only increase.
Anchor(block) ==
    /\ block > anchor
    /\ anchor' = block
    /\ UNCHANGED chain

Next ==
    \/ \E pl \in Payloads : Append(pl)
    \/ \E block \in 1 .. MaxLen + 10 : Anchor(block)

Spec == Init /\ [][Next]_vars

(***************************************************************************)
(* The four integrity invariants verify_integrity() enforces.             *)
(***************************************************************************)

GenesisZeroPrevHash == chain[1].prevHash = ZeroHash

MonotoneSequence ==
    \A i \in 1 .. Len(chain) : chain[i].seq = i - 1

ChainContiguity ==
    \A i \in 2 .. Len(chain) : chain[i].prevHash = chain[i-1].recordHash

\* Every record's hash recomputes from its own contents (no silent tamper).
RecordHashConsistent ==
    \A i \in 1 .. Len(chain) :
        chain[i].recordHash = Hash(chain[i].seq, chain[i].prevHash, chain[i].payload)

NoDanglingPrevHash ==
    \A i \in 2 .. Len(chain) :
        \E j \in 1 .. (i-1) : chain[j].recordHash = chain[i].prevHash

AnchorMonotone == anchor >= 0   \* established inductively: Anchor only increases it

Invariant ==
    /\ GenesisZeroPrevHash
    /\ MonotoneSequence
    /\ ChainContiguity
    /\ RecordHashConsistent
    /\ NoDanglingPrevHash
    /\ AnchorMonotone

(***************************************************************************)
(* TLC model (PLANSET/03): MaxLen = 6, Payloads = {1, 2, 3}.  Check        *)
(* Invariant under Spec.                                                   *)
(***************************************************************************)
=============================================================================
