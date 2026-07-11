# Formal specs — citrate-comms

TLA+ models of the two safety-critical cores (`PLANSET/03_TLA_SPECS.md`). They formalize the
boundaries we *built* — the relay's delivery-service ordering and the audit chain — not OpenMLS's
internals (which we trust and pin, see `PLANSET/03` "what we deliberately do not formalize").

| Module | Mirrors | Key invariants |
|---|---|---|
| [`RelayCommitOrder.tla`](RelayCommitOrder.tla) | `comms-relay/src/lib.rs::{submit, offboard}` (`accepted_commit` + epoch advance + roster drop + MemberRemoved/RoleRevoked) and `comms-core/src/mls.rs` (epoch +1 per Commit; removed member loses the new secret) | `NoEpochFork`, `MonotoneEpoch`, `AppliedExists`, **`OffboardAtomic`** (WP-1.9: crypto membership and RBAC role flip together — no partial offboard), **`NoDecryptAfterOffboard`** (WP-1.9: a removed member never reaches its removal epoch), `ConvergenceOfActive` (liveness) |
| [`AuditChainIntegrity.tla`](AuditChainIntegrity.tla) | `comms-core/src/audit.rs::verify_integrity` | `GenesisZeroPrevHash`, `MonotoneSequence`, `ChainContiguity`, `RecordHashConsistent`, `NoDanglingPrevHash`, `AnchorMonotone` |

`RelayCommitOrder` was refreshed in **COMMS-S1 WP-1.9** to model the **atomic offboard** as a single Commit
that bundles the MLS Remove (crypto membership) and the superseding RoleAssertion (RBAC role). The model
keeps membership and role as separate state and proves they are always in lockstep (`OffboardAtomic`),
matching the runtime guarantee exercised by the `offboard_atomically_revokes_role_and_future_access` test.

**Deliberately NOT modeled — `ServerFrame::Notify` (E-5, advisory notification ping).** The WS transport
pushes a metadata-only `Notify { group_id, kind, group_seq }` to connected recipients when a Submit is
accepted. It is best-effort and **never ordering-relevant**: every total-order obligation modeled by
`RelayCommitOrder` attaches exclusively to `group_seq` on accepted envelopes, and a client that drops
every Notify frame observes an identical order. Adding it to the model would add states without adding
any checkable safety property, so the spec is unchanged — see the variant docs in
`crates/comms-relay/src/ws.rs` and `PLANSET/02` §3.5 duty 5.

## Status

Authored in COMMS-S0 and consistent with the runtime implementation. **TLC model-checking is pending**
a TLA+ toolbox in the build environment (not installed here). The same invariants are already exercised
empirically by the Rust tests:

- `NoEpochFork` ↔ `comms-relay` test `first_writer_wins_per_epoch`
- `MonotoneEpoch` ↔ `comms-core::mls` test `two_member_group_exchanges_a_message` (epoch advances by exactly 1)
- audit invariants ↔ `comms-core::audit` tests (`fresh_chain_verifies`, `tamper_with_event_is_detected`, `tamper_with_link_is_detected`)

## Running TLC (when available)

```
# RelayCommitOrder: Members = {a, b, c}, MaxEpoch = 4 — check Invariant, then Convergence.
# AuditChainIntegrity: MaxLen = 6, Payloads = {1, 2, 3} — check Invariant.
tlc -config RelayCommitOrder.cfg RelayCommitOrder.tla
```

CI integration of TLC is a COMMS-S5 hardening item (`PLANSET/07`).
