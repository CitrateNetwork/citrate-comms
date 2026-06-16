---
created: 2026-06-16T00:00:00Z
branch: main
author: Saul Loveman + Claude Opus 4.8 (1M context)
status: ready-for-handoff
audience: citrate-security auditors (Agentile-Audit standard, cross-model quorum)
---

# Tier-1 Audit Packet — citrate-comms

This is the **spec-to-code compliance baseline** handed to `citrate-security` for the
Tier-1 engagement (`PLANSET/07` §6). citrate-comms handles user secrets, MLS group key
material, and an E2E protocol, so it is classified **Tier 1 — full audit**
(`.agentile/AUDIT_REF.md`). The audit runs under the Agentile-Audit standard
(`citrate-security/.agentile/standard/AGENTILE_AUDIT_STANDARD.md`) with cross-model quorum.

**Audit boundary commit:** `git rev-parse HEAD` at handoff (record in the audit root).
**Scope:** the workspace — `comms-proto`, `comms-core`, `comms-relay`, `comms-agent-bridge`,
`comms-client`, `comms-release`.

## Packet contents

| Artifact | Where | Notes |
|---|---|---|
| Reproducibility-gated binaries + signed manifest | `.github/workflows/release.yml` → release bundle; `crates/comms-release` | two-machine byte-equality gate on `comms-relay`; `release.manifest.toml` Ed25519-signed, `--expect`-bound to the gate hash |
| `cargo audit` + CycloneDX SBOM | release bundle `sbom/`; config `deny.toml` | cargo-audit is **blocking** (no soft-fail); SBOM per crate |
| TLA+ specifications | `formal/RelayCommitOrder.tla`, `formal/AuditChainIntegrity.tla` | safety cores; **TLC run pending a toolbox — see Known gaps** |
| Test corpus | `cargo test --workspace` (**71 passing**, baseline `.agentile/coverage/baseline.json`) | incl. the ciphertext-only-store proof + the hostile-CBOR robustness corpus |
| Air-gap validation | `docs/audit/AIRGAP_TEST.md` | phased offline build/test + offline E2E message exchange |
| Spec baseline | `PLANSET/00,02,03,06,07` | architecture, handshake, MLS mapping, agent custody, hardening/threat model |
| Release signing seam | `docs/audit/HSM_SEAM.md` | soft-key → HSM swap-in (same wire form) |

## Evidence map (focus areas → spec → implementation → test)

The five Tier-1 focus areas from the risk register (`.agentile/AUDIT_REF.md`,
`PLANSET/07` §6), each mapped to the code that implements it and the test that proves it.

### R1 — Relay Commit ordering / delivery-service trust *(hardest correctness property)*
- **Spec:** `formal/RelayCommitOrder.tla` (first-writer-wins per epoch + atomic offboard:
  `OffboardAtomic`, `NoDecryptAfterOffboard`); `PLANSET/02` §3.5.
- **Impl:** `crates/comms-relay/src/lib.rs` — `DeliveryService::submit` rejects a second,
  different Commit for an already-committed epoch (`RelayError::EpochAlreadyCommitted`),
  assigns a monotonic `group_seq`; fail-closed.
- **Test:** `first_writer_wins_per_epoch` (`crates/comms-relay/src/lib.rs`).
- **Residual:** a malicious relay can withhold/delay (liveness DoS), not forge content.

### R3 — KeyPackage / MLS-credential spoofing
- **Spec:** `PLANSET/02` §2.C (wallet binding attestation over
  `BLAKE3(wallet ‖ mls_sig_pubkey ‖ relay_domain ‖ nonce)`).
- **Impl:** `crates/comms-core/src/identity.rs` — `binding_digest` / `sign_binding` /
  `verify_binding`; the relay runs it before admitting a KeyPackage
  (`DeliveryService::publish_key_package`).
- **Test:** the binding round-trips in `crates/comms-client/tests/ws_e2e.rs`
  (`two_clients_exchange_a_message_over_websocket`); low-S enforced (R3 dependency, below).
- **Residual:** trust rests on wallet-key custody; bounded by per-workspace identities + PCS.

### R5 — Agent MLS key custody
- **Spec:** `PLANSET/06` (agent is a cryptographic member, post+read only; per-workspace identity).
- **Impl:** `crates/comms-agent-bridge/src/lib.rs` — `provision` seals the agent's durable
  wallet in the OS keyring (`agent:<did>:wallet`); `accept_sponsor` requires an owner-signed
  `role=agent` grant (`rbac::verify_grant_chain`); the guardrail refuses membership mutation
  (`can(Role::Agent, …)`); the control surface is loopback + bearer (`socket.rs`).
- **Tests:** `sponsor_gate_rejects_bad_grants`, `agent_participates_as_a_member_and_is_guardrailed`
  (`crates/comms-agent-bridge/src/lib.rs`).
- **Residual:** a compromised agent host reads that one workspace until removed (next-Commit PCS).

### At-rest CF encryption + PQ key-wrap path
- **Spec:** `PLANSET/02` §6 (AES-256-GCM CFs, mandatory AAD = CF name, per-CF BLAKE3-derived
  keys; HybridKEM master-key wrap is the documented next step).
- **Impl:** `crates/comms-core/src/store.rs` — `EncryptedStore` (mandatory AAD, per-CF keyed
  KDF; master + derived keys in `Zeroizing`).
- **Tests:** `on_disk_bytes_are_not_plaintext` (`crates/comms-core/src/store.rs`);
  `relay_persists_only_ciphertext_on_disk` (`crates/comms-agent-bridge/src/lib.rs`) — REAL
  MLS ciphertext through a persistent relay; canary absent in SST/WAL/MANIFEST.
- **Gap to review:** HybridKEM (Kyber-768 + X25519) master-key wrap is specced but not yet
  wired — the key-management seam is `keyvault::master_key_for`.

### Constant-time secret handling
- **Spec:** `PLANSET/07` §2.3 (no `==` on secrets; constant-time comparators).
- **Impl:** `subtle::ConstantTimeEq` for the relay admin bearer
  (`crates/comms-relay/src/admin.rs`) and the agent socket bearer
  (`crates/comms-agent-bridge/src/socket.rs`). Low-S enforced on every secp256k1 verify
  path via the shared `recover_address` (`crates/comms-core/src/identity.rs`).
- **Tests:** `high_s_signatures_are_rejected` (`crates/comms-core/src/identity.rs`).

### Cross-cutting: audit integrity, parser robustness, transport hardening
- **Audit chain:** `crates/comms-core/src/audit.rs` (BLAKE3 hash chain) + `formal/AuditChainIntegrity.tla`;
  test `ciphertext_only_store_and_audit_verifies` (`crates/comms-relay/src/lib.rs`).
- **Parser robustness:** `hostile_cbor_never_panics_only_errors` (`crates/comms-proto/src/canonical.rs`) —
  the per-message decode path can never panic on malformed/oversized/nesting-bomb input.
- **Transport hardening:** `crates/comms-relay/src/endpoint.rs` refuses plaintext `ws://` to a
  remote host (fail-closed); admin surface loopback-only.

## Reproduce

```sh
cargo test --workspace --locked                 # 71 passing
cargo clippy --workspace --all-targets --locked -- -D warnings
# Reproducible signed release (CI): tag vX.Y.Z → .github/workflows/release.yml
# Air-gap validation: docs/audit/AIRGAP_TEST.md
```

## Known gaps to flag for the auditors (honest disclosure)

1. **TLC not yet run.** The TLA+ specs are written but not model-checked (no toolbox in the
   build env). The first audit task should run TLC on `RelayCommitOrder.tla` +
   `AuditChainIntegrity.tla` and attach the logs.
2. **HybridKEM master-key wrap not wired.** At-rest uses AES-256-GCM under a keyring/env master
   key; the PQ-hybrid wrap (`PLANSET/02` §6.3) is a specced seam, not yet implemented.
3. **No dedicated fuzzer run.** `comms-proto` has an in-tree robustness corpus; a `cargo-fuzz`
   target is scaffolded-but-not-executed.
4. **Slint client not visually verified** in CI (headless); the session/crypto layer is
   unit-tested, the UI is structural.
5. **Release signing is soft-key** (pre-production) until the HSM ceremony (`docs/audit/HSM_SEAM.md`).
6. **Multi-device (R7)** and **client-encrypted MLS-state backup (R8)** are designed, not built.

## Handoff

On acceptance, `citrate-security` creates `audits/<date>-citrate-comms/`, this repo's report
resolves to `.../per-repo/citrate-comms/REPORT.md`, and `.agentile/AUDIT_REF.md` is updated
from `pending` to the live audit root. Cross-model quorum (independent models reach findings,
then reconcile) per the Agentile-Audit standard.
