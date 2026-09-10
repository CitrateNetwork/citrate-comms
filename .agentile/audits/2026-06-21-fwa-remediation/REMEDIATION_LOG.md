---
created: 2026-06-21
audit_id: 2026-06-20-federation-wide-audit
chunk: FWA-C11
target: citrate-comms
audited_sha: a8b49d5ef7dec67666bf8bae586db5537417dec3
remediation_branch: remediation/fwa-2026-06
standard: Agentile-Audit v0.2
agent: RM-MSG (Claude Opus 4.8, 1M context)
---

# FWA-C11 Remediation Log — citrate-comms

Red-test-driven remediation of the FWA-C11 findings. Toolchain: cargo 1.96.0,
cargo-mutants 25.3.1. `semgrep` not installed locally (rule shipped for CI; see BLOCK-1).

Server-blind invariant was **HOLDS** in the audit; none of these fixes touch it
(the relay still links no `mls` feature and holds no secret types).

Monotonic test count: relay lib **11 → 14** (+3); new relay integration test file
`tests/sender_binding.rs` (+1); comms-core store tests unchanged in count but +1
new test (`at_rest_aead_is_nonce_misuse_resistant`, total store = 3). No existing
test weakened or removed.

---

## FWA-C11-01 (HIGH) — `submit` did not bind `Envelope.sender` to the session — FIXED

**Root cause:** the WS `Submit` arm forwarded the client-supplied `Envelope` straight to
`DeliveryService::submit`, which only checked `require_session(envelope.sender)` against a
GLOBAL session set + `members.contains(envelope.sender)` — never that the sender equalled
the connection's authenticated principal. Any member could submit as another member,
forging the audit receipt and controlling the recipient set.

**Fix:**
- New public `DeliveryService::submit_as(authed, envelope, now)` — rejects
  `envelope.sender != authed` with `RelayError::SenderMismatch` (fail-closed, no silent
  overwrite). The old `submit` is now **private** (trusted internal path).
  `crates/comms-relay/src/lib.rs` (submit_as ~459–475, submit now private ~486).
- WS `Submit` arm calls `submit_as(addr, env, now)`; `PublishKeyPackage` arm rejects
  `pubn.wallet != addr`; `onboard`/`offboard` route their Welcome/Commit through
  `submit_as(admin, …)`. `crates/comms-relay/src/ws.rs` (~225–270).
- All in-process callers (agent-bridge, client net/backend, tests) migrated to
  `submit_as` / the bound path.

**Red → Green:**
- `lib.rs::tests::submit_binds_sender_to_authenticated_session` — Mallory (authed member)
  submits with `sender = Alice`; asserts `SenderMismatch`, no audit receipt written, no
  forged envelope in the log, and the honest self-send still works.
- Over-the-wire: `tests/sender_binding.rs::over_the_wire_onboard_and_sender_binding` — a
  spoofed `submit` over a live socket is rejected; the honest one is accepted.
- **Red proof:** with the binding stripped (`let _ = authed; self.submit(...)`) the unit
  test FAILED — the spoof was accepted (`Ok(1)`). Restored → green.

**Files+LOC:** `crates/comms-relay/src/lib.rs` (+submit_as / submit privatised / onboard /
offboard / SenderMismatch variant); `crates/comms-relay/src/ws.rs` (Submit + PublishKeyPackage
+ Onboard arms, RelayClient::onboard signature).

**Test-count delta:** +2 (submit_binds + over-the-wire) plus the tripwire (+1).
**Mutation:** `submit_as` + `DeliveryService::onboard` — **8/8 caught (100%)** (see MUTATION).
**Tripwire:** `ws::tests::tripwire_ws_dispatch_binds_every_client_identity_to_session`
(Class-A static guard over `ws.rs` source: fails if the un-bound `.submit(` is reached, if
the Submit arm stops calling `submit_as(addr, env, now)`, or if PublishKeyPackage stops
checking `pubn.wallet != addr`) + semgrep `.semgrep/fwa-c11-sender-binding.yml`.
**CODE-QUALITY:** sender binding is now expressed as a one-way type boundary — the only
public submit entry binds the principal; the trusted path is private and documented. No
clones added; error is fail-closed and named.
**DOCUMENTATION:** `submit_as`/`submit` doc-comments state the trust contract; the sweep
table (below) records every WS handler's binding.

### SWEEP — every WS handler vs. client-supplied identity

| Frame | client identity field | bound to session? |
|-------|----------------------|-------------------|
| Challenge | — | n/a |
| Authenticate | `message.address` | SIWE sig + single-use nonce *establishes* `authed` |
| PublishKeyPackage | `pubn.wallet` | **bound** — `pubn.wallet == addr` check + binding attestation |
| TakeKeyPackage | `wallet` (lookup) | read-only directory lookup, not an attribution |
| RegisterGroup | — (uses `addr`) | **bound** |
| Onboard | admin / welcome.sender | **bound** — `addr` admin; welcome via `submit_as(admin,…)`; +RBAC |
| Submit | `env.sender` | **bound** — `submit_as(addr, env, now)` |
| RatchetTree | — | read-only |
| Offboard | admin / removed / commit.sender | **bound** — `addr` admin; commit via `submit_as(admin,…)`; RBAC pre-existing |

Coverage: all 9 arms accounted for; the two that previously trusted a client identity
(Submit, and — defence-in-depth — PublishKeyPackage) are now session-bound.

---

## FWA-C11-03 (MED) — `onboard` had no RBAC — FIXED

**Fix:** `DeliveryService::onboard` gained an `admin_assertion: Option<&RoleAssertion>`
parameter and now runs the SAME check as `offboard`: `admin == owner` OR
`verify_grant_chain(assertion, admin, owner)` + `can(role, Capability::AddMember)`.
Threaded through the WS `Onboard` frame (added `admin_assertion`) and `RelayClient::onboard`.
`crates/comms-relay/src/lib.rs` (~360–372), `crates/comms-relay/src/ws.rs`.

**Red → Green:** `lib.rs::tests::onboard_requires_add_member_authorization` — a plain
`Member` (no `AddMember`, no grant) is rejected with `NotAuthorized` and the victim never
enters the roster; an owner-signed `Admin` grant then lets the same member onboard.
**Red proof:** with the RBAC block stripped the test FAILED — the unauthorized onboard
returned `Ok(())`. Restored → green.

**Test-count delta:** +1. **Mutation:** included in the 8/8 caught set.
**Tripwire:** covered by the onboard-RBAC unit test (a future drop of the check fails it).
**CODE-QUALITY:** symmetric with `offboard` — same helpers, no divergent authz logic.
**DOCUMENTATION:** onboard doc-comment + inline note cite FWA-C11-03 and the capability.

---

## FWA-C11-04 (MED) — random-nonce GCM at-rest without rotation — FIXED

**Fix:** at-rest AEAD switched **AES-256-GCM → AES-256-GCM-SIV** (RFC 8452,
nonce-misuse-resistant). Random 96-bit nonce kept (writes stay unlinkable) but a nonce
reuse no longer leaks the keystream/GHASH key — it degrades only to revealing equality of
(nonce, AAD, plaintext). KDF domain bumped `cf/v1` → `cf/v2` to bind the per-CF key to the
suite. Workspace dep `aes-gcm-siv = 0.11`; `comms-core` `store` feature swaps
`dep:aes-gcm` → `dep:aes-gcm-siv`. `crates/comms-core/src/store.rs`,
`crates/comms-core/Cargo.toml`, root `Cargo.toml`.

**Red → Green:** `store::tests::at_rest_aead_is_nonce_misuse_resistant` — forces the SAME
nonce on two different equal-length plaintexts and asserts the GCM catastrophe
`ct1 ^ ct2 == pt1 ^ pt2` does **not** hold.
**Red proof:** pointing the same test at plain `Aes256Gcm` made it FAIL — `left == right`
(the keystream-XOR identity held, i.e. the plaintext XOR leaked). Under GCM-SIV it passes.

**Test-count delta:** +1 (store tests now 3). **Mutation:** store cipher covered by store
tests; not in the relay-scoped run (BLOCK-2 — rocksdb native build cost; recorded).
**Tripwire:** the misuse-resistance test is permanent; a regression to plain GCM (or any
keystream-reuse AEAD) fails it.
**CODE-QUALITY:** single call-site change behind the `cipher(cf)` helper; AAD + Zeroizing
key handling preserved; module doc explains the threat + choice.
**DOCUMENTATION:** store.rs module doc rewritten (why SIV, NIST SP 800-38D bound); README +
keyvault + main doc-comments updated to AES-256-GCM-SIV.

---

## FWA-C11-02 / FWA-C11-06 (DOC-CLAIM) — undelivered PQ claims — FIXED (claim corrected)

Per CHARTER §3 the smallest honest fix was chosen: **correct every implemented-claim** to
the real classical suite and label PQ as roadmap-only (shipping a real HybridKEM was judged
out of scope — no ratified hybrid MLS ciphersuite exists, and the at-rest wrap is a
key-management feature, not a small change).

**Corrected (was presented as live, now classical / roadmap):**
- `crates/comms-client/ui/screen_security.slint` — the "ACTIVE CIPHER SUITE" now lists the
  real live rows (X25519 DHKEM, Ed25519, MLS/TreeKEM, AES-128-GCM transport, SHA-256,
  AES-256-GCM-SIV at-rest) with a **LIVE** badge; ML-KEM-768 / ML-DSA-65 are separate
  **ROADMAP** rows. Hero changed "Quantum-resistant"→"End-to-end encrypted. Forward-secret";
  "Post-quantum secure"→"E2E encrypted"; the handshake walk's final PQ step is marked
  `done: false` → renders "ROADMAP" (no green ✓). Prose rewritten to the truth.
- `crates/comms-client/src/backend.rs:421` + `ui/screen_audit.slint` — "Device key published
  · ML-KEM-768" → "· X25519/Ed25519".
- `crates/comms-client/ui/nav.slint` — "Security — post-quantum posture" → "cryptographic
  posture". `ui/theme.slint` — `HandshakeStep` gained `done: bool`.
- `README.md` — at-rest line now AES-256-GCM-SIV; HybridKEM/ML-KEM moved to an explicit
  "Roadmap (NOT yet implemented)" block.
- Doc-comments: `crates/comms-core/src/mls.rs` (live suite is classical, no ML-KEM in build),
  `crates/comms-relay/src/keyvault.rs`, `crates/comms-relay/src/main.rs`,
  `crates/comms-core/src/store.rs` — all PQ mentions marked roadmap / NOT implemented.
- `.agentile/AGENT_ENTRY.md` — "keys ARE wrapped with HybridKEM" → roadmap, not implemented.
- `design/handoff/project/README.md` + `NEW_COMPONENTS.md` — surface spec corrected.

**Left as-is (legitimately roadmap / non-claims):** `PLANSET/*` (design + roadmap docs that
already say "future"/"when OpenMLS ships"), `design/handoff/chats/*` (historical transcripts),
`docs/audit/AUDIT_PACKET.md` (already states "specced but not yet implemented"), and the
fictional in-app chat preview "ML-KEM migration plan attached" (reinforces PQ-is-future).

**GREP PROOF** (code + live UI, `--include='*.rs' --include='*.slint'`): every remaining
`ML-KEM|Kyber|HybridKEM` occurrence is roadmap-qualified —
- `mls.rs:22` "no ML-KEM/Kyber is present in the build … future ratified"
- `store.rs:17` / `keyvault.rs:9` / `main.rs:16` "roadmap item … NOT yet implemented"
- `screen_security.slint:3` "on the roadmap — NOT yet implemented", `:157` PQ rows behind the
  ROADMAP badge, `:174` `done:false` "Not yet enabled", `:227` "on the roadmap … not enabled today"
- `screen_comms.slint:54` fictional chat preview ("migration plan")
No occurrence presents PQ as implemented.

**Test-count delta:** 0 (doc/UI). UI validity proven by the client crate compiling +
`ui_smoke::ui_harness_geometry_and_nav_interaction` passing.
**Tripwire:** the corrected `screen_security` rows are data-driven; a future "live PQ" claim
would have to re-introduce a LIVE badge on a PQ row (visible in review). (No automated grep
tripwire wired — see BLOCK-1.)
**CODE-QUALITY:** UI now data-honest (LIVE vs ROADMAP badge split; `done` flag on steps).
**DOCUMENTATION:** this is the documentation fix — claims now match the code.

---

## MUTATION

`cargo mutants -p comms-relay --re 'submit_as|::onboard'` (incl. integration tests):
**8 mutants tested → 8 caught (100%)**, exceeds the ≥90% gate on the bind/authz functions.
(An earlier `-- --lib`-only run left 1 miss — `RelayClient::onboard` no-op — which the new
`tests/sender_binding.rs` over-the-wire test now kills.)

Including the internal `submit` (`--re '::submit\b|submit_as|::onboard'`, 22 mutants):
**19 caught, 3 missed** — all 3 are the SAME pre-existing line `lib.rs:507` (`envelope.epoch.0
> state.current_epoch`, the epoch high-water advance in the first-writer-wins block). That is
not part of the C11-01/03 remediation (it predates this branch) and is not security-load-
bearing for sender-binding/authz; flagged for a future epoch-ordering test, not introduced here.

Whole-file context run (`lib.rs` + `ws.rs`, 129 mutants) had further misses, but all in
untested getters/health-snapshot/client-wrapper helpers OUT of the C11 fix scope
(`snapshot`, `domain`, `is_paused`, `connected`, RelayClient request methods) — not the
remediated security logic.

---

## BLOCKS

- **BLOCK-1 (semgrep not installed):** `semgrep` binary unavailable in this environment.
  The Class-A static guard is therefore enforced two ways: (a) a permanent in-repo Rust
  tripwire test (`tripwire_ws_dispatch_binds_every_client_identity_to_session`) that runs in
  the normal test suite, and (b) a committed semgrep rule
  `.semgrep/fwa-c11-sender-binding.yml` for CI to run once semgrep is available. The DOC-CLAIM
  grep tripwire is run manually (proof above) rather than wired into CI.
- **BLOCK-2 (store mutation not auto-scored):** the comms-core `store` cipher swap is covered
  by a permanent red/green misuse-resistance test but was not put through cargo-mutants here
  (rocksdb native rebuild cost per mutant). The red-proof (GCM fails the test, SIV passes) is
  the equivalent guarantee that the assertion is load-bearing.

## VERIFICATION

`cargo test -p comms-relay` → lib 14, admin 3, sender_binding 1 (all pass).
`cargo test -p comms-agent-bridge` → 9 pass. `cargo test -p comms-client` → 6 + e2e 3 + ws 1
(all pass; slint UI compiles). `cargo test -p comms-core --no-default-features --features store
--lib store::` → 3 pass. No existing test modified to pass; counts monotone non-decreasing.
