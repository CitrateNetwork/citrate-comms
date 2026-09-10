---
created: 2026-06-14T00:00:00Z
branch: main
author: Saul Loveman + Claude Opus 4.8 (1M context)
status: packet-ready
---

# Active audit reference — `citrate-comms`

> This repo's link into the centralized federation audit trail. The canonical audit home is the
> `citrate-security` repo.

**No dedicated security audit has run yet**, but the **Tier-1 audit packet is now assembled and
ready for handoff** — see [`docs/audit/AUDIT_PACKET.md`](../docs/audit/AUDIT_PACKET.md) (spec-to-code
evidence map for R1/R3/R5/at-rest/constant-time, packet contents, reproduce steps, and an honest list
of known gaps) plus the air-gap validation [`docs/audit/AIRGAP_TEST.md`](../docs/audit/AIRGAP_TEST.md).
This repo is classified **Tier 1 — full audit** (it handles user secrets, group key material, and an
E2E protocol). COMMS-S4 (WP-4.1..4.11) closed the hardening + reproducible-release + airgap items that
gated the engagement (see `PLANSET/07_IMPLEMENTATION_AND_HARDENING_PLAN.md` § "Tier-1 audit feed").

When the first audit runs, this file resolves into:

- Audit root: `citrate-security/audits/<date>-<slug>/`
- This repo's report: `.../per-repo/citrate-comms/REPORT.md`
- Standard: `citrate-security/.agentile/standard/AGENTILE_AUDIT_STANDARD.md`
- Audit index: `citrate-security/audits/AUDIT_INDEX.md`

## FWA remediation (2026-06-21) — federation-wide audit chunk FWA-C11

The first dedicated audit ran as **chunk FWA-C11** of
`citrate-security/audits/2026-06-20-federation-wide-audit/` (pinned SHA `a8b49d5`, Agentile-Audit
v0.2). Server-blind invariant: **HOLDS**. Findings remediated on branch `remediation/fwa-2026-06`:

| ID | Sev | Status | Fix |
|----|-----|--------|-----|
| FWA-C11-01 | HIGH | **FIXED** | `submit_as(authed, …)` binds `Envelope.sender` to the session principal; WS `Submit`/`PublishKeyPackage` + `onboard`/`offboard` all route through it. Red test + Class-A tripwire (test + semgrep). |
| FWA-C11-03 | MED | **FIXED** | `onboard` now runs the same RBAC (`verify_grant_chain` + `can(AddMember)`) as `offboard`. Red test. |
| FWA-C11-04 | MED | **FIXED** | At-rest AEAD AES-256-GCM → **AES-256-GCM-SIV** (nonce-misuse-resistant). Red test proves the GCM keystream-XOR leak no longer holds. |
| FWA-C11-02 / -06 | MED / LOW (DOC-CLAIM) | **FIXED (claim corrected)** | Every implemented-claim of PQ (ML-KEM/Kyber/HybridKEM) corrected to the real classical suite across UI, `backend.rs`, `README.md`, doc-comments, `.agentile`. PQ labelled **ROADMAP**. grep proof recorded. |

Full evidence: [`.agentile/audits/2026-06-21-fwa-remediation/REMEDIATION_LOG.md`](audits/2026-06-21-fwa-remediation/REMEDIATION_LOG.md).

## Pre-audit focus areas (carried from the planset risk register)

- **R1** — relay Commit-ordering / delivery-service trust (the hardest correctness property; TLA+ spec it).
- **R3** — KeyPackage / MLS-credential spoofing (wallet binding attestation must be load-bearing).
- **R5** — agent MLS key custody (per-workspace identities; HSM consideration).
- At-rest CF encryption + the PQ-hybrid key-wrap path; constant-time handling of all secret material.
