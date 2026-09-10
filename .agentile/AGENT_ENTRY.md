---
created: 2026-06-14T00:00:00Z
last_updated: 2026-07-16
branch: main
author: Saul Loveman + Claude Opus 4.8 (1M context)
status: active
planset: COMMS
repo: citrate-comms (NEW, Tier-1)
---

# Agent Entry Point — citrate-comms

> Start here. This repo is the federation's **end-to-end-encrypted, agentic team workspace**
> — Comms + CRM + Project Management in one self-hostable binary. Login is a cryptographic
> handshake on `citrate-identity`; messages are MLS-encrypted and routed by a **server-blind
> relay** that never sees plaintext; AI agents join conversations as **cryptographic members**.
> Read this before touching the repo.

## Where am I?

`CitrateNetwork/citrate-comms` — v1 first pass. We are the first team to run it. The product
thesis: if a secure, agentic, on-prem comms+CRM+PM workspace works for our own team, it
productizes for any team on the Citrate network.

## The one rule everything depends on

> **The relay is trusted for *liveness and ordering*, never for *confidentiality*.**
> It stores/forwards ciphertext + routing metadata only. Every byte of plaintext, every MLS
> group secret, and every CRM/PM record lives ONLY on member clients. If you are about to make
> the relay able to read a message, a group secret, or an entity field — stop. That breaks the
> single invariant the whole product is built to guarantee.

A second, equally load-bearing rule: **an agent is a participant, not a wiretap.** Agents get
their own MLS keys and are *added to a channel* exactly like a human (a visible MLS Add). There
is no out-of-band plaintext copy, no escrow key, no "agent-readable" server decryption path.

## Canonical pointers

- **Design (read in order):** `PLANSET/00_OVERVIEW.md` → `01_SCOPE_OF_WORK.md` →
  `02_ARCHITECTURE.md` → `03_TLA_SPECS.md` → `04_FEATURES_BDD.md` → `05_SPRINTS_AND_WPS.md` →
  `06_AGENT_INTEGRATION_SPEC.md` → `07_IMPLEMENTATION_AND_HARDENING_PLAN.md`.
- **Active sprint:** `citrate-federation/repos/citrate-comms/sprints/active/COMMS-S5.md` (native-client
  UI/UX hardening; S0–S4 complete). The **web-app track** (agentic CRM, deployed) is planned under
  `webapp/PLANSET/` (`AGENTS_00_OVERVIEW.md` → `AGENTS_01_BUILD_SPEC.md` → `AGENTS_HANDOFF.md`).
- **Federation rules:** `../citrate-federation/agentile/rules/` (Rule 1 no mocks · Rule 2 tests
  monotone · Rule 5 frontmatter · Rule 8 zero unwraps in GUI src · Rule 10 authorize destructive
  ops · Rule 11 manifest canonical · Rule 12 drift map).

## Reuse contract (do not re-invent)

- **Auth handshake** reuses `citrate-identity` SIWE (`verifySiweLogin`: single-use nonce,
  chainId 40204, low-S, domain/uri/expiry binding, EIP-1271) and the Rust OIDC/PKCE/keyring model
  in `citrate-studio/src/auth.rs` (`AuthConfig`, `Claims`, `KeyringTokenStore`). Identity is the
  `wallet_address` (`sub`).
- **Crypto grade** matches `citrate-chain`: Ed25519 / X25519 / AES-256-GCM-SIV at-rest (mandatory
  AAD, nonce-misuse-resistant) / SHA-256 + BLAKE3 / `zeroize`. Wrapping the at-rest CF master key
  with the chain's `HybridKEM` (`citrate-chain/core/storage/src/crypto/quantum_safe.rs`) is a
  **roadmap item, NOT yet implemented** — the master key is used directly today.
- **Audit chain** mirrors `citrate-agent-runtime` `AuditChain` (monotone sequence, `previous_hash`
  contiguity, genesis, `chain_anchor`); chain-anchoring pattern from `citrate-memories` `mem-sync/src/chain.rs`.
- **Local control surface** copies `citrate-node-agent/crates/supervision/src/server.rs`
  (loopback-bind + per-instance bearer token, fail-closed). **IPC** copies
  `nist-agent/crates/nist-agent-daemon/src/ipc.rs` (Unix-socket, JSON-per-line).
- **Slint UI** consumes `@citrate-ui-kit` from `citrate-studio/ui-kit` (Theme + primitives); the
  client UI is hand-translated 1:1 from the design team's HTML/CSS package.
- **MLS** is provided by OpenMLS — do **not** fork it to inject Keccak/Kyber; accept SHA-512 in-suite
  and do post-quantum at the storage layer (see `07`).

## Current state (2026-07-16)

Two tracks are live.

- **Native Rust workspace** — the crypto + transport spine shipped and hardening continues.
  COMMS-S0–S4 are complete (`comms-proto` wire types; `comms-core::mls` OpenMLS; `comms-core::identity`
  SIWE secp256k1 + nonce + binding attestation; `comms-core::audit` BLAKE3 chain; `comms-relay`
  server-blind `DeliveryService` with total order + KeyPackage directory; WS transport + RocksDB
  persistence; channels/forums/DMs; onboard/offboard via atomic `RoleAssertion`). **COMMS-S5** (active)
  is native-client UI/UX hardening with a headless test harness. `clippy -D warnings` clean; TLA+ in `formal/`.
- **Web app (`webapp/`) — DEPLOYED to Vercel production** and
  engineering-mature through ~E-5: fail-closed OIDC auth (refresh tokens, `src/proxy.ts`), workspaces + RBAC,
  comms + witness Ledger, **agentic CRM** (`lib/domain/crm.ts`), project management (`lib/domain/pm.ts`),
  **agents-as-members membership only** (`lib/domain/agents.ts` — directory/add/seat/pause; runtime NOT wired),
  **SSE notifications** (`api/workspaces/[id]/notifications/stream`), BLAKE3 audit chain, per-workspace
  AES-256-GCM. Stack: Next.js 16, Drizzle + Neon, jose OIDC, Upstash rate-limit. Plan: `webapp/PLANSET/`.
- **Audit posture:** only an **internal self-audit** has run — FWA-C11 (2026-06-21, findings FIXED, see
  `.agentile/AUDIT_REF.md`). There is **no external / third-party audit** yet.
- **Not yet done (do not overstate):** the `https://citrate.ai/entitlement` claim is **parsed but not gating**
  (no paid-entitlement enforcement; revenue not live); the agent **runtime** (privileged tools via
  `comms-agent-runner`) is unbuilt.
