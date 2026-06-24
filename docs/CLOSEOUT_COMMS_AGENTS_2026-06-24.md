---
created: 2026-06-24T00:00:00Z
branch: main
author: Claude Opus 4.8 (1M context), directed by Larry Klosowski (@SaulBuilds)
status: complete
sprint: COMMS-AGENTS closeout (S0–S6 + CRM-D0–D4 + RR/ATT/CH/RES/MEN/CFG/AGT-ART)
purpose: Retrospective + gate-closure record for the citrate-comms webapp agentic build.
---

# COMMS-AGENTS — Closeout & Retrospective

> **One line.** The citrate-comms webapp went from a trusted-tier CRM/comms shell to an
> agent-native workspace — three audited AI personas that read and write the CRM, recall and
> assert to a knowledge graph, do keyless web research, render rich output, handle universal
> attachments, get @-pinged into channels, and are configurable + delegable — all shipped to
> production. This document closes the gates and records what is and isn't done, honestly.

## What shipped (all on `main`, deployed to https://citrate-comms-web.vercel.app)

**Core agentic build (COMMS-AGENTS):**
- **S0 Foundations** — inference adapter + gateway client (per-persona model + frontier route), the
  zod tool registry with the `audited()` wrapper and `/api/.../mcp` parity, persona data model + 3
  default templates, the streaming agentic-loop chat route, the agent panel UI.
- **S1 CRM/PM/Ledger tools** — `crm.*`/`pm.*`/`ledger.write` with HITL approval gates; the Approvals inbox.
- **S2 Knowledge graph** — the `MemoryStore` seam (mem-gateway client + Neon pgvector fallback),
  `memory.recall`/`memory.assert` (HITL), trust-tiered citations in the UI.
- **S4 Documents + Notetaker** — Blob upload + parse (xlsx/docx/pdf/txt/md/csv) + pgvector RAG;
  `documents.read`/`documents.write`; the Notetaker workflow (summarize → Ledger/tasks/graph).
- **S5 Customization** — the per-persona editor (prompt layers 1–4, agentile skills, model/steps/
  temperature, tool allow-list, clone, export/import) with a force-included, unremovable guardrails layer.
- **S6 Hardening** — hard rate/budget/step ceilings, redaction tripwires, semgrep + gitleaks in CI,
  the honest "what can it do?" disclosure.

**CRM depth (COMMS-CRM-DEPTH):** D0 schema + custom-field engine + notes/journal + auto activity feed
+ tags; D1 record-file drill-down; D2 inline editing + admin field manager; D3 agent read/HITL-write of
the file (dynamic schema); D4 saved views + flat tables + search + bulk-tag + CSV export.

**Rich render + attachments + interaction (this stream):**
- **RR-0/1/2/3** — sanitized markdown + GFM tables + code, mermaid diagrams, vega-lite charts, the
  Citrate loader (no code-flash while streaming).
- **ATT-0/1/2/3/DL** — broad parsing, client-direct Blob upload, inline image/video/doc display,
  attachments on channels + chat, and the **audited download proxy**.
- **CH-0/1/2** — chat history + resume, the org-wide conversation directory (admin reads audited), and
  incognito (no persist, no audit, read-only).
- **RES-0/1** — the **keyless** web-research seam (SearXNG → DuckDuckGo, SSRF-guarded fetch + readability).
- **MEN-0/1/2** — @-autocomplete (members + agents), calling an agent into a channel (read-only reply as
  the agent member), and member pings via the new notifications system + bell.
- **CFG** — per-persona resources/knowledge-bases (folded into a PINNED RESOURCES prompt layer) and
  config-rights delegation (`canConfigurePersona` = admin OR grant).
- **AGT-ART** — agents attach real artifacts (`documents.list` + `artifact.attach`) to their replies.

**Migrations applied:** 0006 (message_attachments), 0007 (agent_resources + agent_config_grants),
0008 (notifications). Test suite: 90 passing. Every PR (#24–#29 this session, on top of the earlier
S0–S6/CRM/RR/ATT stream) merged through gates: typecheck, lint, vitest, semgrep tenant-scope, gitleaks, build.

## What is NOT done (honest gaps)

- **comms-agent-runner daemon (S3)** — the BFF delegation half is shipped, but the Rust daemon on the
  DGX/droplet is not built. Until it is, `terminal.exec`/`code.run` and Playwright-rendered fetches return
  "unavailable." Handoff: `docs/HANDOFF_COMMS_AGENT_RUNNER_2026-06-23.md`.
- **SearXNG deploy** — `web.search` falls through to DuckDuckGo HTML (rate-limited) until a SearXNG
  container is up and `SEARXNG_URL` is set. The code is keyless and ready.
- **Vector memory/RAG recall** — works when the gateway serves the bge embed model; lexical fallback
  otherwise. (Inference gateway IS wired for chat.)
- **CFG-3 growable custom-skill catalog**, **RES-2 scrape/crawl**, **RES-3 research skill bundles**, and
  **vision/multimodal** — deferred by design.
- **On-chain anchoring** of the BLAKE3 audit to chain 40204 — a deploy wire-up; the hash-chain and
  "Verify now" already exist.
- **Native (Slint) app track** — `docs/LIVE_DEBUG_CHECKLIST.md` and `docs/audit/AUDIT_PACKET.md` gaps
  (TLC run, HybridKEM wrap, fuzzer, UI CI, HSM signing) belong to the **native** app, NOT this webapp,
  and remain open there. They are intentionally NOT closed by this document.

## Retrospective — what worked, what to keep

- **Branch-before-commit, PR-per-item, gates-on-every-item.** Each feature was one branch → PR → squash
  merge → `vercel --prod`. The discipline caught regressions early and kept `main` always-deployable.
  The one recurring miss — committing to local `main` before branching — is now a saved memory; it cost
  minutes, never prod.
- **Fail-closed by default paid off.** Inference, embeddings, runner tools, and web search all degrade to
  an honest "unavailable" rather than crashing or faking output. The agent says what it can't do.
- **Read-only is the safe substrate for new surfaces.** Incognito (CH-2) and the in-channel agent reply
  (MEN-1) both reuse the same move: drop every HITL/mutating tool so a new context can't silently mutate
  state. One pattern, two features, no new audit holes.
- **Store no content you don't need.** Notifications (MEN-2) deliberately store no message text (bodies are
  encrypted at rest) — they link to the channel. The cheapest way to stay consistent with the trust posture
  is to not hold the data at all.
- **Single source of truth beats parallel lists.** `personas.test` now asserts persona tool-lists against
  `ALL_TOOL_NAMES` instead of a hand-maintained copy — a drift bug (AGT-ART) surfaced immediately.
- **Honesty in the docs is a feature.** The native-app gates above are tempting to wave closed in a
  "closeout"; leaving them open and labeled is the point. A green checkmark you didn't earn is a lie the
  next agent inherits.

## Where this is recorded

- Webapp planset gates closed: `webapp/PLANSET/AGENTS_00_OVERVIEW.md` §6, `webapp/PLANSET/
  RICH_RENDER_AND_ATTACHMENTS.md` §8, `webapp/PLANSET/RESEARCH_keyless_websearch.md`, and the living
  checklist in `docs/DEBUG_WALKTHROUGH_PROTOCOL.md`.
- Journal: `docs/journal/2026-06-24_comms-agents-closeout.md` (citrate-journals field-log voice; ready to
  copy into `citrate-journals/chapters/ch08-honesty-machine/field-log/`).
- Essay: `docs/essays/the-conversation-layer-learns-to-contribute.md` (agentile-history voice; ready to
  promote to `docs/essays/agentile-history/09_*.md` if Saul wants it in the canonical series).
- Federation/lab update (manifest + map + audit-index snippets): `docs/FEDERATION_UPDATE_2026-06-24.md`
  — staged for the agent closing out the labs-root repos, to apply without a merge race.
