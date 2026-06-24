---
created: 2026-06-24T00:00:00Z
branch: main
author: Claude Opus 4.8 (1M context), directed by Larry Klosowski (@SaulBuilds)
status: complete
sprint: COMMS-AGENTS closeout
purpose: Field-log journal of the citrate-comms webapp agentic build closeout. Staged here in
  the comms repo (its own remote) so it can be copied into citrate-journals/chapters/ch08-honesty-machine/
  field-log/ as `comms-agents__2026-06-24_webapp-closeout.md` without a cross-repo merge race.
---

# The conversation layer learned to contribute

The citrate-comms webapp started this arc as honest furniture: a trusted-tier CRM, channels with a
witness Ledger, members, projects, an audit chain — a place to work, but a quiet one. It ends the arc
as a place where three AI personas are first-class, audited members: they read the deals, propose the
writes (you approve), recall and assert to a knowledge graph, research the live web without a paid key,
render diagrams and charts inline, attach real files to their answers, and come when you @-call them
into a channel. None of it is a wiretap; all of it is on the record.

## What got built, in order

The spine (S0–S6) was already standing when this session opened: the inference adapter, the zod tool
registry with `audited()`, the three persona templates, the streaming chat route, CRM read/write with
HITL, the knowledge-graph seam, documents + RAG, the persona editor, the hardening caps. CRM-depth
(D0–D4) had already turned each record into a clickable, journaled file. The rich-render and attachment
streams (RR-0/1/2, ATT-0/1/2/3/DL) had landed too.

This session closed the long tail:

- **CH-1 / CH-2** — an org-wide conversation directory (admins can read any thread, and that read is
  itself written to the audit chain) and a genuinely private **incognito** mode (no persistence, no
  audit, read-only tools — so there is nothing to log because nothing can mutate).
- **RES-1** — a **keyless** web-research seam. The planset had specced Tavily; Saul's standing rule is
  no paid API keys, so it shipped SearXNG-first with a DuckDuckGo HTML fallback and an SSRF guard that
  refuses any host that resolves into a private range (including the cloud-metadata address).
- **MEN-0/1/2** — typing `@` opens a picker of members and agents; @-mentioning an agent runs its
  persona read-only over the channel and posts a reply *as the agent member*; @-mentioning a person
  creates a notification (a new table that stores no message content — it links to the channel) and
  lights the new bell.
- **CFG** — owners can pin resources and knowledge to a persona (folded into a PINNED RESOURCES prompt
  layer, encrypted at rest) and delegate "you may configure this agent" to a teammate without making
  them a workspace admin.
- **AGT-ART** — agents can now attach the artifacts they reference, not just describe them.

Six PRs (#24–#29), each one branch → gates → squash-merge → `vercel --prod`. Migrations 0006/0007/0008
applied. Ninety tests green.

## What I want to be honest about

The "closeout" word is dangerous for an agent. I generate the same confident tone whether a claim is
earned or not, so the discipline has to come from the evidence, not the prose. So, explicitly:

- The **comms-agent-runner daemon is not built.** Its BFF half is shipped; until the Rust daemon is up,
  terminal/code and Playwright fetches honestly return "unavailable." That's an ops handoff, not a
  finished feature.
- **Web search is degraded** to a rate-limited HTML fallback until SearXNG is deployed and `SEARXNG_URL`
  is set. The code is ready; the container is not.
- The **native (Slint) app** still has open gates — TLC, HybridKEM, fuzzing, UI CI, HSM signing. I did
  not touch them and I did not check them off. They are a different track and remain genuinely open.

The point of writing those down is that the next agent inherits the truth, not a green dashboard.

## The pattern worth stealing

Two of this session's features — incognito chat and the in-channel agent reply — are the same idea
wearing two hats: when you open a new surface for an agent, make it **read-only first** by dropping
every mutating tool from the allow-set. There is then nothing that must be audited, because nothing can
change. Safety became a one-line `for (const t of tools) if (HITL_TOOLS.has(t)) allow.delete(t)` instead
of a new policy. The cheapest secure feature is the one that can't do the dangerous thing at all.

*Next: the federation manifest gets a new "shipped" line, and the question of when a team's own tool
becomes a product the network can run.*
