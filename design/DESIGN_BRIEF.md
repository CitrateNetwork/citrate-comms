---
created: 2026-06-14T00:00:00Z
branch: main
author: Saul Loveman + Claude Opus 4.8 (1M context)
status: active
audience: Claude design team (UI/UX) → hands back an HTML/CSS package
---

# citrate-comms — Front-End Design Brief

> **Read this first.** This is a complete, self-contained brief for designing the UI/UX of
> **citrate-comms** — an end-to-end-encrypted, agentic team workspace (Comms + CRM + Project
> Management) that ships as a native desktop app. You will design in **HTML/CSS** (build it in Claude
> Code). The engineering team then **translates your HTML/CSS 1:1 into Slint** (the native UI language)
> against an existing brand kit. Everything you need — the product, the brand tokens, the screens, the
> data each screen renders, the states, and exactly what to hand back — is in this one document.
>
> You do **not** need to read the engineering planset. If you want depth, the source specs are
> `../PLANSET/00_OVERVIEW.md` and `../PLANSET/02_ARCHITECTURE.md`, but this brief is authoritative for design.

---

## 0. How to use this document

1. **§1–§3** — what the product is and the hard constraints that shape every screen. Read fully.
2. **§4** — the brand system (exact color/type/spacing tokens + the component inventory). Design *only*
   with these; they map 1:1 to the native kit.
3. **§5** — the information architecture / sitemap.
4. **§6** — the screen-by-screen specification (the bulk of the work).
5. **§7** — the data models every screen renders (the "structs" — fields, types, enums, relationships).
6. **§8** — the key interaction flows to storyboard.
7. **§9** — states, empty states, and security micro-copy.
8. **§10** — **the deliverable spec**: exactly what to hand back and how to name it so it translates cleanly.
9. **§11** — open questions / where to use your judgement.

---

## 1. The product in one screen

citrate-comms is **one workspace that replaces three tools** for a team: internal **Comms** (channels,
forums, DMs), a lightweight **CRM** (contacts, accounts, deals), and **Project Management** (projects,
tasks, boards) — all woven together so a deal thread, the tasks it spawns, and the chat about it are the
same conversation. It is **end-to-end encrypted** (a relay server moves messages but can never read
them), **self-hosted** (runs on a company's own machine, even offline/air-gapped), and **agentic**: AI
agents join conversations as first-class members.

**Who uses it.** Small teams (ours first), 3–50 people. Roles: **Owner**, **Admin**, **Member**,
**Partner** (external, scoped access), **Guest** (read-only, expiring), and **Agent** (an AI participant).

**The feeling.** Calm, precise, trustworthy, *editorial* — not a noisy consumer chat app. Warm paper
surfaces, a single restrained green accent, generous whitespace, monospaced type for anything
cryptographic or data-like. Security is *present but quiet* — the user should feel safe without being
nagged. Think "a beautifully bound ledger that happens to be a chat app," not "Slack with a lock icon."

---

## 2. Non-negotiable design constraints

These come from the architecture and **cannot be designed around**. They are also what makes this product
distinctive — lean into them.

1. **Native desktop app, not responsive web.** Design at desktop window sizes (target **1440×900**,
   support down to **1100×720**). No mobile layouts. No browser chrome. It's a resizable window with a
   custom title bar. Multi-pane layouts are expected and good.
2. **End-to-end encryption changes the UX.**
   - There is **no server-side full-text search of message content** — the server can't read messages.
     Search is **local only** (the user's own device searches its decrypted cache). Design search as a
     local, per-workspace feature; never imply a global cloud search.
   - A member **cannot read messages sent before they joined** a channel. Design an explicit, calm
     "history starts here / you joined on <date>" divider — not a broken/empty feeling.
   - **Offboarding is forward-only**: when someone is removed, they lose access to *future* messages but
     keep what they already saw. The offboard UI must say this plainly (see §6-G, §9) — do not imply a
     "remote wipe."
3. **Agents are members, not bots-on-a-server.** An AI agent appears in the member roster like a person,
   with its own avatar/glyph and an unmistakable **"AGENT"** marker. Adding/removing an agent is a
   visible membership event in the timeline and the audit log. There is no hidden "the server is reading
   this" state — if an agent can read a channel, it's *in* the channel and everyone can see that.
4. **The audit log is a sealed, evergreen, read-only zone.** It is visually distinct from the rest of the
   app (dark "sealed-ledger" surface, see token set in §4) — append-only, tamper-evident, never editable.
   Treat it like a vault page.
5. **Everything must map to the existing native component kit (§4).** If a screen needs something the kit
   doesn't have, that's allowed — but **flag it explicitly** in your handback as a "new component
   request" with a clear spec, so engineering can add it to the kit. Don't silently invent dozens of
   bespoke widgets; compose from the kit first.
6. **Connection status matters.** Because it's self-hosted and can be air-gapped, the app has real
   connection states (connected to relay / reconnecting / offline). This needs a quiet, always-visible
   indicator.

---

## 3. Identity & sign-in (how login works, so you can design it)

There is no email/password. A user signs in by proving control of a **wallet** (a cryptographic key,
like signing into a crypto app) through a one-click **"Sign in"** that pops a signature request. You do
**not** need to design wallet internals — design:

- a **Connect / Sign-in** screen (brand moment; a single primary action "Sign in with your Citrate
  wallet"; a subtle line about end-to-end encryption),
- a **signing in… / approve the request** transient state,
- a **first-run** state (no workspace yet → create or join one),
- an **error** state (signature rejected / expired / wrong network).

After sign-in the user's identity is their wallet address (shown as a short `0x1f2e…a9` mono string with
a copy affordance, and a human display name they set).

---

## 4. The brand system (design only with these)

These tokens are the **exact** values in the native kit. Build a `tokens.css` with CSS variables of the
**same names**; engineering maps `var(--citrate-green)` → `Theme.citrate-green` mechanically. **Never use
a raw hex outside `tokens.css`.**

### 4.1 Color tokens

```
/* BRAND */
--citrate-green: #8ecc09;  --citrate-green-deep: #5a8205;  --citrate-green-dark: #2f4502;  --citrate-green-tint: #e8f3c6;
--citrate-yellow: #ffbd10; --citrate-yellow-deep: #c89400; --citrate-yellow-dark: #6e5100; --citrate-yellow-tint: #fff1c4;

/* INK (warm near-blacks) */
--ink: #0e0f0c;  --ink-2: #1f221d;  --graphite: #3a3d36;

/* STONE (warm neutrals) */
--stone-900:#2a2c27; --stone-700:#555851; --stone-500:#84867f; --stone-400:#a5a79f;
--stone-300:#c3c4be; --stone-200:#d9dad4; --stone-150:#e3e2dc; --stone-100:#ecebe4; --stone-50:#f1efe8;

/* PAPER (warm surfaces — the default app background) */
--paper: #f4f1ea;  --paper-2: #faf8f3;  --paper-pure: #ffffff;

/* DEPTH / EVERGREEN */
--deep-evergreen: #0f2a1a; --deep-evergreen-2: #1a3b27;

/* SEMANTIC */
--success:#4f8a05; --success-bg:#ecf5d4;  --warning:#b07b00; --warning-bg:#fff1c4;
--danger:#a72414;  --danger-bg:#f6e1de;   --info:#1b4965;    --info-bg:#dbe7ef;

/* FOREGROUND / BORDERS */
--fg-1:#0e0f0c; --fg-2:#555851; --fg-3:#84867f; --fg-accent:#5a8205;
--border-1:#d9dad4; --border-2:#c3c4be; --border-strong:#0e0f0c;

/* SEALED-LEDGER ZONE (the audit vault — dark evergreen, read-only) */
--sealed-bg:#0c2216; --sealed-bg-2:#0f2a1a; --sealed-surface:#123524; --sealed-bg-hard:#07140c;
--sealed-border:#2a3f33; --sealed-border-2:#36503f;
--sealed-fg:#cde7d6; --sealed-fg-2:#8fae99; --sealed-fg-3:#5f7a68;
--sealed-hover:#15311f; --sealed-tint-green:#14361f;

/* FOCUS / SHADOW */
--focus-ring: rgba(142,204,9,.35);  --shadow-soft: rgba(14,15,12,.18);
```

**Usage rules.** Paper (`--paper`) is the app background; `--paper-pure` for cards. Green is the *only*
accent — use it sparingly for primary actions, active states, and the encryption-OK signal. The
**sealed-ledger** palette is used **only** for the audit zone (and optionally a "this is permanent /
on-chain anchored" moment). Hashes, addresses, codes, and timestamps are **always** de-emphasized
(`--fg-3`, mono font) — never bright.

### 4.2 Type

```
--font-display: "Space Grotesk";  /* screen titles, big moments */
--font-sans:    "Geist";          /* all body / UI text */
--font-mono:    "Geist Mono";     /* addresses, hashes, code, timestamps, data */
--font-editorial:"Cormorant";     /* rare editorial italic accents (empty states, quotes) */

/* scale */ --t-3xs:11px; --t-2xs:12px; --t-xs:13px; --t-sm:14px; --t-md:16px;
            --t-lg:18px; --t-xl:22px; --t-2xl:28px; --t-3xl:36px; --t-4xl:48px;
```

Body text is Geist 13–16px. **Anything cryptographic or machine-generated is Geist Mono.** Eyebrow labels
are mono, uppercase, letter-spaced, small (≈11px). Use Cormorant *only* for occasional editorial warmth
(e.g., an empty-state line) — never for UI controls.

### 4.3 Spacing, radii, motion

```
/* spacing — 8pt grid */ --s-1:4 --s-2:8 --s-3:12 --s-4:16 --s-5:20 --s-6:24 --s-7:32 --s-8:40 --s-9:48 --s-10:64 (px)
/* radii */ --r-0:0 --r-1:6 --r-2:8 --r-3:12 --r-pill:999 (px)
/* motion */ --dur-fast:140ms --dur-base:220ms --dur-slow:420ms --dur-narrative:900ms
```

Respect a **reduced-motion** setting. Two density modes exist — design for **"cinematic"** (roomy) as the
default and keep layouts that also survive a **"compact"** mode (tighter padding).

### 4.4 Component inventory (compose from these first)

The native kit already provides these. Build HTML/CSS equivalents with matching names so the mapping is
mechanical. **Reuse before inventing.**

| Component | What it is | Use in citrate-comms |
|---|---|---|
| `Btn` | Button. Variants: `primary`, `ghost`, `danger`, `ghost-dark` (for the sealed zone). `sm` size. Optional leading icon. | All actions. Primary = green. `ghost-dark` only inside the audit vault. |
| `IconButton` | Icon-only button; `on-dark` variant. | Composer actions, toolbar, row affordances. |
| `Card` | Paper surface, hairline border, optional `lifted` shadow. | Every panel, list item group, entity card. |
| `Hairline` | 1px divider (`--border-1`). | Separators, list dividers, the "history starts here" rule. |
| `Label` / `Eyebrow` / `Title` / `Mono` / `Editorial` | Typography primitives (see §4.2). | Section headers (`Eyebrow`), screen titles (`Title`), addresses/hashes (`Mono`). |
| `SelectableText` | Read-only, selectable/copyable text. | Wallet addresses, message-id, audit hashes — anything copyable. |
| `RoleGlyph` | Small square with a role abbreviation; danger styling for sensitive roles. | **Member role chips** (Owner/Admin/Member/Partner/Guest/Agent). You'll extend the abbreviations. |
| `DataChip` | Pill tag for a data classification. | Repurpose as **channel/space tags**, deal stage, task label, "PARTNER/EXTERNAL" markers. |
| `RiskBadge` / `RiskDot` | Tiered pill/dot (`low/medium/high/critical`). | Deal priority, task priority, security posture of a space; the connection-health dot. |
| `SurfBadge` | Tiny mono badge. | "E2E", "AGENT", device/session labels, "ON-PREM". |
| `AnchorMark` | Green anchor + label. | "Anchored to chain @ block N" in the audit zone. |
| `Keyframe` | Diamond gate marker (medium/high/critical). | Optional: approval/gate steps in onboarding or sensitive actions. |
| `SevDot` | Pass/Warn/Blocker dot. | Audit verification status, connection state. |
| `AppIcon` / `CapGlyph` | Icon system (single-stroke, currentColor). | All iconography. Request new glyph names as needed (see §10). |

**The visual language is already security-and-compliance-shaped** (roles, classifications, sealed ledger,
anchors). citrate-comms fits it naturally — you are extending a system, not starting from zero.

---

## 5. Information architecture (sitemap)

A persistent **left rail** + a **content area** that is usually two or three panes. Global structure:

```
┌───────────────────────────────────────────────────────────────────────────────┐
│ Title bar:  ◐ citrate-comms · <Workspace name>      [connection ●]  [me ▾]      │
├──────────┬────────────────────────────────────────────────────────────────────┤
│ LEFT RAIL│  CONTENT AREA (1–3 panes depending on section)                      │
│          │                                                                     │
│  Spaces  │   e.g. Comms:  [ channel list │ message stream │ right info panel ] │
│  · #deals│                                                                     │
│  · #eng  │                                                                     │
│  Forums  │                                                                     │
│  DMs     │                                                                     │
│  ─────   │                                                                     │
│  CRM     │                                                                     │
│  Projects│                                                                     │
│  Agents  │                                                                     │
│  Audit ▣ │   (Audit uses the dark sealed-ledger surface)                       │
│  ─────   │                                                                     │
│  Settings│                                                                     │
└──────────┴────────────────────────────────────────────────────────────────────┘
```

**Top-level sections** (left rail): **Spaces** (channels + forums grouped by team/workspace), **DMs**,
**CRM**, **Projects** (PM), **Agents**, **Audit** (sealed zone), **Settings**. A global **command palette**
(⌘K) for navigation + local search.

Design these primary destinations (each detailed in §6):
- **A.** Auth / onboarding / first-run
- **B.** App shell (title bar, left rail, connection indicator, me-menu, command palette)
- **C.** Comms — channel list, channel (message stream + composer), forum (threaded), DM, member roster panel
- **D.** CRM — contacts, accounts, deals pipeline (board), entity detail
- **E.** Projects (PM) — project list, board (kanban), task detail
- **F.** Agents — agent directory, agent profile, add-agent flow, agent activity
- **G.** Admin & RBAC — member directory, invite/onboard, role management, offboard
- **H.** Audit — the sealed-ledger event log + verification + chain-anchor
- **I.** Settings — identity, devices, notifications, connection, appearance

---

## 6. Screen-by-screen specification

For each screen: **Purpose · Layout · Renders (data) · States · Actions · Notes.** Data names in
`monospace` refer to the models in §7.

### A. Auth, onboarding, first-run

**A1. Sign-in.** *Purpose:* the brand front door.
*Layout:* full-window, centered. Logo, one line of product framing, a single **primary** "Sign in with
your Citrate wallet" button, a small footnote "End-to-end encrypted · self-hosted". *States:* idle;
**signing…** (button → progress, "Approve the request in your wallet"); **error** (rejected / expired /
wrong network — inline, calm, retry). *Notes:* this is the one place to be a little cinematic.

**A2. First-run (no workspace).** *Purpose:* create or join a workspace. *Layout:* two cards — "Create a
workspace" (name, optional logo) and "Join with an invite" (paste invite). *Renders:* `Workspace`.
*States:* creating; joining; invalid-invite error.

**A3. Join-from-invite.** *Purpose:* an invited member/partner accepts. *Renders:* `Invite` (workspace
name, inviter, role being granted, expiry). Show the role they'll receive (esp. **Partner** = scoped/
external) clearly. *Actions:* accept, decline.

### B. App shell

**B1. Title bar.** Workspace switcher (if multiple), centered workspace name, **connection indicator**
(see B3), and a **me-menu** (avatar → identity, settings, sign out).
**B2. Left rail.** Collapsible sections (§5). Unread badges. Active item uses green accent. An agent
present in a channel shows a tiny `SurfBadge` "AGENT" on the channel row.
**B3. Connection indicator.** A quiet `SevDot` + label: **Connected** (green), **Reconnecting** (yellow,
animated), **Offline / air-gapped** (stone, with a tooltip — offline is a *valid* state, not an error).
**B4. Command palette (⌘K).** Fuzzy navigate to any space/person/entity; run actions ("New channel",
"Add agent", "Invite member"); **local** message search (label it "Search this device").

### C. Comms

**C1. Channel list (pane 1).** *Renders:* list of `Channel` (name, kind = channel/forum/DM, unread count,
last-activity, member count, agent-present marker, tags via `DataChip`). Grouped by space. *Actions:*
new channel, search/filter, star/pin.

**C2. Channel view (pane 2) — the core screen.** *Purpose:* the message stream + composer.
*Layout:* header (channel name, topic, member avatars stack + count, "i" to open right panel) · message
stream · composer.
*Renders:* ordered `Message` list. Each message row: author avatar + display name + role glyph,
timestamp (mono, de-emphasized), message body (text; later: attachments), and per-message state
(sending → sent → delivered). **An agent's messages** carry the "AGENT" marker and a subtly distinct
author treatment. Consecutive messages from one author collapse (grouped). System events (member joined/
left, agent added/removed, "history starts here") render as centered, quiet **timeline markers**, not
bubbles.
*Composer:* multiline input, send, and affordances for: mention (`@member`/`@agent`), attach (future),
and **"link a record"** (attach a CRM `Deal` or PM `Task` to the message — a defining feature). A small
**E2E lock** affordance in the composer corner ("Encrypted to N members") — quiet, reassuring.
*States:* populated; **empty** ("This is the start of #name"); **loading** (skeleton rows); **decrypt
boundary** ("You joined on <date> — earlier messages aren't available to you"); **offline** (composer
shows "You're offline — messages will send when reconnected").
*Edge cases:* a message that failed to send (retry affordance); a message you can't decrypt (rare — show
a neutral "couldn't decrypt this message" placeholder, never a scary error).

**C3. Forum view.** *Purpose:* threaded, topic-first conversation (vs. C2's flat stream).
*Layout:* list of `Thread` (title, author, reply count, last reply, participants) → open a thread → a
focused thread view (root post + replies). *Renders:* `Thread`, `Message` (with `thread_id`/`parent_id`).
*Actions:* new topic, reply, follow/unfollow a thread.

**C4. DM.** A 2-person `Channel`. Same as C2 but no roster management; header shows the one other person.

**C5. Member roster / channel info (right panel, pane 3).** *Renders:* members of the channel
(`Member` + `Role`), incl. agents; channel `topic`; tags; "Encrypted — N members"; link to manage
members (admins). *Actions (admin):* add member, add agent, remove member (→ offboard flow §G), edit topic.

### D. CRM

**D1. Contacts.** *Renders:* `Contact` list (name, org via `Account`, last touch, owner). Table or card
grid. *Actions:* new contact, filter, open.
**D2. Accounts.** *Renders:* `Account` (org name, contacts count, open deals, owner).
**D3. Deals pipeline (board).** *Purpose:* a kanban of `Deal` by `stage`. *Renders:* columns = stages
(Lead → Qualified → Proposal → Won/Lost); cards = `Deal` (name, account, value, owner, priority via
`RiskBadge`, linked channel/thread). *Actions:* drag between stages, new deal, open.
**D4. Entity detail (Contact/Account/Deal).** *Layout:* header + tabbed body (Overview · Activity ·
Linked conversation). *Renders:* the entity's fields + **the linked `Channel`/`Thread`** (a defining
feature — a deal shows its conversation inline). *Actions:* edit, link/unlink a conversation, change stage.

### E. Projects (PM)

**E1. Project list.** *Renders:* `Project` (name, status, task counts, members).
**E2. Board (kanban).** *Renders:* `Board` → columns → `Task` cards (title, assignee, priority via
`RiskBadge`/`RiskDot`, due, linked thread). *Actions:* drag, new task, filter by assignee.
**E3. Task detail.** *Renders:* `Task` (title, description, assignee, status, due, subtasks/checklist,
linked `Thread`/`Deal`). *Actions:* edit, assign, change status, link a conversation, comment (which is a
message in the linked thread).

### F. Agents

**F1. Agent directory.** *Renders:* `Agent` list (name, purpose/description, the channels it's a member
of, status: active/paused, owner/sponsor). *Actions:* add agent, pause/resume, open profile.
**F2. Agent profile.** *Renders:* `Agent` detail — its capabilities/guardrails (role = Agent → **read +
post only, cannot change membership**; show this explicitly as a trust statement), the spaces it's in, a
recent-activity list (its messages/actions, all auditable). *Actions:* add to / remove from a channel,
pause, edit description.
**F3. Add-agent flow.** *Purpose:* sponsor an agent into a channel. *Steps:* pick/define the agent →
choose channel(s) → confirm (a clear statement: "@crm-agent will be added as a member and can read this
channel. Everyone in the channel will see it joined."). *Notes:* this is a trust moment — make the
"agent = visible participant, not a hidden listener" idea unmistakable.

### G. Admin & RBAC

**G1. Member directory.** *Renders:* all `Member` (name, address mono, `Role`, status active/invited/
removed, devices count). Filter by role. *Actions:* invite, change role, offboard.
**G2. Invite / onboard.** *Purpose:* bring in an employee or **partner** (external, scoped). *Steps:*
identity (wallet or invite link) → role (Member/Partner/Guest, with a one-line explanation of each) →
scope (which spaces, esp. for Partner) → review → send. *Renders:* `Invite`, `RoleAssertion`.
**G3. Role management.** *Renders:* the role → capability matrix (Owner/Admin/Member/Partner/Guest/Agent
× capabilities). Read-mostly reference + change-a-member's-role action.
**G4. Offboard (sensitive).** *Purpose:* remove a member/partner/agent. *Layout:* a confirm dialog that
**states the real semantics plainly**: "Removing <name> revokes their access to **future** messages in
<scope> immediately. They keep messages they already received — this cannot be undone, and is not a
remote wipe." Require explicit confirm (and for Owner-removing-Admin, an extra gate via `Keyframe`).
*Renders:* the member, the scope, the effect. This is the single most important "honest UI" moment in the
app — design it with care and zero ambiguity.

### H. Audit (the sealed-ledger zone)

**H1. Audit log.** *Purpose:* the tamper-evident record of *metadata* events (never message content).
*Surface:* the **dark sealed-ledger palette** (`--sealed-*`) — visually a vault, clearly read-only.
*Renders:* ordered `AuditRecord` list. Each row: sequence #, time (mono), event type + summary
(`AuditEvent`: group created, member added/removed, agent added/removed, key published, envelope receipt,
role asserted/revoked), actor, and a truncated hash (mono, `SelectableText`). Filter by type/space/actor.
**Important:** the log shows *that* things happened (who joined, a message was delivered + its size/hash)
— **never the message text.** Make this explicit in a header note.
**H2. Verification + anchor.** *Renders:* chain integrity status (a `SevDot`: "Verified — N records,
intact") and, when present, an `AnchorMark` "Anchored to chain @ block N at <time>". *Actions:* "Verify
now" (re-walks the chain locally), "Export log". *Notes:* this is where the product proves it is
trustworthy — a quiet, confident, permanent-feeling page.

### I. Settings

**I1. Identity.** Display name, avatar, wallet address (`SelectableText` mono), KYC/verification status
(badge). **I2. Devices.** *Renders:* `Device` list (this device + others, each its own cryptographic
member; name, last active, "this device"). *Actions:* add a device (shows a pairing flow), remove a
device (revokes it). Explain simply: "Each device is its own secure member." **I3. Notifications.**
Per-space mute, mention-only, etc. **I4. Connection.** The relay address, status, on-prem/air-gap mode
indicator; a "this workspace is self-hosted at <host>" line. **I5. Appearance.** Theme density
(cinematic/compact), reduced-motion, zone-contrast.

---

## 7. Data models (the "structs" each screen renders)

These are the entities the UI displays. Express them in your designs (fields, enums, relationships).
Types are design-friendly; `mono` fields are cryptographic/machine values shown in Geist Mono and
de-emphasized. (Source of truth: `../crates/comms-proto/src/lib.rs` and `../PLANSET/02` §5.)

### Identity & membership
- **`Member`** — `address` (mono `0x…`, the identity), `display_name`, `avatar`, `role` (Role enum),
  `status` (`active | invited | removed`), `kyc_status` (`none | pending | verified | revoked`),
  `devices_count`, `is_agent` (bool).
- **`Role`** (enum) — `Owner | Admin | Member | Partner | Guest | Agent`. Render with `RoleGlyph`; show a
  one-line capability summary on hover.
- **`RoleAssertion`** — a signed grant: `subject` (member), `role`, `scope` (whole workspace or a
  specific channel), `not_after` (optional expiry), `issuer` (who granted it). Drives invites/offboard.
- **`Device`** — `name`, `last_active`, `is_current` (bool), `mls_key` (mono, hidden by default). Each
  device is a separate member of every space.
- **`Invite`** — `workspace_name`, `inviter`, `role`, `scope`, `expires_at`, `accepted` (bool).
- **`Workspace`** — `name`, `logo`, `member_count`, `relay_host`, `self_hosted` (bool).
- **`Session`** — `connection_state` (`connected | reconnecting | offline`), `relay_host`.

### Conversations
- **`Channel`** (a "Space") — `id` (mono), `name`, `kind` (`channel | forum | dm`), `topic`, `members`
  (list of Member), `tags` (DataChip labels), `unread_count`, `last_activity`, `has_agent` (bool),
  `is_starred`.
- **`Message`** — `id` (mono), `author` (Member), `timestamp` (mono), `body` (text), `kind`
  (`text | system`), `state` (`sending | sent | delivered | failed`), `thread_id` (optional),
  `parent_id` (optional), `linked_records` (list of Deal/Task refs), `from_agent` (bool). **Never**
  expose ciphertext to the UI — the UI always has plaintext for messages it can read.
- **`Thread`** (forum topic) — `id`, `title`, `author`, `reply_count`, `participants`, `last_reply_at`,
  `following` (bool).
- **System/timeline events** to render inline: member joined / left, agent added / removed, role changed,
  "history starts here / you joined on <date>", offboard notice.

### CRM
- **`Contact`** — `name`, `email`, `title`, `account` (Account ref), `owner` (Member), `last_touch`,
  `linked_channel` (optional).
- **`Account`** — `name`, `domain`, `contacts` (count/list), `open_deals` (count), `owner`.
- **`Deal`** (Opportunity) — `name`, `account` (ref), `value` (money), `stage`
  (`Lead | Qualified | Proposal | Won | Lost`), `priority` (low/medium/high → RiskBadge), `owner`,
  `close_date`, `linked_channel`/`linked_thread` (the conversation).

### Project management
- **`Project`** — `name`, `status` (`active | paused | done`), `members`, `task_counts` (by status),
  `boards` (list).
- **`Board`** — `name`, `columns` (list of status lanes).
- **`Task`** — `title`, `description`, `assignee` (Member), `status` (`Todo | Doing | Review | Done`),
  `priority` (RiskDot/RiskBadge), `due_date`, `checklist` (subtasks), `linked_thread`/`linked_deal`.

### Agents
- **`Agent`** — `name` (e.g. `@crm-agent`), `description`/purpose, `status` (`active | paused`),
  `sponsor` (the admin who added it), `channels` (where it's a member), `capabilities` (read+post; **no**
  membership changes), `recent_activity` (list of its messages/actions, all auditable).

### Audit (sealed zone)
- **`AuditRecord`** — `sequence` (int), `timestamp` (mono), `event` (AuditEvent), `actor` (Member),
  `hash` (mono, truncated, `SelectableText`).
- **`AuditEvent`** (enum) — `GroupCreated | MemberAdded | MemberRemoved | AgentAdded | AgentRemoved |
  KeyPackagePublished | EnvelopeReceipt(size, kind) | RoleAsserted | RoleRevoked`. **Metadata only — no
  message content ever appears here.**
- **`AnchorCheckpoint`** — `block_number`, `block_hash` (mono), `time`, `chain_id` (40204). Rendered via
  `AnchorMark`.
- **`IntegrityStatus`** — `verified` (bool), `record_count`, `last_checked`. Rendered via `SevDot`.

---

## 8. Key interaction flows to storyboard

Provide click-through frames (or an annotated flow) for each:

1. **Sign in** → approve signature → land in last workspace (or first-run).
2. **Create a channel** → name + add members + (optional) add an agent → land in the empty channel.
3. **Send a message** → typing → sending → sent → delivered; and the **failed → retry** path.
4. **Onboard a member/partner** → invite (role + scope) → their accept → they appear in the roster + a
   timeline "joined" marker + an audit entry.
5. **Add an agent to a channel** → the trust-confirm → agent appears as a member with the AGENT marker.
6. **Link a deal to a conversation** → from a message composer "link record" → pick `Deal` → the deal
   chip appears in the message and the deal's detail now shows this thread.
7. **Offboard a member** → the honest-semantics confirm (§6-G4) → they're removed → timeline + audit
   entry; the removed member's app shows they can no longer see new messages in that scope.
8. **Verify the audit log** → open Audit → "Verify now" → "Verified, N records intact" (+ anchor if present).

---

## 9. States, empty states, and security micro-copy

Design **all four** states for every data surface: **empty**, **loading** (skeletons), **error**,
**populated**. Specific, security-aware copy is part of the design — draft it. Examples to get the tone:

- **Empty channel:** "This is the beginning of **#deals**. Say hello, or add a teammate." (Cormorant
  accent acceptable here.)
- **Decrypt boundary:** "— You joined on Jun 14. Earlier messages stay private to members who were here. —"
- **Offboard confirm:** "Remove **Priya**? She loses access to new messages in **#deals** right away. She
  keeps what she already saw — this isn't a remote wipe, and it can't be undone."
- **Agent add:** "Add **@crm-agent** to **#deals**? It becomes a member and can read this channel.
  Everyone here will see it joined."
- **Offline:** "You're offline. citrate-comms is self-hosted — messages send when you reconnect."
- **Can't decrypt (rare):** "This message can't be opened on this device." (neutral, not alarming)
- **Audit header:** "A permanent, tamper-evident record of **what happened** — who joined, what was
  delivered. Never the contents of your messages."

**Security affordances** (quiet, consistent): the E2E lock in the composer ("Encrypted to N members"),
the AGENT marker, the connection dot, the sealed-ledger vault styling, and the "Verified" integrity badge.
Never use red/danger except for genuinely destructive or failed actions.

---

## 10. Deliverable — what to hand back (so it translates to Slint cleanly)

Hand back an **HTML/CSS package** (static, buildable in Claude Code) structured for a mechanical 1:1
translation to Slint. Specifically:

1. **`tokens.css`** — every token from §4 as CSS variables with the **exact names**. All other CSS
   references `var(--token)` only; **no raw hex anywhere else.** (This is the single most important rule —
   it's what makes the translation mechanical.)
2. **A component library page** (`components.html`) — one page showing every reusable component you built
   (matching the kit names in §4.4 where possible: `Btn`, `Card`, `RoleGlyph`, `DataChip`, `RiskBadge`,
   `Hairline`, `SurfBadge`, `AnchorMark`, `SevDot`, message row, member row, entity card, etc.), each with
   its variants and states. This is your "kit-gallery" — engineering builds the Slint kit from it.
3. **One HTML file per screen** in §6 (e.g. `auth-signin.html`, `channel-view.html`, `forum-thread.html`,
   `deals-pipeline.html`, `task-detail.html`, `agent-add.html`, `member-offboard.html`, `audit-log.html`,
   …), each showing the **populated** state. Provide **state variants** for the screens that need them
   (empty/loading/error/offline/decrypt-boundary) — either separate files (`channel-view--empty.html`) or
   toggled sections, clearly labeled.
4. **Realistic placeholder data** drawn from §7 (real-looking names, deals, tasks, mono addresses/hashes)
   — not "lorem ipsum". It helps the translation and the review.
5. **Semantic, stable class names** that mirror component structure (`.message-row`, `.member-row`,
   `.deal-card`, `.audit-row`, `.role-glyph`) — these become Slint component boundaries.
6. **A `NEW_COMPONENTS.md`** — any component the existing kit (§4.4) doesn't cover, with a short spec
   (props, variants, states) so engineering adds it to the native kit. Don't bury new widgets inside
   screens; surface them here.
7. **A short `README.md`** — index of screens + components, and any design decisions/assumptions.

**Design within these translation constraints:**
- **No JS-framework UI**, no Tailwind/utility-class soup, no CSS-in-JS — plain HTML + a CSS file per
  component/screen referencing `tokens.css`. (Light vanilla JS for a click-through demo is fine but must
  not carry visual styling.)
- **Avoid web-only patterns that don't exist natively:** no `position: sticky` magic, no scroll-snap
  carousels, no hover-only interactions that hide critical info, no CSS the kit can't express. Layout with
  fl/grid is fine (maps to Slint layouts). When unsure if something maps, prefer the simpler construction.
- **Desktop fixed/resizable windows**, not responsive breakpoints. Design the 1440×900 layout; note how
  panes collapse at the 1100px-wide minimum.
- **Fonts:** Geist / Geist Mono / Space Grotesk / Cormorant (all already in the kit). Use system fallbacks
  in the HTML; engineering swaps in the bundled fonts.
- **Icons:** use simple inline SVG with `currentColor`, single-stroke, 24×24 — they map to the kit's
  `AppIcon`. List the icon names you use in `NEW_COMPONENTS.md` if they're not obvious.

---

## 11. Open questions / where to use your judgement

These are genuinely open — propose your best answer in the design:
1. **Density of the message stream** — bubble-less editorial rows (recommended, fits the brand) vs.
   classic chat bubbles. We lean editorial; show us.
2. **How prominent should "linked records" be** in a message (an inline chip vs. a richer card)? This is a
   signature feature — make it feel first-class but not heavy.
3. **The agent presence treatment** — how to make "an agent is here" obvious-but-calm without it feeling
   like surveillance. This is the hardest and most important visual problem; give it real thought.
4. **CRM/PM information density** — table-heavy vs. card-heavy. Teams of 3–50, not enterprise sales orgs;
   keep it light.
5. **The sealed-ledger (Audit) zone** — how far to push the "vault / permanent record" feeling without it
   feeling like a different app. Show the transition from paper (warm) to sealed (dark).
6. **Onboarding empty states** — a brand-new workspace is empty everywhere; design a warm first-run that
   guides setup (create a channel, invite a teammate, add your first agent).

When something here is ambiguous and you can't resolve it from the brand or the flows, make a clear,
reasonable choice and note it in the README — don't block.

---

### Appendix — quick reference for the engineer translating to Slint
- `tokens.css` `var(--x)` → `Theme.x` (global). · `.btn.primary` → `Btn { kind: "primary" }`. ·
  `.card` → `Card`. · `.role-glyph` → `RoleGlyph`. · `.data-chip` → `DataChip`. · mono+selectable →
  `SelectableText` (Geist Mono). · the dark audit surface → `--sealed-*` tokens, `Btn kind:"ghost-dark"`.
- Native kit source (for the engineer, not the designer): `citrate-studio/ui-kit/ui/{theme,typography,
  primitives,icons}.slint`; consumed as `@citrate-ui-kit`. citrate-native is a working precedent of a
  Slint app on this kit.
