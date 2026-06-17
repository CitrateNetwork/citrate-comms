# Live-debug checklist — citrate-comms UI

Run the instrumented build and capture the trace:

```bash
CITRATE_COMMS_DEBUG=1 ./citrate-comms 2>ui-debug.log
# (or watch the terminal directly)
```

Then click **everything** below, in order. For each item note: did it respond? did it look
right? Send me `ui-debug.log` + your notes. A control that produces **no `[ui]` line and no
visible effect is dead** (a confirmed bug). I'll render each screen to a golden to see what
you saw, and turn this into the COMMS-S6 fix list.

> Known from the audit (don't need to re-confirm, but note severity): CRM / Projects /
> Agents / Security / Settings have **no working controls**; the spaces rail doesn't switch
> channel; all non-message data is mock. The session is to catch the **runtime/visual**
> issues on top of these.

## Shell
- [ ] Sign in → does the header pill go `connecting… → live`? (expect `[ui] connect fired`, `[ui] signed-in -> true`)
- [ ] Title-bar avatar (top-right) → does a me-menu open? (`[ui] me-menu open`)
- [ ] Search bar / ⌘K → does the command palette open? type → does it navigate? (`[ui] command-palette open`)
- [ ] Esc → closes palette/overlays?

## Left rail — SPACES (the channels)
- [ ] Click each: `# deals`, `≡ announcements`, `# eng`, `# design`, `# security`
- [ ] Does the **content actually change** to that channel? (Expected bug: it does NOT — all land on the same comms/forum view. Trace: `[ui] space-click … does NOT switch channel`)
- [ ] Unread badges / agent dots — real or mock?

## Left rail — sections
- [ ] CRM / Projects / Agents / Members / Security / Audit / Settings — each routes? (`[ui] route -> …`)
- [ ] Does each screen show **real** data or fixtures?

## Comms screen
- [ ] Composer: type + Enter → does it send? does your message appear? (`[ui] send-message`)
- [ ] `+ New` button (top of channel list) → anything? (expect dead)
- [ ] Member panel (right) → real members or mock? Add member / Add an agent buttons → do they open dialogs?
- [ ] Ledger / Info tabs (right panel) → switch? real data?
- [ ] Message rows — selectable text? links (DEAL-…) clickable?

## Settings  (expected: tabs dead, data mock)
- [ ] Sub-nav: Identity / Devices / Connection / Appearance / Automation — click each → does the pane change? (expect NO)
- [ ] Is the wallet address **your real** address or a mock?
- [ ] Devices list — real (your machine) or 3 fake devices?
- [ ] Toggles (theme/density/automation) → any effect?

## Members  (expected: rows mock, invite/offboard → overlays)
- [ ] Filter chips (All/Owner/Admin/…) → filter the list? (expect NO)
- [ ] `+ Invite` → opens invite dialog? type address + Send → creates a channel? (`[ui] overlay -> invite`, `[ui] create-channel`)
- [ ] `Offboard` (a row) → opens dialog? (`[ui] overlay -> offboard`)
- [ ] Are the members **real** (you + your peer) or the 9 fixtures?

## CRM / Projects / Agents / Security / Audit / Forum  (expected: all mock, mostly dead)
- [ ] CRM: click a deal card / contact row / Filter / + New deal → anything?
- [ ] Projects: click a task / + New task → anything?
- [ ] Agents: the 2 agents — real or mock? any control?
- [ ] Audit: Verify now / Export → work? records real or mock?
- [ ] Security: any interaction? data real?
- [ ] Forum: click a thread / + New topic → anything?

## Anything else
- [ ] Resize the window — does anything break/overlap at small sizes?
- [ ] Any visual glitch, flicker, wrong color, cut-off text, crash, freeze — note it with the screen + what you did.
