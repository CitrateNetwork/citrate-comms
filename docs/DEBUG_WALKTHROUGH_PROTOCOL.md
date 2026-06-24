# Live debug + walkthrough protocol (Saul ↔ Claude)

How we build, test, and fix the rich-render + attachments work (and anything else)
together — one small item at a time, on a preview URL, with a tight feedback loop.

---

## The loop (per item)
1. **Claude ships ONE item** on its own branch and deploys a **Vercel preview** (not prod).
2. Claude posts: **"▶ Ready to test: `<item id>` — preview: `<url>` — steps below."**
3. **Saul tests on the preview URL** and reports each item using the report shape below.
4. Claude **fixes → redeploys the same preview → re-pings.** Repeat until ✅.
5. On ✅, Claude **merges → promotes to prod** (`vercel --prod`), and we move to the next item.

> Preview-first means we never debug on prod, and you always test the exact build before it
> ships. Claude runs typecheck + 60+ tests + lint + semgrep + gitleaks + build on every item
> before asking you to look.

## Report shape (paste this back per item)
```
Item: <id, e.g. RR-0.tables>
Did: <what you clicked/typed — be specific>
Expected: <what you thought would happen>
Got: <what actually happened>
Console/Network: <any red console error, or failing request + status>
Verdict: ✅ works | ❌ broken | ⚠️ works-but (note)
```
Screenshots/pastes welcome. If it's visual, a screenshot beats words.

## Status legend
🔲 not built · 🟡 on preview, awaiting your test · ✅ verified by Saul · ❌ failing · ⏸ deferred

## Where to capture what went wrong
- **Browser DevTools → Console** (red errors) and **Network** (failing request + status code).
- **In-app → Audit** screen (did the action get logged? what event?).
- **Vercel** dashboard → the deployment → **Runtime Logs** (server errors), or `vercel logs <url>`.
- For agent behavior: the chat **tool-trace** + the **Approvals** inbox (for HITL writes).

## What Claude needs from you to start
- Confirm a **Vercel Blob store** is linked to `citrate-comms-web` (needed for images/video/large
  uploads). If not, say so and we'll do RR-0..RR-2 (rendering, no Blob needed) first while you link it.
- Which item to start with (default: **RR-0**, markdown + tables — fastest visible win).

---

## Living checklist (updated each round)

### Stream A — rich rendering
| ID | Feature | How to test | Expected | Status |
|----|---------|-------------|----------|--------|
| RR-0.md | Markdown | ask an agent for a bulleted summary | bold/lists/headings render (not raw `*`) | 🔲 |
| RR-0.tables | GFM tables | "show my deals as a markdown table" | a real rendered table | 🔲 |
| RR-0.code | Code blocks | "show a JSON example" | mono block + copy button | 🔲 |
| RR-0.stream | Streaming | watch a long answer stream | renders progressively, no flicker/crash | 🔲 |
| RR-1.mermaid | Mermaid | "draw the deal pipeline as a mermaid flowchart" | a diagram (not code) | 🔲 |
| RR-1.badmermaid | Mermaid error | force a broken diagram | falls back to showing the code, no crash | 🔲 |
| RR-2.chart | Vega-Lite | "chart deal value by stage" | a rendered bar/line chart | 🔲 |
| RR-3.prompt | Agent uses it | normal asks | agent chooses tables/diagrams/charts appropriately | 🔲 |

### Stream B — attachments
| ID | Feature | How to test | Expected | Status |
|----|---------|-------------|----------|--------|
| ATT-0.xlsx | xlsx RAG | upload an .xlsx to a deal, then ask about it | agent answers from the sheet (documents.read) | 🔲 |
| ATT-0.docx | docx RAG | upload a .docx, ask about it | agent answers from the doc | 🔲 |
| ATT-1.big | Large/media upload | upload a 50 MB mp4 | uploads via Blob (no 413) | 🔲 |
| ATT-1.types | Type allow-list | try an .exe | rejected with a clear message | 🔲 |
| ATT-2.img | Image display | upload a png/svg/jpg/webp | renders inline in Documents | 🔲 |
| ATT-2.video | Video player | open an uploaded mp4 | plays in a `<video>` element | 🔲 |
| ATT-3.channel | Channel attach | attach a file in a channel message | shows in the thread | 🔲 |
| ATT-3.chat | Chat attach | attach a file in agent chat | agent can read/cite it | 🔲 |
| ATT-4.audit | Audit | any upload | a `document_ingested` audit row | 🔲 |

(We tick these to ✅ as you verify them on each preview.)
