# Halcyon S9.4 — Tabbed UI (design)

**Status:** draft for review · **Date:** 2026-07-29 · **Author:** KK + Claude
**Extends:** `2026-07-29-halcyon-s9-hosted-lab-two-mode-design.md` §7. S9.1–S9.3 + S9.5
backends are merged; this slice is the **frontend only**. No endpoint, guard,
validator, or audit-log change.

---

## 1. Scope

Rebuild `halcyon/templates/chat.html` into a **tabbed, layer-keyed lab UI** that:

1. Brings M6 (MCP), M7 (dispute), M8 (guarded chat) in from curl-only into browser panels.
2. Adds the S9.2 **per-session L1/L2 guardrail sidebar** (`/api/level`).
3. Adds the S9.3 **five-provider model-config modal** (`/api/config`), replacing the
   stale 2-provider (local/remote) control the current template still carries.
4. Adds a header link to the S9.5 **captured-attacks board** (`/board`).
5. Supports the multi-turn crescendo pedagogy with a per-surface **New conversation** reset.

Everything binds to **already-existing routes** in `halcyon/web.py`. Nothing server-side
changes in this slice.

### What is explicitly preserved
Append-only audit log · the eight validators · the eight guards · the MCP servers · the
LangGraph dispute pipeline · mechanism-based grading · CSP nonce discipline · the single
deliberate M2 XSS sink. This slice touches one template.

## 2. Confirmed decisions (from brainstorm 2026-07-29)

- **Aesthetic:** clean/minimal **light** — system-ui, neutral surfaces, one blue accent.
  Chosen over a dark SOC theme for payload legibility; keeps CSS small.
- **Guardrail sidebar scope:** **per-tab (contextual)** — the sidebar shows only the
  active layer's module toggles, not all modules at once.
- **M6 toggle:** **shown but disabled**, with a note that the MCP guardrail level is
  process-wide this release (per-session MCP flip is deferred to the per-participant MCP
  isolation work — S9 spec §12). No false affordance; no scope creep into backend.
- **Extras (all in):** header **Attack board** link · per-chat-surface **New
  conversation** button · L3 **MCP Inspector** hint.
- **File structure:** remains a **single self-contained Jinja template** (HTML + inline
  `<style>` + one nonce'd `<script>`). The page is server-rendered per request (CSP
  nonce, M2 sink, initial-state injection), so a static-file split would add a
  `StaticFiles` mount for no reliability gain. Extract later only if it becomes unwieldy.

## 3. Layout

```
┌ Halcyon — Halo Lab                 [Attack board]  [⚙ Model: local · llama3.1:8b] ┐
├───────────────────────────────────────────────────────────────────────────────────┤
│  L0 Chatbot │ L1 RAG │ L2 Agent │ L3 MCP │ L4 Multi-agent │ L5 Production           │
├────────────────┬────────────────────────────────────────────────────────────────────┤
│ GUARDRAILS     │   <active layer's panel(s)>                                         │
│  M1  [○L1 ●L2] │                                                                     │
│  M2  [○L1 ●L2] │                                                                     │
└────────────────┴────────────────────────────────────────────────────────────────────┘
```

- **Header:** title · `Attack board` link → `/board` (opens in a new tab; instructor
  projects it) · model button showing `provider · model`, opens the config modal.
- **Tab bar:** 6 layer tabs. Tab switch is pure client-side: hides/shows the panel
  `<section>`s and rebuilds the sidebar from a static per-tab module map. No reload.
- **Sidebar:** the active tab's modules only. Each row = a two-state L1/L2 control →
  `POST /api/level {session_id, module, level}`. Seeded once from `GET /api/level` on
  load; a module absent from the map defaults to its `HALCYON_MODE` level (rendered L1
  unless the map says otherwise). M6 row disabled with tooltip.
- **Session id:** unchanged — `?session=` query param, default `"dev"`.

### Layer → module → endpoint map

| Tab | Layer         | Module(s)                | Endpoints (existing)                         |
|-----|---------------|--------------------------|----------------------------------------------|
| L0  | Chatbot       | M1 injection, M2 XSS     | `/api/chat`, `/api/profile`, `/reset/m1`     |
| L1  | RAG           | M3                       | `/api/kb`, `/api/ask`                        |
| L2  | Agent         | M4 supply-chain, M5 tools| `/submit/m4`, `/api/agent`, `/reset/m5`      |
| L3  | MCP           | M6                       | `/api/mcp-agent`                             |
| L4  | Multi-agent   | M7 dispute               | `/api/dispute`                               |
| L5  | Production    | M8 guardrails            | `/api/guarded-chat`                          |

Guardrail toggles are offered for modules with a runtime guard in `MODULE_FLAGS`
(M1, M2, M3, M5, M6*, M7, M8). **M4 has no runtime guard** → no toggle on its panel.
(*M6 shown-disabled.)

## 4. Panels

Each panel is a `<section data-layer="Lx">` in the main column; exactly one visible.

- **L0 — Chatbot.** Multi-turn message log (append `you:`/`halo:` lines) over `/api/chat`.
  `New conversation` → `POST /reset/m1` then clears the log client-side. Below it, the
  **display-name setter** (`/api/profile`): the returned greeting is rendered through the
  Jinja `display_name_html | safe` sink — the deliberate M2 XSS, gated by
  `SEC_OUTPUT_ENCODING` (server already encodes when the flag/level is on). This greeting
  is the ONE `|safe` path in the template.
- **L1 — RAG.** KB note submit (`/api/kb`) + a `New conversation`-free ask box
  (`/api/ask`) rendering the answer via `textContent`.
- **L2 — Agent.** M4 block: artifact-hash + vulnerable-package submits (`/submit/m4`),
  status via `textContent`. M5 block: `Reset accounts` (`/reset/m5`) + agent ask
  (`/api/agent`), rendering `reply` plus each `tool_calls[]` entry as text.
- **L3 — MCP.** MCP agent ask (`/api/mcp-agent`), same reply+tool-calls rendering as M5.
  A collapsible **MCP Inspector** hint: `npx @modelcontextprotocol/inspector` pointed at
  the exposed MCP ports. M6 sidebar toggle disabled.
- **L4 — Multi-agent.** Dispute form: `dispute_text` + `account` + `amount` → `/api/dispute`.
  Renders `decision` and the signed `transcript[]` (`from` / `content`) as text lines.
- **L5 — Production.** Guarded chat (`/api/guarded-chat`); single-turn reply via `textContent`.

## 5. Model-config modal (S9.3)

- Opened from the header button; overlays the page. Provider `<select>`:
  Local / Anthropic / OpenAI / Gemini / xAI. Editable `model` text field seeded with the
  provider's current default (from §6 of the parent spec) and re-seeded on provider change.
  Password `api_key` field.
- Save → `POST /api/config {session_id, provider, model, api_key}`. On success, update the
  header label from the response `{provider, model}`. **The key is never read back**;
  `GET /api/config` (used to seed the label on load) returns provider+model only.
- Per-request overrides on individual calls are dropped from the UI — the modal is the one
  place model config lives now (the endpoints still accept per-request `provider/model/api_key`,
  but the UI relies on the saved session config via `_mcfg`).

## 6. Safe rendering discipline

- All model/user output written with `textContent`. No `innerHTML` anywhere except the
  server-rendered M2 greeting sink.
- The nonce'd `<script>` stays inline; CSP `script-src 'self' 'nonce-…'` is emitted by the
  existing middleware when `SEC_OUTPUT_ENCODING` is on. No external scripts, no inline
  event handlers beyond the nonce'd block wiring.

## 7. Initial-state bootstrap (on load)

1. Read `session` from the query string.
2. `GET /api/level?session=` → seed sidebar toggle states.
3. `GET /api/config?session=` → seed the header model label (blank ⇒ show `local · <default>`).
4. Render L0 as the default active tab.

## 8. Testing

- Backend deterministic suite is untouched (no server change) — must stay green.
- Extend the existing template-render test: assert `/chat` renders all six `data-layer`
  markers and the key form element IDs for each panel (chat input, kb, ask, m4 hash/pkg,
  m5, mcp, dispute, guarded). This guards against a panel silently dropping out.
- Manual verification against the running stack on `:8010`: tab switching, a live L0
  multi-turn exchange, a level flip taking effect on the next turn, the model modal
  round-trip (label updates, key not echoed), and the M2 sink firing at L1 / being encoded
  at L2.

## 9. Build sequence

1. Scaffold the shell: header, tab bar, sidebar frame, empty panel sections, tab-switch JS.
2. Model-config modal + header label + `/api/config` wiring + on-load bootstrap.
3. Guardrail sidebar: per-tab module map, `/api/level` wiring, M6 disabled, on-load seed.
4. Port existing panels (L0 chat + M2 sink, L1 RAG, L2 M4+M5) into the new shell.
5. New panels: L3 MCP (+Inspector hint), L4 dispute, L5 guarded chat.
6. New-conversation buttons + Attack-board header link.
7. Extend template-render test; manual sweep on `:8010`.

## 10. Risks / notes

- **M6 level is process-wide** this release — surfaced honestly in the UI, not silently
  broken. Lands properly with per-participant MCP isolation (parent spec §12).
- **Large single template** (~700 lines). Accepted for deploy reliability; the tab-switch
  and per-panel wiring are independent blocks, so it stays legible. Revisit a static split
  only if it impedes edits.
- **No UI test framework** in the repo — coverage is a render-smoke assertion plus a manual
  sweep, consistent with how the current template is verified.
