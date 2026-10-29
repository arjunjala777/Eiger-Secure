# Eiger Product Refresh (design)

**Status:** draft for review · **Date:** 2026-07-30 · **Author:** KK + Claude
**Scope:** Sub-project A of a two-part effort. A = this (rebrand + welcome + dark
visual refresh). B = per-tab "Learn" teaching panels (separate spec, built after A).
The instructor dashboard idea is **dropped** — a colleague's Trainer Console owns that.

---

## 1. Why

The lab works but looks like a bare test harness. Eiger is a fictional **AI-first
neobank**, so the participant app should feel like a real product: branded, colorful,
with a welcome screen. This makes demos land better and frames the two-mode pedagogy in
a believable product. Purely a presentation layer over the merged S9.4 UI + M6 toggle —
no change to endpoints, guards, validators, audit log, or grading.

## 2. Goals / non-goals

**Goals**
- Rebrand the **user-facing** app to **Eiger**, assistant **Iggy** (was Halcyon / Halo).
- A branded **welcome screen** that also captures an optional display name.
- A **dark alpine-premium** visual system applied across the whole app.
- Keep every element ID, the M2 XSS sink, the CSP nonce, and the two-mode behavior intact.

**Non-goals**
- No rename of internal identifiers: the `halcyon` Python package, `HALCYON_MODE`, the
  honeytoken (`HALCYON-OPS-…`), audit event types, validator logic. Grading is untouched.
- No structural change to the tabbed app (6 tabs, sidebar, model modal, panels stay).
- No new endpoints. No teaching panels (that is Sub-project B).
- No instructor dashboard.

## 3. Rebrand map (user-facing strings only)

| Was | Now | Where |
|---|---|---|
| "Halo" (assistant name) | **Iggy** | `templates/chat.html` copy + chat labels; `guards.py` system-prompt persona (`"You are Halo…"` → `"You are Iggy…"`, 3 occurrences) |
| "Halcyon" (bank/app name, user-facing) | **Eiger** | `templates/chat.html` title/wordmark; `templates/reach.html` title/heading; `guards.py` prompt bank name |
| — | ⛰ summit wordmark | inline SVG in both templates |

**Explicitly NOT renamed** (internal — would break grading/config): the `halcyon`
package and imports, `HALCYON_MODE`, `SEC_*` flags, the honeytoken string, `audit.*`
event constants, validator/canary logic, and the M4 lab copy that references the real
module path `halcyon.scan_artifact`.

**Verification the rebrand is safe:** the full suite must stay green. During the plan,
grep `tests/` for assertions on the literal strings "Halo"/"Halcyon" in prompts or
replies and update any that assert the persona/bank name (not the honeytoken). The
honeytoken and override-marker mechanics are not touched.

## 4. Visual system (dark alpine-premium)

A small CSS-variable palette defined once at the top of each template's `<style>`, no
external assets (CSP: `img-src 'self' data:`, single nonce'd `<script>`):

- `--bg` deep navy/near-black · `--surface`/`--surface-2` raised cards · `--line` hairline
  borders · `--text`/`--muted` · `--accent` glacier cyan-blue · `--accent-ink` (on-accent).
- Per-layer hue chips for the six tabs (L0…L5), used on the tab icon + active state.
- Graphical elements, all inline SVG: a summit/mountain wordmark; a small set of per-layer
  glyphs; the welcome hero illustration; an Iggy avatar mark. CSS gradients for the hero.

Applied across: the header/wordmark, tab bar, guardrail sidebar (colored L1/L2 badges),
chat surface (Iggy avatar + name, message bubbles), card-style panels, the model-config
modal, and `reach.html`.

## 5. Welcome screen

A branded overlay shown on entering `/chat`:

- Full-bleed hero: glacier gradient + summit SVG, "**Meet Iggy** — your Eiger banking
  assistant," and a one-line frame: "a deliberately vulnerable teaching lab."
- Optional **display-name** field → `POST /api/profile {session_id, display_name}` (the
  existing endpoint; this is the name the greeting renders — and the M2 surface). Empty is
  allowed (greeting falls back to current behavior).
- **Enter the lab** button dismisses the overlay to the tabbed app.
- Dismissal remembered in `localStorage` (keyed by session) so a reload doesn't renag;
  clicking the wordmark reopens it. `?session=` query param unchanged.
- Rendered inside `chat.html` (no new route/template); pure client-side show/hide, wired
  from the existing nonce'd `<script>`.

## 6. What is preserved (load-bearing)

- The **only** raw-HTML/`|safe` path stays the M2 greeting sink `{{ display_name_html | safe }}`
  in `<span id="dn">`; everything else renders via `textContent`.
- `<div id="cfg" data-encoding="{{ output_encoding }}" data-mode="{{ mode }}">`, the single
  `<script nonce="{{ nonce }}">`, and **every element ID** the S9.4 render-contract test
  pins (`msg`, `chat-newconv`, `setname`, `kbsubmit`, `askbtn`, `m4hash`/`m4pkg`, `m5send`,
  `mcpsend`, `dsend`/`dtext`, `gsend`, `sidebar`, `model-modal`, `cfg-provider`, the six
  `data-tab`/`data-layer` markers, `href="/board"`, the inspector hint).
- The per-tab guardrail sidebar (incl. the now-enabled M6 toggle), the model modal, and
  all panel→endpoint wiring behave exactly as today.

## 7. Testing

- All existing template/render-contract tests stay green (IDs + markers preserved) —
  this is the guardrail against the reskin dropping a control.
- Add a smoke test: `/chat` renders the Eiger wordmark + "Iggy" and the welcome hero
  (`id="welcome"`), and does **not** contain the user-facing strings "Halo"/"Halcyon";
  `reach.html` renders "Eiger".
- A `guards.py` test-safety check: the system prompts say "Iggy"/"Eiger" and still carry
  the honeytoken; existing prompt/canary tests updated if they assert the old names.
- Manual visual pass on `:8010`: welcome → enter → tabs, dark theme, Iggy chat identity,
  a live turn (Iggy replies), the M2 sink still fires (raw at L1, escaped at L2).

## 8. Build sequence (for the plan)

1. Palette + wordmark/SVGs + dark theme skeleton in `chat.html` (IDs unchanged); update
   the render/smoke tests to expect Eiger/Iggy + welcome, keep the S9.4 contract green.
2. Rebrand copy in `chat.html` + `guards.py` system prompts (Halo→Iggy, Halcyon→Eiger),
   honeytoken untouched; fix any test asserting the old strings.
3. Welcome overlay (hero + display-name + Enter + localStorage).
4. Reskin `reach.html` to Eiger branding.
5. Manual visual pass; full suite + ruff + mypy.

## 9. Risks

- **Rebrand catching an internal string** → mitigated by the explicit not-renamed list and
  a test asserting "Halo"/"Halcyon" are absent from user-facing template output while the
  honeytoken remains.
- **Reskin dropping a pinned ID** → the S9.4 render-contract test catches it.
- **Single large template** grows further; accepted (same rationale as S9.4). If it becomes
  unwieldy, a static-asset split is a later option, but CSP-nonce + the server-rendered M2
  sink keep it a single template for now.
