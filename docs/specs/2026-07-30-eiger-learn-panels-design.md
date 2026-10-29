# Eiger "Learn" Panels (design)

**Status:** draft for review · **Date:** 2026-07-30 · **Author:** KK + Claude
**Scope:** Sub-project B of the app work. Turns Eiger from a pure attack target into a
**training tool** by adding a per-layer "How this works" teaching panel that shows the real
vulnerable code and the real guard code, annotated, with a tight conceptual primer — without
handing over the exploit.

---

## 1. Why

Participants currently attack each layer but the app never explains *how the layer is built*
or *why the vanilla version is vulnerable*. Adding an in-app, per-layer explainer — grounded
in the **actual source** they're attacking — deepens understanding and makes the
Build→**understand**→Break→Secure loop self-contained. The guard code is the "Secure" half of
the lesson; showing it (with the `SEC_*` diff) is the point. The one thing withheld is the
**exploit payload** — that stays the participant's to discover.

## 2. Goals / non-goals

**Goals**
- A collapsible **"📖 How this works"** section at the top of each layer panel (L0–L5).
- Each holds: a **tight primer** (how the layer works + why vanilla is vulnerable) and
  **curated excerpts of the real source** — the vulnerable branch and the guard branch — with
  line-by-line annotations.
- A **drift guard**: a test asserts every shown code excerpt is a literal substring of its
  real source file, so "real source" stays honest as the code evolves.

**Non-goals**
- No exploit payloads / working attack strings in the Learn content.
- No external syntax-highlighter or assets (CSP: self-contained inline only).
- No change to attack panels, endpoints, guards, validators, or grading.
- Not a rebuild of the tabbed UI — the Learn section slots into each existing panel.

## 3. Content model

A new `halcyon/learn_content.py` holds a plain-data structure, one entry per layer:

```python
LEARN: dict[str, LayerLearn]
# LayerLearn = {
#   "title": str,                       # e.g. "L1 · RAG — retrieval-augmented generation"
#   "primer": str,                      # a few short paragraphs; plain text, rendered as <p>s
#   "snippets": list[Snippet],
# }
# Snippet = {
#   "title": str,                       # e.g. "Vulnerable: every retrieved chunk is authoritative"
#   "kind": "vulnerable" | "guard",     # drives the colored label
#   "source": str,                      # repo-relative path, e.g. "halcyon/guards.py"
#   "code": str,                        # a LITERAL excerpt copied from that file
#   "notes": list[str],                 # annotation bullets explaining the excerpt
# }
```

The `code` is copied verbatim from the source (curated excerpt, not the whole file). The
drift test (below) guarantees it stays a literal substring of `source`.

### Per-layer content (what each Learn section covers)

| Layer | Primer topic | Vulnerable excerpt(s) | Guard excerpt(s) (`SEC_*`) |
|---|---|---|---|
| **L0** Chatbot (M1+M2) | system prompt + user turn → model; secrets-in-prompt & unescaped output | `guards.assemble` single-turn concat; `guards.encode_output` passthrough | `guards.assemble` secure role-separation (`SEC_SYSTEM_PROMPT_HARDENING`); `input_filter_blocks` (`SEC_INPUT_FILTER`); `encode_output` `html.escape` + CSP middleware (`SEC_OUTPUT_ENCODING`) |
| **L1** RAG (M3) | split → embed → vector store → retrieve top-k → stuff into prompt | `guards.assemble_rag` vulnerable (concatenate all chunks as authoritative) | `guards.assemble_rag` secure trusted/untrusted split + injection quarantine; `rag.answer` restricted-doc owner filter (`SEC_RAG_PROVENANCE`) |
| **L2** Agent (M4+M5) | agents call tools; untrusted artifacts/deps | `guards.authorize_tool_call` passthrough; `scan_artifact.scan` on a poisoned pickle | `authorize_tool_call` ownership check (`SEC_TOOL_SCOPE_ENFORCEMENT`); safetensors/hash verification (`SEC_ARTIFACT_VERIFICATION`) |
| **L3** MCP (M6) | tools come from external servers; a tool *description* is untrusted metadata | `mcp_host.schemas_for_llm` serving a poisoned description | `schemas_for_llm` pin/quarantine (`SEC_MCP_DESC_PINNING`); `authorize_token_access` (`SEC_MCP_TOKEN_SCOPING`) |
| **L4** Multi-agent (M7) | pipeline of agents; inter-agent messages implicitly trusted | `guards.assemble_agent_prompt` inlining untrusted dispute text | `assemble_agent_prompt` quarantine + `verify_chain` signed provenance (`SEC_INTER_AGENT_AUTH`) |
| **L5** Production (M8) | a guardrail/prompt-firewall fronts the model; naive blocklists miss obfuscation | `guards.guardrail_check` raw-only match | `guardrail_check` + `canonicalize` hardened match (`SEC_GUARDRAILS`) |

Content is authored from the real code + the trainer guide's mechanism write-ups.

## 4. Rendering

- The `/chat` handler passes `LEARN` into the template (one extra render kwarg).
- Each `<section data-layer="Lx">` gains, **at the top**, a native disclosure:

  ```html
  <details class="learn">
    <summary>📖 How this works — why L1 is vulnerable</summary>
    <div class="learn-body">
      <p>…primer paragraph…</p>
      <div class="snippet vulnerable">
        <div class="snip-head"><span class="tag">vulnerable</span> Title · <code>halcyon/guards.py</code></div>
        <pre><code>…escaped excerpt…</code></pre>
        <ul class="notes"><li>…annotation…</li></ul>
      </div>
      <div class="snippet guard"> … </div>
    </div>
  </details>
  ```

- **Native `<details>`** → no JS for expand/collapse; starts collapsed. The code is
  **server-rendered and HTML-escaped** (Jinja autoescape; it's our own source, escaped for
  safety and correct rendering). Minimal CSS: monospace block, muted annotations, a colored
  tag (vulnerable = warm, guard = accent). **No external highlighter.**
- This adds **no** new `|safe`/raw path — the M2 sink stays the only one. All existing element
  IDs, `data-tab`/`data-layer` markers, the nonce'd script, and attack panels are untouched.

## 5. No-spoiler rule

The Learn content includes: the primer, the real vulnerable code, why it's exploitable, the
real guard code, and how the guard defends. It **excludes** any working exploit payload — no
poison-note text, no verbatim-dump prompt, no XSS string, no canonical M7 dispute. The primer
describes the *shape* of the attack ("an injected instruction rides in with the retrieved
text"), never the literal payload. Enforced by author discipline + review + a test that the
known attack markers/payloads (e.g. the M3 poison note, the M2 `onerror` payload) do not
appear in `learn_content.py`. (The objective *marker* like `RAG-OWNED-7788` is already shown
in the attack panel as the goal — that is fine; the *payload* that produces it is not.)

## 6. Testing

- **Drift guard** (`tests/test_learn_content.py`): for every snippet, `snippet["code"]` is a
  substring of `read(snippet["source"])`. Fails loudly if a guard is refactored, prompting a
  content update — this is what keeps "real source" true.
- **Structure test:** every layer `L0`–`L5` present; each has a non-empty primer and ≥1
  `vulnerable` + ≥1 `guard` snippet; every `source` path exists.
- **No-spoiler test:** a small denylist of known exploit strings is absent from the rendered
  Learn content.
- **Render-smoke** (`tests/test_web.py`): `/chat` renders a `<details class="learn">` for each
  layer with its primer text and a `<pre>` code block; existing render-contract tests stay
  green.

## 7. Build sequence (for the plan)

1. **Scaffold + one layer (L1 RAG):** `learn_content.py` with the `LEARN` structure + L1
   content; the template rendering (collapsible + snippet styling); the drift/structure/render
   tests. Proves the pattern end-to-end.
2. **L0 Chatbot** content (M1 + M2).
3. **L2 Agent** content (M4 + M5).
4. **L3 MCP** content (M6).
5. **L4 Multi-agent** content (M7).
6. **L5 Production** content (M8).
7. Manual visual pass on `:8010` (each panel's disclosure expands, code + notes read well).

Each content task appends one layer's entry and extends the drift/structure tests; the
scaffold task carries the rendering + tests.

## 8. Risks

- **Content drift** → the drift test is the mitigation; keep excerpts small and stable.
- **Accidental spoiler** → the no-spoiler denylist test + review.
- **Template growth** → the Learn markup is a compact loop over `LEARN[layer]`; content lives
  in `learn_content.py`, not the template, so the template stays a thin renderer.
- **Authoring accuracy** → excerpts are real source (drift-tested); annotations are reviewed
  against the code in each content task's review.
