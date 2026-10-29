# Halcyon S9 — Hosted Two-Mode Lab Upgrade (design)

**Status:** draft for review · **Date:** 2026-07-29 · **Author:** KK + Claude
**Supersedes/extends:** the S1–S8 module builds (M1–M8 code-complete). This is an
*additive* slice — no teaching module is rebuilt; the audit log, validators, guards,
MCP servers, and LangGraph pipeline are all preserved.

---

## 1. Why this slice

M1–M8 are code-complete and the four hard rules hold. But live validation against
real frontier models (`docs`/memory: `byok-frontier-validation`) exposed that the lab,
as built, is **CTF-thin and single-mode**:

- **Every endpoint is stateless.** `halo.handle_turn` and `agent.run` build a fresh
  message list per request — no conversation history. So the *multi-turn crescendo*
  that is the only realistic way to crack a frontier model is impossible today.
- **The vulnerable/secure flip is process-global and needs a restart.** Participants
  can't self-serve the Break→Secure loop, and there's no per-person level.
- **Only one weak model.** Frontier models *refuse* the canonical M1/M5/M7 payloads
  (validated). The pedagogy that actually works is a **two-mode arc**: start on an
  easily-jailbroken local model (easy wins), then switch to a frontier model and watch
  the bar rise — direct attacks fail, and only *indirection* (M6 tool-poisoning),
  *social engineering* (M5 with a cover story), and *multi-turn crescendo* (M1) get
  through. That teaches the real lesson: **foundation-model alignment is itself a
  security layer.**
- **M6/M7/M8 are API-only** and there is no way to show the class what worked.

This slice makes the lab a **hosted, session-isolated, two-mode** experience with the
UX proven in KK's YouTube "Vulnerable AI Lab" (tabbed layers · per-module guardrail
toggles · in-UI multi-provider model config).

## 2. Goals / non-goals

**Goals**
- Per-session **multi-turn conversation memory** (the non-negotiable; unlocks frontier M1).
- **Self-serve, per-session, per-module L1/L2 guardrail flip** (no restart).
- **Multi-provider BYOK** (Anthropic · OpenAI · Gemini · xAI Grok · Local) via **LiteLLM**,
  with an editable model field (model IDs churn monthly — see §6).
- **Tabbed browser UI** that brings M6/M7/M8 in from the CLI.
- A hosted-only **"captured attacks" board** the instructor projects to the class.
- Deploy **hosted-primary on a GPU box**; keep local/own-cloud as an optional fallback.

**Non-goals**
- No third guardrail level. **Two levels only** — L1 (no guardrails) / L2 (full guardrails).
  The model axis supplies the rest of the difficulty gradient.
- No rebuild of the eight modules' attack/guard logic. No change to audit-log grading.
- Not moving off the deterministic test model (Stub stays for the suite).

## 3. The two orthogonal axes (the conceptual core)

The whole design exposes **two independent controls**, which together form the attack
matrix that *is* the pedagogy:

```
                 L1 (no guardrail)     L2 (full guardrail)
  Local (llama)  trivial               teaches the guard
  Grok / Gemini  easy → obfuscation    needs finesse
  GPT / Claude   multi-turn crescendo  "now we're really playing"
```

- **Model axis** (§6): Local weak model → frontier BYOK. Difficulty gradient + the
  "compare alignment postures across vendors" demo.
- **Guardrail axis** (§5): L1 vulnerable → L2 secure, per module, live.

Both are **per-session** so 16/31 participants explore the matrix independently on one
shared app, and the instructor can drive a synchronized demo.

## 4. Component S9.1 — Per-session state + multi-turn memory (the backbone; build first)

Everything else depends on this. Introduce **session-scoped state**, resolved per
request, for three things: conversation history, guardrail-level overrides, and model
config.

### Data model
Add a `SessionState` record keyed by `session_id`, persisted through the existing
`Store` abstraction (InMemory for tests + Postgres for deploy), so it survives a web
restart on the hosted box:

```
SessionState(session_id):
  conversations: dict[surface -> list[message]]   # surface = "chat" | "agent" | "mcp" | "dispute" | "guarded"
  levels:        dict[module  -> "L1" | "L2"]      # per-module guardrail level (default from HALCYON_MODE)
  model_cfg:     {provider, model, api_key}        # api_key held session-scoped, never written to the audit log
```

### Conversation memory
- `halo.handle_turn` and `agent.run` load the session's history for the surface, **prepend
  it** to the message list, run the turn, then **append** the new user + assistant
  messages. `guards.assemble` / `guards.assemble_rag` / the agent loop take an optional
  `history` argument (default `[]`, preserving current behavior + all existing tests).
- Canary/audit scanning is unchanged and runs per turn — so a crescendo that finally
  leaks on turn 6 fires the same `internal_token_disclosed` event. **Grading is untouched.**
- `POST /reset/{module}` also clears that surface's conversation (a "new conversation"
  affordance in the UI does the same). `/validate` still counts events after the latest reset.

### Effective-settings resolution
- Keep the frozen `Settings` dataclass as the **process default**. Add
  `effective_settings(base, session_state, module)` that overlays the session's per-module
  level (L1 → SEC_* off, L2 → SEC_* on for that module's flags). Web handlers resolve
  once per request and pass the result into the (unchanged) guards. **Guards don't change.**

### Why store-backed
Multi-turn state must survive the web container bouncing on the hosted box (same reason
progress lives outside the container). Ephemeral in-process memory would drop a
participant's crescendo mid-attempt.

## 5. Component S9.2 — Self-serve L1/L2 flip

- New `POST /api/level {session_id, module, level}` sets the per-module level in
  `SessionState.levels`. New `GET /api/level?session=` returns the map for the sidebar.
- The request pipeline uses `effective_settings(...)` (§4) — so flipping a module to L2
  takes effect on the **next request, no restart**, per session.
- **Two levels:** L1 = that module's `SEC_*` flags off; L2 = on. (E.g. M1 L2 =
  `SEC_SYSTEM_PROMPT_HARDENING` + `SEC_INPUT_FILTER` on; M8 L2 = `SEC_GUARDRAILS` on.)
- Modules with no runtime guard (M4 supply-chain) simply have no toggle.
- UI: a left "Guardrail Settings" sidebar with an L1/L2 switch per module, mirroring the
  reference app. This finally makes Break→Secure→re-break a self-serve loop.

## 6. Component S9.3 — LiteLLM multi-provider BYOK

### Decision: use LiteLLM
Rationale (validated): it **normalizes tool-calling across Anthropic/OpenAI/Gemini/xAI**
(the fiddly, Day-2-critical part that broke on Ollama for M6 and was only smoke-tested
elsewhere); adding a provider/model becomes a **string, not a class** (model IDs shipped
a new family across *all four* vendors between Jan–Jul 2026 — hardcoding is a maintenance
trap); and it **also fronts Ollama**, unifying Mode 1 + Mode 2 behind one call.

### Contained refactor (net code deletion)
- Keep the `LLM` and `ToolLLM` **Protocol interfaces** exactly as they are, so
  `create_app`, `agent.run`/`run_mcp`, `dispute_pipeline`, validators, and the MCP host
  are **untouched**.
- Replace the hand-rolled provider classes (`RemoteProvider`, `OpenAIToolProvider`,
  `AnthropicToolProvider`, Ollama providers) with thin LiteLLM-backed `LiteLLM` /
  `LiteLLMTool` implementations. `build_llm` / `build_tool_llm` map `(provider, model,
  api_key)` → a LiteLLM model string (`anthropic/…`, `openai/…`, `gemini/…`, `xai/…`,
  `ollama/…`).
- **`StubLLM` / `StubToolLLM` stay** — the deterministic suite is unaffected.

### Model config (per session)
- `POST /api/config {session_id, provider, model, api_key}` → stored in
  `SessionState.model_cfg`. `GET /api/config?session=` returns provider+model (never the key).
- **Editable model field** + provider dropdown (Local / Anthropic / OpenAI / Gemini / xAI),
  seeded with current defaults, but participants can paste any current ID:

  | Provider | default (cheap) | stronger option(s) |
  |---|---|---|
  | Anthropic | `claude-haiku-4-5` | `claude-sonnet-5`, `claude-opus-4-8` |
  | OpenAI | `gpt-5.6-luna` | `gpt-5.6-terra`, `gpt-5.6-sol` |
  | Gemini | `gemini-3.5-flash-lite` | `gemini-2.5-flash`, `gemini-2.5-pro` |
  | xAI | `grok-4.3` | `grok-4.5` |
  | Local | `llama3.1:8b` (Mode 1) | — |

  *(IDs verified at ai.google.dev, developers.openai.com, docs.x.ai, and the Anthropic
  model reference on 2026-07-29. Treat as defaults, not gospel — the field is editable
  and we may later populate it from each provider's `/models` endpoint.)*
- **Key handling:** the BYOK key lives in session state (or, cleaner, is passed per
  request and never persisted) and is **never written to the audit log or the attack
  board**. Document this to participants.

## 7. Component S9.4 — Tabbed UI (brings M6/M7/M8 into the browser)

- Rebuild `templates/chat.html` into a **tabbed app keyed by layer** (L0 chatbot →
  L5 guardrail), each tab hosting its module panel(s). M6 (MCP), M7 (dispute), M8
  (guarded chat) get real panels over their existing endpoints — no more curl-only.
- Left sidebar: the S9.2 guardrail toggles + a **model-config modal** (S9.3), matching
  the reference app.
- Preserve the safe rendering discipline: all model/user output via `textContent`
  **except** the deliberate M2 `display_name` XSS sink (that stays, gated by
  `SEC_OUTPUT_ENCODING`/level).
- Optional per-tab **MCP Inspector hint** for M6 (point `npx @modelcontextprotocol/inspector`
  at the exposed MCP ports) — the "see the protocol" pedagogy, near-zero build.

## 8. Component S9.5 — Captured-attacks board (hosted-only payoff)

- `GET /board` (instructor view): query the audit log across sessions for the core "win"
  events (reuse `capstone.CORE_EVENTS`), and render an anonymized wall — session alias ·
  module · which model + level it beat · turn count · the payload/transcript.
- Enables the marquee moment: *"Priya cracked Claude on M1 at turn 6 — here's how,"*
  projected to the room. **Hosted-only by nature** (needs the shared backend) — which is
  the concrete reason the hosted instance is primary, not a backup.
- Privacy: opt-in display names; BYOK keys never surfaced.

## 9. Deployment

- **Hosted-primary, single shared app, session-isolated**, on a **GPU box** (~$1/hr;
  budget $100–200) so 16/31 bursty Mode-1 users on the shared Ollama are snappy. Mode-2
  is BYOK → **no shared-inference load on the heavy day.**
- **Local / own-cloud** offered from the same image for tinkering and connectivity
  insurance — not primary.
- Session isolation via `session_id` across audit log, progress, conversation memory,
  levels, and model config. (Revisits the "container-per-participant" assumption: with
  per-session state + no real participant RCE on the frontier path, one well-resourced
  app instance serves everyone; keep container-per-participant only if a later RCE lab
  needs it.)

## 10. Testing

- **Deterministic suite unchanged** (Stub LLM/ToolLLM). Add unit tests for: session-state
  CRUD, `effective_settings` resolution, conversation append/reset, level-flip changing
  the guarded path, and model-config round-trip (no key leakage into audit).
- **Per-provider tool-calling matrix** as a gated live e2e (`RUN_BYOK_TESTS`): M5/M6/M7
  against Anthropic/OpenAI/Gemini/xAI via LiteLLM — the one thing LiteLLM turns from N
  implementations into one matrix to spot-check.
- Multi-turn: a live crescendo e2e on M1 (frontier) — non-deterministic, so asserted on
  the *mechanism* (event eventually fires within N turns), not wording.

## 11. Build sequence

1. **S9.1** per-session state + multi-turn memory (backbone; unlocks the rest).
2. **S9.2** self-serve L1/L2 flip wired to `effective_settings`.
3. **S9.3** LiteLLM refactor + multi-provider config (Grok/Gemini added; Together later if wanted).
4. **S9.4** tabbed UI incl. M6–M8 panels + config modal + level sidebar.
5. **S9.5** captured-attacks board.

Each step is independently useful and independently testable.

## 12. Open questions / risks

- **Conversation-memory scope per module:** one history per surface (chat/agent/mcp/…),
  or per (surface, module)? Proposed: per surface — matches how a real chat session works.
- **Level granularity:** per-module toggles (proposed, matches reference app) vs. one
  session-wide L1/L2. Per-module is richer; confirm it's not too fiddly for the room.
- **LiteLLM + Anthropic:** wrapping the API loses native-SDK features (adaptive thinking);
  fine for chat+tools, but note it.
- **Frontier non-determinism:** multi-turn M1 wins are probabilistic; the board must
  handle "didn't land this run" gracefully and grading stays mechanism-based.
- **Container-per-participant:** this design leans toward one shared session-isolated app;
  if a future lab needs real participant RCE isolation, revisit.

---

### What is explicitly preserved
Append-only audit log · per-module validators · the eight guards · real MCP servers ·
the LangGraph dispute pipeline · mechanism-based grading · the four hard rules
(mechanism-not-words · one-build-+-flags · model-floor/BYOK-ceiling · deterministic +
resettable + self-service). This slice adds a per-session control layer and a frontend;
it does not touch the load-bearing walls.
