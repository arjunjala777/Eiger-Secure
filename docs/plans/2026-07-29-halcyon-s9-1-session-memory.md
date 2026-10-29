# S9.1 — Per-Session State + Multi-Turn Memory Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Give Halcyon per-session working state — multi-turn conversation memory for the chat surface, and a per-module guardrail-level resolution layer — without touching the append-only audit log, the guards, or grading.

**Architecture:** A new `session_state.py` holds mutable per-session state (conversation history + per-module L1/L2 level) behind a `SessionState` Protocol with an in-memory default, mirroring how `create_app` already takes one dependency per stateful concern (kb, bank, tool_llm_factory, mcp_host_factory). A pure `effective_settings()` helper overlays a session's per-module level onto the frozen base `Settings`, so the existing guards keep receiving a `Settings` and don't change. `halo.handle_turn` and `guards.assemble` gain an optional `history` argument (default `[]`) that preserves current single-turn behavior exactly.

**Tech Stack:** Python 3.12, FastAPI, pytest, `dataclasses`, existing `halcyon` package.

## Global Constraints

- Mechanism-based grading is untouched: no change to `audit.py`, `canary.py`, or any `validators/*.py`.
- Backward compatible: every new function parameter has a default that reproduces current behavior; the existing 181-pass suite must stay green.
- `Settings` is a frozen dataclass — build modified copies with `dataclasses.replace`, never mutate.
- Conversation state is **separate** from the audit `Store` (audit log is append-only/immutable; session state is mutable working state). Postgres persistence of session state is out of scope for S9.1 (in-memory only; a later deploy-hardening task adds a backing store).
- Scope is the **chat surface** (M1/M2 via `/api/chat`) only — the crown-jewel multi-turn path. Agent/MCP/dispute multi-turn is a later slice.
- `ruff check .` and `mypy halcyon` must stay clean.

---

### Task 1: `SessionState` store (conversation history + per-module level)

**Files:**
- Create: `halcyon/session_state.py`
- Test: `tests/test_session_state.py`

**Interfaces:**
- Produces:
  - `class SessionState(Protocol)` with:
    - `get_history(session_id: str, surface: str) -> list[dict]`
    - `append_turn(session_id: str, surface: str, user_msg: str, assistant_msg: str) -> None`
    - `clear_history(session_id: str, surface: str) -> None`
    - `get_level(session_id: str, module: str) -> str | None`
    - `set_level(session_id: str, module: str, level: str) -> None`
  - `class InMemorySessionState` implementing it.
  - History entries are OpenAI-style dicts: `{"role": "user"|"assistant", "content": str}`. `append_turn` appends two entries (user then assistant). `get_history` returns a copy.

- [ ] **Step 1: Write the failing test**

```python
# tests/test_session_state.py
from halcyon.session_state import InMemorySessionState


def test_history_starts_empty_and_appends_in_order():
    s = InMemorySessionState()
    assert s.get_history("alice", "chat") == []
    s.append_turn("alice", "chat", "hi", "hello")
    s.append_turn("alice", "chat", "who are you", "Halo")
    assert s.get_history("alice", "chat") == [
        {"role": "user", "content": "hi"},
        {"role": "assistant", "content": "hello"},
        {"role": "user", "content": "who are you"},
        {"role": "assistant", "content": "Halo"},
    ]


def test_history_is_isolated_by_session_and_surface():
    s = InMemorySessionState()
    s.append_turn("alice", "chat", "a", "b")
    assert s.get_history("bob", "chat") == []
    assert s.get_history("alice", "agent") == []


def test_clear_history_empties_only_that_surface():
    s = InMemorySessionState()
    s.append_turn("alice", "chat", "a", "b")
    s.append_turn("alice", "agent", "c", "d")
    s.clear_history("alice", "chat")
    assert s.get_history("alice", "chat") == []
    assert len(s.get_history("alice", "agent")) == 2


def test_get_history_returns_a_copy():
    s = InMemorySessionState()
    s.append_turn("alice", "chat", "a", "b")
    s.get_history("alice", "chat").append({"role": "user", "content": "x"})
    assert len(s.get_history("alice", "chat")) == 2


def test_level_defaults_none_and_round_trips():
    s = InMemorySessionState()
    assert s.get_level("alice", "m1") is None
    s.set_level("alice", "m1", "L2")
    assert s.get_level("alice", "m1") == "L2"
    assert s.get_level("alice", "m2") is None
    assert s.get_level("bob", "m1") is None
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run pytest tests/test_session_state.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'halcyon.session_state'`

- [ ] **Step 3: Write minimal implementation**

```python
# halcyon/session_state.py
from dataclasses import dataclass, field
from typing import Protocol


class SessionState(Protocol):
    def get_history(self, session_id: str, surface: str) -> list[dict]: ...
    def append_turn(
        self, session_id: str, surface: str, user_msg: str, assistant_msg: str
    ) -> None: ...
    def clear_history(self, session_id: str, surface: str) -> None: ...
    def get_level(self, session_id: str, module: str) -> str | None: ...
    def set_level(self, session_id: str, module: str, level: str) -> None: ...


@dataclass
class InMemorySessionState:
    _history: dict[tuple[str, str], list[dict]] = field(default_factory=dict)
    _levels: dict[tuple[str, str], str] = field(default_factory=dict)

    def get_history(self, session_id: str, surface: str) -> list[dict]:
        return [dict(m) for m in self._history.get((session_id, surface), [])]

    def append_turn(
        self, session_id: str, surface: str, user_msg: str, assistant_msg: str
    ) -> None:
        h = self._history.setdefault((session_id, surface), [])
        h.append({"role": "user", "content": user_msg})
        h.append({"role": "assistant", "content": assistant_msg})

    def clear_history(self, session_id: str, surface: str) -> None:
        self._history.pop((session_id, surface), None)

    def get_level(self, session_id: str, module: str) -> str | None:
        return self._levels.get((session_id, module))

    def set_level(self, session_id: str, module: str, level: str) -> None:
        self._levels[(session_id, module)] = level
```

- [ ] **Step 4: Run test to verify it passes**

Run: `uv run pytest tests/test_session_state.py -v`
Expected: PASS (5 tests)

- [ ] **Step 5: Commit**

```bash
git add halcyon/session_state.py tests/test_session_state.py
git commit -m "feat(s9.1): add SessionState store for per-session history and level"
```

---

### Task 2: `effective_settings()` — overlay per-session level onto base Settings

**Files:**
- Modify: `halcyon/config.py` (append after `load_settings`)
- Test: `tests/test_effective_settings.py`

**Interfaces:**
- Consumes: `Settings` (from `config.py`); `SessionState.get_level` (Task 1).
- Produces:
  - `MODULE_FLAGS: dict[str, tuple[str, ...]]` mapping each module to the `Settings` attribute names it gates.
  - `effective_settings(base: Settings, session_state, session_id: str, module: str) -> Settings` — if the session has no level override for `module`, returns `base` unchanged; if `"L1"`, returns a copy with that module's flags forced `False`; if `"L2"`, forced `True`. Other modules' flags are left at `base`'s values.

- [ ] **Step 1: Write the failing test**

```python
# tests/test_effective_settings.py
from dataclasses import replace

from halcyon.config import effective_settings, load_settings
from halcyon.session_state import InMemorySessionState

BASE = load_settings({"HALCYON_MODE": "vulnerable"})  # all SEC_* off


def test_no_override_returns_base_unchanged():
    ss = InMemorySessionState()
    eff = effective_settings(BASE, ss, "alice", "m1")
    assert eff is BASE


def test_L2_turns_on_only_that_modules_flags():
    ss = InMemorySessionState()
    ss.set_level("alice", "m1", "L2")
    eff = effective_settings(BASE, ss, "alice", "m1")
    assert eff.sec_system_prompt_hardening is True
    assert eff.sec_input_filter is True
    # an unrelated module's flag stays at base (off)
    assert eff.sec_guardrails is False


def test_L1_forces_that_modules_flags_off_even_if_base_secure():
    secure = load_settings({"HALCYON_MODE": "secure"})  # all SEC_* on
    ss = InMemorySessionState()
    ss.set_level("alice", "m8", "L1")
    eff = effective_settings(secure, ss, "alice", "m8")
    assert eff.sec_guardrails is False
    # other modules stay secure
    assert eff.sec_system_prompt_hardening is True


def test_module_with_no_flags_returns_base():
    ss = InMemorySessionState()
    ss.set_level("alice", "m4", "L2")
    eff = effective_settings(BASE, ss, "alice", "m4")
    assert eff is BASE
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run pytest tests/test_effective_settings.py -v`
Expected: FAIL with `ImportError: cannot import name 'effective_settings'`

- [ ] **Step 3: Write minimal implementation**

Append to `halcyon/config.py`:

```python
from dataclasses import replace  # add to existing imports at top of file

MODULE_FLAGS: dict[str, tuple[str, ...]] = {
    "m1": ("sec_system_prompt_hardening", "sec_input_filter"),
    "m2": ("sec_output_encoding", "sec_system_prompt_hardening"),
    "m3": ("sec_rag_provenance",),
    "m5": ("sec_tool_scope_enforcement",),
    "m6": ("sec_mcp_desc_pinning", "sec_mcp_token_scoping"),
    "m7": ("sec_inter_agent_auth",),
    "m8": ("sec_guardrails",),
}


def effective_settings(base: Settings, session_state, session_id: str, module: str) -> Settings:
    level = session_state.get_level(session_id, module)
    flags = MODULE_FLAGS.get(module)
    if level is None or not flags:
        return base
    value = level == "L2"
    return replace(base, **{name: value for name in flags})
```

- [ ] **Step 4: Run test to verify it passes**

Run: `uv run pytest tests/test_effective_settings.py -v`
Expected: PASS (4 tests)

- [ ] **Step 5: Commit**

```bash
git add halcyon/config.py tests/test_effective_settings.py
git commit -m "feat(s9.1): add effective_settings level-overlay resolver"
```

---

### Task 3: Thread conversation history into `guards.assemble` + `halo.handle_turn`

**Files:**
- Modify: `halcyon/guards.py` (the `assemble` function, ~lines 48-57)
- Modify: `halcyon/halo.py` (the `handle_turn` function)
- Test: `tests/test_multiturn_memory.py`

**Interfaces:**
- Consumes: `SessionState` (Task 1); `Settings` (Task 2).
- Produces:
  - `guards.assemble(settings, user_message, history=None) -> list[dict]` — `history` is a list of prior `{"role","content"}` dicts. With `history=None`/`[]` the output is byte-identical to today's. With history, prior turns are inserted before the current user message (after the system message in the secure branch; after a leading token-bearing turn in the vulnerable branch).
  - `halo.handle_turn(store, llm, settings, session_id, message, module="m1", history=None) -> str` — unchanged return (the reply string). It does **not** itself persist history; the caller (web) owns load/append so `handle_turn` stays pure and the existing tests that call it without `history` keep passing.

- [ ] **Step 1: Write the failing test**

```python
# tests/test_multiturn_memory.py
from halcyon import guards
from halcyon.config import load_settings

VULN = load_settings({"HALCYON_MODE": "vulnerable"})
SECURE = load_settings({"HALCYON_MODE": "secure"})


def test_assemble_no_history_is_unchanged_vulnerable():
    msgs = guards.assemble(VULN, "hello")
    assert msgs == [{"role": "user", "content": guards.SYSTEM_WITH_TOKEN + "\n\nUser: hello"}]


def test_assemble_no_history_is_unchanged_secure():
    msgs = guards.assemble(SECURE, "hello")
    assert msgs == [
        {"role": "system", "content": guards.SYSTEM_BASE},
        {"role": "user", "content": "hello"},
    ]


def test_assemble_with_history_secure_inserts_between_system_and_user():
    hist = [{"role": "user", "content": "earlier"}, {"role": "assistant", "content": "ok"}]
    msgs = guards.assemble(SECURE, "now", history=hist)
    assert msgs == [
        {"role": "system", "content": guards.SYSTEM_BASE},
        {"role": "user", "content": "earlier"},
        {"role": "assistant", "content": "ok"},
        {"role": "user", "content": "now"},
    ]


def test_assemble_with_history_vulnerable_keeps_token_context_then_history():
    hist = [{"role": "user", "content": "earlier"}, {"role": "assistant", "content": "ok"}]
    msgs = guards.assemble(VULN, "now", history=hist)
    assert msgs[0] == {"role": "user", "content": guards.SYSTEM_WITH_TOKEN}
    assert msgs[1:3] == hist
    assert msgs[-1] == {"role": "user", "content": "User: now"}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run pytest tests/test_multiturn_memory.py -v`
Expected: FAIL (the two history tests error: `assemble() got an unexpected keyword argument 'history'`)

- [ ] **Step 3: Write minimal implementation**

Replace `assemble` in `halcyon/guards.py`:

```python
def assemble(settings: Settings, user_message: str, history: list[dict] | None = None) -> list[dict]:
    hist = list(history or [])
    if settings.sec_system_prompt_hardening:
        # Secret removed; structured role separation. History sits between system and user.
        return (
            [{"role": "system", "content": SYSTEM_BASE}]
            + hist
            + [{"role": "user", "content": user_message}]
        )
    if not hist:
        # Vulnerable single-turn: token spliced into one flat user turn (unchanged).
        concatenated = SYSTEM_WITH_TOKEN + "\n\nUser: " + user_message
        return [{"role": "user", "content": concatenated}]
    # Vulnerable multi-turn: token-bearing context first, then prior turns, then the new user turn.
    return (
        [{"role": "user", "content": SYSTEM_WITH_TOKEN}]
        + hist
        + [{"role": "user", "content": "User: " + user_message}]
    )
```

Modify `handle_turn` in `halcyon/halo.py` to accept and pass `history`:

```python
def handle_turn(
    store: Store,
    llm: LLM,
    settings: Settings,
    session_id: str,
    message: str,
    module: str = "m1",
    history: list[dict] | None = None,
) -> str:
    if settings.sec_input_filter and guards.input_filter_blocks(message):
        audit.record(store, session_id, module, audit.INPUT_FILTERED, session_id,
                     {"message": message})
        return REFUSAL
    messages = guards.assemble(settings, message, history)
    try:
        reply = llm.chat(messages)
    except Exception:
        return LLM_ERROR
    canary.scan_and_record(store, session_id, module, reply, actor=session_id)
    return reply
```

- [ ] **Step 4: Run tests to verify they pass (incl. the full suite for no-regression)**

Run: `uv run pytest tests/test_multiturn_memory.py -v && uv run pytest -q`
Expected: new file PASS (4 tests); whole suite still `181 passed, 4 skipped`.

- [ ] **Step 5: Commit**

```bash
git add halcyon/guards.py halcyon/halo.py tests/test_multiturn_memory.py
git commit -m "feat(s9.1): thread conversation history through assemble + handle_turn"
```

---

### Task 4: Wire session state into `create_app` — `/api/chat` remembers, `/reset` clears

**Files:**
- Modify: `halcyon/web.py` (`create_app` signature; `chat` handler; `reset` handler)
- Modify: `halcyon/main.py` (construct and pass a default `InMemorySessionState`)
- Modify: `tests/*` test client factory/factories that call `create_app` (add the new arg)
- Test: `tests/test_chat_memory_endpoint.py`

**Interfaces:**
- Consumes: `InMemorySessionState` (Task 1); `effective_settings` (Task 2); `handle_turn(history=...)` (Task 3).
- Produces:
  - `create_app(store, settings, llm_factory, kb, bank, tool_llm_factory, mcp_host_factory, session_state)` — one new trailing parameter.
  - `/api/chat` behavior: resolve `eff = effective_settings(settings, session_state, session_id, "m1")`, load `history = session_state.get_history(session_id, "chat")`, call `handle_turn(..., eff, ..., history=history)`, then `session_state.append_turn(session_id, "chat", message, reply)`.
  - `/reset/{module}` for `module in ("m1","m2")` also calls `session_state.clear_history(session_id, "chat")`.

- [ ] **Step 1: Write the failing test**

```python
# tests/test_chat_memory_endpoint.py
from halcyon.session_state import InMemorySessionState
# Reuse the repo's existing app test harness. Most tests build the client via a
# make_client helper in tests/conftest.py or a shared module; this test asserts
# the multi-turn wiring through the real endpoint using an echo/stub LLM.
from tests.helpers import make_client  # adjust to the repo's actual harness import


def test_chat_history_grows_across_requests(monkeypatch):
    # Stub LLM echoes how many prior messages it received, so we can prove history is fed back.
    client, ss = make_client(mode="vulnerable")
    client.post("/api/chat", json={"session_id": "u1", "message": "one"})
    client.post("/api/chat", json={"session_id": "u1", "message": "two"})
    hist = ss.get_history("u1", "chat")
    assert [m["content"] for m in hist] == ["one", <first reply>, "two", <second reply>]


def test_reset_m1_clears_chat_history():
    client, ss = make_client(mode="vulnerable")
    client.post("/api/chat", json={"session_id": "u1", "message": "one"})
    client.post("/reset/m1", json={"session_id": "u1"})
    assert ss.get_history("u1", "chat") == []
```

> Note to implementer: the repo's existing client harness (see how `tests/test_halo.py` / `tests/test_web*.py` build a client and pass the 7 current `create_app` args) is the pattern to extend — add an `InMemorySessionState`, return it alongside the client, and assert on it. Match the repo's real stub-LLM convention; the two `<...reply...>` placeholders above are whatever the stub returns.

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run pytest tests/test_chat_memory_endpoint.py -v`
Expected: FAIL (`create_app()` missing/rejecting the `session_state` argument, or history not persisted).

- [ ] **Step 3: Write minimal implementation**

In `halcyon/web.py`, add the parameter and import, and update the two handlers:

```python
from halcyon.config import Settings, effective_settings   # extend existing import
from halcyon.session_state import SessionState

def create_app(store, settings, llm_factory, kb, bank, tool_llm_factory,
               mcp_host_factory, session_state: SessionState):
    ...
    @app.post("/api/chat")
    def chat(body: ChatIn) -> dict:
        llm = llm_factory(body.provider, body.model, body.api_key)
        eff = effective_settings(settings, session_state, body.session_id, "m1")
        history = session_state.get_history(body.session_id, "chat")
        reply = halo.handle_turn(store, llm, eff, body.session_id, body.message, history=history)
        session_state.append_turn(body.session_id, "chat", body.message, reply)
        return {"reply": reply}

    @app.post("/reset/{module}")
    def reset(module: str, body: ResetIn) -> dict:
        store.write_reset_marker(body.session_id, module)
        if module in ("m1", "m2"):
            session_state.clear_history(body.session_id, "chat")
        if module == "m3":
            kb.clear(); kb.seed(kb_fixtures.SEED)
        if module in ("m5", "m6", "m7"):
            bank.clear(); bank.seed(bank_fixtures.seed_for(body.session_id))
        return {"status": "reset", "module": module}
```

In `halcyon/main.py`, construct and pass it:

```python
from halcyon.session_state import InMemorySessionState
_session_state = InMemorySessionState()
app = create_app(_store, _settings, _factory, _kb, _bank, _tool_llm_factory,
                 _mcp_host_factory, _session_state)
```

Update every other `create_app(...)` call site (test harness/`make_client*`) to pass an `InMemorySessionState()`.

- [ ] **Step 4: Run tests to verify they pass (+ full suite + lint/types)**

Run: `uv run pytest tests/test_chat_memory_endpoint.py -v && uv run pytest -q && uv run ruff check . && uv run mypy halcyon`
Expected: new tests PASS; whole suite `183 passed, 4 skipped` (181 + 2 new files' cases resolve); ruff + mypy clean.

- [ ] **Step 5: Commit**

```bash
git add halcyon/web.py halcyon/main.py tests/
git commit -m "feat(s9.1): per-session chat memory via create_app; reset clears it"
```

---

## Self-Review

- **Spec coverage (S9.1 slice of the design doc §4):** conversation memory (Tasks 3–4 ✓), per-module level store + `effective_settings` resolver (Tasks 1–2 ✓), reset clears conversation (Task 4 ✓), guards untouched (✓ — they still take `Settings`), grading untouched (✓ — no audit/validator edits). Deferred by design: Postgres backing of session state, agent/MCP/dispute surfaces, the `/api/level` endpoint + UI (S9.2), model_cfg (S9.3).
- **Placeholder scan:** the only intentional `<...>` are in the Task-4 test, flagged with an implementer note to match the repo's real stub-LLM harness — every other step is complete code.
- **Type consistency:** `SessionState` method names/signatures are identical across Tasks 1, 3, 4; `effective_settings(base, session_state, session_id, module)` signature identical in Tasks 2 and 4; `assemble(settings, user_message, history)` and `handle_turn(..., history=None)` identical in Tasks 3 and 4.
- **Constraint check:** every new param defaults to current behavior; `dataclasses.replace` used (no mutation); no audit/validator/canary edits.
