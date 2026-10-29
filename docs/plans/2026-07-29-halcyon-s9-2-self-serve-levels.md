# S9.2 — Self-Serve L1/L2 Level Flip Implementation Plan

> Continues S9.1. Uses the `effective_settings` resolver already built. TDD, small commits.

**Goal:** Let a participant flip any module between L1 (no guardrail) and L2 (full guardrail)
for their own session, live, with no restart — and have every module endpoint honour it.

**Architecture:** Add `get_levels` to `SessionState`; add `POST/GET /api/level`; replace the
raw `settings` passed into each module handler with
`effective_settings(settings, session, session_id, module)`. The UI sidebar is deferred to
S9.4 (the tabbed rebuild) — S9.2 makes the flip functional and API-testable.

## Global Constraints
- No changes to guards/validators/audit/canary. Backward compatible. `ruff`/`mypy` clean. Suite stays green.

---

### Task 1: `get_levels` + `/api/level` endpoints

**Files:** Modify `halcyon/session_state.py`, `halcyon/web.py`. Test `tests/test_level_endpoint.py`.

**Interfaces produced:**
- `SessionState.get_levels(session_id) -> dict[str, str]` (explicit overrides only).
- `POST /api/level {session_id, module, level}` → validates `level in {L1,L2}` and `module in MODULE_FLAGS`; sets it.
- `GET /api/level?session=` → the overrides map.

- [ ] Write failing test (round-trip + validation), run (fail), implement, run (pass), commit.

### Task 2: Thread `effective_settings` into the remaining handlers

**Files:** Modify `halcyon/web.py` (chat_page/m2, ask/m3, agent/m5, mcp-agent/m6, dispute/m7,
guarded-chat/m8). Test `tests/test_level_flip_behavior.py`.

**Behavior:** each handler computes `eff = effective_settings(settings, session, session_id, "<module>")`
and passes `eff` instead of `settings`. Deterministic end-to-end proof via M8:
- base vulnerable + no override → leetspeak payload records `guardrail_bypassed` (core pass).
- `POST /api/level {module:"m8", level:"L2"}` → same payload records `guardrail_hardened_block`.

- [ ] Write failing test, run (fail), implement, run (pass + full suite + lint/types), commit.
