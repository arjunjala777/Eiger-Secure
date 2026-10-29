# Black-box Hardening — Batch 1 (design)

**Status:** draft for review · **Date:** 2026-07-30 · **Author:** KK + Claude
**Source:** `docs/labs/blackbox-findings-2026-07-29.md` (live hosted black-box test).
**Scope:** the four clear-cut engineering findings — **#1** Postgres connection
exhaustion, **#2/#3** cross-session state bleed, **#6** M4 un-completable hosted, **#8**
`/openapi.json` exposure. The grading-*design* findings (#4 M7, #5 M2 beacon, #7 M3
word-grading) are a **separate later effort** (they need their own brainstorm). #9
(stale image) and RCE container isolation are **infra**, owned by the colleague.

Live acceptance oracle: `docs/labs/blackbox/blackbox.py` — `regressions` encodes #1/#4/#5/#6
(currently 0/4). This batch should move **#1 and #6 to PASS** after redeploy.

---

## Global constraints

- **No change to the deterministic test suite's semantics.** `InMemoryStore`, `Bank`,
  `ChromaKB` (in-memory), and `StubLLM`/`StubToolLLM` stay; new tests use them.
- **Grading unchanged in meaning.** These fixes remove cross-session corruption and
  availability failures; they do not change what counts as a pass for a *single* session
  (except M4 stretch, which by design now requires the version pin — see #6).
- **The image is the unit of change.** Fixes land only after a rebuild+redeploy (colleague).
  `COPY labs` and the `psycopg_pool` dependency both require an image rebuild.
- **Interpreter:** `.venv/bin/python -m pytest`; gates `.venv/bin/ruff check halcyon tests`
  and `.venv/bin/mypy halcyon`.
- **Out of scope:** Postgres `max_connections` tuning and Modal scaling (infra); RCE
  isolation for M4/M6 (needs container-per-participant); findings #4/#5/#7/#9.

---

## #1 — Postgres connection pool (CRITICAL)

**Problem.** `halcyon/pg_store.py` calls `psycopg.connect()` per operation (9 sites); no
pool. One `/api/agent` request writes many audit rows, so ~8 concurrent requests exhaust
`max_connections`; the `psycopg.OperationalError` is unhandled → instant HTTP 500. Measured
1/22 at class size. Highest Aug-1 risk.

**Fix.**
- Add dependency `psycopg_pool` to `pyproject.toml` (+ `uv.lock`).
- In `PostgresStore.__init__`, open one module/instance-level
  `psycopg_pool.ConnectionPool(database_url, min_size=1, max_size=N, open=True)` where
  `N = int(os.environ.get("EIGER_DB_POOL_MAX", "10"))`. Replace every `with psycopg.connect(...)`
  with `with self._pool.connection() as conn`. `ping()` uses the pool too.
- In `create_app`, register a FastAPI exception handler for `psycopg.OperationalError` and
  `psycopg_pool.PoolTimeout` → `JSONResponse(status_code=503, {"error": "busy, retry"})`
  with a `Retry-After: 1` header. So overload degrades to a retryable 503, never a 500.

**Tests (deterministic).** `PostgresStore` is only exercised in the Postgres-gated test
(`test_store_postgres.py`, skipped without a DB). Add there: the pool round-trips
read/write; `ping()` works via the pool. Add a `create_app`-level unit test that a handler
raising `psycopg.OperationalError` produces a 503 (inject a store whose method raises).
The real concurrency proof is `blackbox.py concurrency`/`regressions` post-deploy.

## #2 / #3 — In-process per-session Bank + KB (HIGH)

**Problem.** `main.py` holds one `_bank = Bank()` and one `_kb = ChromaKB()` for all
sessions. `/reset` clears them globally (corrupting other participants' state and grading);
`ChromaKB.clear()` does `delete_collection("halcyon")` on a collection other threads may be
querying; user KB chunks are visible across sessions. Verified: session A's note hijacked
session B's M3 answer.

**Fix — per-session providers.**
- Introduce provider callables resolved per request:
  `bank_for(session_id) -> Bank` and `kb_for(session_id) -> KnowledgeBase`.
- Back them with small in-process registries in `main.py`:
  - `BankRegistry`: `dict[session_id -> Bank]`; on first use, create a `Bank()` and seed it
    with `bank_fixtures.seed_for(session_id)`.
  - `KBRegistry`: `dict[session_id -> ChromaKB]`; on first use, create a `ChromaKB` bound to
    a **per-session collection** named `eiger-<slug(session_id)>` and seed it with
    `kb_fixtures.SEED`. `slug()` maps an arbitrary session_id to a valid Chroma collection
    name (3–63 chars, `[a-zA-Z0-9_-]`, alnum ends) — e.g. `"s" + sha1(sid).hexdigest()[:32]`.
- `ChromaKB.__init__` takes a `collection` name (default `"halcyon"` to keep current tests
  working); `clear()` drops+recreates **that instance's** collection only.
- `create_app` signature changes: `kb, bank` → `kb_for, bank_for` (callables). Handlers
  (`/api/kb`, `/api/ask`, `/api/agent`, `/api/dispute`, and `/reset/{m3,m5,m6,m7}`) resolve
  the per-session instance. `/reset/{m5,m6,m7}` re-seeds **only** that session's bank;
  `/reset/m3` resets **only** that session's collection.
- The MCP host uses the per-session bank too: `mcp_host_factory(session_id, settings)` builds
  its host with `bank_for(session_id)`.
- **Test callers updated:** every `create_app(...)` in tests passes `lambda sid: bank` /
  `lambda sid: kb` (shared instance → current behavior preserved). New isolation tests pass
  a real per-session registry.

**Why in-process (not persisted).** Bank/KB are re-seedable fixtures; only progress + audit
must survive a redeploy, and those already live in the external store keyed by session. So a
redeploy re-seeds cleanly. One shared app process (per the S9 hosted design) holds ≤22 small
banks + collections — negligible memory. This is the data-bleed fix; it is **not** RCE
isolation (that still needs per-participant containers).

**Tests (deterministic, InMemory/in-memory Chroma).**
- Bank isolation: after `bank_for("A")` seeds and a transfer, `bank_for("B")` still has its
  own untouched fixtures; `/reset/m5` for A leaves B's bank intact.
- KB isolation: a user note added under session A does **not** appear in `kb_for("B").retrieve(...)`;
  A's `/reset/m3` does not disturb B's collection; both still retrieve the shared seed.
- Regression: existing M3/M5/M6/M7 endpoint + validator tests stay green with the new
  provider wiring.

## #6 — M4 as a self-sufficient download (HIGH)

**Problem.** `Dockerfile` copies only `pyproject.toml`, `uv.lock`, `halcyon/` — so
`labs/m4/artifacts/*` never reach the container; a hosted participant cannot obtain the
artifact sha256 by any route, yet core requires it. Separately, `m4_answers.normalize_package`
strips the version, so a bare `pyyaml` guess passes stretch with no audit performed.

**Fix — serve a download bundle + require the pin.**
- `Dockerfile`: add `COPY labs ./labs` so the artifacts + `requirements-vulnerable.txt` are
  in the image. (Baking the poisoned pickle adds **no** RCE surface: nothing in the app calls
  `pickle.load` on it; `scan_artifact` uses `pickletools` only.)
- New `GET /api/m4/bundle` → a `.zip` (built in-memory with `zipfile`) containing:
  the poisoned artifact(s) from `labs/m4/artifacts/`, `labs/m4/requirements-vulnerable.txt`,
  a **stdlib-only copy of the scanner** (`scan_artifact.py` — already `hashlib`/`pickletools`/
  `pathlib` only), and a `README.md`. The M4 panel gains a **"Download audit bundle"** button.
- The README instructs: run `python scan_artifact.py <artifact>` to see the poisoned pickle's
  dangerous opcodes + its sha256 (core), and read the pinned dependency in
  `requirements-vulnerable.txt` (stretch). Fallback with no Python: `shasum -a 256 <artifact>`
  for the hash; open the txt for the pin. The README carries a prominent
  **"scan or hash it — never `pickle.load` it"** warning (that danger is the M4 lesson).
- **Stretch requires the pin:** set `m4_answers.VULNERABLE_PACKAGE = "pyyaml==5.3.1"` and make
  `normalize_package` preserve the version (strip whitespace/case only). Bare `pyyaml` now
  fails; `pyyaml==5.3.1` (readable in the bundle) passes.

**Tests (deterministic).**
- `GET /api/m4/bundle` returns a zip whose namelist includes the artifact, the requirements
  file, `scan_artifact.py`, and `README.md`; content-type is `application/zip`.
- `m4_answers`: `pyyaml` → stretch **incorrect**; `pyyaml==5.3.1` → **correct**; hash path
  unchanged (existing `test_m4_answers`/`test_m4_submit` updated for the new pin).
- The bundled scanner run over the baked artifact flags it (reuse `test_scan_artifact`).

## #8 — Hide OpenAPI/docs in hosted mode (LOW)

**Problem.** `/openapi.json` (and `/docs`) served unauthenticated enumerated the hidden
M6–M8 endpoints — how they were discovered.

**Fix.** Add `expose_openapi: bool` to `Settings` (env `EIGER_EXPOSE_OPENAPI`, default
**False**). In `create_app`, when false, construct
`FastAPI(title="Eiger", openapi_url=None, docs_url=None, redoc_url=None)`. Trainer flips the
env to expose the schema deliberately.

**Tests.** vulnerable/default client → `GET /openapi.json` returns 404 and `/docs` 404;
with `EIGER_EXPOSE_OPENAPI=1` → `/openapi.json` returns 200. Existing endpoint tests are
unaffected (they call routes directly, not the schema).

---

## Preserved / not touched

Append-only audit log, the eight validators (except the M4 stretch answer value), the eight
guards, mechanism-based grading, the S9.4/M6 UI behavior, session memory/levels/model-config,
the M2 `|safe` sink, and the CSP nonce. No user-facing rebrand work here.

## Build sequence (for the plan)

1. **#8 openapi** (smallest; isolated `Settings` + `create_app` change).
2. **#1 pool** (`pg_store.py` + dependency + 503 handler).
3. **#6 M4 bundle** (`Dockerfile`, `/api/m4/bundle`, panel button, pin change).
4. **#2/#3 per-session Bank+KB** (the refactor; `create_app` signature + all callers) — last,
   since it touches the most surface and benefits from the others being settled.

## Risks

- **`create_app` signature churn** (#2/#3) ripples to ~10 test callers → mechanical, covered
  by keeping a `lambda sid: shared` shim in existing tests.
- **Chroma per-session collections**: validate the `slug()` name is always Chroma-legal; 22
  small collections are cheap, but confirm no per-collection model re-download (the embedding
  function is process-global, so it is not re-downloaded).
- **Malicious pickle on participant laptops** (#6): deliberate and warned; the app never
  unpickles it. Flag in the participant guide too.
- **Pool sizing**: `EIGER_DB_POOL_MAX` default 10 must stay under the deploy's Postgres
  `max_connections` × replicas — a value the colleague confirms at deploy.
