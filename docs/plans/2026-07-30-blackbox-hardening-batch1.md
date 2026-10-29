# Black-box Hardening Batch 1 — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Fix the four clear-cut black-box findings — #1 Postgres connection exhaustion, #2/#3 cross-session state bleed, #6 M4 un-completable hosted, #8 OpenAPI exposure — so the hosted lab survives a 22-person class and grades each participant in isolation.

**Architecture:** Additive, mechanism-preserving. A connection pool in `pg_store.py`; per-session `Bank`/`ChromaKB` behind provider callables resolved per request in `create_app`; a downloadable M4 audit bundle served from baked `labs/`; OpenAPI gated by a setting. The deterministic suite (InMemory/Stub) keeps its meaning; new tests prove isolation and the M4 pin.

**Tech Stack:** FastAPI, `psycopg` + new `psycopg_pool`, ChromaDB (in-process), pytest + `fastapi.testclient.TestClient`, `zipfile` (stdlib).

## Global Constraints

- **Interpreter:** run `.venv/bin/python -m pytest`. Gates: `.venv/bin/ruff check halcyon tests` and `.venv/bin/mypy halcyon`. Both must be clean before every commit.
- **Deterministic suite semantics unchanged:** `InMemoryStore`, in-memory `Bank`/`ChromaKB`/`InMemoryKB`, `StubLLM`/`StubToolLLM` stay. No test may require a live model or DB except the already-gated `test_store_postgres.py`.
- **Single-session grading meaning is unchanged**, with ONE intended exception: M4 stretch now requires the version pin `pyyaml==5.3.1` (bare `pyyaml` must fail).
- **Do not rename** internal identifiers: `halcyon` package, `HALCYON_MODE`, `SEC_*` flags, `HONEYTOKEN`, `OVERRIDE_MARKER`, audit constants.
- **New env vars:** `EIGER_DB_POOL_MAX` (default `10`), `EIGER_EXPOSE_OPENAPI` (default off/false).
- **Live acceptance oracle:** `docs/labs/blackbox/blackbox.py` `regressions` — #1 and #6 must flip to PASS after this batch (Task 5 runs it locally).

---

### Task 1: #8 — Hide OpenAPI/docs behind a setting

**Files:**
- Modify: `halcyon/config.py` (add `expose_openapi` to `Settings` + `load_settings`)
- Modify: `halcyon/web.py` (FastAPI construction, ~line 120)
- Test: `tests/test_web.py`

**Interfaces:**
- Produces: `Settings.expose_openapi: bool`; `/openapi.json` returns 404 unless `EIGER_EXPOSE_OPENAPI` is truthy.

- [ ] **Step 1: Write the failing test** — add to `tests/test_web.py`:

```python
def test_openapi_hidden_by_default_exposed_when_flagged():
    default, _ = make_client({"HALCYON_MODE": "vulnerable"}, "hi")
    assert default.get("/openapi.json").status_code == 404
    assert default.get("/docs").status_code == 404
    exposed, _ = make_client({"HALCYON_MODE": "vulnerable", "EIGER_EXPOSE_OPENAPI": "1"}, "hi")
    assert exposed.get("/openapi.json").status_code == 200
```

- [ ] **Step 2: Run it — expect FAIL**

Run: `.venv/bin/python -m pytest tests/test_web.py::test_openapi_hidden_by_default_exposed_when_flagged -v`
Expected: FAIL — `/openapi.json` currently returns 200.

- [ ] **Step 3: Add the setting** — in `halcyon/config.py`, add a field to the `Settings` dataclass (after `default_provider: str`):

```python
    default_provider: str
    expose_openapi: bool
```

and in `load_settings`, add to the returned `Settings(...)` (after `default_provider=...`):

```python
        default_provider=env.get("DEFAULT_PROVIDER", "local"),
        expose_openapi=_flag(env, "EIGER_EXPOSE_OPENAPI", False),
```

- [ ] **Step 4: Gate FastAPI construction** — in `halcyon/web.py`, replace `app = FastAPI(title="Halcyon")` with:

```python
    if settings.expose_openapi:
        app = FastAPI(title="Eiger")
    else:
        app = FastAPI(title="Eiger", openapi_url=None, docs_url=None, redoc_url=None)
```

- [ ] **Step 5: Verify + gates**

Run: `.venv/bin/python -m pytest tests/test_web.py -q && .venv/bin/ruff check halcyon tests && .venv/bin/mypy halcyon`
Expected: new test passes; the full `test_web.py` still passes (routes are called directly, not via the schema); ruff + mypy clean.

- [ ] **Step 6: Commit**

```bash
git add halcyon/config.py halcyon/web.py tests/test_web.py
git commit -m "fix(#8): hide OpenAPI/docs unless EIGER_EXPOSE_OPENAPI

The unauthenticated /openapi.json enumerated the hidden M6-M8 endpoints.
Default off in hosted; trainer flips the env to expose deliberately.

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

---

### Task 2: #1 — Postgres connection pool + 503 handler

**Files:**
- Modify: `pyproject.toml` (add `psycopg_pool` dependency), regenerate `uv.lock`
- Rewrite: `halcyon/pg_store.py` (pool instead of per-op connect)
- Modify: `halcyon/web.py` (503 exception handler)
- Test: `tests/test_store_postgres.py` (pool round-trip — gated), `tests/test_web.py` (503 mapping)

**Interfaces:**
- Consumes: `Settings.database_url`.
- Produces: `PostgresStore(dsn, max_size=…)` backed by a `ConnectionPool`; a `create_app` exception handler that maps `psycopg.OperationalError`/`psycopg_pool.PoolTimeout` → HTTP 503.

- [ ] **Step 1: Add the dependency**

Edit `pyproject.toml` — add `"psycopg-pool>=3.2"` to the `dependencies` list (next to `psycopg`). Then run: `cd /Users/kkmookhey/Projects/eiger && uv lock` to update `uv.lock`, and `uv sync` so `.venv` has it.
Verify: `.venv/bin/python -c "import psycopg_pool; print(psycopg_pool.__version__)"` prints a version.

- [ ] **Step 2: Write the failing 503-handler test** — add to `tests/test_web.py`:

```python
def test_db_error_returns_503_not_500():
    import psycopg
    from tests.test_web import make_client  # reuse helper if needed
    # a store whose read raises the DB error the pool surfaces under exhaustion
    client, store = make_client({"HALCYON_MODE": "vulnerable"}, "hi")

    def boom(*a, **k):
        raise psycopg.OperationalError("connection pool exhausted")

    store.list_sessions = boom  # /board calls list_sessions
    r = client.get("/board")
    assert r.status_code == 503
    assert "retry" in r.text.lower()
```

- [ ] **Step 3: Run it — expect FAIL**

Run: `.venv/bin/python -m pytest tests/test_web.py::test_db_error_returns_503_not_500 -v`
Expected: FAIL — the error currently propagates as an unhandled 500.

- [ ] **Step 4: Register the 503 handler in `create_app`** — in `halcyon/web.py`, near the top of `create_app` (after `app = FastAPI(...)`), add:

```python
    import psycopg
    import psycopg_pool
    from fastapi.responses import JSONResponse

    @app.exception_handler(psycopg.OperationalError)
    @app.exception_handler(psycopg_pool.PoolTimeout)
    async def _db_busy(_request, _exc):  # type: ignore[no-untyped-def]
        return JSONResponse(
            status_code=503,
            content={"error": "database busy, please retry"},
            headers={"Retry-After": "1"},
        )
```

- [ ] **Step 5: Rewrite `halcyon/pg_store.py` to use a pool**

Replace the file with (pool opened in `__init__`; every op uses `self._pool.connection()`):

```python
import json
import os
from pathlib import Path

import psycopg
from psycopg_pool import ConnectionPool

from halcyon.store import MODULE_RESET, Event

_SCHEMA = (Path(__file__).parent / "schema.sql").read_text()


def init_schema(dsn: str) -> None:
    with psycopg.connect(dsn) as conn:
        conn.execute(_SCHEMA)
        conn.commit()


class PostgresStore:
    def __init__(self, dsn: str, max_size: int | None = None) -> None:
        self._dsn = dsn
        size = max_size if max_size is not None else int(os.environ.get("EIGER_DB_POOL_MAX", "10"))
        # open=True: establish min connections now; check_timeout keeps a hung conn from wedging.
        self._pool = ConnectionPool(dsn, min_size=1, max_size=size, open=True, timeout=10.0)

    def append_event(
        self, session_id: str, module: str, event_type: str, actor: str, details: dict
    ) -> None:
        with self._pool.connection() as conn:
            conn.execute(
                "INSERT INTO audit_log (session_id, module, event_type, actor, details) "
                "VALUES (%s, %s, %s, %s, %s)",
                (session_id, module, event_type, actor, json.dumps(details or {})),
            )

    def events_since_reset(self, session_id: str, module: str) -> list[Event]:
        with self._pool.connection() as conn:
            row = conn.execute(
                "SELECT COALESCE(MAX(id), 0) FROM audit_log "
                "WHERE session_id=%s AND module=%s AND event_type=%s",
                (session_id, module, MODULE_RESET),
            ).fetchone()
            last_reset = row[0] if row else 0
            rows = conn.execute(
                "SELECT session_id, module, event_type, actor, details, id "
                "FROM audit_log WHERE session_id=%s AND module=%s AND id>%s "
                "AND event_type<>%s ORDER BY id",
                (session_id, module, last_reset, MODULE_RESET),
            ).fetchall()
        return [Event(r[0], r[1], r[2], r[3], r[4], r[5]) for r in rows]

    def write_reset_marker(self, session_id: str, module: str) -> None:
        self.append_event(session_id, module, MODULE_RESET, session_id, {})

    def get_progress(self, session_id: str, module: str) -> tuple[bool, bool]:
        with self._pool.connection() as conn:
            row = conn.execute(
                "SELECT core, stretch FROM progress WHERE session_id=%s AND module=%s",
                (session_id, module),
            ).fetchone()
        return (row[0], row[1]) if row else (False, False)

    def upsert_progress(
        self, session_id: str, module: str, core: bool, stretch: bool
    ) -> None:
        with self._pool.connection() as conn:
            conn.execute(
                "INSERT INTO progress (session_id, module, core, stretch, updated_at) "
                "VALUES (%s, %s, %s, %s, now()) "
                "ON CONFLICT (session_id, module) DO UPDATE SET "
                "core=EXCLUDED.core, stretch=EXCLUDED.stretch, updated_at=now()",
                (session_id, module, core, stretch),
            )

    def set_profile(self, session_id: str, display_name: str) -> None:
        with self._pool.connection() as conn:
            conn.execute(
                "INSERT INTO profile (session_id, display_name) VALUES (%s, %s) "
                "ON CONFLICT (session_id) DO UPDATE SET display_name=EXCLUDED.display_name",
                (session_id, display_name),
            )

    def get_profile(self, session_id: str) -> str:
        with self._pool.connection() as conn:
            row = conn.execute(
                "SELECT display_name FROM profile WHERE session_id=%s", (session_id,)
            ).fetchone()
        return row[0] if row else ""

    def list_sessions(self) -> list[str]:
        with self._pool.connection() as conn:
            rows = conn.execute(
                "SELECT DISTINCT session_id FROM audit_log ORDER BY session_id"
            ).fetchall()
        return [r[0] for r in rows]

    def ping(self) -> bool:
        try:
            with self._pool.connection() as conn:
                conn.execute("SELECT 1")
            return True
        except psycopg.Error:
            return False
```

Note: `psycopg_pool` auto-commits on clean `connection()` block exit (it does not run in autocommit but commits when the context manager closes without error), so the explicit `conn.commit()` calls are dropped — writes still commit. `init_schema` keeps its own direct connect (one-shot at boot).

- [ ] **Step 6: Add a pool round-trip assertion to the gated Postgres test**

In `tests/test_store_postgres.py`, add (inside the existing skip-if-no-DB guard pattern used by that file):

```python
def test_pool_round_trips(pg_dsn):  # pg_dsn = the existing fixture/skip guard in this file
    store = PostgresStore(pg_dsn, max_size=3)
    store.append_event("s", "m1", "e", "s", {})
    assert store.ping() is True
    assert "s" in store.list_sessions()
```
(Match the file's existing fixture/skip mechanism for obtaining `pg_dsn`; if it constructs `PostgresStore` inline, mirror that.)

- [ ] **Step 7: Verify + gates**

Run: `.venv/bin/python -m pytest tests/test_web.py::test_db_error_returns_503_not_500 -v && .venv/bin/python -m pytest -q && .venv/bin/ruff check halcyon tests && .venv/bin/mypy halcyon`
Expected: 503 test passes; full suite green (the Postgres test skips without a DB — that's fine); ruff + mypy clean.

- [ ] **Step 8: Commit**

```bash
git add pyproject.toml uv.lock halcyon/pg_store.py halcyon/web.py tests/test_web.py tests/test_store_postgres.py
git commit -m "fix(#1): pool Postgres connections + 503 on exhaustion

PostgresStore opened a new psycopg connection per op (9 sites); one
/api/agent request writes many audit rows, so ~8 concurrent requests
exhausted max_connections and 500'd. Use psycopg_pool.ConnectionPool and
map OperationalError/PoolTimeout to a retryable 503.

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

---

### Task 3: #6 — M4 self-sufficient download bundle + require the pin

**Files:**
- Modify: `Dockerfile` (`COPY labs ./labs`)
- Modify: `halcyon/m4_answers.py` (pin the package answer; keep the version in normalize)
- Modify: `halcyon/web.py` (new `GET /api/m4/bundle`)
- Modify: `halcyon/templates/chat.html` (a "Download audit bundle" link in the M4 panel)
- Test: `tests/test_m4_answers.py`, `tests/test_web.py`

**Interfaces:**
- Produces: `GET /api/m4/bundle` → `application/zip`; `m4_answers.VULNERABLE_PACKAGE == "pyyaml==5.3.1"` with `normalize_package` preserving the version.

- [ ] **Step 1: Write the failing tests** — add to `tests/test_m4_answers.py`:

```python
def test_stretch_requires_version_pin():
    from halcyon import m4_answers
    assert m4_answers.normalize_package("pyyaml") != m4_answers.VULNERABLE_PACKAGE       # bare fails
    assert m4_answers.normalize_package("PyYAML==5.3.1") == m4_answers.VULNERABLE_PACKAGE  # pin passes
```

and to `tests/test_web.py`:

```python
def test_m4_bundle_download():
    import io, zipfile
    client, _ = make_client({"HALCYON_MODE": "vulnerable"}, "hi")
    r = client.get("/api/m4/bundle")
    assert r.status_code == 200
    assert r.headers["content-type"] == "application/zip"
    names = zipfile.ZipFile(io.BytesIO(r.content)).namelist()
    assert any(n.endswith("scan_artifact.py") for n in names)
    assert any("requirements-vulnerable.txt" in n for n in names)
    assert any(n.endswith("README.md") for n in names)
    assert any(n.endswith(".pkl") or "artifact" in n for n in names)  # the poisoned artifact
```

- [ ] **Step 2: Run them — expect FAIL**

Run: `.venv/bin/python -m pytest tests/test_m4_answers.py::test_stretch_requires_version_pin tests/test_web.py::test_m4_bundle_download -v`
Expected: both FAIL — `VULNERABLE_PACKAGE` is bare `pyyaml`; no `/api/m4/bundle` route.

- [ ] **Step 3: Pin the package answer** — in `halcyon/m4_answers.py`:

```python
VULNERABLE_PACKAGE = "pyyaml==5.3.1"  # CVE-2020-14343


def normalize_package(value: str) -> str:
    # keep the version pin; normalize only whitespace/case and underscores
    return value.strip().lower().replace("_", "-")
```

- [ ] **Step 4: Add the bundle endpoint** — in `halcyon/web.py`, add (near the other `/submit/m4`/`/api` routes):

```python
    import io
    import zipfile

    _LABS_M4 = Path(__file__).parent.parent / "labs" / "m4"

    _M4_README = (
        "# M4 supply-chain audit bundle\n\n"
        "1. SCAN the artifact — do NOT run/unpickle it:\n"
        "   python scan_artifact.py artifacts/<file>\n"
        "   (no Python? hash it: shasum -a 256 artifacts/<file>)\n"
        "   Submit the poisoned artifact's sha256 as the malicious artifact.\n\n"
        "2. Read requirements-vulnerable.txt and submit the vulnerable pin "
        "(name==version) as the vulnerable dependency.\n\n"
        "WARNING: the artifact is a real malicious pickle. Scan or hash it only; "
        "loading it with pickle.load executes attacker code on your machine.\n"
    )

    @app.get("/api/m4/bundle")
    def m4_bundle() -> Response:
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
            for art in sorted((_LABS_M4 / "artifacts").glob("*")):
                if art.is_file():
                    z.write(art, f"artifacts/{art.name}")
            req = _LABS_M4 / "requirements-vulnerable.txt"
            if req.exists():
                z.write(req, "requirements-vulnerable.txt")
            z.write(Path(__file__).parent / "scan_artifact.py", "scan_artifact.py")
            z.writestr("README.md", _M4_README)
        return Response(content=buf.getvalue(), media_type="application/zip",
                        headers={"Content-Disposition": "attachment; filename=eiger-m4-audit.zip"})
```
(`Response` and `Path` are already imported in `web.py`.)

- [ ] **Step 5: Add the panel link** — in `halcyon/templates/chat.html`, inside the L2 panel's M4 block (near the `m4hash`/`m4pkg` inputs), add a download control. Keep it `textContent`/anchor only (no new JS needed — it's a plain download link):

```html
      <p><a id="m4-bundle" href="/api/m4/bundle">Download audit bundle (artifact + scanner + README)</a></p>
```
Place it right after the M4 `<h3>`/intro `<p>` and before the `m4hash` row.

- [ ] **Step 6: Add `COPY labs`** — in `Dockerfile`, after `COPY halcyon ./halcyon`:

```dockerfile
COPY halcyon ./halcyon
COPY labs ./labs
```

- [ ] **Step 7: Verify + gates**

Run: `.venv/bin/python -m pytest tests/test_m4_answers.py tests/test_web.py -q && .venv/bin/python -m pytest -q && .venv/bin/ruff check halcyon tests && .venv/bin/mypy halcyon`
Expected: the two new tests pass; the existing M4 submit/validator tests still pass (they submit the sha256 for core, unaffected; any that submitted bare `pyyaml` for stretch must be updated to `pyyaml==5.3.1` — update them if present). Full suite green; gates clean.

- [ ] **Step 8: Commit**

```bash
git add Dockerfile halcyon/m4_answers.py halcyon/web.py halcyon/templates/chat.html tests/test_m4_answers.py tests/test_web.py
git commit -m "fix(#6): serve M4 audit bundle + require the version pin

Bake labs/ into the image and serve GET /api/m4/bundle (poisoned
artifact + stdlib scanner + requirements-vulnerable.txt + README) so a
hosted participant can complete M4 by scanning/hashing locally. Stretch
now requires pyyaml==5.3.1 so a bare-name guess no longer passes.

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

---

### Task 4: #2/#3 — In-process per-session Bank + KB

**Files:**
- Create: `halcyon/session_resources.py` (providers + `slug`)
- Modify: `halcyon/chroma_kb.py` (per-instance collection name)
- Modify: `halcyon/web.py` (`create_app` signature: `kb, bank` → `kb_for, bank_for`; handlers + reset resolve per session)
- Modify: `halcyon/main.py` (build providers; MCP factory uses `bank_for`)
- Modify: every `create_app(...)` test caller (6 files, 12 sites) → pass `lambda sid: shared` shims
- Test: `tests/test_session_resources.py` (new), `tests/test_web.py` (isolation)

**Interfaces:**
- Consumes: `bank_fixtures.seed_for(session_id)`, `kb_fixtures.SEED`, `Bank`, `KnowledgeBase`.
- Produces:
  - `session_resources.slug(session_id: str) -> str` (Chroma-legal collection name).
  - `session_resources.BankProvider(seed_for)` — callable `(session_id) -> Bank`, lazily created+seeded, memoized per session.
  - `session_resources.KBProvider(make_kb, seed)` — callable `(session_id) -> KnowledgeBase`, lazily created+seeded, memoized per session.
  - `create_app(store, settings, llm_factory, kb_for, bank_for, tool_llm_factory, mcp_host_factory, session_state=None)` where `kb_for: Callable[[str], KnowledgeBase]`, `bank_for: Callable[[str], Bank]`.
  - `mcp_host_factory(session_id, settings)` unchanged in shape; in `main.py` it now builds the host with `bank_for(session_id)`.

- [ ] **Step 1: Write the failing provider + isolation tests**

Create `tests/test_session_resources.py`:

```python
from halcyon import bank_fixtures, kb_fixtures
from halcyon.kb import InMemoryKB
from halcyon.session_resources import BankProvider, KBProvider, slug


def test_slug_is_chroma_legal_and_stable():
    s = slug("some/weird session:id")
    assert 3 <= len(s) <= 63
    assert s.replace("-", "").replace("_", "").isalnum()
    assert s[0].isalnum() and s[-1].isalnum()
    assert slug("x") == slug("x")  # stable


def test_bank_provider_isolates_and_memoizes():
    bank_for = BankProvider(bank_fixtures.seed_for)
    a1 = bank_for("A")
    a2 = bank_for("A")
    b = bank_for("B")
    assert a1 is a2                       # memoized per session
    assert a1 is not b                    # isolated per session
    # A draining its own view does not change B's balances
    acct = "acct-victim"
    a1.debit(acct, 100)
    assert b.get(acct).balance != a1.get(acct).balance


def test_kb_provider_isolates_user_chunks():
    kb_for = KBProvider(lambda sid: InMemoryKB(), kb_fixtures.SEED)
    a = kb_for("A")
    b = kb_for("B")
    assert a is not b
    a.add("PWNED-note secret", "user", owner_session="A")
    # B never sees A's user chunk
    assert all("PWNED-note" not in c.text for c in b.retrieve("secret", "B"))
```

and the endpoint-level isolation test in `tests/test_web.py` (uses real per-session providers, not the shim):

```python
def test_reset_and_kb_are_session_isolated():
    from halcyon import bank_fixtures, crm_fixtures, kb_fixtures
    from halcyon.kb import InMemoryKB
    from halcyon.session_resources import BankProvider, KBProvider
    settings = load_settings({"HALCYON_MODE": "vulnerable"})
    store = InMemoryStore()
    vault = TokenVault({SERVER_CORE: "c", SERVER_CRM: "d"})
    bank_for = BankProvider(bank_fixtures.seed_for)
    kb_for = KBProvider(lambda sid: InMemoryKB(), kb_fixtures.SEED)
    tool_llm_factory = lambda p, m, k: StubToolLLM([FinalAnswer("ok")])  # noqa: E731
    mcp_host_factory = lambda sid, s: in_memory_host(  # noqa: E731
        bank_for(sid), vault, crm_fixtures.SEED, store, s, sid)
    app = create_app(store, settings, lambda p, m, k: StubLLM(""),
                     kb_for, bank_for, tool_llm_factory, mcp_host_factory)
    client = TestClient(app)
    # A poisons the KB; B must not retrieve it
    client.post("/api/kb", json={"session_id": "A", "text": "PWNED-M3 secret note"})
    rb = client.post("/api/ask", json={"session_id": "B", "query": "secret note"}).json()
    assert "PWNED-M3" not in rb.get("reply", "")
    # A resets m5; B's bank is untouched (B still owns its own acct-me)
    client.post("/reset/m5", json={"session_id": "A"})
    assert bank_for("B").owns("B", "acct-me")
```

- [ ] **Step 2: Run them — expect FAIL**

Run: `.venv/bin/python -m pytest tests/test_session_resources.py tests/test_web.py::test_reset_and_kb_are_session_isolated -v`
Expected: FAIL — `session_resources` does not exist; `create_app` does not accept providers.

- [ ] **Step 3: Create `halcyon/session_resources.py`**

```python
"""Per-session, in-process resource providers.

Bank and KB state is re-seedable fixture data, so it lives in the app process
keyed by session_id (progress + audit already persist in the external store).
This isolates the 22 participants from each other; it is NOT RCE isolation.
"""
import hashlib
from collections.abc import Callable

from halcyon.bank import Bank
from halcyon.kb import KnowledgeBase


def slug(session_id: str) -> str:
    """A Chroma-legal collection name (3-63 chars, [a-zA-Z0-9_-], alnum ends)."""
    return "s" + hashlib.sha1(session_id.encode()).hexdigest()[:32]


class BankProvider:
    def __init__(self, seed_for: Callable[[str], list[dict]]) -> None:
        self._seed_for = seed_for
        self._banks: dict[str, Bank] = {}

    def __call__(self, session_id: str) -> Bank:
        bank = self._banks.get(session_id)
        if bank is None:
            bank = Bank()
            bank.seed(self._seed_for(session_id))
            self._banks[session_id] = bank
        return bank


class KBProvider:
    def __init__(self, make_kb: Callable[[str], KnowledgeBase], seed: list[dict]) -> None:
        self._make_kb = make_kb
        self._seed = seed
        self._kbs: dict[str, KnowledgeBase] = {}

    def __call__(self, session_id: str) -> KnowledgeBase:
        kb = self._kbs.get(session_id)
        if kb is None:
            kb = self._make_kb(session_id)
            kb.seed(self._seed)
            self._kbs[session_id] = kb
        return kb
```

- [ ] **Step 4: Per-instance collection in `ChromaKB`** — in `halcyon/chroma_kb.py`, change `__init__` and `clear`:

```python
    def __init__(self, collection: str = "halcyon") -> None:
        self._client = chromadb.Client()
        self._name = collection
        self._collection = self._client.get_or_create_collection(collection)
        self._seq = 0
```
and wherever `clear()` currently calls `delete_collection("halcyon")`, use the instance name and recreate:
```python
    def clear(self) -> None:
        self._client.delete_collection(self._name)
        self._collection = self._client.get_or_create_collection(self._name)
        self._seq = 0
```

- [ ] **Step 5: Refactor `create_app` to use providers** — in `halcyon/web.py`:

Change the signature params `kb: KnowledgeBase, bank: Bank` to:
```python
    kb_for: Callable[[str], KnowledgeBase],
    bank_for: Callable[[str], Bank],
```
Then in each handler, resolve per session at the top of the handler body:
- `/api/kb`: `kb = kb_for(body.session_id)` before `kb.add(...)`.
- `/api/ask`: `kb = kb_for(body.session_id)`; pass it into `rag.answer(kb, ...)`.
- `/api/agent`: `bank = bank_for(body.session_id)` before `agent.run(..., bank, ...)`.
- `/api/dispute`: `bank = bank_for(body.session_id)` before `dispute_pipeline.run_dispute(..., bank, ...)`.
- `/reset/{module}` — replace the global clear/seed with per-session resets:
```python
        if module == "m3":
            kb = kb_for(body.session_id)
            kb.clear()
            kb.seed(kb_fixtures.SEED)
        if module in ("m5", "m6", "m7"):
            bank = bank_for(body.session_id)
            bank.clear()
            bank.seed(bank_fixtures.seed_for(body.session_id))
```
(`/api/mcp-agent` gets its bank via `mcp_host_factory`, which `main.py` wires to `bank_for` — no change inside the handler beyond what Task exists.)

- [ ] **Step 6: Wire providers in `main.py`**

Replace the singletons and pass providers:
```python
from halcyon.session_resources import BankProvider, KBProvider, slug
from halcyon.chroma_kb import ChromaKB
...
_kb_for = KBProvider(lambda sid: ChromaKB(collection=slug(sid)), kb_fixtures.SEED)
_bank_for = BankProvider(bank_fixtures.seed_for)
```
Delete `_kb = ChromaKB(); _kb.seed(...)` and `_bank = Bank()`. Update both `_mcp_host_factory(session_id, settings)` closures to build with `_bank_for(session_id)` instead of `_bank`. Update the final `create_app(...)` call to pass `_kb_for, _bank_for` in place of `_kb, _bank`.

- [ ] **Step 7: Update the test `create_app` callers (shims)**

In each of the 6 test files that call `create_app(...)` (`tests/test_web.py`, `tests/test_web_m6.py`, `tests/test_web_m7.py`, `tests/test_web_m8.py`, `tests/test_chat_memory_endpoint.py`, `tests/test_model_config.py`), the current call passes a `kb`/`bank` singleton. Wrap them so behavior is unchanged:
- replace the `kb` argument with `lambda sid: kb` and the `bank` argument with `lambda sid: bank` (a shared instance → identical behavior to today).
Do NOT change the new `test_reset_and_kb_are_session_isolated`, which passes real providers.
Run `grep -rn 'create_app(' tests/` to find all 12 call sites; update each.

- [ ] **Step 8: Verify + gates**

Run: `.venv/bin/python -m pytest tests/test_session_resources.py tests/test_web.py -v && .venv/bin/python -m pytest -q && .venv/bin/ruff check halcyon tests && .venv/bin/mypy halcyon`
Expected: the new provider + isolation tests pass; every existing endpoint/validator test (M3/M5/M6/M7 incl. the S9.x memory/level/config tests) still passes via the shims; full suite green; ruff + mypy clean.

- [ ] **Step 9: Commit**

```bash
git add halcyon/session_resources.py halcyon/chroma_kb.py halcyon/web.py halcyon/main.py tests/
git commit -m "fix(#2,#3): per-session Bank + KB, isolated resets

Replace the process-global Bank/ChromaKB with in-process per-session
providers resolved per request; /reset clears only the caller's session;
each session gets its own Chroma collection so user-submitted chunks
can't leak across participants. In-process + re-seedable (progress/audit
still persist in the store). Not RCE isolation.

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

---

### Task 5: Local black-box acceptance

No production code. Rebuild the local stack and run the live oracle to confirm #1 and #6 flipped.

**Files:** none.

- [ ] **Step 1: Rebuild + redeploy web locally**

Run: `cd /Users/kkmookhey/Projects/eiger && docker compose -p halcyon up -d --no-deps --build web`, wait for `curl -sf http://localhost:8010/health`.

- [ ] **Step 2: Run the regression oracle against the local instance**

Run:
```bash
cd /Users/kkmookhey/Projects/eiger
EIGER_BASE_URL=http://localhost:8010 .venv/bin/python docs/labs/blackbox/blackbox.py regressions
```
Expected: **#1 (no 5xx under concurrency)** and **#6 (m4 stretch needs version pin)** now PASS. #4 and #5 remain FAIL (out of scope for this batch — that's expected and correct).

- [ ] **Step 3: Spot-check isolation + openapi live**

Run:
```bash
cd /Users/kkmookhey/Projects/eiger
curl -s -o /dev/null -w "%{http_code}\n" http://localhost:8010/openapi.json   # expect 404
curl -sf http://localhost:8010/api/m4/bundle -o /tmp/eiger-m4.zip && unzip -l /tmp/eiger-m4.zip   # bundle contents
```
Expected: `/openapi.json` → 404; the bundle lists the artifact, `requirements-vulnerable.txt`, `scan_artifact.py`, `README.md`.

- [ ] **Step 4: Record the result** — note the regressions board (expect 2/4 fixed: #1, #6). If #1 or #6 still fails, diagnose against the finding and fix in the owning task (re-run its tests to stay green). No commit unless a fix was made.

---

## Self-Review

**Spec coverage** (against `2026-07-30-blackbox-hardening-batch1-design.md`):
- #1 pool + 503 → Task 2. ✓
- #2/#3 per-session Bank+KB, per-session collection, scoped reset, provider wiring, MCP bank → Task 4. ✓
- #6 COPY labs + bundle endpoint + panel link + pin → Task 3. ✓
- #8 openapi setting + gated FastAPI → Task 1. ✓
- Live oracle (#1/#6 flip) → Task 5. ✓
- Out-of-scope (#4/#5/#7/#9, RCE) → not in any task, per spec. ✓

**Placeholder scan:** no TBD/TODO; each code step has concrete code or an exact command. The one soft spot — `tests/test_store_postgres.py` fixture name (`pg_dsn`) — is called out to "match the file's existing mechanism", since that file's skip guard wasn't quoted here; the implementer reads that file. Acceptable (the test is DB-gated and not on the critical path).

**Type/name consistency:** `bank_for`/`kb_for` provider callables are named identically across `create_app` (Task 4 Step 5), `main.py` (Step 6), the test shims (Step 7), and the isolation test (Step 1). `slug`, `BankProvider`, `KBProvider` match between `session_resources.py` (Step 3) and their tests (Step 1). `VULNERABLE_PACKAGE == "pyyaml==5.3.1"` matches between Task 3 Step 3 and its test Step 1. `EIGER_EXPOSE_OPENAPI`/`EIGER_DB_POOL_MAX` match between config, pg_store, and tests. `expose_openapi` field matches between `Settings` and `create_app`.
