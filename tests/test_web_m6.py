import pytest
from fastapi.testclient import TestClient

from halcyon import audit, crm_fixtures, kb_fixtures
from halcyon.bank import Bank
from halcyon.config import load_settings
from halcyon.kb import InMemoryKB
from halcyon.llm import FinalAnswer, StubLLM, StubToolLLM, ToolCall
from halcyon.mcp_host import in_memory_host
from halcyon.mcp_vault import SERVER_CORE, SERVER_CRM, TokenVault
from halcyon.store import InMemoryStore
from halcyon.web import create_app


@pytest.fixture
def m6_client():
    store = InMemoryStore()
    settings = load_settings({"HALCYON_MODE": "vulnerable"})
    kb = InMemoryKB()
    kb.seed(kb_fixtures.SEED)
    bank = Bank()
    vault = TokenVault({SERVER_CORE: "core-token", SERVER_CRM: "crm-token"})
    tool_llm_factory = lambda p, m, k: StubToolLLM([FinalAnswer("ok")])  # noqa: E731
    mcp_host_factory = lambda sid, _s: in_memory_host(  # noqa: E731
        bank, vault, crm_fixtures.SEED, store, settings, sid
    )
    app = create_app(
        store, settings, lambda provider, model, api_key: StubLLM(""),
        lambda sid: kb, lambda sid: bank,
        tool_llm_factory, mcp_host_factory,
    )
    return TestClient(app)


def test_mcp_agent_endpoint_and_validate(m6_client):
    r = m6_client.post("/api/mcp-agent", json={"session_id": "s", "message": "hi"})
    assert r.status_code == 200
    assert "reply" in r.json() and "tool_calls" in r.json()
    assert m6_client.get("/validate/m6", params={"session": "s"}).status_code == 200
    assert m6_client.post("/reset/m6", json={"session_id": "s"}).json()["status"] == "reset"


def test_m6_level_flip_is_per_session_no_restart():
    """Flipping M6 to L2 via /api/level must engage the MCP token-scoping guard for
    that session on the next request — no process restart — while a default (L1)
    session in the same app stays vulnerable."""
    store = InMemoryStore()
    settings = load_settings({"HALCYON_MODE": "vulnerable"})
    kb = InMemoryKB()
    kb.seed(kb_fixtures.SEED)
    bank = Bank()
    vault = TokenVault({SERVER_CORE: "core-token", SERVER_CRM: "crm-token"})
    # every request: a stub that tries to steal the cross-service integration token
    tool_llm_factory = lambda p, m, k: StubToolLLM([  # noqa: E731
        ToolCall("crm__get_integration_token", {"service": SERVER_CORE}),
        FinalAnswer("done"),
    ])
    # the endpoint resolves per-session effective settings and passes them in; the
    # `s=None` default lets this shim survive both the old (1-arg) and new (2-arg) call.
    mcp_host_factory = lambda sid, s=None: in_memory_host(  # noqa: E731
        bank, vault, crm_fixtures.SEED, store, s or settings, sid
    )
    app = create_app(
        store, settings, lambda p, m, k: StubLLM(""),
        lambda sid: kb, lambda sid: bank,
        tool_llm_factory, mcp_host_factory,
    )
    client = TestClient(app)

    # default L1 session: token scoping off -> theft succeeds (TOKEN_READ recorded)
    client.post("/api/mcp-agent", json={"session_id": "vuln", "message": "sync"})
    assert audit.has_event(store, "vuln", "m6", audit.TOKEN_READ)

    # a different session flips M6 to L2 in the same running app (no restart)
    client.post("/api/level", json={"session_id": "sec", "module": "m6", "level": "L2"})
    client.post("/api/mcp-agent", json={"session_id": "sec", "message": "sync"})
    # token scoping now engaged for this session -> access denied, no TOKEN_READ
    assert not audit.has_event(store, "sec", "m6", audit.TOKEN_READ)


def test_health_reports_mcp_key(monkeypatch):
    monkeypatch.delenv("MCP_CORE_URL", raising=False)
    monkeypatch.delenv("MCP_CRM_URL", raising=False)
    store = InMemoryStore()
    settings = load_settings({"HALCYON_MODE": "vulnerable"})
    kb = InMemoryKB()
    kb.seed(kb_fixtures.SEED)
    bank = Bank()
    vault = TokenVault({SERVER_CORE: "core-token", SERVER_CRM: "crm-token"})
    tool_llm_factory = lambda p, m, k: StubToolLLM([FinalAnswer("ok")])  # noqa: E731
    mcp_host_factory = lambda sid, _s: in_memory_host(  # noqa: E731
        bank, vault, crm_fixtures.SEED, store, settings, sid
    )
    app = create_app(
        store, settings, lambda provider, model, api_key: StubLLM(""),
        lambda sid: kb, lambda sid: bank,
        tool_llm_factory, mcp_host_factory,
    )
    client = TestClient(app)
    r = client.get("/health")
    assert r.status_code == 200
    assert r.json()["mcp"] == "in-process"
