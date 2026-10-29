from fastapi.testclient import TestClient

from halcyon import crm_fixtures, kb_fixtures
from halcyon.bank import Bank
from halcyon.config import load_settings
from halcyon.kb import InMemoryKB
from halcyon.llm import FinalAnswer, StubLLM, StubToolLLM
from halcyon.mcp_host import in_memory_host
from halcyon.mcp_vault import SERVER_CORE, SERVER_CRM, TokenVault
from halcyon.session_state import InMemorySessionState
from halcyon.store import InMemoryStore
from halcyon.web import create_app


def make_client_capturing():
    """App whose llm_factory records the (provider, model, api_key) it was called with."""
    captured: list = []
    store = InMemoryStore()
    settings = load_settings({"HALCYON_MODE": "vulnerable"})
    kb = InMemoryKB()
    kb.seed(kb_fixtures.SEED)
    bank = Bank()
    vault = TokenVault({SERVER_CORE: "c", SERVER_CRM: "d"})
    ss = InMemorySessionState()

    def llm_factory(p, m, k):
        captured.append((p, m, k))
        return StubLLM("R")

    tool_llm_factory = lambda p, m, k: StubToolLLM([FinalAnswer("x")])  # noqa: E731
    mcp_host_factory = lambda sid, _s: in_memory_host(  # noqa: E731
        bank, vault, crm_fixtures.SEED, store, settings, sid
    )
    app = create_app(
        store, settings, llm_factory, lambda sid: kb, lambda sid: bank,
        tool_llm_factory, mcp_host_factory,
        session_state=ss,
    )
    return TestClient(app), captured


def test_chat_uses_session_model_config_when_request_omits_it():
    client, captured = make_client_capturing()
    client.post("/api/config", json={
        "session_id": "u1", "provider": "anthropic",
        "model": "claude-haiku-4-5", "api_key": "sk-x",
    })
    client.post("/api/chat", json={"session_id": "u1", "message": "hi"})
    assert captured[-1] == ("anthropic", "claude-haiku-4-5", "sk-x")


def test_explicit_request_values_win_over_session_config():
    client, captured = make_client_capturing()
    client.post("/api/config", json={"session_id": "u1", "provider": "anthropic", "api_key": "sk-x"})
    client.post("/api/chat", json={
        "session_id": "u1", "message": "hi", "provider": "openai", "api_key": "sk-y",
    })
    assert captured[-1] == ("openai", None, "sk-y")


def test_get_config_never_returns_api_key():
    client, _ = make_client_capturing()
    client.post("/api/config", json={"session_id": "u1", "provider": "xai", "api_key": "sk-secret"})
    got = client.get("/api/config", params={"session": "u1"}).json()
    assert got["provider"] == "xai"
    assert "sk-secret" not in str(got)
