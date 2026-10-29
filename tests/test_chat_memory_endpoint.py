from fastapi.testclient import TestClient

from halcyon import bank_fixtures, crm_fixtures, kb_fixtures  # noqa: F401
from halcyon.bank import Bank
from halcyon.config import load_settings
from halcyon.kb import InMemoryKB
from halcyon.llm import FinalAnswer, StubLLM, StubToolLLM
from halcyon.mcp_host import in_memory_host
from halcyon.mcp_vault import SERVER_CORE, SERVER_CRM, TokenVault
from halcyon.session_state import InMemorySessionState
from halcyon.store import InMemoryStore
from halcyon.web import create_app


def make_client(reply="stub-reply", mode="vulnerable"):
    store = InMemoryStore()
    settings = load_settings({"HALCYON_MODE": mode})
    kb = InMemoryKB()
    kb.seed(kb_fixtures.SEED)
    bank = Bank()
    vault = TokenVault({SERVER_CORE: "core-token", SERVER_CRM: "crm-token"})
    ss = InMemorySessionState()
    tool_llm_factory = lambda p, m, k: StubToolLLM([FinalAnswer("(no agent)")])  # noqa: E731
    mcp_host_factory = lambda sid, _s: in_memory_host(  # noqa: E731
        bank, vault, crm_fixtures.SEED, store, settings, sid
    )
    app = create_app(
        store, settings, lambda p, m, k: StubLLM(reply),
        lambda sid: kb, lambda sid: bank,
        tool_llm_factory, mcp_host_factory, session_state=ss,
    )
    return TestClient(app), ss


def test_chat_history_grows_across_requests():
    client, ss = make_client(reply="R")
    client.post("/api/chat", json={"session_id": "u1", "message": "one"})
    client.post("/api/chat", json={"session_id": "u1", "message": "two"})
    hist = ss.get_history("u1", "chat")
    assert [m["content"] for m in hist] == ["one", "R", "two", "R"]


def test_reset_m1_clears_chat_history():
    client, ss = make_client(reply="R")
    client.post("/api/chat", json={"session_id": "u1", "message": "one"})
    client.post("/reset/m1", json={"session_id": "u1"})
    assert ss.get_history("u1", "chat") == []
