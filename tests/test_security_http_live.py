"""Opt-in test of the real SDK HTTP client, signed delegation and service executor."""

import os
import socket
import threading
import time
import json
import anyio
import pytest
import uvicorn
from halcyon.bank import Bank
from halcyon.config import load_settings
from halcyon.mcp_deploy import core_banking_app, crm_app
from halcyon.mcp_host import http_host
from halcyon.mcp_vault import TokenVault, SERVER_CORE, SERVER_CRM
from halcyon.store import InMemoryStore

pytestmark = pytest.mark.skipif(
    os.getenv("RUN_SECURITY_HTTP_TESTS") != "1",
    reason="requires explicit localhost HTTP test opt-in",
)


def test_sdk_http_preserves_identity_and_authorized_operations(monkeypatch):
    monkeypatch.setenv("HALCYON_MODE", "secure")
    monkeypatch.setenv("HALCYON_PROFILE", "lab")
    monkeypatch.setenv("HALCYON_MCP_CORE_DELEGATION_SECRET", "core-delegation-test-secret-0123456789")
    monkeypatch.setenv("HALCYON_MCP_CRM_DELEGATION_SECRET", "crm-delegation-test-secret-0123456789")
    bank = Bank()
    bank.seed(
        [
            {"id": "alice", "owner_session": "alice", "balance": 100, "email": "a@example.test"},
            {"id": "bob", "owner_session": "bob", "balance": 0, "email": "b@example.test"},
        ]
    )
    vault = TokenVault({
        SERVER_CORE: "live-core-secret-0123456789-abcdef",
        SERVER_CRM: "live-crm-secret-0123456789-abcdef",
    })
    servers = []
    threads = []
    sockets = []
    urls = []
    try:
        for app in (core_banking_app(bank, vault), crm_app(bank, vault, {})):
            sock = socket.socket()
            sock.bind(("127.0.0.1", 0))
            sock.listen()
            sockets.append(sock)
            urls.append("http://127.0.0.1:" + str(sock.getsockname()[1]) + "/mcp")
            server = uvicorn.Server(uvicorn.Config(app, log_level="error"))
            servers.append(server)
            thread = threading.Thread(target=server.run, kwargs={"sockets": [sock]}, daemon=True)
            thread.start()
            threads.append(thread)
        for _ in range(100):
            if all(s.started for s in servers):
                break
            time.sleep(0.05)
        assert all(s.started for s in servers)

        async def run():
            settings = load_settings({"HALCYON_MODE": "secure"})
            async with http_host(*urls, vault, InMemoryStore(), settings, "alice") as host:
                tools = await host.list_tools()
                host.approve(tools)
                assert "core_banking__transfer_funds" in {
                    s["name"] for s in await host.schemas_for_llm()
                }
                result = json.loads(
                    await host.call(
                        "core_banking__transfer_funds",
                        {
                            "from_account": "alice",
                            "to_account": "bob",
                            "amount": 10,
                            "idempotency_key": "live-one",
                        },
                    )
                )
                assert result["status"] == "success"
                denied = await host.call("core_banking__get_account_details", {"account": "bob"})
                assert "denied" in denied and "b@example.test" not in denied
            assert bank.get("alice").balance == 90 and bank.get("bob").balance == 10

        anyio.run(run)
    finally:
        for server in servers:
            server.should_exit = True
        for thread in threads:
            thread.join(timeout=5)
        for sock in sockets:
            sock.close()
