"""Run inside the built image against a disposable PostgreSQL database only.

Requires EIGER_DISPOSABLE_SMOKE=1 and production credentials in the environment.
Creates test accounts in a fresh bank namespace; refuses any existing accounts.
"""

import asyncio
import json
import os
import subprocess
import time

import httpx
import psycopg


def main():
    if os.environ.get("EIGER_DISPOSABLE_SMOKE") != "1":
        raise SystemExit("Explicit disposable database opt-in required")
    from halcyon.security.ledger import PostgresBank, init_ledger_schema
    from halcyon.config import load_settings
    from halcyon.mcp_host import http_host
    from halcyon.mcp_vault import TokenVault, SERVER_CORE, SERVER_CRM
    from halcyon.store import InMemoryStore

    dsn = os.environ["DATABASE_URL"]
    init_ledger_schema(dsn)
    bank = PostgresBank(dsn)
    with psycopg.connect(dsn) as conn:
        state = conn.execute("SELECT state FROM security_ledger WHERE namespace='bank'").fetchone()[
            0
        ]
        if state.get("accounts"):
            raise SystemExit("Refusing to seed a populated ledger")
    bank.seed(
        [
            {"id": "alice", "owner_session": "alice", "balance": 100, "email": "a@example.test"},
            {"id": "bob", "owner_session": "bob", "balance": 0, "email": "b@example.test"},
        ]
    )
    children = []
    try:
        for target, port in [
            ("halcyon.mcp_deploy:CORE_ASGI", 9001),
            ("halcyon.mcp_deploy:CRM_ASGI", 9002),
            ("halcyon.main:app", 8000),
        ]:
            children.append(
                subprocess.Popen(
                    [
                        "/app/.venv/bin/uvicorn",
                        target,
                        "--host",
                        "127.0.0.1",
                        "--port",
                        str(port),
                        "--log-level",
                        "error",
                    ],
                    stdout=subprocess.DEVNULL,
                )
            )
        with httpx.Client(timeout=10, trust_env=False) as client:
            for port in (9001, 9002, 8000):
                deadline = time.monotonic() + 30
                while True:
                    try:
                        response = (
                            client.get(f"http://127.0.0.1:{port}/mcp")
                            if port != 8000
                            else client.post(
                                "http://127.0.0.1:8000/api/ask",
                                json={"session_id": "alice", "query": "hello"},
                            )
                        )
                        break
                    except httpx.ConnectError:
                        if time.monotonic() >= deadline:
                            raise
                        time.sleep(0.2)
                assert response.status_code == 401, (port, response.status_code)
            for port, key in [(9001, "HALCYON_MCP_CORE_TOKEN"), (9002, "HALCYON_MCP_CRM_TOKEN")]:
                response = client.post(
                    f"http://127.0.0.1:{port}/mcp",
                    headers={"Authorization": "Bearer " + os.environ[key]},
                    json={},
                )
                assert response.status_code == 401
            print(
                "PASS: production web and both MCP processes start; anonymous and bearer-only calls denied",
                flush=True,
            )

        async def execute():
            vault = TokenVault(
                {
                    SERVER_CORE: os.environ["HALCYON_MCP_CORE_TOKEN"],
                    SERVER_CRM: os.environ["HALCYON_MCP_CRM_TOKEN"],
                }
            )
            settings = load_settings(os.environ)
            async with http_host(
                "http://127.0.0.1:9001/mcp",
                "http://127.0.0.1:9002/mcp",
                vault,
                InMemoryStore(),
                settings,
                "alice",
            ) as host:
                host.approve(await host.list_tools())
                args = {
                    "from_account": "alice",
                    "to_account": "bob",
                    "amount": 10,
                    "idempotency_key": "container-replay",
                }
                for _ in range(2):
                    result = json.loads(await host.call("core_banking__transfer_funds", args))
                    assert result["status"] == "success", result
                denied = await host.call("core_banking__get_account_details", {"account": "bob"})
                assert "denied" in denied and "b@example.test" not in denied
                token = await host.call("crm__get_integration_token", {"service": "core_banking"})
                assert os.environ["HALCYON_MCP_CORE_TOKEN"] not in token
                assert os.environ["HALCYON_MCP_CRM_TOKEN"] not in token

        asyncio.run(execute())
        restored = PostgresBank(dsn)
        assert restored.get("alice").balance == 90 and restored.get("bob").balance == 10
        with psycopg.connect(dsn) as conn:
            assert conn.execute("SELECT count(*) FROM security_ledger_audit").fetchone()[0] >= 2
        print(
            "PASS: signed SDK payment, scoped replay, cross-account denial, credential denial and durable ledger audit",
            flush=True,
        )
        with httpx.Client(timeout=15, trust_env=False) as client:
            readiness = client.get("http://127.0.0.1:8000/ready")
            assert readiness.status_code == 503
            checks = readiness.json()["checks"]
            assert checks["database"] and checks["nemo"] and not checks["models"], checks
        print(
            "PASS: missing model service fails production readiness while database and real NeMo checks pass",
            flush=True,
        )
    finally:
        for child in children:
            child.terminate()
        for child in children:
            try:
                child.wait(timeout=5)
            except subprocess.TimeoutExpired:
                child.kill()
                child.wait()


if __name__ == "__main__":
    main()
