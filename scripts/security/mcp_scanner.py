"""Scoped empirical admission probes over both in-process and HTTP boundaries."""

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
import anyio
from fastapi.testclient import TestClient
from halcyon.bank import Bank
from halcyon.config import load_settings
from halcyon.mcp_host import in_memory_host
from halcyon.mcp_deploy import core_banking_app
from halcyon.mcp_vault import TokenVault, SERVER_CORE, SERVER_CRM
from halcyon.store import InMemoryStore
from halcyon.security.context import authenticated_context
from halcyon.security.transport import DelegationAuth


async def run_mcp_probes():
    bank = Bank()
    bank.seed(
        [
            {
                "id": "acct-victim",
                "owner_session": "victim",
                "balance": 5000,
                "email": "victim@test.local",
            },
            {"id": "acct-attacker", "owner_session": "attacker", "balance": 0, "email": ""},
        ]
    )
    vault = TokenVault({SERVER_CORE: "review-core", SERVER_CRM: "review-crm"})
    settings = load_settings({"HALCYON_MODE": "secure"})
    findings = []
    probes = []

    def check(name, passed):
        probes.append({"name": name, "passed": bool(passed)})
        if not passed:
            findings.append({"severity": "HIGH", "probe": name})

    async with in_memory_host(bank, vault, {}, InMemoryStore(), settings, "attacker") as host:
        read = await host.call("core_banking__get_account_details", {"account": "acct-victim"})
        check("host_cross_account_read", "denied" in read and "victim@test.local" not in read)
        moved = await host.call(
            "core_banking__transfer_funds",
            {
                "from_account": "acct-victim",
                "to_account": "acct-attacker",
                "amount": 100,
                "idempotency_key": "probe-transfer",
            },
        )
        check(
            "host_cross_account_transfer",
            "denied" in moved and bank.get("acct-victim").balance == 5000,
        )
        boolean = await host.call(
            "core_banking__transfer_funds",
            {
                "from_account": "acct-attacker",
                "to_account": "acct-victim",
                "amount": True,
                "idempotency_key": "probe-boolean",
            },
        )
        check("strict_amount", "integer" in boolean and bank.get("acct-attacker").balance == 0)
        token = await host.call("crm__get_integration_token", {"service": "crm"})
        check("no_agent_credentials", "review-crm" not in token and "denied" in token)
    with TestClient(core_banking_app(bank, vault)) as client:
        req = {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {
                "name": "transfer_funds",
                "arguments": {
                    "from_account": "acct-victim",
                    "to_account": "acct-attacker",
                    "amount": 50,
                    "idempotency_key": "probe-http",
                },
            },
        }
        check("http_no_credentials", client.post("/mcp", json=req).status_code == 401)
        check(
            "http_service_only",
            client.post(
                "/mcp", json=req, headers={"Authorization": "Bearer review-core"}
            ).status_code
            == 401,
        )
        auth = DelegationAuth(
            "review-core", SERVER_CORE, authenticated_context("attacker", "system_internal")
        )
        response = client.post(
            "/mcp", json=req, headers={"Accept": "application/json, text/event-stream"}, auth=auth
        )
        check(
            "http_bound_user_authorization",
            response.status_code == 200
            and "denied" in response.text
            and bank.get("acct-victim").balance == 5000,
        )
        req["params"]["arguments"]["_caller_session"] = "victim"
        response = client.post(
            "/mcp", json=req, headers={"Accept": "application/json, text/event-stream"}, auth=auth
        )
        check(
            "http_payload_identity_rejected",
            bank.get("acct-victim").balance == 5000
            and ("Unexpected" in response.text or "Additional" in response.text),
        )
        del req["params"]["arguments"]["_caller_session"]
        req["params"]["arguments"]["amount"] = 10
        authorized = client.post(
            "/mcp",
            json=req,
            headers={"Accept": "application/json, text/event-stream"},
            auth=DelegationAuth(
                "review-core", SERVER_CORE, authenticated_context("victim", "system_internal")
            ),
        )
        check(
            "http_authorized_transfer",
            authorized.status_code == 200
            and bank.get("acct-victim").balance == 4990
            and bank.get("acct-attacker").balance == 10,
        )
    return {
        "scanner": "Eiger scoped MCP admission",
        "admission_status": "PASS" if not findings else "FAIL",
        "probes_executed": len(probes),
        "probes_passed": sum(p["passed"] for p in probes),
        "probes": probes,
        "findings": findings,
    }


if __name__ == "__main__":
    report = anyio.run(run_mcp_probes)
    path = Path("reports/mcp_security_scan.json")
    path.parent.mkdir(exist_ok=True)
    path.write_text(json.dumps(report, indent=2))
    print(report["admission_status"])
    raise SystemExit(0 if report["admission_status"] == "PASS" else 1)
