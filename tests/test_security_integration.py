"""Regression evidence for the application and HTTP trust boundaries."""

import json
import os
import pickle
import subprocess
import sys
from pathlib import Path
from unittest.mock import AsyncMock
import pytest
from fastapi.testclient import TestClient
from halcyon.bank import Bank
from halcyon.config import load_settings
from halcyon.mcp_deploy import core_banking_app
from halcyon.mcp_vault import TokenVault, SERVER_CORE, SERVER_CRM
from halcyon.security.context import authenticated_context
from halcyon.security.transport import DelegationAuth
from halcyon.security.executor import SecurityExecutor
from halcyon.security.contracts import (
    block_assessment,
    unavailable_assessment,
    parse_llama_guard_raw_output,
    SecurityDecision,
)
from halcyon.security.wazuh_logger import WazuhSecurityLogger
from halcyon.store import InMemoryStore
from tests.conftest import authenticate_test_client
from tests.test_negative_security import _build_test_app


@pytest.mark.parametrize("service", ["CORE", "CRM"])
def test_deployed_mcp_initializes_with_only_its_own_credentials(service):
    env = {key: value for key, value in os.environ.items() if not key.startswith("HALCYON_MCP_")}
    env.update(
        {
            "HALCYON_MODE": "secure",
            "HALCYON_PROFILE": "lab",
            f"HALCYON_MCP_{service}_TOKEN": "service-test-token-" + "x" * 32,
            f"HALCYON_MCP_{service}_DELEGATION_SECRET": "delegation-test-key-" + "y" * 32,
        }
    )
    code = (
        "from fastapi.testclient import TestClient\n"
        f"from halcyon.mcp_deploy import {service}_ASGI as app\n"
        "with TestClient(app) as client:\n"
        "    assert client.get('/health').status_code == 200\n"
        "    assert client.post('/mcp', json={}).status_code == 401\n"
    )
    result = subprocess.run(
        [sys.executable, "-B", "-c", code], env=env, capture_output=True, text=True, timeout=15
    )
    assert result.returncode == 0, result.stderr




@pytest.fixture
def banking():
    bank = Bank()
    bank.seed(
        [
            {
                "id": "alice-account",
                "owner_session": "alice",
                "balance": 100,
                "email": "a@example.test",
            },
            {"id": "bob-account", "owner_session": "bob", "balance": 0, "email": "b@example.test"},
        ]
    )
    vault = TokenVault({SERVER_CORE: "test-banking-credential", SERVER_CRM: "test-crm-credential"})
    return bank, vault


def rpc(args):
    return {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/call",
        "params": {"name": "transfer_funds", "arguments": args},
    }


@pytest.mark.parametrize("caller", [None, "alice"])
def test_service_token_and_payload_identity_cannot_authorize(banking, caller):
    bank, vault = banking
    args = {
        "from_account": "alice-account",
        "to_account": "bob-account",
        "amount": 10,
        "idempotency_key": "request-one",
    }
    if caller:
        args["_caller_session"] = caller
    with TestClient(core_banking_app(bank, vault)) as client:
        response = client.post(
            "/mcp", json=rpc(args), headers={"Authorization": "Bearer test-banking-credential"}
        )
    assert response.status_code == 401
    assert bank.get("alice-account").balance == 100
    assert bank.get("bob-account").balance == 0


def test_http_authorization_replay_and_payload_tampering(banking):
    bank, vault = banking
    args = {
        "from_account": "alice-account",
        "to_account": "bob-account",
        "amount": 10,
        "idempotency_key": "request-one",
    }
    with TestClient(core_banking_app(bank, vault)) as client:
        headers = {"Accept": "application/json, text/event-stream"}
        attacker = DelegationAuth(
            "test-banking-credential", SERVER_CORE, authenticated_context("bob", "system_internal")
        )
        denied = client.post("/mcp", json=rpc(args), headers=headers, auth=attacker)
        assert "denied" in denied.text and bank.get("alice-account").balance == 100
        owner = DelegationAuth(
            "test-banking-credential",
            SERVER_CORE,
            authenticated_context("alice", "system_internal"),
        )
        allowed = client.post("/mcp", json=rpc(args), headers=headers, auth=owner)
        assert allowed.status_code == 200 and "success" in allowed.text
        assert bank.get("alice-account").balance == 90 and bank.get("bob-account").balance == 10
        # Identical signed transport request is rejected before dispatch.
        replay = client.send(allowed.request)
        assert replay.status_code == 401
        # Fresh transport request, identical operation key: no duplicate debit.
        again = client.post("/mcp", json=rpc(args), headers=headers, auth=owner)
        assert "success" in again.text and bank.get("alice-account").balance == 90
        args["_caller_session"] = "bob"
        forged = client.post("/mcp", json=rpc(args), headers=headers, auth=owner)
        assert "Additional" in forged.text or "Unexpected" in forged.text
        assert bank.get("alice-account").balance == 90


def test_wrong_delegation_key_cannot_impersonate_with_service_credential(banking):
    bank, vault = banking
    auth = DelegationAuth(
        "test-banking-credential",
        SERVER_CORE,
        authenticated_context("alice", "system_internal"),
        signing_key="untrusted-delegation-key",
    )
    with TestClient(core_banking_app(bank, vault)) as client:
        response = client.post(
            "/mcp",
            json=rpc(
                {
                    "from_account": "alice-account",
                    "to_account": "bob-account",
                    "amount": 10,
                    "idempotency_key": "one",
                }
            ),
            auth=auth,
        )
    assert response.status_code == 401 and bank.get("alice-account").balance == 100


def test_executor_refund_is_real_authorized_and_idempotent(banking):
    bank, _ = banking
    bank.transfer(
        "alice-account", "bob-account", 20, session_id="alice", idempotency_key="purchase"
    )
    original = bank._idempotency_map["purchase"].transaction
    executor = SecurityExecutor(bank, InMemoryStore(), load_settings({"HALCYON_MODE": "secure"}))
    args = {"original_tx_id": original.id, "amount": 10, "idempotency_key": "refund-one"}
    denied = executor.execute(authenticated_context("bob", "system_internal"), "issue_refund", args)
    assert denied["status"] == "denied"
    first = executor.execute(
        authenticated_context("alice", "system_internal"), "issue_refund", args
    )
    again = executor.execute(
        authenticated_context("alice", "system_internal"), "issue_refund", args
    )
    assert first["status"] == again["status"] == "success"
    assert bank.get("alice-account").balance == 90 and bank.get("bob-account").balance == 10
    assert (
        executor.execute(
            authenticated_context("alice", "system_internal"),
            "get_balance",
            {"account": "alice-account", "_caller_session": "alice"},
        )["status"]
        == "error"
    )


@pytest.mark.parametrize("decision,status", [("block", 403), ("unavailable", 503)])
def test_real_web_route_honors_guard_outcome_before_generation(monkeypatch, decision, status):
    app, store, bank, kb, settings = _build_test_app({"HALCYON_MODE": "secure"})
    runtime = app.state.guard_runtime
    runtime.mode = "enforce"
    assessment = (
        block_assessment("test", "blocked")
        if decision == "block"
        else unavailable_assessment("test", "offline")
    )
    runtime.assess = AsyncMock(return_value=[assessment])
    with TestClient(app) as client:
        authenticate_test_client(client, "alice", settings.session_secret)
        response = client.post("/api/chat", json={"session_id": "alice", "message": "review"})
    assert response.status_code == status
    assert runtime.assess.await_count == 1
    assert runtime.assess.await_args.args[2].principal == "alice"


def test_real_web_observe_mode_executes_both_assessments():
    app, store, bank, kb, settings = _build_test_app({"HALCYON_MODE": "secure"})
    runtime = app.state.guard_runtime
    runtime.mode = "observe"
    runtime.assess = AsyncMock(return_value=[block_assessment("test", "observed")])
    with TestClient(app) as client:
        authenticate_test_client(client, "alice", settings.session_secret)
        response = client.post("/api/chat", json={"session_id": "alice", "message": "review"})
    assert response.status_code == 200 and runtime.assess.await_count == 2
    assert [c.args[1] for c in runtime.assess.await_args_list] == ["input", "output"]


@pytest.mark.parametrize(
    "text", ["safe\nunsafe\nS7", "unsafe", "unsafe\nS99", "safe\nS1", "unsafe\nS1 garbage"]
)
def test_malformed_classifier_cannot_allow(text):
    assert parse_llama_guard_raw_output(text).decision == SecurityDecision.UNAVAILABLE


def test_scanner_unknown_and_malicious_fail_ci(tmp_path):
    from scripts.security.supply_chain_scanner import scan_artifacts

    (tmp_path / "unknown.pkl").write_bytes(b"not a pickle")
    assert scan_artifacts(tmp_path)["admission_verdict"] == "FAIL"
    (tmp_path / "dangerous.pkl").write_bytes(pickle.dumps(eval))  # No execution.
    scanner = Path("scripts/security/supply_chain_scanner.py").resolve()
    proc = subprocess.run(
        [
            sys.executable,
            "-B",
            str(scanner),
            str(tmp_path),
            "--output",
            str(tmp_path / "result.json"),
        ],
        capture_output=True,
        text=True,
    )
    assert (
        proc.returncode != 0
        and json.loads((tmp_path / "result.json").read_text())["admission_verdict"] == "FAIL"
    )


def test_logger_redacts_content_and_retains_failed_exports(tmp_path, monkeypatch):
    logger = WazuhSecurityLogger(tmp_path / "events.json")
    original = logger._export
    monkeypatch.setattr(logger, "_export", lambda conn: (_ for _ in ()).throw(OSError("disk full")))
    event = logger.log(
        "review",
        "high",
        100401,
        "review",
        "BLOCK",
        session_id="alice",
        message="sk-sensitive-token",
        details={"api_key": "sk-sensitive-token"},
    )
    assert logger.last_error is not None
    with logger._connect() as conn:
        saved = conn.execute("SELECT payload FROM pending").fetchone()[0]
        assert "sk-sensitive-token" not in saved
    monkeypatch.setattr(logger, "_export", original)
    logger.log("recovery", "low", 100001, "review", "ALLOW")
    assert event["event_id"] in (tmp_path / "events.json").read_text()
    with logger._connect() as conn:
        assert conn.execute("SELECT count(*) FROM pending").fetchone()[0] == 0


def test_bom_full_schema_rejects_invalid_model_card(tmp_path):
    from scripts.security.generate_ai_bom import generate_ai_bom, validate_bom
    from jsonschema import ValidationError

    bom = generate_ai_bom(tmp_path / "bom.json")
    model = next(c for c in bom["components"] if c["type"] == "machine-learning-model")
    model["modelCard"]["modelParameters"]["approach"] = {"type": "safety-classifier"}
    with pytest.raises(ValidationError):
        validate_bom(bom)
