"""
Tests for Unified SecurityExecutor.

Validates schema bounds, rejection of booleans, account ownership enforcement,
rejection of spoofed payload arguments, and response field projection.
"""

import pytest

from halcyon.bank import Bank
from halcyon.config import load_settings
from halcyon.security.context import authenticated_context, anonymous_context
from halcyon.security.executor import SecurityExecutor
from halcyon.store import InMemoryStore


def _setup_fixture():
    bank = Bank()
    bank.seed([
        {"id": "acct-alice", "owner_session": "alice", "balance": 1000, "email": "alice@test.local"},
        {"id": "acct-bob", "owner_session": "bob", "balance": 500, "email": "bob@test.local"},
    ])
    store = InMemoryStore()
    settings = load_settings({"HALCYON_MODE": "secure"})
    executor = SecurityExecutor(bank, store, settings)
    return bank, executor


def test_executor_blocks_unapproved_tools():
    bank, executor = _setup_fixture()
    ctx = authenticated_context("alice", auth_method="session_cookie")

    res = executor.execute(ctx, "execute_shell_cmd", {"cmd": "id"})
    assert res["status"] == "error"
    assert "not registered" in res["error"]


def test_executor_rejects_boolean_amount_and_floats():
    bank, executor = _setup_fixture()
    ctx = authenticated_context("alice", auth_method="session_cookie")

    # Boolean passed as integer
    res_bool = executor.execute(
        ctx, "transfer_funds",
        {"from_account": "acct-alice", "to_account": "acct-bob", "amount": True, "idempotency_key": "unit-operation"}
    )
    assert res_bool["status"] == "error"
    assert "must be an integer" in res_bool["error"]

    # Float passed as integer
    res_float = executor.execute(
        ctx, "transfer_funds",
        {"from_account": "acct-alice", "to_account": "acct-bob", "amount": 25.5, "idempotency_key": "unit-operation"}
    )
    assert res_float["status"] == "error"
    assert "must be an integer" in res_float["error"]

    # Balances strictly unchanged
    assert bank.get("acct-alice").balance == 1000
    assert bank.get("acct-bob").balance == 500


def test_executor_rejects_extra_unexpected_parameters():
    bank, executor = _setup_fixture()
    ctx = authenticated_context("alice", auth_method="session_cookie")

    res = executor.execute(
        ctx, "get_balance",
        {"account": "acct-alice", "extra_injected_flag": "bypass_auth"}
    )
    assert res["status"] == "error"
    assert "Unexpected parameter" in res["error"]


def test_executor_enforces_account_ownership_from_trusted_context():
    bank, executor = _setup_fixture()
    ctx_alice = authenticated_context("alice", auth_method="session_cookie")

    # Alice tries to read Bob's account details -> DENIED
    res_read = executor.execute(ctx_alice, "get_account_details", {"account": "acct-bob"})
    assert res_read["status"] == "denied"
    assert "does not own" in res_read["error"]

    # Alice tries to debit Bob's account -> DENIED
    res_tx = executor.execute(
        ctx_alice, "transfer_funds",
        {"from_account": "acct-bob", "to_account": "acct-alice", "amount": 100, "idempotency_key": "unit-operation"}
    )
    assert res_tx["status"] == "denied"
    assert "does not own" in res_tx["error"]

    # Invariant: Denied operations cause zero balance change
    assert bank.get("acct-bob").balance == 500
    assert bank.get("acct-alice").balance == 1000


def test_executor_ignores_caller_spoofing_in_payload():
    """Critical: Payload arguments like session_id cannot override SecurityContext or bypass schema."""
    bank, executor = _setup_fixture()
    ctx_attacker = authenticated_context("attacker", auth_method="session_cookie")

    # Attacker passes spoofed session_id in payload trying to debit Alice's account
    res = executor.execute(
        ctx_attacker, "transfer_funds",
        {
            "from_account": "acct-alice",
            "to_account": "acct-bob",
            "amount": 200, "idempotency_key": "unit-operation",
            "session_id": "alice",
        }
    )
    assert res["status"] in ("denied", "error")

    # Alice's funds remain intact
    assert bank.get("acct-alice").balance == 1000


def test_executor_authorized_operation_and_response_projection():
    bank, executor = _setup_fixture()
    ctx_alice = authenticated_context("alice", auth_method="session_cookie")

    # Authorized read
    res_bal = executor.execute(ctx_alice, "get_balance", {"account": "acct-alice"})
    assert res_bal["status"] == "success"
    assert res_bal["data"] == {"account": "acct-alice", "balance": 1000, "currency": "USD"}

    # Authorized transfer
    res_tx = executor.execute(
        ctx_alice, "transfer_funds",
        {"from_account": "acct-alice", "to_account": "acct-bob", "amount": 150, "idempotency_key": "unit-operation"}
    )
    assert res_tx["status"] == "success"
    assert res_tx["data"]["status"] == "completed"
    assert res_tx["data"]["amount"] == 150
    assert bank.get("acct-alice").balance == 850
    assert bank.get("acct-bob").balance == 650
