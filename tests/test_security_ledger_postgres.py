"""Run against an explicitly supplied disposable PostgreSQL test database."""

import os
import uuid
from concurrent.futures import ThreadPoolExecutor
import pytest
from halcyon.security.ledger import PostgresBank, init_ledger_schema
import halcyon.security.ledger as ledger

DSN = os.getenv("SECURITY_TEST_DATABASE_URL")
pytestmark = pytest.mark.skipif(
    not DSN, reason="requires explicit disposable SECURITY_TEST_DATABASE_URL"
)


@pytest.fixture
def bank():
    init_ledger_schema(DSN)
    bank = PostgresBank(DSN, "test-" + uuid.uuid4().hex)
    bank.seed(
        [
            {"id": "alice", "owner_session": "alice", "balance": 100, "email": ""},
            {"id": "bob", "owner_session": "bob", "balance": 0, "email": ""},
        ]
    )
    return bank


def test_ledger_recreation_retains_balances_and_idempotency(bank):
    assert bank.transfer("alice", "bob", 10, session_id="alice", idempotency_key="payment")
    recreated = PostgresBank(DSN, bank.namespace)
    assert recreated.get("alice").balance == 90
    assert recreated.transfer("alice", "bob", 10, session_id="alice", idempotency_key="payment")
    assert recreated.get("alice").balance == 90 and recreated.get("bob").balance == 10
    assert not recreated.transfer("alice", "bob", 11, session_id="alice", idempotency_key="payment")


def test_two_workers_commit_one_duplicate_operation(bank):
    def pay(_):
        worker = PostgresBank(DSN, bank.namespace)
        return worker.transfer(
            "alice", "bob", 10, session_id="alice", idempotency_key="concurrent-payment"
        )

    with ThreadPoolExecutor(max_workers=4) as workers:
        assert all(workers.map(pay, range(12)))
    assert bank.get("alice").balance == 90 and bank.get("bob").balance == 10


def test_audit_failure_rolls_back_balance_update(bank, monkeypatch):
    def fail_audit(*args, **kwargs):
        raise RuntimeError("injected audit outage")

    monkeypatch.setattr(ledger, "_append_audit", fail_audit)
    with pytest.raises(RuntimeError, match="audit outage"):
        bank.transfer("alice", "bob", 10, session_id="alice", idempotency_key="audit-failure")
    assert PostgresBank(DSN, bank.namespace).get("alice").balance == 100
    assert PostgresBank(DSN, bank.namespace).get("bob").balance == 0
