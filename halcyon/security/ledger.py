"""PostgreSQL-backed Bank adapter with transactional state and audit.

A namespace row serializes each bank's operations. This favors correctness over
high throughput and avoids process-local locking as a production guarantee.
"""

from dataclasses import asdict
import hashlib
import json
import psycopg
from psycopg.types.json import Jsonb
from halcyon.bank import Bank, Account, Transaction, IdempotencyRecord
from halcyon.security.context import request_context

SCHEMA = """
CREATE TABLE IF NOT EXISTS security_ledger (
 namespace TEXT PRIMARY KEY, state JSONB NOT NULL, revision BIGINT NOT NULL DEFAULT 0);
CREATE TABLE IF NOT EXISTS security_ledger_audit (
 id BIGSERIAL PRIMARY KEY, namespace TEXT NOT NULL, revision BIGINT NOT NULL,
 operation TEXT NOT NULL, state_digest TEXT NOT NULL, request_id TEXT,
 created_at TIMESTAMPTZ NOT NULL DEFAULT now(), UNIQUE(namespace, revision));
"""


def init_ledger_schema(dsn):
    with psycopg.connect(dsn) as conn:
        conn.execute("SELECT pg_advisory_xact_lock(593204751)")
        conn.execute(SCHEMA)


def _dump(bank):
    return {
        "accounts": {k: asdict(v) for k, v in bank._accounts.items()},
        "transactions": {k: asdict(v) for k, v in bank._transactions.items()},
        "idempotency": {
            k: {
                "principal": v.principal,
                "operation": v.operation,
                "params": v.params,
                "transaction_id": v.transaction.id,
            }
            for k, v in bank._idempotency_map.items()
        },
    }


def _load(state):
    bank = Bank()
    bank._accounts = {k: Account(**v) for k, v in state.get("accounts", {}).items()}
    bank._transactions = {k: Transaction(**v) for k, v in state.get("transactions", {}).items()}
    bank._idempotency_map = {
        k: IdempotencyRecord(
            v["principal"], v["operation"], v["params"], bank._transactions[v["transaction_id"]]
        )
        for k, v in state.get("idempotency", {}).items()
    }
    return bank


def _append_audit(conn, namespace, revision, operation, digest, request_id):
    conn.execute(
        "INSERT INTO security_ledger_audit(namespace,revision,operation,state_digest,request_id) VALUES (%s,%s,%s,%s,%s)",
        (namespace, revision, operation, digest, request_id),
    )


class PostgresBank:
    def __init__(self, dsn, namespace="bank"):
        if not dsn:
            raise ValueError("Production ledger requires DATABASE_URL")
        self.dsn, self.namespace = dsn, namespace
        with psycopg.connect(dsn) as conn:
            conn.execute(
                "INSERT INTO security_ledger(namespace,state) VALUES (%s,%s) ON CONFLICT DO NOTHING",
                (namespace, Jsonb(_dump(Bank()))),
            )

    def _operation(self, name, *args, mutating=False, **kwargs):
        with psycopg.connect(self.dsn) as conn:
            row = conn.execute(
                "SELECT state,revision FROM security_ledger WHERE namespace=%s"
                + (" FOR UPDATE" if mutating else ""),
                (self.namespace,),
            ).fetchone()
            if row is None:
                raise RuntimeError("Ledger namespace unavailable")
            bank = _load(row[0])
            result = getattr(bank, name)(*args, **kwargs)
            if mutating:
                state = _dump(bank)
                revision = row[1] + 1
                digest = hashlib.sha256(
                    json.dumps(state, sort_keys=True, separators=(",", ":")).encode()
                ).hexdigest()
                context = request_context.get()
                conn.execute(
                    "UPDATE security_ledger SET state=%s,revision=%s WHERE namespace=%s",
                    (Jsonb(state), revision, self.namespace),
                )
                _append_audit(
                    conn,
                    self.namespace,
                    revision,
                    name,
                    digest,
                    context.request_id if context else None,
                )
            return result  # The connection context commits state and audit together.

    def get(self, *a, **kw):
        return self._operation("get", *a, **kw)

    def owns(self, *a, **kw):
        return self._operation("owns", *a, **kw)

    def primary_account_for(self, *a, **kw):
        return self._operation("primary_account_for", *a, **kw)

    def get_transaction(self, *a, **kw):
        return self._operation("get_transaction", *a, **kw)

    def transfer(self, *a, **kw):
        return self._operation("transfer", *a, mutating=True, **kw)

    def issue_refund(self, *a, **kw):
        return self._operation("issue_refund", *a, mutating=True, **kw)

    def set_email(self, *a, **kw):
        return self._operation("set_email", *a, mutating=True, **kw)

    def credit(self, *a, **kw):
        return self._operation("credit", *a, mutating=True, **kw)

    def debit(self, *a, **kw):
        return self._operation("debit", *a, mutating=True, **kw)

    def seed(self, *a, **kw):
        return self._operation("seed", *a, mutating=True, **kw)

    def clear(self):
        return self._operation("clear", mutating=True)
