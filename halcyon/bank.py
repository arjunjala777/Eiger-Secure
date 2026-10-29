import threading
import time
from dataclasses import dataclass, field
import uuid


@dataclass
class Account:
    id: str
    owner_session: str
    balance: int
    email: str


@dataclass
class Transaction:
    id: str
    from_account: str
    to_account: str
    amount: int
    currency: str = "USD"
    idempotency_key: str = ""
    timestamp: float = field(default_factory=time.time)
    refunded_amount: int = 0


@dataclass
class RefundResult:
    success: bool
    transaction: Transaction | None = None
    error: str = ""

    def __bool__(self) -> bool:
        return self.success


@dataclass
class IdempotencyRecord:
    principal: str
    operation: str
    params: dict
    transaction: Transaction


@dataclass
class Bank:
    _accounts: dict[str, Account] = field(default_factory=dict)
    _transactions: dict[str, Transaction] = field(default_factory=dict)
    _idempotency_map: dict[str, IdempotencyRecord] = field(default_factory=dict)
    _lock: threading.RLock = field(default_factory=threading.RLock)

    def get(self, account_id: str) -> Account | None:
        with self._lock:
            return self._accounts.get(account_id)

    def credit(self, account_id: str, amount: int) -> bool:
        # Strictly reject booleans, non-ints, and non-positive numbers
        if type(amount) is not int or isinstance(amount, bool) or amount <= 0:
            return False
        with self._lock:
            if account_id not in self._accounts:
                return False
            self._accounts[account_id].balance += amount
            return True

    def debit(self, account_id: str, amount: int) -> bool:
        if type(amount) is not int or isinstance(amount, bool) or amount <= 0:
            return False
        with self._lock:
            if account_id not in self._accounts:
                return False
            if self._accounts[account_id].balance < amount:
                return False
            self._accounts[account_id].balance -= amount
            return True

    def transfer(
        self, from_account: str | None, to_account: str, amount: int,
        session_id: str | None = None, idempotency_key: str = "", currency: str = "USD"
    ) -> bool:
        # P0: Reject invalid types before coercion (including bool which subclasses int in Python)
        if type(amount) is not int or isinstance(amount, bool) or amount <= 0:
            return False

        # Funded transfers require valid, distinct source and destination accounts
        if not from_account or not to_account or from_account == to_account:
            return False

        with self._lock:
            from_act = self._accounts.get(from_account)
            to_act = self._accounts.get(to_account)
            if from_act is None or to_act is None:
                return False

            if session_id and from_act.owner_session != session_id:
                return False

            # Idempotency check with scoped parameter verification
            if idempotency_key:
                if idempotency_key in self._idempotency_map:
                    rec = self._idempotency_map[idempotency_key]
                    expected_params = {"from_account": from_account, "to_account": to_account, "amount": amount, "currency": currency}
                    if (
                        rec.principal != (session_id or "")
                        or rec.operation != "transfer"
                        or rec.params != expected_params
                    ):
                        return False
                    return True

            if from_act.balance < amount:
                return False

            # Atomic balance update (strictly conserving total supply)
            from_act.balance -= amount
            to_act.balance += amount

            # Record durable transaction
            tx_id = f"tx-{uuid.uuid4().hex[:12]}"
            tx = Transaction(
                id=tx_id,
                from_account=from_account,
                to_account=to_account,
                amount=amount,
                currency=currency,
                idempotency_key=idempotency_key,
            )
            self._transactions[tx_id] = tx
            if idempotency_key:
                self._idempotency_map[idempotency_key] = IdempotencyRecord(
                    principal=session_id or "",
                    operation="transfer",
                    params={"from_account": from_account, "to_account": to_account, "amount": amount, "currency": currency},
                    transaction=tx,
                )
            return True

    def issue_refund(
        self, original_tx_id: str, amount: int, to_account: str,
        session_id: str | None = None, idempotency_key: str = ""
    ) -> RefundResult:
        """P0: Derive refund amount, currency, and destination from the original transaction.
        Enforces cumulative refund limits, idempotency, session ownership, and atomic balance updates.
        """
        if type(amount) is not int or isinstance(amount, bool) or amount <= 0:
            return RefundResult(success=False, error="invalid amount: must be positive integer")

        with self._lock:
            orig = self._transactions.get(original_tx_id)
            if orig is None:
                return RefundResult(success=False, error="original transaction not found")

            # Check caller authorization: session_id must own destination account
            if session_id and not self.owns(session_id, to_account):
                return RefundResult(
                    success=False,
                    error=f"session {session_id} does not own destination account {to_account}"
                )

            # Derive destination from original transaction: refund must return to the sender!
            if to_account != orig.from_account:
                return RefundResult(
                    success=False,
                    error=f"destination {to_account} does not match original payer {orig.from_account}"
                )

            # Idempotency check: validate caller authorization and params BEFORE returning existing transaction
            if idempotency_key:
                if idempotency_key in self._idempotency_map:
                    rec = self._idempotency_map[idempotency_key]
                    expected_params = {"original_tx_id": original_tx_id, "amount": amount, "to_account": to_account}
                    if (
                        rec.principal != (session_id or "")
                        or rec.operation != "refund"
                        or rec.params != expected_params
                    ):
                        return RefundResult(
                            success=False,
                            error="idempotency key reuse with mismatched parameters or operation"
                        )
                    return RefundResult(
                        success=True,
                        transaction=rec.transaction,
                        error="duplicate idempotency key returned existing transaction"
                    )

            # Enforce cumulative refund limit
            if orig.refunded_amount + amount > orig.amount:
                return RefundResult(
                    success=False,
                    error=f"refund amount {amount} exceeds remaining refundable limit {orig.amount - orig.refunded_amount}"
                )

            # Source of refund is the beneficiary of the original transaction
            source_act = self._accounts.get(orig.to_account)
            dest_act = self._accounts.get(orig.from_account)
            if source_act is None or dest_act is None:
                return RefundResult(success=False, error="accounts not found")
            if source_act.balance < amount:
                return RefundResult(success=False, error="insufficient merchant balance for refund")

            # Atomic commit of balances, refund totals, and transaction records together
            source_act.balance -= amount
            dest_act.balance += amount
            orig.refunded_amount += amount

            refund_tx_id = f"rf-{uuid.uuid4().hex[:12]}"
            refund_tx = Transaction(
                id=refund_tx_id,
                from_account=orig.to_account,
                to_account=to_account,
                amount=amount,
                currency=orig.currency,
                idempotency_key=idempotency_key,
            )
            self._transactions[refund_tx_id] = refund_tx
            if idempotency_key:
                self._idempotency_map[idempotency_key] = IdempotencyRecord(
                    principal=session_id or "",
                    operation="refund",
                    params={"original_tx_id": original_tx_id, "amount": amount, "to_account": to_account},
                    transaction=refund_tx,
                )
            return RefundResult(success=True, transaction=refund_tx)

    def primary_account_for(self, session_id: str) -> str | None:
        with self._lock:
            for aid, act in self._accounts.items():
                if act.owner_session == session_id:
                    return aid
            return None

    def get_transaction(self, tx_id: str) -> Transaction | None:
        with self._lock:
            return self._transactions.get(tx_id)

    def set_email(self, account_id: str, email: str) -> None:
        with self._lock:
            if account_id in self._accounts:
                self._accounts[account_id].email = email

    def owns(self, session_id: str, account_id: str) -> bool:
        with self._lock:
            a = self._accounts.get(account_id)
            return a is not None and a.owner_session == session_id

    def seed(self, fixtures: list[dict]) -> None:
        with self._lock:
            for f in fixtures:
                self._accounts[f["id"]] = Account(
                    f["id"], f["owner_session"], f["balance"], f["email"])
                # Seed an initial purchase transaction for existing balance
                if f["balance"] > 0:
                    tx_id = f"tx-seed-{f['id']}"
                    self._transactions[tx_id] = Transaction(
                        id=tx_id,
                        from_account=f["id"],
                        to_account="acct-merchant",
                        amount=f["balance"],
                    )
            # Ensure acct-merchant exists so refunds can debit from it
            if "acct-merchant" not in self._accounts:
                self._accounts["acct-merchant"] = Account(
                    "acct-merchant", "system", 1000000, "merchant@eiger.test"
                )

    def clear(self) -> None:
        with self._lock:
            self._accounts = {}
            self._transactions = {}
            self._idempotency_map = {}
