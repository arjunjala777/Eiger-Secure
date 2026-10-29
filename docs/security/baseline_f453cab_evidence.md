# Eiger Security Hardening Baseline Evidence (Commit f453cab)

## 1. Commit and Inventory Record
- **Target Repository:** `eiger repo 2`
- **Branch:** `security-hardening`
- **Reviewed HEAD:** `f453cab` (`fix(security): remediate 4 reopened probe vulnerabilities and add negative entry-point regression tests`)
- **Baseline Benchmark Repository:** `eiger` on `m3-submission` (100% clean, read-only benchmark)
- **Evaluation Date:** October 26, 2026

## 2. Test Suite & Invariant Execution Baseline
Execution of full test suite across `eiger repo 2` at commit `f453cab`:
- **Results:** 376 passed, 0 failed, 5 skipped (external databases), 18 deselected.
- **Dedicated Negative Security Tests:** 35 passed (100% pass rate in `tests/test_negative_security.py`).

## 3. Replay Verification of Prior Probes at Current HEAD
All four prior probe findings were replayed against `f453cab`:
1. **Merchant-Source Withdrawal:**
   - Probe: Calling `transfer_funds` with `from_account="acct-merchant"`.
   - Result: Blocked with error; `bank.owns("caller", "acct-merchant")` is false. Caller balance: unchanged (100). Merchant balance: unchanged (1,000,000).
   - Invariant verified: Every debit strictly requires caller ownership of the source account.
2. **Anonymous Dispute Invocation:**
   - Probe: Anonymous POST to `/api/dispute`.
   - Result: HTTP 401/403. Balance: unchanged (100). Zero refund minted.
   - Invariant verified: State mutation requires authenticated ownership before model execution.
3. **MCP Tool Account Authorization:**
   - Probe: Attacker host calling `core_banking__transfer_funds` from victim to attacker.
   - Result: Denied by `core_banking.py` because `_caller_session` ("attacker") does not own `acct-victim`. Zero balance change.
   - Invariant verified: Transport service tokens do not grant account permissions; user identity is enforced inside banking tools.
4. **Duplicate Treasury Disbursement:**
   - Probe: Repeated execution of the same treasury scenario.
   - Result: Bound to server-controlled payment ID `treasury-payout-{session_id}-{scenario.key}`. First run transfers 45,000. Second run returns cached completed result without moving funds. Balance remains 45,000 (not 90,000).
   - Invariant verified: Scoped idempotency prevents duplicate disbursements.

## 4. The 5 Mandatory System Invariants
1. **Funded Authorized Source:** Every debit operation must draw from an authorized, caller-owned source account with verified available balance (`balance >= amount`).
2. **Legitimate Refund Reference:** Every refund must reference a valid, non-refunded original purchase transaction and cannot exceed the original transaction value or alter the refund destination.
3. **One-Time Treasury Execution:** Each pending treasury payment executes exactly once via an authoritative server-controlled idempotency key.
4. **Strict Cross-Tenant Isolation:** Cross-tenant reads and mutations (accounts, sessions, knowledge chunks, briefs, capstone states) are strictly denied with 401/403.
5. **Zero Side Effects on Denial:** Every denied or invalid operation causes strictly zero modifications to balances, ledgers, or account states.
