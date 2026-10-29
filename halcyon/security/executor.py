"""
Unified Deterministic Tool Executor.

Enforces trusted caller context, authoritative tool registries, strict parameter
types, account ownership, idempotency parameter binding, and response field projection.
"""

from __future__ import annotations

import logging
from typing import Any, Mapping

from halcyon.bank import Bank
from halcyon.config import Settings
from halcyon.security.context import SecurityContext
from halcyon.security.policy import (
    APPROVED_TOOLS,
    ToolSpec,
    validate_param_types,
)
from halcyon.security.wazuh_logger import log_security_event
from halcyon.store import Store

_LOGGER = logging.getLogger("eiger.executor")


class SecurityExecutor:
    """Unified execution boundary for native and MCP tool invocations."""

    def __init__(self, bank: Bank, store: Store, settings: Settings, customers: dict | None = None):
        self.bank = bank
        self.store = store
        self.settings = settings
        self.customers = customers or {}

    def execute(
        self,
        context: SecurityContext,
        tool_name: str,
        arguments: Mapping[str, Any],
    ) -> dict[str, Any]:
        """
        Execute tool within trusted security boundary.
        Returns structured dictionary with 'status' ('success' or 'denied'/'error'),
        'data' (projected task-relevant fields), or 'error'.
        """
        if not isinstance(tool_name, str) or not isinstance(arguments, Mapping):
            return {"status": "error", "error": "Invalid tool request"}
        # 1. Lookup Tool in Approved Registry
        service, separator, clean_name = tool_name.partition("__")
        if not separator:
            clean_name = service
            service = None
        spec = APPROVED_TOOLS.get(clean_name)
        if spec is None or (service is not None and service != spec.service):
            log_security_event(
                event_type="unknown_tool_blocked",
                severity="medium",
                rule_id=100204,
                action="tool_execution",
                decision="BLOCK",
                session_id=context.principal,
                actor=context.principal or "anonymous",
                target_resource=tool_name,
                message=f"Attempted invocation of unapproved tool '{tool_name}'",
            )
            return {"status": "error", "error": f"Tool '{tool_name}' is not registered or approved"}

        if not context.is_authenticated():
            return {"status": "denied", "error": "Authentication required"}

        # 2. Strict Schema and Type Validation
        valid, err_msg = validate_param_types(spec, arguments)
        if not valid:
            log_security_event(
                event_type="invalid_tool_parameters",
                severity="high",
                rule_id=100201,
                action="tool_execution",
                decision="BLOCK",
                session_id=context.principal,
                actor=context.principal,
                target_resource=tool_name,
                details={"error": err_msg},
                message=f"Rejected parameter schema violation for tool '{tool_name}': {err_msg}",
            )
            return {"status": "error", "error": err_msg}

        # 3. Deterministic Account Ownership Authorization
        if spec.requires_ownership:
            account_id = str(arguments.get(spec.ownership_param, "")).strip()
            # Must be authenticated
            if not context.is_authenticated():
                log_security_event(
                    event_type="unauthenticated_tool_attempt",
                    severity="high",
                    rule_id=100401,
                    action="tool_execution",
                    decision="BLOCK",
                    session_id=context.principal,
                    target_resource=account_id,
                    message=f"Unauthenticated attempt to access account '{account_id}' via '{tool_name}'",
                )
                return {
                    "status": "denied",
                    "error": f"Authentication required to access account '{account_id}'",
                }

            # Verify caller owns the source account
            if not self.bank.owns(context.principal, account_id):
                log_security_event(
                    event_type="unauthorized_financial",
                    severity="critical",
                    rule_id=100401,
                    action="tool_execution",
                    decision="BLOCK",
                    session_id=context.principal,
                    actor=context.principal,
                    target_resource=account_id,
                    details={"tool": tool_name, "ownership_param": spec.ownership_param},
                    message=f"Access denied: caller '{context.principal}' does not own account '{account_id}'",
                )
                return {
                    "status": "denied",
                    "error": f"Access denied: principal does not own account '{account_id}'",
                }

        # 4. Dispatch Execution
        idempotency_key = arguments.get("idempotency_key")

        try:
            log_security_event(
                "tool_authorized",
                "low",
                100205,
                "tool_execution",
                "ALLOW",
                session_id=context.principal,
                details={"tool": spec.name},
            )
            raw_result = self._dispatch_operation(spec, context, arguments, idempotency_key)
            if isinstance(raw_result, dict) and raw_result.get("status") in ("error", "denied"):
                return raw_result

            # 5. Data Minimization: Response Field Projection
            projected = self._project_response(spec, raw_result)
            import json
            from halcyon.security.mcp_gateway import MCPSecurityGateway

            protected = MCPSecurityGateway().inspect_response(
                tool_name, json.dumps(projected), session_id=context.principal
            )
            return {"status": "success", "data": json.loads(protected)}

        except Exception as e:
            _LOGGER.exception("Error executing tool %s: %s", tool_name, e)
            return {"status": "error", "error": "Tool execution unavailable"}

    def _dispatch_operation(
        self,
        spec: ToolSpec,
        context: SecurityContext,
        args: Mapping[str, Any],
        idempotency_key: str | None,
    ) -> Any:
        if spec.name == "get_balance":
            acct = self.bank.get(args["account"])
            if not acct:
                return {"status": "error", "error": "Account not found"}
            return {"account": acct.id, "balance": acct.balance, "currency": "USD"}

        elif spec.name == "get_account_details":
            acct = self.bank.get(args["account"])
            if not acct:
                return {"status": "error", "error": "Account not found"}
            return {
                "account": acct.id,
                "owner": acct.owner_session,
                "email": acct.email,
                "status": "active",
            }

        elif spec.name == "transfer_funds":
            from_acct = args["from_account"]
            to_acct = args["to_account"]
            amount = args["amount"]
            success = self.bank.transfer(
                from_account=from_acct,
                to_account=to_acct,
                amount=amount,
                session_id=context.principal,
                idempotency_key=idempotency_key or "",
            )
            if not success:
                return {
                    "status": "denied",
                    "error": "Transfer failed: insufficient funds or invalid accounts",
                }
            return {
                "from_account": from_acct,
                "to_account": to_acct,
                "amount": amount,
                "status": "completed",
            }

        elif spec.name == "issue_refund":
            orig_id = args["original_tx_id"]
            amount = args["amount"]
            original = self.bank.get_transaction(orig_id)
            if original is None or not self.bank.owns(context.principal, original.from_account):
                return {
                    "status": "denied",
                    "error": "Refund denied: original payment not authorized",
                }
            success = self.bank.issue_refund(
                original_tx_id=orig_id,
                amount=amount,
                to_account=original.from_account,
                session_id=context.principal,
                idempotency_key=idempotency_key or "",
            )
            if not success:
                return {
                    "status": "denied",
                    "error": "Refund denied: unowned, exceeded limit, or invalid transaction",
                }
            return {
                "original_tx_id": orig_id,
                "refund_amount": amount,
                "status": "completed",
            }

        elif spec.name == "update_email":
            self.bank.set_email(args["account"], args["email"])
            return {"account": args["account"], "status": "updated"}
        elif spec.name in ("get_customer", "get_notes"):
            customer = self.customers.get(args["account"])
            if customer is None:
                return {"status": "error", "error": "Customer not found"}
            return {"account": args["account"], **customer}

        return {"status": "error", "error": f"Unhandled operation {spec.name}"}

    @staticmethod
    def _project_response(spec: ToolSpec, raw: Any) -> dict[str, Any]:
        """Project result dictionary to only authorized task-relevant fields."""
        if not isinstance(raw, dict):
            return {"result": raw}
        if not spec.response_fields:
            return raw
        return {k: raw[k] for k in spec.response_fields if k in raw}
