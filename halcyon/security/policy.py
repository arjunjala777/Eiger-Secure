"""
Tool Registry and Execution Policy Definitions.

Defines approved schemas, parameter bounds, authorization requirements,
and server-side operation records for deterministic tool execution.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from typing import Any, Mapping


@dataclass(frozen=True)
class ToolSpec:
    name: str
    service: str
    is_mutation: bool
    required_params: tuple[str, ...]
    allowed_params: tuple[str, ...]
    param_types: Mapping[str, type]
    requires_ownership: bool = True
    ownership_param: str = "account"
    response_fields: tuple[str, ...] = ()


# Authoritative Tool Registry
APPROVED_TOOLS: dict[str, ToolSpec] = {
    "get_balance": ToolSpec(
        name="get_balance",
        service="core_banking",
        is_mutation=False,
        required_params=("account",),
        allowed_params=("account",),
        param_types={"account": str},
        requires_ownership=True,
        ownership_param="account",
        response_fields=("account", "balance", "currency"),
    ),
    "get_account_details": ToolSpec(
        name="get_account_details",
        service="core_banking",
        is_mutation=False,
        required_params=("account",),
        allowed_params=("account",),
        param_types={"account": str},
        requires_ownership=True,
        ownership_param="account",
        response_fields=("account", "owner", "email", "status"),
    ),
    "transfer_funds": ToolSpec(
        name="transfer_funds",
        service="core_banking",
        is_mutation=True,
        required_params=("from_account", "to_account", "amount", "idempotency_key"),
        allowed_params=("from_account", "to_account", "amount", "idempotency_key"),
        param_types={
            "from_account": str,
            "to_account": str,
            "amount": int,
            "idempotency_key": str,
        },
        requires_ownership=True,
        ownership_param="from_account",
        response_fields=("from_account", "to_account", "amount", "status"),
    ),
    "issue_refund": ToolSpec(
        name="issue_refund",
        service="core_banking",
        is_mutation=True,
        required_params=("original_tx_id", "amount", "idempotency_key"),
        allowed_params=("original_tx_id", "amount", "idempotency_key"),
        param_types={
            "original_tx_id": str,
            "amount": int,
            "idempotency_key": str,
        },
        requires_ownership=False,  # Checked via original transaction ownership
        response_fields=("original_tx_id", "refund_amount", "status"),
    ),
    "update_email": ToolSpec(
        name="update_email",
        service="core_banking",
        is_mutation=True,
        required_params=("account", "email"),
        allowed_params=("account", "email"),
        param_types={"account": str, "email": str},
        response_fields=("account", "status"),
    ),
    "get_customer": ToolSpec(
        name="get_customer",
        service="crm",
        is_mutation=False,
        required_params=("account",),
        allowed_params=("account",),
        param_types={"account": str},
        response_fields=("account", "name", "tier"),
    ),
    "get_notes": ToolSpec(
        name="get_notes",
        service="crm",
        is_mutation=False,
        required_params=("account",),
        allowed_params=("account",),
        param_types={"account": str},
        response_fields=("account", "notes"),
    ),
}


def compute_param_digest(params: Mapping[str, Any]) -> str:
    """Compute deterministic SHA-256 digest of canonical sorted parameters."""
    normalized = {}
    for k in sorted(params.keys()):
        # Omit transport-level caller or transient keys from digest
        if k.startswith("_"):
            continue
        v = params[k]
        normalized[k] = v
    canonical_json = json.dumps(normalized, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical_json.encode("utf-8")).hexdigest()


def validate_param_types(spec: ToolSpec, args: Mapping[str, Any]) -> tuple[bool, str | None]:
    """Strictly validate argument types and disallow extra or malformed parameters."""
    # Check extra properties
    for k in args:
        if k not in spec.allowed_params:
            return False, f"Unexpected parameter '{k}' not permitted for tool '{spec.name}'"

    # Check required properties
    for req in spec.required_params:
        if req not in args:
            return False, f"Missing required parameter '{req}' for tool '{spec.name}'"

    # Check types and numeric constraints
    for k, v in args.items():
        if k.startswith("_") or k not in spec.param_types:
            continue
        expected_type = spec.param_types[k]

        # Invariant: Python booleans are instances of int; strictly reject booleans for int fields
        if expected_type is int:
            if isinstance(v, bool) or type(v) is not int:
                return False, f"Parameter '{k}' must be an integer, got {type(v).__name__}"
            if v <= 0 or v > 2**63 - 1:
                return False, f"Parameter '{k}' must be a strictly positive integer minor unit"

        elif expected_type is str:
            if not isinstance(v, str):
                return False, f"Parameter '{k}' must be a string, got {type(v).__name__}"
            if not v.strip() or len(v) > 256:
                return False, f"Parameter '{k}' exceeds maximum allowed length of 256 characters"

    return True, None


def tool_schema(spec: ToolSpec) -> dict:
    return {
        "type": "object",
        "properties": {
            name: (
                {"type": "integer", "minimum": 1, "maximum": 2**63 - 1}
                if typ is int
                else {"type": "string", "minLength": 1, "maxLength": 256}
            )
            for name, typ in spec.param_types.items()
        },
        "required": list(spec.required_params),
        "additionalProperties": False,
    }
