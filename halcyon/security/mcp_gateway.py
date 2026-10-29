"""
Lasso-style MCP Security Gateway.

Applies configurable request and response filters to all MCP communications:
- Pre-execution validation & parameter schema hardening
- Egress Data Loss Prevention (DLP) masking sensitive PII/secrets before LLM consumption
- Full audit event logging to Wazuh SIEM
"""

from __future__ import annotations

import re
from typing import Any, Mapping
from halcyon.security.wazuh_logger import log_security_event


class MCPSecurityGateway:
    """Security Gateway interceptor for Model Context Protocol (MCP) tool calls."""

    # Targeted DLP regex patterns (distinct from benign acct-* IDs)
    _DLP_CREDIT_CARD = re.compile(r"\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13})\b")
    _DLP_API_KEY = re.compile(
        r"\b(?:sk-[a-zA-Z0-9_-]{16,}|token-[a-zA-Z0-9_-]{12,}|prod-secret-[a-zA-Z0-9_-]{10,})\b"
    )
    _DLP_SSN = re.compile(r"\b\d{3}-\d{2}-\d{4}\b")

    # High-risk parameter injection patterns
    _INJECTION_PATTERNS = [
        re.compile(r"<\s*script", re.IGNORECASE),
        re.compile(r"system\s*:\s*override", re.IGNORECASE),
        re.compile(r"ignore\s+all\s+rules", re.IGNORECASE),
        re.compile(r"\bposix\.system\b", re.IGNORECASE),
        re.compile(r"\brm\s+-rf\b", re.IGNORECASE),
    ]

    def __init__(self, dlp_enabled: bool = True, strict_types: bool = True):
        self.dlp_enabled = dlp_enabled
        self.strict_types = strict_types

    def inspect_request(
        self,
        tool_name: str,
        arguments: Mapping[str, Any],
        session_id: str | None = None,
        caller: str = "agent",
    ) -> tuple[bool, str | None]:
        """
        Inspect tool execution request before dispatching to MCP server.
        Returns (is_allowed, error_message).
        """
        from halcyon.security.policy import APPROVED_TOOLS, validate_param_types

        service, sep, name = tool_name.partition("__")
        if not sep:
            name, service = service, None
        spec = APPROVED_TOOLS.get(name)
        if spec is None or (service is not None and service != spec.service):
            return False, "unapproved tool"
        valid, reason = validate_param_types(spec, arguments)
        if not valid:
            log_security_event(
                "mcp_gateway_block",
                "high",
                100201,
                "inspect_request",
                "BLOCK",
                session_id=session_id,
                reason_code="INVALID_TOOL_SCHEMA",
            )
            return False, "invalid tool parameters: " + str(reason)

        # 2. Check for injection payloads inside tool arguments
        for k, v in arguments.items():
            str_val = str(v)
            for pat in self._INJECTION_PATTERNS:
                if pat.search(str_val):
                    log_security_event(
                        event_type="mcp_gateway_block",
                        severity="critical",
                        rule_id=100202,
                        action="inspect_request",
                        decision="BLOCK",
                        session_id=session_id,
                        actor=caller,
                        target_resource=tool_name,
                        details={"parameter": k, "pattern_matched": pat.pattern},
                        message=f"MCP Gateway intercepted malicious payload in tool '{tool_name}' argument '{k}'",
                    )
                    return (
                        False,
                        f"MCP Gateway: malicious parameter pattern blocked in argument '{k}'",
                    )

        return True, None

    def inspect_response(
        self,
        tool_name: str,
        response_text: str,
        session_id: str | None = None,
    ) -> str:
        """
        Inspect and sanitize tool output before returning to the LLM.
        Applies DLP redaction and strips deceptive prompt injection wrappers.
        """
        if not self.dlp_enabled or not response_text:
            return response_text

        import json

        if len(response_text.encode()) > 65536:
            return json.dumps({"status": "error", "error": "Tool response exceeds security budget"})

        def scrub(text):
            text = self._DLP_API_KEY.sub("[REDACTED_API_KEY]", text)
            text = re.sub(
                r"(?<![\w-])(?:\d[ -]?){12,18}\d(?![\w-])", "[REDACTED_CARD_NUMBER]", text
            )
            text = self._DLP_SSN.sub("[REDACTED_SSN]", text)
            text = re.sub(
                r"\beiger-[A-Za-z0-9]+(?:\.[A-Za-z0-9]+){0,3}\b", "[REDACTED_SESSION]", text
            )
            return re.sub(
                r"(?is)\bSYSTEM\s+(?:INSTRUCTION|NOTE):.*", "[REDACTED_INDIRECT_INJECTION]", text
            )

        def walk(value):
            if isinstance(value, dict):
                return {
                    k: (
                        "[REDACTED_CREDENTIAL]"
                        if k.lower()
                        in {"api_key", "password", "token", "authorization", "session_id", "owner"}
                        else walk(v)
                    )
                    for k, v in value.items()
                }
            if isinstance(value, list):
                return [walk(v) for v in value]
            return scrub(value) if isinstance(value, str) else value

        try:
            sanitized = json.dumps(walk(json.loads(response_text)))
        except (ValueError, TypeError):
            sanitized = scrub(response_text)
        if sanitized != response_text:
            log_security_event(
                "mcp_dlp_sanitized",
                "medium",
                100203,
                "inspect_response",
                "SANITIZE",
                session_id=session_id,
            )
        return sanitized
