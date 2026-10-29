"""
Halcyon Blue-Team Defensive AI Security Integration Suite.

Includes:
- Wazuh SIEM structured JSON audit logging
- Llama Guard 3 input/output safety classifier
- Lasso-style MCP Security Gateway (request & response inspection)
- NeMo Guardrails configuration and runtime filter
"""

from halcyon.security.wazuh_logger import log_security_event, WazuhSecurityLogger
from halcyon.security.contracts import SecurityAssessment, SecurityDecision
from halcyon.security.llama_guard import LlamaGuardClassifier
from halcyon.security.mcp_gateway import MCPSecurityGateway
from halcyon.security.nemo_integration import NeMoGuardrailsIntegration

__all__ = [
    "log_security_event",
    "WazuhSecurityLogger",
    "SecurityAssessment",
    "SecurityDecision",
    "LlamaGuardClassifier",
    "MCPSecurityGateway",
    "NeMoGuardrailsIntegration",
]
