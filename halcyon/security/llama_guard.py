"""
Llama Guard 3 Classifier Integration.

Implements Meta's Llama Guard 3-1B taxonomy (S1-S13) with explicit Eiger policy codes.
Enforces strict outcome typing: ALLOW, BLOCK, REVIEW, UNAVAILABLE.
Never translates missing evidence, network timeouts, or malformed responses into safe.
Supports observe-only telemetry mode for safe rollout.
"""

from __future__ import annotations

import os
import time
import httpx

from halcyon.security.contracts import (
    SecurityAssessment,
    SecurityDecision,
    unavailable_assessment,
    parse_llama_guard_raw_output,
)
from halcyon.security.wazuh_logger import log_security_event

DEFAULT_OLLAMA_URL = os.getenv("OLLAMA_URL", "http://127.0.0.1:11434")
DEFAULT_GUARD_MODEL = os.getenv("LLAMA_GUARD_MODEL", "llama-guard3:1b")


class LlamaGuardClassifier:
    """Evaluates input prompts and model outputs using Meta Llama Guard 3-1B."""

    def __init__(
        self,
        ollama_url: str = DEFAULT_OLLAMA_URL,
        model: str = DEFAULT_GUARD_MODEL,
        timeout: float = 3.0,
        observe_only: bool = True,
        gateway_token: str = "",
    ):
        self.ollama_url = ollama_url.rstrip("/")
        self.model = model
        self.timeout = timeout
        self.observe_only = observe_only
        self.gateway_token = gateway_token

    def assess_input(
        self,
        user_message: str,
        session_id: str | None = None,
    ) -> SecurityAssessment:
        """
        Evaluate user message before it reaches the conversational LLM.
        Returns a structured SecurityAssessment (never returns None or untyped bool).
        """
        start = time.perf_counter()

        # Format Llama Guard 3 instruction prompt according to Meta specification
        formatted_prompt = self._format_input_prompt(user_message)
        assessment = self._call_ollama(formatted_prompt, start)

        # Log assessment result to Wazuh
        if assessment.decision == SecurityDecision.BLOCK:
            log_security_event(
                event_type="guardrail_violation",
                severity="high",
                rule_id=100102,
                action="llama_guard_input",
                decision="OBSERVE_BLOCK" if self.observe_only else "BLOCK",
                session_id=session_id,
                details={
                    "native_categories": assessment.native_categories,
                    "eiger_policy_codes": assessment.eiger_policy_codes,
                    "latency_ms": assessment.latency_ms,
                    "observe_only": self.observe_only,
                },
                message=f"Llama Guard 3 flagged input: {assessment.reason}",
            )
        elif assessment.decision == SecurityDecision.UNAVAILABLE:
            log_security_event(
                event_type="guardrail_unavailable",
                severity="medium",
                rule_id=100104,
                action="llama_guard_input",
                decision="DEGRADED",
                session_id=session_id,
                details={"reason": assessment.reason, "model": self.model},
                message=f"Llama Guard 3 service unavailable: {assessment.reason}",
            )

        return assessment

    def assess_output(
        self,
        agent_message: str,
        session_id: str | None = None,
    ) -> SecurityAssessment:
        """Evaluate agent output before returning to user (output rail)."""
        start = time.perf_counter()
        formatted_prompt = self._format_output_prompt(agent_message)
        assessment = self._call_ollama(formatted_prompt, start)

        if assessment.decision == SecurityDecision.BLOCK:
            log_security_event(
                event_type="data_leakage_prevented",
                severity="high",
                rule_id=100103,
                action="llama_guard_output",
                decision="OBSERVE_BLOCK" if self.observe_only else "BLOCK",
                session_id=session_id,
                details={
                    "native_categories": assessment.native_categories,
                    "latency_ms": assessment.latency_ms,
                },
                message=f"Llama Guard 3 flagged agent output: {assessment.reason}",
            )

        return assessment

    def _call_ollama(self, prompt: list[dict], start_time: float) -> SecurityAssessment:
        try:
            with httpx.Client(timeout=self.timeout) as client:
                res = client.post(
                    f"{self.ollama_url}/api/chat",
                    headers={"Authorization": f"Bearer {self.gateway_token}"}
                    if self.gateway_token else {},
                    json={
                        "model": self.model,
                        "messages": prompt,
                        "stream": False,
                        "options": {"temperature": 0, "num_predict": 64},
                    },
                )
                latency = round((time.perf_counter() - start_time) * 1000, 2)
                if res.status_code != 200:
                    return unavailable_assessment(
                        detector_id=f"llama_guard_3:{self.model}",
                        reason=f"Ollama returned HTTP status {res.status_code}",
                        details={"status_code": res.status_code, "latency_ms": latency},
                    )

                raw = res.json().get("message", {}).get("content", "").strip()
                return parse_llama_guard_raw_output(
                    raw_text=raw,
                    detector_id=f"llama_guard_3:{self.model}",
                    latency_ms=latency,
                )
        except httpx.TimeoutException:
            latency = round((time.perf_counter() - start_time) * 1000, 2)
            return unavailable_assessment(
                detector_id=f"llama_guard_3:{self.model}",
                reason=f"Classifier timed out after {self.timeout}s",
                details={"timeout_seconds": self.timeout, "latency_ms": latency},
            )
        except Exception as e:
            latency = round((time.perf_counter() - start_time) * 1000, 2)
            return unavailable_assessment(
                detector_id=f"llama_guard_3:{self.model}",
                reason=f"Classifier network/IO error: {str(e)}",
                details={"error": str(e), "latency_ms": latency},
            )

    @staticmethod
    def _format_input_prompt(user_text: str) -> list[dict]:
        # Ollama applies the model's native Llama Guard conversation template.
        return [{"role": "user", "content": user_text}]

    @staticmethod
    def _format_output_prompt(agent_text: str) -> list[dict]:
        return [
            {"role": "user", "content": "Provide authorized banking information."},
            {"role": "assistant", "content": agent_text},
        ]
