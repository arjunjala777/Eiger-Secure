"""Application-level input/output assessments with explicit observe/enforce policy."""

import anyio
from halcyon.security.contracts import SecurityDecision, unavailable_assessment
from halcyon.security.llama_guard import LlamaGuardClassifier
from halcyon.security.nemo_integration import NeMoGuardrailsIntegration
from halcyon.security.wazuh_logger import log_security_event

_SHARED_NEMO = None


class GuardrailRuntime:
    def __init__(
        self,
        mode="observe",
        ollama_url="http://127.0.0.1:11434",
        model="llama-guard3:1b",
        timeout=3,
        gateway_token="",
    ):
        if mode not in ("off", "observe", "enforce"):
            raise ValueError("Guard mode must be off, observe or enforce")
        self.mode = mode
        self.classifier = LlamaGuardClassifier(
            ollama_url, model, timeout, observe_only=mode != "enforce",
            gateway_token=gateway_token,
        )
        self._nemo = None
        self.last_decisions = []
        self._limiter = anyio.CapacityLimiter(4)

    async def assess(self, text, direction, context):
        global _SHARED_NEMO
        if self.mode == "off":
            return []
        if len(text) > 32768:
            return [unavailable_assessment("guard_budget", "Assessment exceeds input budget")]
        results = []
        with anyio.move_on_after(self.classifier.timeout + 2) as scope:
            if self._nemo is None:
                if _SHARED_NEMO is None:
                    _SHARED_NEMO = await anyio.to_thread.run_sync(
                        NeMoGuardrailsIntegration, limiter=self._limiter
                    )
                self._nemo = _SHARED_NEMO
            nemo_method = (
                self._nemo.assess_input if direction == "input" else self._nemo.assess_output
            )
            results.append(await nemo_method(text, context.principal))
            method = (
                self.classifier.assess_input
                if direction == "input"
                else self.classifier.assess_output
            )
            results.append(
                await anyio.to_thread.run_sync(
                    method, text, context.principal, limiter=self._limiter
                )
            )
        if scope.cancel_called or len(results) != 2:
            results.append(unavailable_assessment("guard_budget", "Assessment deadline exceeded"))
        self.last_decisions = [r.decision.value for r in results]
        for result in results:
            log_security_event(
                "guard_assessment",
                "medium" if result.is_unavailable else "low",
                100104,
                "guard_" + direction,
                ("OBSERVE_" if self.mode == "observe" else "") + result.decision.value,
                session_id=context.principal,
                detector_id="guard_runtime",
                details={"detector": result.detector_id, "degraded": result.is_unavailable},
            )
        return results

    def rejection_status(self, results):
        if self.mode != "enforce":
            return None
        if any(
            r.decision in (SecurityDecision.UNAVAILABLE, SecurityDecision.REVIEW) for r in results
        ):
            return 503
        if any(r.is_blocked for r in results):
            return 403
        return None
