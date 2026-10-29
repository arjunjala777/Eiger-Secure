"""NeMo input/output checks, using structured outcomes and no generation model."""

from pathlib import Path
import re
from halcyon.security.contracts import (
    allow_assessment,
    block_assessment,
    unavailable_assessment,
    EIGER_PROMPT_INJECTION,
)

CONFIG_PATH = Path(__file__).parent / "nemo_config"


class NeMoGuardrailsIntegration:
    def __init__(self, config_dir=CONFIG_PATH, observe_only=True):
        self.observe_only = observe_only
        self._rails = None
        self._error = None
        try:
            from nemoguardrails import LLMRails, RailsConfig
            from nemoguardrails.actions import action

            self._rails = LLMRails(RailsConfig.from_path(str(config_dir)))

            @action(is_system_action=True)
            async def eiger_input_check(text):
                return not bool(
                    re.search(
                        r"ignore\s+(?:all\s+)?previous|developer mode|pretend you have no rules",
                        text,
                        re.I,
                    )
                )

            @action(is_system_action=True)
            async def eiger_output_check(text):
                return not bool(re.search(r"<script|(?:sk-|token-)[A-Za-z0-9_-]{20,}", text, re.I))

            self._rails.register_action(eiger_input_check, name="eiger_input_check")
            self._rails.register_action(eiger_output_check, name="eiger_output_check")
        except Exception as exc:
            self._error = type(exc).__name__
            self._rails = None

    @property
    def is_degraded(self):
        return self._rails is None

    @property
    def engine_name(self):
        return "nemo_llmrails_0.24.1" if self._rails else "nemo_unavailable"

    async def assess_input(self, prompt, session_id=None):
        return await self._assess(prompt, "user")

    async def assess_output(self, text, session_id=None):
        return await self._assess(text, "assistant")

    async def _assess(self, text, role):
        if self._rails is None:
            return unavailable_assessment(
                "nemo", "NeMo configuration unavailable: " + str(self._error)
            )
        try:
            from nemoguardrails.rails.llm.options import RailStatus

            result = await self._rails.check_async([{"role": role, "content": text}])
            if result.status == RailStatus.BLOCKED:
                return block_assessment(
                    "nemo",
                    "Configured rail blocked content",
                    eiger_policy_codes=(EIGER_PROMPT_INJECTION,),
                )
            if result.status == RailStatus.PASSED:
                return allow_assessment("nemo", "Configured rail passed")
            return unavailable_assessment("nemo", "Unexpected modified rail result")
        except Exception as exc:
            return unavailable_assessment("nemo", "NeMo check failed: " + type(exc).__name__)
