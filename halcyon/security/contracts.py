"""
Explicit Security Assessment Contracts & Taxonomy Mapping.

Enforces strict outcome typing: ALLOW, BLOCK, REVIEW, UNAVAILABLE.
Distinguishes native Meta Llama Guard 3-1B categories (S1-S13) from distinct
Eiger policy violation codes. Never translates missing or failed evidence into ALLOW.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

# ============================================================================
# Meta Llama Guard 3-1B Native Taxonomy (Official Model Card)
# ============================================================================
LLAMA_GUARD_3_TAXONOMY: dict[str, str] = {
    "S1": "Violent Crimes",
    "S2": "Non-Violent Crimes",
    "S3": "Sex-Related Crimes",
    "S4": "Child Sexual Exploitation and Abuse",
    "S5": "Defamation",
    "S6": "Specialized Advice (Financial / Legal / Medical)",
    "S7": "Privacy & PII Violations",
    "S8": "Intellectual Property",
    "S9": "Indiscriminate Weapons (CBRN)",
    "S10": "Hate Speech",
    "S11": "Suicide or Self-Harm",
    "S12": "Sexual Content",
    "S13": "Elections (Official Meta Definition)",
}

# ============================================================================
# Distinct Eiger Application Policy Codes (Application-Layer Authority)
# ============================================================================
EIGER_PROMPT_INJECTION = "EIGER_PROMPT_INJECTION"
EIGER_UNAUTHORIZED_FINANCIAL = "EIGER_UNAUTHORIZED_FINANCIAL"
EIGER_CROSS_TENANT_ACCESS = "EIGER_CROSS_TENANT_ACCESS"
EIGER_DATA_DISCLOSURE = "EIGER_DATA_DISCLOSURE"
EIGER_DELIMITER_BREAKOUT = "EIGER_DELIMITER_BREAKOUT"

EIGER_POLICY_DESCRIPTIONS: dict[str, str] = {
    EIGER_PROMPT_INJECTION: "Direct or indirect prompt injection, jailbreak, or system override attempt",
    EIGER_UNAUTHORIZED_FINANCIAL: "Unauthorized financial transfer, unowned debit, fake refund, or treasury breach",
    EIGER_CROSS_TENANT_ACCESS: "Cross-session identity spoofing or unauthorized tenant access",
    EIGER_DATA_DISCLOSURE: "Sensitive credential, PII, or internal system instruction disclosure",
    EIGER_DELIMITER_BREAKOUT: "XML or context boundary breakout attempting to fake system/verified content",
}


class SecurityDecision(str, Enum):
    """Explicit security evaluation decision. Never ambiguous."""

    ALLOW = "ALLOW"
    BLOCK = "BLOCK"
    REVIEW = "REVIEW"
    UNAVAILABLE = "UNAVAILABLE"


@dataclass(frozen=True)
class SecurityAssessment:
    """
    Structured outcome of an AI or deterministic guardrail inspection.
    Missing evidence or model failure MUST be marked UNAVAILABLE.
    """

    decision: SecurityDecision
    detector_id: str
    native_categories: tuple[str, ...] = field(default_factory=tuple)
    eiger_policy_codes: tuple[str, ...] = field(default_factory=tuple)
    model_digest: str | None = None
    policy_version: str = "2026-10-26"
    latency_ms: float | None = None
    reason: str = ""
    details: dict[str, Any] = field(default_factory=dict)

    @property
    def is_allowed(self) -> bool:
        return self.decision == SecurityDecision.ALLOW

    @property
    def is_blocked(self) -> bool:
        return self.decision == SecurityDecision.BLOCK

    @property
    def is_unavailable(self) -> bool:
        return self.decision == SecurityDecision.UNAVAILABLE


def allow_assessment(
    detector_id: str,
    reason: str = "Input passed safety evaluation",
    latency_ms: float | None = None,
    details: dict[str, Any] | None = None,
) -> SecurityAssessment:
    return SecurityAssessment(
        decision=SecurityDecision.ALLOW,
        detector_id=detector_id,
        reason=reason,
        latency_ms=latency_ms,
        details=details or {},
    )


def block_assessment(
    detector_id: str,
    reason: str,
    native_categories: tuple[str, ...] = (),
    eiger_policy_codes: tuple[str, ...] = (),
    latency_ms: float | None = None,
    details: dict[str, Any] | None = None,
) -> SecurityAssessment:
    return SecurityAssessment(
        decision=SecurityDecision.BLOCK,
        detector_id=detector_id,
        native_categories=tuple(native_categories),
        eiger_policy_codes=tuple(eiger_policy_codes),
        reason=reason,
        latency_ms=latency_ms,
        details=details or {},
    )


def unavailable_assessment(
    detector_id: str,
    reason: str,
    details: dict[str, Any] | None = None,
) -> SecurityAssessment:
    """Explicit result when a detector encounters an error, timeout, or missing model."""
    return SecurityAssessment(
        decision=SecurityDecision.UNAVAILABLE,
        detector_id=detector_id,
        reason=reason,
        details=details or {},
    )


def parse_llama_guard_raw_output(
    raw_text: str,
    detector_id: str = "llama_guard_3_1b",
    latency_ms: float | None = None,
) -> SecurityAssessment:
    """
    Parse native Llama Guard 3 model text output strictly adhering to Meta format.
    Output must be 'safe' OR 'unsafe\nS1,S2...'.
    Empty, malformed, or missing text yields UNAVAILABLE; never ALLOW.
    """
    if not raw_text or not raw_text.strip():
        return unavailable_assessment(
            detector_id=detector_id,
            reason="Empty or null output received from safety classifier",
        )

    lines = [line.strip() for line in raw_text.strip().splitlines() if line.strip()]
    first_line = lines[0].lower()

    if first_line == "safe" and len(lines) == 1:
        return allow_assessment(
            detector_id=detector_id,
            reason="Classified safe by Llama Guard 3",
            latency_ms=latency_ms,
        )

    if first_line == "unsafe":
        if len(lines) != 2 or not re.fullmatch(
            r"S(?:[1-9]|1[0-3])(?:\s*,\s*S(?:[1-9]|1[0-3]))*", lines[1]
        ):
            return unavailable_assessment(detector_id, "Invalid classifier category list")
        native_cats: list[str] = []
        if len(lines) > 1:
            tokens = re.split(r"[,\s]+", lines[1])
            native_cats = [t.upper() for t in tokens if t.upper() in LLAMA_GUARD_3_TAXONOMY]

        # Map to Eiger policy codes if applicable
        eiger_codes: list[str] = []
        # Specialized advice is not evidence of an unauthorized financial operation.
        if "S7" in native_cats:
            eiger_codes.append(EIGER_DATA_DISCLOSURE)

        cat_names = [f"{c} ({LLAMA_GUARD_3_TAXONOMY.get(c, 'Unknown')})" for c in native_cats]
        reason_msg = f"Llama Guard 3 flagged unsafe: {', '.join(cat_names) if cat_names else 'Policy violation'}"

        return block_assessment(
            detector_id=detector_id,
            reason=reason_msg,
            native_categories=tuple(native_cats),
            eiger_policy_codes=tuple(eiger_codes),
            latency_ms=latency_ms,
            details={"raw_model_response": raw_text},
        )

    # Malformed output from model
    return unavailable_assessment(
        detector_id=detector_id,
        reason=f"Malformed model response; expected 'safe' or 'unsafe', got: {raw_text[:80]}",
        details={"raw_model_response": raw_text},
    )
