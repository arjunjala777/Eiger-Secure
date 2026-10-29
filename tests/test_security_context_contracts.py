"""
Tests for SecurityContext and SecurityAssessment Contracts.

Validates immutability, taxonomy correctness, fail-closed handling,
and refusal to translate missing evidence into safe.
"""

import pytest
from dataclasses import FrozenInstanceError

from halcyon.security.context import (
    SecurityContext,
    authenticated_context,
    anonymous_context,
)
from halcyon.security.contracts import (
    SecurityDecision,
    SecurityAssessment,
    allow_assessment,
    block_assessment,
    unavailable_assessment,
    parse_llama_guard_raw_output,
    LLAMA_GUARD_3_TAXONOMY,
    EIGER_PROMPT_INJECTION,
    EIGER_UNAUTHORIZED_FINANCIAL,
    EIGER_DATA_DISCLOSURE,
)


def test_security_context_immutability():
    ctx = authenticated_context(
        principal="alice",
        auth_method="session_cookie",
        roles=("user",),
        grants=("read_account",),
    )
    assert ctx.principal == "alice"
    assert ctx.is_authenticated()

    # Invariant: SecurityContext is frozen; attempts to mutate raise FrozenInstanceError
    with pytest.raises(FrozenInstanceError):
        ctx.principal = "bob"  # type: ignore

    with pytest.raises(FrozenInstanceError):
        ctx.roles = ("admin",)  # type: ignore


def test_security_context_rejects_empty_principal_or_invalid_auth():
    with pytest.raises(ValueError, match="non-empty principal"):
        authenticated_context(principal="", auth_method="session_cookie")

    with pytest.raises(ValueError, match="Invalid auth_method"):
        authenticated_context(principal="alice", auth_method="spoofed_header")


def test_anonymous_context_unauthenticated():
    ctx = anonymous_context()
    assert not ctx.is_authenticated()
    assert ctx.principal == ""
    assert ctx.roles == ("anonymous",)


def test_llama_guard_taxonomy_has_13_categories_with_s13_as_elections():
    assert len(LLAMA_GUARD_3_TAXONOMY) == 13
    assert LLAMA_GUARD_3_TAXONOMY["S13"] == "Elections (Official Meta Definition)"
    assert LLAMA_GUARD_3_TAXONOMY["S1"] == "Violent Crimes"
    assert LLAMA_GUARD_3_TAXONOMY["S6"] == "Specialized Advice (Financial / Legal / Medical)"


def test_parse_llama_guard_safe():
    res = parse_llama_guard_raw_output("safe\n")
    assert res.decision == SecurityDecision.ALLOW
    assert res.is_allowed
    assert not res.is_blocked


def test_parse_llama_guard_unsafe_with_categories():
    raw = "unsafe\nS6, S7"
    res = parse_llama_guard_raw_output(raw)
    assert res.decision == SecurityDecision.BLOCK
    assert res.is_blocked
    assert "S6" in res.native_categories
    assert "S7" in res.native_categories
    assert EIGER_UNAUTHORIZED_FINANCIAL not in res.eiger_policy_codes
    assert EIGER_DATA_DISCLOSURE in res.eiger_policy_codes


def test_parse_llama_guard_fail_closed_on_empty_or_malformed():
    """Critical: Missing, empty, or malformed classifier responses MUST yield UNAVAILABLE; never ALLOW."""
    # Empty string
    res_empty = parse_llama_guard_raw_output("")
    assert res_empty.decision == SecurityDecision.UNAVAILABLE
    assert not res_empty.is_allowed

    # Whitespace
    res_ws = parse_llama_guard_raw_output("   \n\t  ")
    assert res_ws.decision == SecurityDecision.UNAVAILABLE
    assert not res_ws.is_allowed

    # Malformed text (e.g. conversational chatter)
    res_chat = parse_llama_guard_raw_output("I am an AI assistant and I cannot determine if this is safe.")
    assert res_chat.decision == SecurityDecision.UNAVAILABLE
    assert not res_chat.is_allowed
