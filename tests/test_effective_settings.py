from halcyon.config import effective_settings, load_settings
from halcyon.session_state import InMemorySessionState

BASE = load_settings({"HALCYON_MODE": "vulnerable"})  # all SEC_* off


def test_no_override_returns_base_unchanged():
    ss = InMemorySessionState()
    eff = effective_settings(BASE, ss, "alice", "m1")
    assert eff is BASE


def test_L2_turns_on_only_that_modules_flags():
    ss = InMemorySessionState()
    ss.set_level("alice", "m1", "L2")
    eff = effective_settings(BASE, ss, "alice", "m1")
    assert eff.sec_system_prompt_hardening is True
    assert eff.sec_input_filter is True
    assert eff.sec_guardrails is False


def test_L1_forces_that_modules_flags_off_even_if_base_secure():
    secure = load_settings({"HALCYON_MODE": "secure"})  # all SEC_* on
    ss = InMemorySessionState()
    ss.set_level("alice", "m8", "L1")
    eff = effective_settings(secure, ss, "alice", "m8")
    assert eff.sec_guardrails is False
    assert eff.sec_system_prompt_hardening is True


def test_module_with_no_flags_returns_base():
    ss = InMemorySessionState()
    ss.set_level("alice", "m4", "L2")
    eff = effective_settings(BASE, ss, "alice", "m4")
    assert eff is BASE
