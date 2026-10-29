from halcyon import guards
from halcyon.config import load_settings

VULN = load_settings({"HALCYON_MODE": "vulnerable"})
SECURE = load_settings({"HALCYON_MODE": "secure"})


def test_assemble_no_history_is_unchanged_vulnerable():
    msgs = guards.assemble(VULN, "hello")
    assert msgs == [
        {"role": "user", "content": guards.SYSTEM_WITH_TOKEN + "\n\nUser: hello"}
    ]


def test_assemble_no_history_is_unchanged_secure():
    msgs = guards.assemble(SECURE, "hello")
    assert msgs == [
        {"role": "system", "content": guards.SYSTEM_BASE},
        {"role": "user", "content": "hello"},
    ]


def test_assemble_with_history_secure_inserts_between_system_and_user():
    hist = [
        {"role": "user", "content": "earlier"},
        {"role": "assistant", "content": "ok"},
    ]
    msgs = guards.assemble(SECURE, "now", history=hist)
    assert msgs == [
        {"role": "system", "content": guards.SYSTEM_BASE},
        {"role": "user", "content": "earlier"},
        {"role": "assistant", "content": "ok"},
        {"role": "user", "content": "now"},
    ]


def test_assemble_with_history_vulnerable_keeps_token_context_then_history():
    hist = [
        {"role": "user", "content": "earlier"},
        {"role": "assistant", "content": "ok"},
    ]
    msgs = guards.assemble(VULN, "now", history=hist)
    assert msgs[0] == {"role": "user", "content": guards.SYSTEM_WITH_TOKEN}
    assert msgs[1:3] == hist
    assert msgs[-1] == {"role": "user", "content": "User: now"}
