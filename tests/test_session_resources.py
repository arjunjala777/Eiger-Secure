from halcyon import bank_fixtures, kb_fixtures
from halcyon.kb import InMemoryKB
from halcyon.session_resources import BankProvider, KBProvider, slug


def test_slug_is_chroma_legal_and_stable():
    s = slug("some/weird session:id")
    assert 3 <= len(s) <= 63
    assert s.replace("-", "").replace("_", "").isalnum()
    assert s[0].isalnum() and s[-1].isalnum()
    assert slug("x") == slug("x")  # stable


def test_bank_provider_isolates_and_memoizes():
    bank_for = BankProvider(bank_fixtures.seed_for)
    a1 = bank_for("A")
    a2 = bank_for("A")
    b = bank_for("B")
    assert a1 is a2                       # memoized per session
    assert a1 is not b                    # isolated per session
    # A draining its own view does not change B's balances
    acct = "acct-victim"
    a1.debit(acct, 100)
    assert b.get(acct).balance != a1.get(acct).balance


def test_kb_provider_isolates_user_chunks():
    kb_for = KBProvider(lambda sid: InMemoryKB(), kb_fixtures.SEED)
    a = kb_for("A")
    b = kb_for("B")
    assert a is not b
    a.add("PWNED-note secret", "user", owner_session="A")
    # B never sees A's user chunk
    assert all("PWNED-note" not in c.text for c in b.retrieve("secret", "B"))
