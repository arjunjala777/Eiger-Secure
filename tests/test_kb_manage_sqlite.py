"""Tenant and ownership checks against the persistent production KB backend."""

from halcyon.sqlite_kb import SQLiteKB


def _kb(tmp_path) -> SQLiteKB:
    kb = SQLiteKB(collection="kb-manage-bypass", db_path=str(tmp_path / "kb.sqlite3"))
    kb.seed([{"text": "Wire cut-off is 16:00 local.", "provenance": "trusted"}])
    kb.add("my first attempt", "user", owner_session="alice")
    kb.add("my second attempt", "user", owner_session="alice")
    kb.add("bob's attempt", "user", owner_session="bob")
    return kb


def test_list_own_returns_only_the_callers_uploads(tmp_path):
    kb = _kb(tmp_path)
    texts = [c.text for c in kb.list_own("alice")]
    assert texts == ["my first attempt", "my second attempt"]


def test_list_own_never_exposes_the_seed_corpus(tmp_path):
    kb = _kb(tmp_path)
    assert all(c.provenance == "user" for c in kb.list_own("alice"))
    assert not any("Wire cut-off" in c.text for c in kb.list_own("alice"))


def test_delete_own_removes_only_that_chunk(tmp_path):
    kb = _kb(tmp_path)
    target = kb.list_own("alice")[0]
    assert kb.delete_own("alice", target.id) is True
    assert [c.text for c in kb.list_own("alice")] == ["my second attempt"]


def test_cannot_delete_another_sessions_upload(tmp_path):
    kb = _kb(tmp_path)
    bob_chunk = kb.list_own("bob")[0]
    assert kb.delete_own("alice", bob_chunk.id) is False
    assert len(kb.list_own("bob")) == 1


def test_cannot_delete_a_seed_document(tmp_path):
    kb = _kb(tmp_path)
    seeded = kb.retrieve("wire cut-off", "alice", k=1)[0]
    assert kb.delete_own("alice", seeded.id) is False
    hits = kb.retrieve("wire cut-off", "alice", k=3)
    assert "Wire cut-off is 16:00 local." in [c.text for c in hits]


def test_delete_own_is_false_for_unknown_id(tmp_path):
    assert _kb(tmp_path).delete_own("alice", "nope") is False
