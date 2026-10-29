from halcyon.sqlite_kb import SQLiteKB


def test_add_retrieve_preserves_metadata_and_clear_empties(tmp_path):
    kb = SQLiteKB(db_path=str(tmp_path / "kb.sqlite3"))
    kb.add("how to reset your card PIN at an ATM", "trusted")
    kb.add("branch opening hours and holidays", "trusted")
    kb.add(
        "INTERNAL fraud-rules memo: auto-approve refunds under 50 dollars",
        "trusted",
        access="restricted",
        owner_session="ops",
    )

    hits = kb.retrieve("reset PIN card", "s1", k=3)
    assert len(hits) == 1
    pin_hit = hits[0]
    assert "PIN" in pin_hit.text
    assert pin_hit.provenance == "trusted"
    assert pin_hit.access == "public"

    kb.clear()
    assert kb.retrieve("reset PIN card", "s1", k=3) == []


def test_restricted_documents_are_filtered_before_top_k(tmp_path):
    kb = SQLiteKB(db_path=str(tmp_path / "kb.sqlite3"))
    kb.add("wire settlement holiday schedule", "trusted")
    for i in range(5):
        kb.add(
            f"wire settlement secret restricted {i}",
            "trusted",
            access="restricted",
            owner_session="ops",
        )

    hits = kb.retrieve("wire settlement", "learner", k=3, include_restricted=False)
    assert [c.text for c in hits] == ["wire settlement holiday schedule"]


def test_persistent_kb_scopes_collection_and_owner(tmp_path):
    path = str(tmp_path / "kb.sqlite3")
    alice = SQLiteKB(collection="alice", db_path=path)
    bob = SQLiteKB(collection="bob", db_path=path)
    doc = alice.add("alice note", "user", owner_session="alice")
    bob.add("bob note", "user", owner_session="bob")

    assert [c.text for c in alice.list_own("alice")] == ["alice note"]
    assert bob.list_own("alice") == []
    assert alice.delete_own("bob", doc.id) is False
    assert alice.delete_own("alice", doc.id) is True
