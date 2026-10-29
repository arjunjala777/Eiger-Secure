from halcyon.session_state import InMemorySessionState


def test_history_starts_empty_and_appends_in_order():
    s = InMemorySessionState()
    assert s.get_history("alice", "chat") == []
    s.append_turn("alice", "chat", "hi", "hello")
    s.append_turn("alice", "chat", "who are you", "Halo")
    assert s.get_history("alice", "chat") == [
        {"role": "user", "content": "hi"},
        {"role": "assistant", "content": "hello"},
        {"role": "user", "content": "who are you"},
        {"role": "assistant", "content": "Halo"},
    ]


def test_history_is_isolated_by_session_and_surface():
    s = InMemorySessionState()
    s.append_turn("alice", "chat", "a", "b")
    assert s.get_history("bob", "chat") == []
    assert s.get_history("alice", "agent") == []


def test_clear_history_empties_only_that_surface():
    s = InMemorySessionState()
    s.append_turn("alice", "chat", "a", "b")
    s.append_turn("alice", "agent", "c", "d")
    s.clear_history("alice", "chat")
    assert s.get_history("alice", "chat") == []
    assert len(s.get_history("alice", "agent")) == 2


def test_get_history_returns_a_copy():
    s = InMemorySessionState()
    s.append_turn("alice", "chat", "a", "b")
    s.get_history("alice", "chat").append({"role": "user", "content": "x"})
    assert len(s.get_history("alice", "chat")) == 2


def test_level_defaults_none_and_round_trips():
    s = InMemorySessionState()
    assert s.get_level("alice", "m1") is None
    s.set_level("alice", "m1", "L2")
    assert s.get_level("alice", "m1") == "L2"
    assert s.get_level("alice", "m2") is None
    assert s.get_level("bob", "m1") is None
