from tests.test_chat_memory_endpoint import make_client


def test_set_and_get_level_round_trip():
    client, ss = make_client()
    assert client.get("/api/level", params={"session": "u1"}).json() == {}
    r = client.post("/api/level", json={"session_id": "u1", "module": "m1", "level": "L2"})
    assert r.json()["status"] == "ok"
    assert client.get("/api/level", params={"session": "u1"}).json() == {"m1": "L2"}
    assert ss.get_level("u1", "m1") == "L2"


def test_rejects_bad_level_and_module():
    client, _ = make_client()
    assert "error" in client.post(
        "/api/level", json={"session_id": "u1", "module": "m1", "level": "L9"}
    ).json()
    assert "error" in client.post(
        "/api/level", json={"session_id": "u1", "module": "m99", "level": "L1"}
    ).json()


def test_levels_are_isolated_per_session():
    client, _ = make_client()
    client.post("/api/level", json={"session_id": "u1", "module": "m8", "level": "L2"})
    assert client.get("/api/level", params={"session": "u2"}).json() == {}
