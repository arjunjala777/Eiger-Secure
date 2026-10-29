import json

from fastapi.testclient import TestClient

from halcyon import ollama_gateway


class _UpstreamResponse:
    status_code = 200
    headers = {"content-type": "application/json"}
    content = b'{"models":[]}'

    def __init__(self, payload):
        self._payload = payload
        self.content = json.dumps(payload).encode()

    def json(self):
        return self._payload


class _FakeAsyncClient:
    last_request = None

    def __init__(self, **_kwargs):
        pass

    async def __aenter__(self):
        return self

    async def __aexit__(self, *_args):
        return None

    async def request(self, method, url, **kwargs):
        type(self).last_request = (method, url, kwargs)
        if url.endswith("/api/tags"):
            return _UpstreamResponse({"models": [
                {"name": "llama3.1:8b", "digest": "a" * 64},
                {"name": "eiger-pwn-model", "digest": "unapproved"},
            ]})
        return _UpstreamResponse({"message": {"content": "ok"}})


def _configure(monkeypatch):
    monkeypatch.setattr(ollama_gateway, "approved_digest", lambda model: "a" * 64)
    monkeypatch.setattr(ollama_gateway, "TOKEN", "gateway-secret-for-tests-0123456789abcdef")
    monkeypatch.setattr(ollama_gateway, "ALLOWED_MODELS", frozenset({"llama3.1:8b"}))
    monkeypatch.setattr(ollama_gateway.httpx, "AsyncClient", _FakeAsyncClient)
    return TestClient(ollama_gateway.app)


def test_gateway_requires_auth_and_hides_management_routes(monkeypatch):
    client = _configure(monkeypatch)
    assert client.get("/api/tags").status_code == 401
    headers = {"Authorization": "Bearer gateway-secret-for-tests-0123456789abcdef"}
    assert client.post("/api/create", headers=headers, json={}).status_code == 404
    assert client.request("DELETE", "/api/delete", headers=headers, json={}).status_code == 404


def test_gateway_filters_models_and_rejects_unapproved_inference(monkeypatch):
    client = _configure(monkeypatch)
    headers = {"Authorization": "Bearer gateway-secret-for-tests-0123456789abcdef"}
    tags = client.get("/api/tags", headers=headers)
    assert [m["name"] for m in tags.json()["models"]] == ["llama3.1:8b"]

    denied = client.post("/api/chat", headers=headers, json={
        "model": "eiger-pwn-model", "messages": [], "stream": False,
    })
    assert denied.status_code == 403
    assert _FakeAsyncClient.last_request[1].endswith("/api/tags")

    allowed = client.post("/api/chat", headers=headers, json={
        "model": "llama3.1:8b", "messages": [], "stream": False,
    })
    assert allowed.status_code == 200
    assert _FakeAsyncClient.last_request[1].endswith("/api/chat")


def test_gateway_blocks_replaced_approved_tag_before_inference(monkeypatch):
    client = _configure(monkeypatch)
    monkeypatch.setattr(ollama_gateway, "approved_digest", lambda model: "b" * 64)
    response = client.post("/api/chat", headers={"Authorization": "Bearer gateway-secret-for-tests-0123456789abcdef"}, json={"model": "llama3.1:8b", "messages": []})
    assert response.status_code == 503
    assert _FakeAsyncClient.last_request[1].endswith("/api/tags")


def test_manifest_requires_reviewed_digest(tmp_path, monkeypatch):
    import pytest
    monkeypatch.setattr(ollama_gateway, "MANIFEST", str(tmp_path / "missing.json"))
    with pytest.raises(OSError):
        ollama_gateway.approved_digest("llama3.1:8b")
    manifest = tmp_path / "models.json"
    manifest.write_text(json.dumps({"llama3.1:8b": "a" * 64}))
    monkeypatch.setattr(ollama_gateway, "MANIFEST", str(manifest))
    assert ollama_gateway.approved_digest("llama3.1:8b") == "a" * 64
