"""Offline unit tests replace only the external classifier transport.

Application wiring, NeMo checks, policy and executor still run. Tests that
explicitly exercise classifier transport or a live model opt out.
"""
import pytest


def authenticate_test_client(client, session_id: str, secret: str) -> None:
    """Install the same signed session and double-submit CSRF pair as a browser."""
    from halcyon.web import _csrf_token, _sign_session

    client.cookies.set("eiger_session", _sign_session(session_id, secret))
    csrf = _csrf_token(session_id, secret)
    client.cookies.set("eiger_csrf", csrf)
    client.headers.update({"X-CSRF-Token": csrf})


@pytest.fixture(autouse=True)
def offline_classifier_transport(request, monkeypatch):
    if request.node.path.name == "test_model_guardrails.py" or request.node.get_closest_marker("live_guard"):
        return
    from halcyon.security.llama_guard import LlamaGuardClassifier
    from halcyon.security.contracts import allow_assessment
    monkeypatch.setattr(LlamaGuardClassifier, "_call_ollama", lambda *args: allow_assessment("offline-test-classifier"))
