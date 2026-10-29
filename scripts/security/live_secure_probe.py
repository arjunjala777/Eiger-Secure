"""Disposable live probe for the local Secure Lab process stack."""

import os
import uuid

import httpx

from halcyon.web import _csrf_token, _sign_session


def main() -> None:
    app = os.environ.get("EIGER_APP_URL", "http://127.0.0.1:8000")
    gateway = os.environ.get("OLLAMA_URL", "http://127.0.0.1:11435")
    sid = "secure-probe-" + uuid.uuid4().hex
    secret = os.environ["HALCYON_SESSION_SECRET"]
    csrf = _csrf_token(sid, secret)
    session_headers = {
        "Cookie": f"eiger_session={_sign_session(sid, secret)}; eiger_csrf={csrf}",
        "X-CSRF-Token": csrf,
    }
    timeout = httpx.Timeout(10)

    with httpx.Client(timeout=timeout, trust_env=False) as client:
        health = client.get(app + "/health")
        health.raise_for_status()
        assert health.headers.get("x-content-type-options") == "nosniff"
        assert health.headers.get("x-frame-options") == "DENY"
        assert health.headers.get("access-control-allow-origin") is None

        assert client.get(app + "/chat?session=attacker-selected").status_code == 400
        assert client.post(
            app + "/api/config",
            json={"session_id": sid, "provider": "local", "model": "unapproved-model"},
        ).status_code == 401

        own_write = client.post(
            app + "/api/kb", json={"session_id": sid, "text": "secure probe note"},
            headers=session_headers,
        )
        own_write.raise_for_status()
        oversized = client.post(
            app + "/api/kb", json={"session_id": sid, "text": "x" * 10000},
            headers=session_headers,
        )
        assert oversized.status_code == 413

        downgrade = client.post(
            app + "/api/level",
            json={"session_id": sid, "module": "m3", "level": "L1"},
            headers=session_headers,
        )
        assert downgrade.status_code == 403
        invalid_model = client.post(
            app + "/api/config",
            json={"session_id": sid, "provider": "local", "model": "unapproved-model"},
            headers=session_headers,
        )
        assert invalid_model.status_code == 400
        wrong_origin = client.post(
            app + "/api/profile",
            json={"session_id": sid, "display_name": "probe"},
            headers={**session_headers, "Origin": "https://attacker.invalid"},
        )
        assert wrong_origin.status_code == 403

        cleanup = client.post(
            app + "/reset/m3", json={"session_id": sid}, headers=session_headers
        )
        cleanup.raise_for_status()

        token = os.environ["EIGER_OLLAMA_GATEWAY_TOKEN"]
        tags = client.get(gateway + "/api/tags", headers={"Authorization": f"Bearer {token}"})
        tags.raise_for_status()
        assert all(not item["name"].startswith("eiger-pwn") for item in tags.json().get("models", []))
        assert client.get(gateway + "/api/create", headers={"Authorization": f"Bearer {token}"}).status_code == 404

        unauth_mcp = client.post(
            os.environ.get("MCP_CORE_URL", "http://127.0.0.1:9001/mcp"),
            json={"jsonrpc": "2.0", "method": "tools/list", "id": 1},
        )
        assert unauth_mcp.status_code == 401

    print("Secure Lab live probes passed: auth/CSRF, session URL rejection, ingestion cap, model policy, MCP auth, Ollama inference-only gateway.")


if __name__ == "__main__":
    main()
