"""Inference-only gateway for the unauthenticated Ollama control plane.

The Ollama daemon remains on a private network. Application containers can
reach this gateway, which permits only inference/readiness operations and an
exact model allowlist; model create/delete/pull/push/copy endpoints are never
forwarded.
"""

from __future__ import annotations

import hmac
import json
import os
import re
from pathlib import Path

import httpx
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse, Response

UPSTREAM = os.getenv("OLLAMA_UPSTREAM_URL", "http://127.0.0.1:11434").rstrip("/")
TOKEN = os.getenv("EIGER_OLLAMA_GATEWAY_TOKEN", "")
ALLOWED_MODELS = frozenset(
    value.strip()
    for value in os.getenv(
        "EIGER_OLLAMA_MODELS",
        ",".join(filter(None, [os.getenv("OLLAMA_MODEL", "llama3.1:8b"), os.getenv("LLAMA_GUARD_MODEL", "llama-guard3:1b")])),
    ).split(",")
    if value.strip()
)
MAX_BODY = 4 * 1024 * 1024
MANIFEST = os.getenv("EIGER_MODEL_MANIFEST", "config/models.json")


def approved_digest(model: str) -> str:
    """Fail closed; never approve a model by recording its current digest here."""
    pins = json.loads(Path(MANIFEST).read_text(encoding="utf-8"))
    digest = pins[model]
    if not isinstance(digest, str) or not re.fullmatch(r"(?:sha256:)?[a-f0-9]{64}", digest):
        raise ValueError("invalid model digest")
    return digest.removeprefix("sha256:")
_ALLOWED_PATHS = {
    ("GET", "/api/tags"),
    ("GET", "/api/version"),
    ("POST", "/api/chat"),
    ("POST", "/api/show"),
    ("POST", "/v1/chat/completions"),
}

app = FastAPI(title="Eiger Ollama Inference Gateway", docs_url=None, redoc_url=None, openapi_url=None)


@app.get("/health")
async def health() -> JSONResponse:
    configured = len(TOKEN) >= 32
    return JSONResponse(
        {"status": "ok" if configured else "unavailable"},
        status_code=200 if configured else 503,
    )


@app.api_route("/{path:path}", methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"])
async def inference_only(request: Request, path: str) -> Response:
    method = request.method.upper()
    normalized = "/" + path
    if (method, normalized) not in _ALLOWED_PATHS:
        return JSONResponse({"error": "Ollama management operation is not exposed"}, status_code=404)
    authorization = request.headers.get("authorization", "")
    expected = "Bearer " + TOKEN
    if len(TOKEN) < 32 or not hmac.compare_digest(authorization, expected):
        return JSONResponse({"error": "unauthorized"}, status_code=401)

    body = bytearray()
    async for chunk in request.stream():
        body.extend(chunk)
        if len(body) > MAX_BODY:
            return JSONResponse({"error": "request too large"}, status_code=413)
    body = bytes(body)
    payload = None
    if method == "POST":
        try:
            payload = json.loads(body)
        except (ValueError, UnicodeError):
            return JSONResponse({"error": "valid JSON request required"}, status_code=400)
        if not isinstance(payload, dict):
            return JSONResponse({"error": "JSON object required"}, status_code=400)
        if normalized in ("/api/chat", "/api/show", "/v1/chat/completions"):
            model = payload.get("model")
            if not isinstance(model, str) or model not in ALLOWED_MODELS:
                return JSONResponse({"error": "model is not approved"}, status_code=403)

    try:
        async with httpx.AsyncClient(timeout=120, trust_env=False) as client:
            if method == "POST":
                try:
                    expected_digest = approved_digest(payload["model"])
                    inventory = await client.request("GET", UPSTREAM + "/api/tags")
                    if inventory.status_code != 200:
                        raise ValueError("inventory unavailable")
                    matches = [m for m in inventory.json()["models"] if m.get("name") == payload["model"]]
                    if len(matches) != 1 or matches[0].get("digest", "").removeprefix("sha256:") != expected_digest:
                        raise ValueError("model digest mismatch")
                except (OSError, ValueError, KeyError, TypeError, AttributeError):
                    return JSONResponse({"error": "approved model integrity could not be verified"}, status_code=503)
            upstream = await client.request(
                method,
                UPSTREAM + normalized,
                content=body if method == "POST" else None,
                headers={"content-type": "application/json"} if method == "POST" else None,
            )
    except httpx.HTTPError:
        return JSONResponse({"error": "inference service unavailable"}, status_code=502)

    response_headers = {}
    for name in ("content-type", "content-length"):
        if name in upstream.headers:
            response_headers[name] = upstream.headers[name]
    response_body = upstream.content
    if normalized == "/api/tags" and upstream.status_code == 200:
        try:
            data = upstream.json()
            data["models"] = [
                model for model in data.get("models", [])
                if isinstance(model, dict) and model.get("name") in ALLOWED_MODELS
            ]
            response_body = json.dumps(data, separators=(",", ":")).encode()
            response_headers.pop("content-length", None)
            response_headers["content-type"] = "application/json"
        except (ValueError, TypeError):
            return JSONResponse({"error": "invalid inference service response"}, status_code=502)
    return Response(response_body, status_code=upstream.status_code, headers=response_headers)
