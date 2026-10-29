import hashlib
import hmac
import io
import base64
import json
import os
import re
import secrets
import threading
import time
import urllib.parse
import zipfile
from collections.abc import Callable
from contextlib import AbstractAsyncContextManager
from pathlib import Path
from typing import TYPE_CHECKING

import httpx
from fastapi import FastAPI, HTTPException, Response
from fastapi.responses import HTMLResponse, JSONResponse
from jinja2 import Environment, FileSystemLoader, select_autoescape
from pydantic import BaseModel
from starlette.requests import Request

from halcyon import (
    agent, audit, bank_fixtures, capstone, dispute_pipeline, guards, halo, kb_fixtures,
    learn_content, m4_answers, rag, source_browser, treasury_agent, treasury_corpus,
)
from halcyon.bank import Bank
from halcyon.config import (
    MODULE_FLAGS, Settings, effective_settings, is_model_approved,
    validate_provider_destination as validate_provider_destination,
)
from halcyon.kb import KnowledgeBase
from halcyon.session_state import InMemorySessionState, SessionState
from halcyon.llm import LLM, OllamaProvider, ToolLLM
from halcyon.store import Store
from halcyon.treasury_state import TreasuryProvider, TreasurySession
from halcyon.validators import chain as chain_validator
from halcyon.validators import m1, m2, m3, m4, m5, m6, m7, m8

if TYPE_CHECKING:
    from halcyon.mcp_host import MCPHost

LLMFactory = Callable[[str | None, str | None, str | None], LLM]
ToolLLMFactory = Callable[[str | None, str | None, str | None], ToolLLM]
MCPHostFactory = Callable[[str, Settings], AbstractAsyncContextManager["MCPHost"]]


class ChatIn(BaseModel):
    session_id: str
    message: str
    provider: str | None = None
    model: str | None = None
    api_key: str | None = None


class ResetIn(BaseModel):
    session_id: str


class ProfileIn(BaseModel):
    session_id: str
    display_name: str


class KbIn(BaseModel):
    session_id: str
    text: str


class AskIn(BaseModel):
    session_id: str
    query: str


class SubmitIn(BaseModel):
    session_id: str
    finding_type: str
    value: str


class AgentIn(BaseModel):
    session_id: str
    message: str
    provider: str | None = None
    model: str | None = None
    api_key: str | None = None


class DisputeIn(BaseModel):
    session_id: str
    original_tx_id: str | None = None
    idempotency_key: str | None = None
    dispute_text: str
    account: str
    amount: int
    provider: str | None = None
    model: str | None = None
    api_key: str | None = None


class LevelIn(BaseModel):
    session_id: str
    module: str
    level: str


class ConfigIn(BaseModel):
    session_id: str
    provider: str
    model: str | None = None
    api_key: str | None = None


class IngestIn(BaseModel):
    session_id: str
    key: str
    text: str


class DeleteIn(BaseModel):
    session_id: str
    chunk_id: str
    key: str | None = None


class ReviewIn(BaseModel):
    session_id: str
    provider: str | None = None
    model: str | None = None
    api_key: str | None = None


_VALIDATORS = {
    "m1": m1.validate,
    "m2": m2.validate,
    "m3": m3.validate,
    "m4": m4.validate,
    "m5": m5.validate,
    "m6": m6.validate,
    "m7": m7.validate,
    "m8": m8.validate,
}

_MODULE_TITLES = {
    "m1": "prompt injection",
    "m2": "output handling",
    "m3": "RAG poisoning",
    "m4": "supply-chain audit",
    "m5": "excessive agency",
    "m6": "MCP tool poisoning",
    "m7": "multi-agent trust",
    "m8": "guardrail bypass",
}

_GIF = bytes.fromhex(
    "47494638396101000100800000ffffff00000021f90401000000002c00000000010001000002024401003b"
)

_REVOKED_SESSIONS: set[str] = set()
_OIDC_JWKS_CLIENTS: dict[str, object] = {}


def _sign_session(session_id: str, secret: str, ttl_seconds: int = 86400) -> str:
    """Issue a versioned, integrity-protected session cookie."""
    now = int(time.time())
    payload = json.dumps(
        {"sid": session_id, "iat": now, "exp": now + ttl_seconds,
         "nonce": secrets.token_urlsafe(16)},
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    encoded = base64.urlsafe_b64encode(payload).rstrip(b"=").decode("ascii")
    signed = "eiger-session-v2." + encoded
    signature = hmac.new(secret.encode(), signed.encode("ascii"), hashlib.sha256).hexdigest()
    return f"{signed}.{signature}"


def _verify_session(cookie: str | None, secret: str, max_age: int = 86400) -> str | None:
    """Verify a v2 signature, bounded lifetime, nonce, and revocation state."""
    if not cookie:
        return None
    parts = cookie.split(".")
    if len(parts) != 3 or parts[0] != "eiger-session-v2":
        return None
    signed = ".".join(parts[:2])
    expected = hmac.new(secret.encode(), signed.encode("ascii"), hashlib.sha256).hexdigest()
    if not hmac.compare_digest(expected, parts[2]):
        return None
    try:
        padded = parts[1] + "=" * (-len(parts[1]) % 4)
        payload = json.loads(base64.urlsafe_b64decode(padded.encode("ascii")))
        sid, issued, expires, nonce = (
            payload["sid"], payload["iat"], payload["exp"], payload["nonce"]
        )
        now = int(time.time())
        if (
            not isinstance(sid, str) or not sid or len(sid) > 256
            or type(issued) is not int or type(expires) is not int
            or issued > now + 60 or expires <= now
            or expires - issued > max_age or now - issued > max_age
            or not isinstance(nonce, str) or len(nonce) < 20
            or sid in _REVOKED_SESSIONS
        ):
            return None
        return sid
    except (ValueError, TypeError, KeyError, UnicodeError, json.JSONDecodeError):
        return None


def _verify_oidc_bearer(token: str, settings: Settings) -> str | None:
    """Validate a production OIDC JWT using only the configured issuer/JWKS."""
    if settings.profile != "production" or not token:
        return None
    try:
        import jwt

        client = _OIDC_JWKS_CLIENTS.get(settings.oidc_jwks_url)
        if client is None:
            client = jwt.PyJWKClient(settings.oidc_jwks_url, timeout=3, cache_keys=True)
            _OIDC_JWKS_CLIENTS[settings.oidc_jwks_url] = client
        key = client.get_signing_key_from_jwt(token).key
        claims = jwt.decode(
            token,
            key,
            algorithms=["RS256", "ES256"],
            audience=settings.oidc_audience,
            issuer=settings.oidc_issuer,
            options={"require": ["exp", "iat", "iss", "sub", "aud"]},
            leeway=30,
        )
        subject = claims.get("sub")
        if not isinstance(subject, str) or not subject or len(subject) > 256:
            return None
        # Avoid exposing the upstream subject or issuer in cookies, URLs, or logs.
        pseudonym = hmac.new(
            settings.session_secret.encode(),
            (settings.oidc_issuer + "\0" + subject).encode(),
            hashlib.sha256,
        ).hexdigest()
        return "oidc-" + pseudonym
    except Exception:
        # Authentication failures are intentionally indistinguishable to callers.
        return None


def _csrf_token(session_id: str, secret: str) -> str:
    return hmac.new(
        secret.encode(), ("eiger-csrf-v1\0" + session_id).encode(), hashlib.sha256
    ).hexdigest()


# re-export for backwards compatibility
__all_web__ = ["validate_provider_destination", "create_app"]


def create_app(
    store: Store,
    settings: Settings,
    llm_factory: LLMFactory,
    kb_for: Callable[[str], KnowledgeBase],
    bank_for: Callable[[str], Bank],
    tool_llm_factory: ToolLLMFactory,
    mcp_host_factory: MCPHostFactory,
    session_state: SessionState | None = None,
    treasury_for: TreasuryProvider | None = None,
    treasury_kb_for: Callable[[str], KnowledgeBase] | None = None,
    guard_runtime=None,
) -> FastAPI:
    if settings.expose_openapi:
        app = FastAPI(title="Eiger")
    else:
        app = FastAPI(title="Eiger", openapi_url=None, docs_url=None, redoc_url=None)

    import json
    from halcyon.security.context import request_context, authenticated_context, anonymous_context
    from halcyon.security.runtime import GuardrailRuntime
    from halcyon.security.wazuh_logger import AuditUnavailable
    runtime = guard_runtime or GuardrailRuntime(
        settings.guard_mode, settings.ollama_url, settings.guard_model,
        settings.guard_timeout, gateway_token=settings.ollama_gateway_token,
    )
    app.state.guard_runtime = runtime
    model_routes = {"/api/chat", "/api/ask", "/api/agent", "/api/mcp-agent", "/api/dispute", "/api/guarded-chat", "/api/treasury/review"}

    @app.exception_handler(AuditUnavailable)
    async def _audit_unavailable(request, exc):
        return JSONResponse({"error": "Security audit unavailable"}, status_code=503)

    @app.middleware("http")
    async def _trusted_security_pipeline(request: Request, call_next):
        identity = _get_auth_session(request)
        context = authenticated_context(identity, "bearer_token" if request.headers.get("authorization") else "session_cookie") if identity else anonymous_context()
        request.state.security_context = context
        marker = request_context.set(context)
        try:
            protected_model = request.url.path in model_routes and request.method == "POST" and (settings.mode == "secure" or settings.profile == "production")
            if request.method in ("POST", "PUT", "PATCH", "DELETE"):
                chunks, size = [], 0
                async for chunk in request.stream():
                    size += len(chunk)
                    if size > 1024 * 1024:
                        return JSONResponse({"error": "Request too large"}, status_code=413)
                    chunks.append(chunk)
                request._body = b"".join(chunks)
            if protected_model:
                if not context.is_authenticated():
                    return JSONResponse({"error": "unauthorized", "detail": "unauthorized: valid authentication required"}, status_code=401)
                body = await request.body()
                if len(body) > 65536:
                    return JSONResponse({"error": "Request too large"}, status_code=413)
                try:
                    data = json.loads(body)
                except (ValueError, UnicodeError):
                    return JSONResponse({"error": "Invalid JSON"}, status_code=400)
                if not isinstance(data, dict):
                    return JSONResponse({"error": "Expected JSON object"}, status_code=400)
                if data.get("session_id") != context.principal:
                    return JSONResponse({"error": "Cross-session access denied", "detail": "Cross-session access denied"}, status_code=403)
                text = str(data.get("message", data.get("query", data.get("dispute_text", "Review the authorized pending payment."))))
                results = await runtime.assess(text, "input", context)
                rejected = runtime.rejection_status(results)
                if rejected:
                    return JSONResponse({"error": "Security assessment rejected or unavailable"}, status_code=rejected)
            response = await call_next(request)
            if protected_model and response.status_code < 400:
                body = b"".join([chunk async for chunk in response.body_iterator])
                if len(body) > 1024 * 1024:
                    return JSONResponse({"error": "Response exceeds security budget"}, status_code=503)
                from halcyon.security.mcp_gateway import MCPSecurityGateway
                body = MCPSecurityGateway().inspect_response("application_response", body.decode("utf-8"), session_id=context.principal).encode()
                results = await runtime.assess(body.decode("utf-8", errors="strict"), "output", context)
                rejected = runtime.rejection_status(results)
                if rejected:
                    return JSONResponse({"error": "Response withheld by security policy"}, status_code=rejected)
                headers = dict(response.headers)
                headers.pop("content-length", None)
                response = Response(body, status_code=response.status_code, headers=headers)
            response.headers["X-Request-ID"] = context.request_id
            return response
        except AuditUnavailable:
            return JSONResponse({"error": "Security audit unavailable"}, status_code=503)
        finally:
            request_context.reset(marker)

    import psycopg
    import psycopg_pool

    @app.exception_handler(psycopg.OperationalError)
    @app.exception_handler(psycopg_pool.PoolTimeout)
    async def _db_busy(_request, _exc):  # type: ignore[no-untyped-def]
        return JSONResponse(
            status_code=503,
            content={"error": "database busy, please retry"},
            headers={"Retry-After": "1"},
        )

    @app.exception_handler(HTTPException)
    async def _http_exc_handler(_request, exc: HTTPException):
        return JSONResponse(
            status_code=exc.status_code,
            content={"error": str(exc.detail), "detail": str(exc.detail)},
        )

    sess: SessionState = session_state or InMemorySessionState()
    treasury: TreasuryProvider = treasury_for or TreasuryProvider(
        scenarios=treasury_corpus.SCENARIO_KEYS)
    _ingest_lock = threading.Lock()
    _ingest_times: dict[str, list[float]] = {}
    _ingest_last_sweep = 0.0

    def _admit_ingest(kb: KnowledgeBase, session_id: str) -> tuple[bool, str]:
        """Apply per-session document and burst limits to both ingestion routes."""
        nonlocal _ingest_last_sweep
        now = time.monotonic()
        with _ingest_lock:
            if now - _ingest_last_sweep >= 60:
                for known_session, timestamps in list(_ingest_times.items()):
                    active = [t for t in timestamps if now - t < 60]
                    if active:
                        _ingest_times[known_session] = active
                    else:
                        _ingest_times.pop(known_session, None)
                _ingest_last_sweep = now
            if len(_ingest_times) > 10000 and session_id not in _ingest_times:
                return False, "ingestion capacity temporarily exhausted"
            events = [t for t in _ingest_times.get(session_id, []) if now - t < 60]
            if len(kb.list_own(session_id)) >= 100:
                return False, "per-session document quota exceeded (100 documents)"
            if len(events) >= 30:
                return False, "ingestion rate limit exceeded (30 writes per minute)"
            events.append(now)
            _ingest_times[session_id] = events
            return True, ""

    def _treasury_kb(session_id: str) -> KnowledgeBase:
        if treasury_kb_for is None:
            raise RuntimeError(
                "create_app() was called without treasury_kb_for: the treasury-heist "
                "capstone (module \"chain\") requires its own KnowledgeBase provider, "
                "separate from kb_for (M3's)."
            )
        return treasury_kb_for(session_id)

    def _seed_treasury_bank(session_id: str, ts: TreasurySession) -> None:
        if settings.profile == "production":
            return  # Production accounts are provisioned separately; reads never create funds.
        bank = bank_for(session_id)
        scenario = treasury_corpus.SCENARIOS[ts.scenario]
        for acct_id, owner in (
            (ts.attacker_account, session_id),
            (scenario.legit_account, "treasury-desk"),
            ("acct-treasury-reserve", "treasury-vault"),
        ):
            if bank.get(acct_id) is None:
                bal = 10000000 if acct_id == "acct-treasury-reserve" else 0
                bank.seed([{"id": acct_id, "owner_session": owner, "balance": bal, "email": ""}])

    def _treasury(session_id: str) -> TreasurySession:
        ts = treasury(session_id)
        _seed_treasury_bank(session_id, ts)
        return ts

    def _mcfg(
        session_id: str, p: str | None = None, m: str | None = None, k: str | None = None
    ) -> tuple[str | None, str | None, str | None]:
        cfg = sess.get_model_cfg(session_id)
        return (
            p or cfg.get("provider") or None,
            m or cfg.get("model") or None,
            k or cfg.get("api_key") or None,
        )

    def _validate_model_override(body_prov: str | None, body_mod: str | None) -> None:
        if body_prov is None and body_mod is None:
            return
        if settings.mode != "secure" and settings.profile != "production":
            return
        prov = str(body_prov or settings.default_provider).strip()
        mod = str(body_mod or settings.ollama_model).strip()
        if not is_model_approved(prov, body_mod, settings.default_provider, settings.ollama_model):
            raise HTTPException(status_code=400, detail=f"disallowed provider/model: {prov}/{mod}")

    def _present_tool_calls(calls: list) -> list[dict]:
        if settings.mode == "secure" or settings.profile == "production":
            # A model proposal is not an authorization decision. Do not echo
            # rejected destinations, account identifiers, or requested amounts.
            return [{"name": name} for name, _args, _result in calls]
        return [{"name": name, "args": args} for name, args, _result in calls]

    def _get_auth_session(request: Request) -> str | None:
        auth = request.headers.get("Authorization")
        if auth:
            scheme, _, token = auth.partition(" ")
            if scheme.lower() != "bearer" or not token.strip():
                return None
            token = token.strip()
            if settings.profile == "production":
                return _verify_oidc_bearer(token, settings)
            verified = _verify_session(token, settings.session_secret)
            if verified:
                return verified
            if settings.mode == "vulnerable":
                return token
            return None
        cookie = request.cookies.get("eiger_session")
        if cookie:
            verified = _verify_session(cookie, settings.session_secret)
            if verified:
                return verified
            if settings.mode == "vulnerable" and settings.profile != "production":
                return cookie.partition(".")[0] if "." in cookie else cookie
        return None

    def _check_csrf(request: Request) -> None:
        """Require same-origin requests and a session-bound CSRF token for cookies."""
        if settings.mode == "secure" or settings.profile == "production":
            if request.method in ("POST", "PUT", "DELETE", "PATCH"):
                origin = request.headers.get("origin")
                if origin and origin.rstrip("/") not in settings.allowed_origins:
                    raise HTTPException(status_code=403, detail="CSRF origin check failed")
                if request.headers.get("Authorization"):
                    # Bearer credentials are explicitly attached by the API client;
                    # they are not ambient browser credentials.
                    return
                session_id = _get_auth_session(request)
                if not session_id:
                    return  # _check_auth returns the appropriate 401.
                cookie_token = request.cookies.get("eiger_csrf", "")
                header_token = request.headers.get("X-CSRF-Token", "")
                expected = _csrf_token(session_id, settings.session_secret)
                if not (
                    hmac.compare_digest(cookie_token, expected)
                    and hmac.compare_digest(header_token, expected)
                ):
                    raise HTTPException(status_code=403, detail="CSRF token missing or invalid")

    def _check_auth(
        request: Request,
        body_session_id: str | None = None,
        query_session_id: str | None = None,
        is_stateful: bool = True,
        require_ownership: bool = True,
        is_public: bool = False,
    ) -> None:
        if is_public:
            return

        _check_csrf(request)

        auth_session = _get_auth_session(request)
        target_session = body_session_id if body_session_id is not None else query_session_id

        # Never use a URL as an identity source. Return 403 when it attempts a
        # cross-session read, and 400 for same-session legacy URLs.
        if (settings.mode == "secure" or settings.profile == "production") and is_stateful:
            query_identity = request.query_params.get("session")
            if query_identity is not None:
                if not auth_session:
                    raise HTTPException(status_code=401, detail="valid session required")
                if query_identity != auth_session:
                    raise HTTPException(status_code=403, detail="cross-session access denied")
                raise HTTPException(status_code=400, detail="session IDs are not accepted in URLs; use the secure cookie")

        if settings.profile == "production":
            if not auth_session:
                raise HTTPException(status_code=401, detail="unauthorized: valid session authentication required")
            if target_session is not None and target_session != auth_session:
                raise HTTPException(status_code=403, detail="forbidden: cross-session access denied")
            return

        if settings.mode == "secure":
            if require_ownership:
                if not auth_session:
                    raise HTTPException(status_code=401, detail="unauthorized: valid session authentication required")
                if target_session and auth_session != target_session:
                    raise HTTPException(status_code=403, detail="forbidden: cannot perform actions across sessions")
            else:
                if auth_session and target_session is not None and auth_session != target_session:
                    raise HTTPException(status_code=403, detail="forbidden: cannot perform actions across sessions")

    def _require_lab_enabled() -> None:
        if settings.disable_lab_endpoints or settings.profile == "production":
            raise HTTPException(status_code=403, detail="lab endpoint disabled in production mode")

    @app.middleware("http")
    async def _csp(request: Request, call_next):
        nonce = secrets.token_urlsafe(16)
        request.state.csp_nonce = nonce
        resp = await call_next(request)
        session_id = _get_auth_session(request)
        if settings.mode == "vulnerable" and settings.profile == "lab":
            session_id = request.query_params.get("session") or session_id
        m2_settings = (
            effective_settings(settings, sess, session_id, "m2")
            if session_id else settings
        )
        if m2_settings.sec_output_encoding:
            resp.headers["Content-Security-Policy"] = (
                f"default-src 'self'; script-src 'self' 'nonce-{nonce}'; img-src 'self' data:"
            )
        return resp

    @app.middleware("http")
    async def _security_headers(request: Request, call_next):
        resp = await call_next(request)
        resp.headers["X-Content-Type-Options"] = "nosniff"
        resp.headers["X-Frame-Options"] = "DENY"
        resp.headers["Referrer-Policy"] = "no-referrer"
        if settings.cookie_secure:
            resp.headers["Strict-Transport-Security"] = "max-age=63072000; includeSubDomains"
        return resp

    templates = Environment(
        loader=FileSystemLoader(Path(__file__).parent / "templates"),
        autoescape=select_autoescape(),
    )

    _ollama_probe: dict[str, float | bool] = {"ts": 0.0, "up": False}

    def _ollama_up() -> bool:
        now = time.monotonic()
        if now - _ollama_probe["ts"] > 5.0:
            _ollama_probe["up"] = OllamaProvider(
                settings.ollama_url, settings.ollama_model,
                trusted_local_url=settings.trusted_ollama_url,
                gateway_token=settings.ollama_gateway_token,
            ).ping()
            _ollama_probe["ts"] = now
        return bool(_ollama_probe["up"])

    _mcp_core_url = os.environ.get("MCP_CORE_URL")
    _mcp_crm_url = os.environ.get("MCP_CRM_URL")
    _mcp_probe: dict[str, float | bool] = {"ts": 0.0, "up": False}

    def _mcp_up(core_url: str, crm_url: str) -> bool:
        now = time.monotonic()
        if now - _mcp_probe["ts"] > 5.0:
            up = True
            for url in (core_url, crm_url):
                try:
                    parsed = urllib.parse.urlsplit(url)
                    health_url = urllib.parse.urlunsplit(
                        (parsed.scheme, parsed.netloc, "/health", "", "")
                    )
                    response = httpx.get(health_url, timeout=2.0, trust_env=False)
                    response.raise_for_status()
                except Exception:
                    up = False
                    break
            _mcp_probe["up"] = up
            _mcp_probe["ts"] = now
        return bool(_mcp_probe["up"])

    def _mcp_status() -> str:
        if not (_mcp_core_url and _mcp_crm_url):
            return "in-process"
        return "up" if _mcp_up(_mcp_core_url, _mcp_crm_url) else "down"

    @app.get("/ready")
    async def readiness():
        import json
        checks = {"database": bool(store.ping()), "guard_mode": runtime.mode, "models": False, "nemo": False}
        try:
            from halcyon.security.nemo_integration import NeMoGuardrailsIntegration
            if runtime._nemo is None:
                import anyio
                runtime._nemo = await anyio.to_thread.run_sync(NeMoGuardrailsIntegration)
            checks["nemo"] = not runtime._nemo.is_degraded
            async with httpx.AsyncClient(timeout=3, trust_env=False) as client:
                result = await client.get(
                    settings.ollama_url.rstrip("/") + "/api/tags",
                    headers={"Authorization": f"Bearer {settings.ollama_gateway_token}"}
                    if settings.ollama_gateway_token else {},
                )
                result.raise_for_status()
                models = {m["name"]: m["digest"] for m in result.json()["models"]}
            manifest_path = os.getenv("EIGER_MODEL_MANIFEST")
            manifest = json.loads(Path(manifest_path).read_text(encoding="utf-8")) if manifest_path else {}
            required = (settings.ollama_model, settings.guard_model)
            checks["models"] = all(name in models and (settings.profile != "production" or manifest.get(name) == models[name]) for name in required)
        except Exception:
            pass
        good = checks["database"] and checks["models"] and checks["nemo"]
        return JSONResponse({"status": "ready" if good else "unavailable", "checks": checks}, status_code=200 if good else 503)

    @app.get("/health")
    def health() -> dict:
        ollama = _ollama_up()
        return {
            "status": "ok",
            "mode": settings.mode,
            "ollama": "up" if ollama else "down",
            "db": "up" if store.ping() else "down",
            "mcp": _mcp_status(),
        }

    @app.post("/api/logout")
    def logout(request: Request) -> JSONResponse:
        """Revoke the current app session and clear both browser credentials."""
        _check_csrf(request)
        auth_session = _get_auth_session(request)
        if not auth_session:
            raise HTTPException(status_code=401, detail="valid authentication required")
        if auth_session:
            _REVOKED_SESSIONS.add(auth_session)
        resp = JSONResponse({"status": "logged_out"})
        resp.delete_cookie(
            "eiger_session", path="/", secure=settings.cookie_secure,
            httponly=True, samesite="strict",
        )
        resp.delete_cookie(
            "eiger_csrf", path="/", secure=settings.cookie_secure,
            httponly=False, samesite="strict",
        )
        return resp

    @app.post("/api/session")
    def exchange_oidc_token(request: Request) -> JSONResponse:
        """Exchange a verified OIDC bearer token for an app-owned browser session."""
        if settings.profile != "production":
            raise HTTPException(status_code=404, detail="not found")
        auth = request.headers.get("Authorization", "")
        scheme, _, token = auth.partition(" ")
        principal = _verify_oidc_bearer(token.strip(), settings) if scheme.lower() == "bearer" else None
        if not principal:
            raise HTTPException(status_code=401, detail="valid OIDC bearer token required")
        response = JSONResponse({"status": "authenticated"})
        _set_session_cookies(response, principal)
        return response

    @app.post("/api/chat")
    def chat(body: ChatIn, request: Request) -> dict:
        _check_auth(request, body_session_id=body.session_id)
        _validate_model_override(body.provider, body.model)
        llm = llm_factory(*_mcfg(body.session_id, body.provider, body.model, body.api_key))
        eff = effective_settings(settings, sess, body.session_id, "m1")
        history = sess.get_history(body.session_id, "chat")
        reply = halo.handle_turn(
            store, llm, eff, body.session_id, body.message, history=history
        )
        sess.append_turn(body.session_id, "chat", body.message, reply)
        return {"reply": reply}

    @app.get("/validate/{module}")
    def validate(module: str, request: Request, session: str | None = None) -> dict:
        _require_lab_enabled()
        session = session or _get_auth_session(request)
        if not session:
            raise HTTPException(status_code=401, detail="valid session required")
        _check_auth(request, query_session_id=session, require_ownership=True)
        if module == "chain":
            return chain_validator.validate(store, session, _treasury(session).attacker_account)
        validator = _VALIDATORS.get(module)
        if validator is None:
            return {"error": f"unknown module {module}"}
        return validator(store, session)

    @app.post("/reset/{module}")
    def reset(module: str, body: ResetIn, request: Request) -> dict:
        _require_lab_enabled()
        valid_modules = set(_VALIDATORS.keys()) | {"chain"}
        if module not in valid_modules:
            return {"error": f"unknown module {module}"}
        admin_hdr = request.headers.get("X-Admin-Key", "")
        is_admin = bool(settings.admin_api_key and secrets.compare_digest(admin_hdr, settings.admin_api_key))
        if not is_admin:
            _check_auth(request, body_session_id=body.session_id, require_ownership=True)
        store.write_reset_marker(body.session_id, module)
        if module == "chain":
            kb = _treasury_kb(body.session_id)
            ts = treasury.reset(body.session_id)
            kb.clear()
            kb.seed(treasury_corpus.SEED)
            bank = bank_for(body.session_id)
            bank.clear()
            _seed_treasury_bank(body.session_id, ts)
            return {"status": "reset", "module": "chain"}
        if module in ("m1", "m2"):
            sess.clear_history(body.session_id, "chat")
        if module == "m3":
            kb = kb_for(body.session_id)
            kb.clear()
            kb.seed(kb_fixtures.SEED)
        if module in ("m5", "m6", "m7"):
            bank = bank_for(body.session_id)
            bank.clear()
            bank.seed(bank_fixtures.seed_for(body.session_id))
        return {"status": "reset", "module": module}

    @app.post("/api/kb")
    def add_kb(body: KbIn, request: Request) -> dict:
        _check_auth(request, body_session_id=body.session_id)
        eff = effective_settings(settings, sess, body.session_id, "m3")
        hardened = settings.mode == "secure" or settings.profile == "production"
        # Resource ceilings are platform controls and do not follow per-module L1/L2 switches.
        if hardened and len(body.text) > 8192:
            raise HTTPException(status_code=413, detail="chunk exceeds maximum allowed size (8192 chars)")
        kb = kb_for(body.session_id)
        if hardened:
            admitted, reason = _admit_ingest(kb, body.session_id)
            if not admitted:
                raise HTTPException(status_code=429, detail=reason)
        # Provenance/injection behavior remains independently testable in Secure Lab.
        if eff.sec_rag_provenance:
            if guards._looks_like_injection(body.text):
                return {"status": "error", "error": "untrusted input quarantined: prompt injection pattern detected"}
        # Server-side metadata assignment: uploader can never claim "trusted" provenance
        kb.add(body.text, provenance="user", access="public", owner_session=body.session_id)
        return {"status": "ok"}

    @app.post("/api/ask")
    def ask(body: AskIn, request: Request) -> dict:
        _check_auth(request, body_session_id=body.session_id)
        eff = effective_settings(settings, sess, body.session_id, "m3")
        kb = kb_for(body.session_id)
        reply, _ = rag.answer(
            kb, llm_factory(*_mcfg(body.session_id)), store, eff, body.session_id, body.query
        )
        return {"reply": reply}

    def _resolve_session(request: Request, supplied: str | None) -> str:
        """Resolve identity from verified credentials, never from a page URL."""
        auth_session = _get_auth_session(request)
        if settings.profile == "production" or settings.mode == "secure":
            if request.query_params.get("session"):
                raise HTTPException(status_code=400, detail="session IDs are not accepted in URLs")
            if auth_session:
                return auth_session
            if settings.profile == "production":
                raise HTTPException(status_code=401, detail="valid OIDC authentication required")
            # Secure Lab creates a fresh, unguessable bearer session when a new
            # browser arrives. Caller-selected IDs are never accepted.
            return f"eiger-{secrets.token_hex(6)}"
        return supplied or request.cookies.get("eiger_session") or f"eiger-{secrets.token_hex(4)}"

    def _set_session_cookies(response: Response, session_id: str) -> Response:
        secure_cookie = bool(settings.cookie_secure or settings.profile == "production" or settings.mode == "secure")
        cookie_val = (
            _sign_session(session_id, settings.session_secret)
            if secure_cookie else session_id
        )
        same_site = "strict" if secure_cookie else "lax"
        response.set_cookie(
            "eiger_session", cookie_val, httponly=True, samesite=same_site,
            secure=secure_cookie, max_age=86400, path="/",
        )
        if secure_cookie:
            response.set_cookie(
                "eiger_csrf", _csrf_token(session_id, settings.session_secret),
                httponly=False, samesite="strict", secure=True, max_age=86400, path="/",
            )
        return response

    def _with_session_cookie(html: str, session_id: str) -> HTMLResponse:
        response = HTMLResponse(html)
        _set_session_cookies(response, session_id)
        return response

    @app.get("/", response_class=HTMLResponse)
    def root(request: Request, session: str | None = None) -> HTMLResponse:
        session_id = _resolve_session(request, session)
        ollama = _ollama_up()
        html = templates.get_template("reach.html").render(
            ollama=ollama,
            db=store.ping(),
            mcp=_mcp_status(),
            mode=settings.mode,
            session_id=session_id,
        )
        return _with_session_cookie(html, session_id)

    @app.get("/chat", response_class=HTMLResponse)
    def chat_page(request: Request, session: str | None = None) -> HTMLResponse:
        session_id = _resolve_session(request, session)
        name = store.get_profile(session_id)
        eff = effective_settings(settings, sess, session_id, "m2")
        html = templates.get_template("chat.html").render(
            output_encoding="on" if eff.sec_output_encoding else "off",
            display_name_html=guards.encode_output(name, eff),
            nonce=request.state.csp_nonce,
            mode=settings.mode,
            session_id=session_id,
            learn=learn_content.LEARN,
        )
        return _with_session_cookie(html, session_id)

    @app.post("/api/profile")
    def set_profile(body: ProfileIn, request: Request) -> dict:
        _check_auth(request, body_session_id=body.session_id)
        store.set_profile(body.session_id, body.display_name)
        return {"status": "ok"}

    @app.get("/beacon/xss")
    def beacon(request: Request, session: str | None = None) -> Response:
        _require_lab_enabled()
        session = session or _get_auth_session(request)
        if not session:
            raise HTTPException(status_code=401, detail="valid session required")
        _check_auth(request, query_session_id=session)
        audit.record(store, session, "m2", audit.XSS_BEACON, session)
        return Response(content=_GIF, media_type="image/gif")

    @app.post("/api/agent")
    def agent_endpoint(body: AgentIn, request: Request) -> dict:
        _check_auth(request, body_session_id=body.session_id)
        _validate_model_override(body.provider, body.model)
        tool_llm = tool_llm_factory(*_mcfg(body.session_id, body.provider, body.model, body.api_key))
        eff = effective_settings(settings, sess, body.session_id, "m5")
        bank = bank_for(body.session_id)
        reply, calls = agent.run(tool_llm, body.session_id, body.message, bank, store, eff)
        return {"reply": reply, "tool_calls": _present_tool_calls(calls)}

    @app.post("/api/mcp-agent")
    async def mcp_agent(body: AgentIn, request: Request) -> dict:
        _check_auth(request, body_session_id=body.session_id)
        _validate_model_override(body.provider, body.model)
        tool_llm = tool_llm_factory(*_mcfg(body.session_id, body.provider, body.model, body.api_key))
        eff = effective_settings(settings, sess, body.session_id, "m6")
        async with mcp_host_factory(body.session_id, eff) as host:
            reply, calls = await agent.run_mcp(
                tool_llm, body.session_id, body.message, host, store, eff
            )
        return {"reply": reply, "tool_calls": _present_tool_calls(calls)}

    @app.post("/api/dispute")
    def dispute_endpoint(body: DisputeIn, request: Request) -> dict:
        _check_auth(request, body_session_id=body.session_id, require_ownership=True)
        _validate_model_override(body.provider, body.model)
        tool_llm = tool_llm_factory(*_mcfg(body.session_id, body.provider, body.model, body.api_key))
        eff = effective_settings(settings, sess, body.session_id, "m7")
        bank = bank_for(body.session_id)
        decision, transcript = dispute_pipeline.run_dispute(
            tool_llm, body.session_id,
            {"account": body.account, "amount": body.amount, "dispute_text": body.dispute_text, "original_tx_id": body.original_tx_id, "idempotency_key": body.idempotency_key},
            bank, store, eff)
        return {
            "decision": decision,
            "transcript": [{"from": m["signer"], "content": m["content"]} for m in transcript],
        }

    @app.post("/api/guarded-chat")
    def guarded_chat(body: ChatIn, request: Request) -> dict:
        _check_auth(request, body_session_id=body.session_id, require_ownership=True)
        _validate_model_override(body.provider, body.model)
        llm = llm_factory(*_mcfg(body.session_id, body.provider, body.model, body.api_key))
        eff = effective_settings(settings, sess, body.session_id, "m8")
        reply = halo.guarded_turn(store, llm, eff, body.session_id, body.message)
        return {"reply": reply}

    @app.get("/capstone")
    def capstone_view(request: Request, session: str | None = None) -> dict:
        _require_lab_enabled()
        session = session or _get_auth_session(request)
        if not session:
            raise HTTPException(status_code=401, detail="valid session required")
        _check_auth(request, query_session_id=session, require_ownership=True)
        return capstone.residual_risk(store, session)

    @app.get("/board")
    def board_view(request: Request) -> dict:
        _require_lab_enabled()
        if settings.mode == "secure" or settings.profile == "production":
            own_id = _get_auth_session(request)
            if not own_id:
                raise HTTPException(status_code=401, detail="valid session required")
            own = capstone.residual_risk(store, own_id)
            rows = [] if own["exploited_count"] == 0 else [{
                "session": "Your session",
                "modules": own["modules"],
                "exploited_count": own["exploited_count"],
                "total": own["total"],
            }]
            return {"sessions": rows, "total": len(rows)}
        return capstone.board(store)

    @app.get("/progress", response_class=HTMLResponse)
    def progress_view(request: Request, session: str | None = None) -> HTMLResponse:
        session_id = _resolve_session(request, session)
        levels = sess.get_levels(session_id)
        rows = []
        for module, validator in _VALIDATORS.items():
            result = validator(store, session_id)
            level = levels.get(module, "L2" if settings.mode == "secure" else "L1")
            rows.append({
                "module": module.upper(),
                "title": _MODULE_TITLES[module],
                "core": result.get("core", "fail"),
                "stretch": result.get("stretch", "fail"),
                "mode": "Hardened" if level == "L2" else "Vulnerable",
            })
        risk = capstone.residual_risk(store, session_id)
        html = templates.get_template("progress.html").render(
            session_id=session_id,
            rows=rows,
            chain=next(m for m in risk["modules"] if m["module"] == "chain"),
        )
        return _with_session_cookie(html, session_id)

    @app.get("/attack-board", response_class=HTMLResponse)
    def attack_board_view(request: Request) -> Response:
        _require_lab_enabled()
        if settings.mode == "secure" or settings.profile == "production":
            own_id = _get_auth_session(request)
            if not own_id:
                raise HTTPException(status_code=401, detail="valid session required")
            own = capstone.residual_risk(store, own_id)
            rows = [] if own["exploited_count"] == 0 else [{
                "session": "Your session",
                "modules": own["modules"],
                "exploited_count": own["exploited_count"],
                "total": own["total"],
            }]
            board = {"sessions": rows, "total": len(rows)}
        else:
            board = capstone.board(store)
        return HTMLResponse(templates.get_template("board.html").render(board=board))

    @app.post("/api/level")
    def set_level(body: LevelIn, request: Request) -> dict:
        _check_auth(request, body_session_id=body.session_id)
        if body.level not in ("L1", "L2"):
            return {"error": "level must be L1 or L2"}
        if body.module not in MODULE_FLAGS:
            return {"error": f"unknown module {body.module}"}
        if (settings.lock_security_levels or settings.mode == "secure" or settings.profile == "production") and body.level == "L1":
            raise HTTPException(status_code=403, detail="security level downgrade to L1 is locked in secure/production mode")
        sess.set_level(body.session_id, body.module, body.level)
        return {"status": "ok", "module": body.module, "level": body.level}

    @app.get("/api/level")
    def get_levels(request: Request, session: str | None = None) -> dict:
        session = session or _get_auth_session(request)
        if not session:
            raise HTTPException(status_code=401, detail="valid session required")
        _check_auth(request, query_session_id=session)
        return sess.get_levels(session)

    @app.post("/api/config")
    def set_config(body: ConfigIn, request: Request) -> dict:
        _check_auth(request, body_session_id=body.session_id)
        prov = str(body.provider or "").strip()
        mod = str(body.model or settings.ollama_model).strip()
        if settings.mode == "secure" or settings.profile == "production":
            if not is_model_approved(prov, body.model, settings.default_provider, settings.ollama_model):
                raise HTTPException(status_code=400, detail=f"disallowed provider/model: {prov}/{mod}")
        else:
            if any(bad in mod.lower() for bad in ("pwn", "eval", "evil", "override", "root")):
                return {"error": f"disallowed model: {mod}"}
        sess.set_model_cfg(
            body.session_id, body.provider, body.model or "", body.api_key or ""
        )
        return {"status": "ok", "provider": body.provider, "model": body.model or ""}

    @app.get("/api/config")
    def get_config(request: Request, session: str | None = None) -> dict:
        session = session or _get_auth_session(request)
        if not session:
            raise HTTPException(status_code=401, detail="valid session required")
        _check_auth(request, query_session_id=session)
        cfg = sess.get_model_cfg(session)
        return {"provider": cfg.get("provider", ""), "model": cfg.get("model", "")}

    _LABS_M4 = Path(__file__).parent.parent / "labs" / "m4"

    _M4_README = (
        "# M4 supply-chain audit bundle\n\n"
        "1. Review artifacts/community_model.quarantine.json. The original pickle was removed;\n"
        "   the record contains its historical SHA-256 and static finding summary only.\n"
        "   Submit that recorded SHA-256 as the quarantined artifact.\n\n"
        "2. AUDIT the dependencies against a CVE database:\n"
        "   pip-audit -r requirements-vulnerable.txt\n"
        "   (or look each pin up on osv.dev / NVD). Submit the flagged pin\n"
        "   (name==version) as the vulnerable dependency.\n\n"
        "No executable pickle is included in this bundle. Never recreate or load the quarantined artifact.\n"
    )

    @app.get("/api/m4/bundle")
    def m4_bundle(request: Request) -> Response:
        _require_lab_enabled()
        if settings.mode == "secure" or settings.profile == "production":
            raise HTTPException(status_code=404, detail="artifact bundle disabled in hardened mode")
        _check_auth(request, require_ownership=True)
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
            for art in sorted((_LABS_M4 / "artifacts").glob("*")):
                if art.is_file():
                    z.write(art, f"artifacts/{art.name}")
            req = _LABS_M4 / "requirements-vulnerable.txt"
            if req.exists():
                z.write(req, "requirements-vulnerable.txt")
            z.write(Path(__file__).parent / "scan_artifact.py", "scan_artifact.py")
            z.writestr("README.md", _M4_README)
        return Response(content=buf.getvalue(), media_type="application/zip",
                        headers={"Content-Disposition": "attachment; filename=eiger-m4-audit.zip"})

    @app.post("/submit/m4")
    def submit_m4(body: SubmitIn, request: Request) -> dict:
        _require_lab_enabled()
        _check_auth(request, body_session_id=body.session_id)
        correct = False
        if body.finding_type == "malicious_artifact":
            correct = m4_answers.normalize_hash(body.value) == m4_answers.QUARANTINED_ARTIFACT_SHA256
            if correct:
                audit.record(store, body.session_id, "m4",
                             audit.MALICIOUS_ARTIFACT_IDENTIFIED, body.session_id)
        elif body.finding_type == "vulnerable_dependency":
            correct = m4_answers.normalize_package(body.value) == m4_answers.VULNERABLE_PACKAGE
            if correct:
                audit.record(store, body.session_id, "m4",
                             audit.VULNERABLE_DEPENDENCY_IDENTIFIED, body.session_id)
        return {"correct": correct}

    @app.get("/source/tree")
    def source_tree(request: Request, session: str | None = None) -> dict:
        _require_lab_enabled()
        session = session or _get_auth_session(request)
        if not session:
            raise HTTPException(status_code=401, detail="valid session required")
        _check_auth(request, query_session_id=session, require_ownership=True)
        return {"tree": source_browser.tree()}

    @app.get("/source/blob")
    def source_blob(request: Request, path: str = "", session: str | None = None) -> dict:
        _require_lab_enabled()
        session = session or _get_auth_session(request)
        if not session:
            raise HTTPException(status_code=401, detail="valid session required")
        _check_auth(request, query_session_id=session, require_ownership=True)
        ts = _treasury(session)
        content = guards.scrub_secrets(
            source_browser.blob(path, ts.ingest_key), ts.ingest_key, settings)
        # VAPT-026: Also redact static mock staging tokens from source browser in secure mode
        if settings.sec_secret_scanning:
            content = re.sub(r"stg_[a-f0-9]{16}", "***REDACTED-BY-SECRET-SCANNER***", content)
        return {"path": path, "content": content}

    @app.get("/treasury/brief")
    def treasury_brief(request: Request, session: str | None = None) -> dict:
        session = session or _get_auth_session(request)
        if not session:
            raise HTTPException(status_code=401, detail="valid session required")
        _check_auth(request, query_session_id=session, require_ownership=True)
        ts = _treasury(session)
        scenario = treasury_corpus.SCENARIOS[ts.scenario]
        return {"brief": scenario.brief, "amount": scenario.amount,
                "attacker_account": ts.attacker_account}

    @app.post("/ingest/docs")
    def ingest_doc(body: IngestIn, request: Request) -> dict:
        _check_auth(request, body_session_id=body.session_id)
        ts = _treasury(body.session_id)
        if body.key != ts.ingest_key:
            return {"ok": False, "reason": "invalid ingest key", "chunk_id": ""}
        hardened = settings.mode == "secure" or settings.profile == "production"
        if hardened and len(body.text) > 8192:
            raise HTTPException(status_code=413, detail="document exceeds maximum allowed size (8192 chars)")
        kb = _treasury_kb(body.session_id)
        if hardened:
            admitted, reason = _admit_ingest(kb, body.session_id)
            if not admitted:
                raise HTTPException(status_code=429, detail=reason)
        audit.record(store, body.session_id, "chain", audit.INGEST_KEY_ACCEPTED,
                     body.session_id, {})
        chunk = kb.add(
            body.text, "user", owner_session=body.session_id)
        audit.record(store, body.session_id, "chain", audit.POLICY_DOC_INGESTED,
                     body.session_id, {"chunk": chunk.id})
        return {"ok": True, "reason": "published", "chunk_id": chunk.id}

    @app.get("/ingest/docs")
    def list_docs(request: Request, session: str | None = None) -> dict:
        session = session or _get_auth_session(request)
        if not session:
            raise HTTPException(status_code=401, detail="valid session required")
        _check_auth(request, query_session_id=session, require_ownership=True)
        docs = _treasury_kb(session).list_own(session)
        return {"docs": [{"id": c.id, "text": c.text} for c in docs]}

    @app.post("/ingest/delete")
    def delete_doc(body: DeleteIn, request: Request) -> dict:
        _check_auth(request, body_session_id=body.session_id)
        if settings.sec_rag_provenance:
            ts = _treasury(body.session_id)
            if not body.key or body.key != ts.ingest_key:
                return {"deleted": False, "error": "invalid ingest key required for deletion"}
        return {"deleted": _treasury_kb(body.session_id).delete_own(
            body.session_id, body.chunk_id)}

    @app.post("/api/treasury/review")
    def treasury_review(body: ReviewIn, request: Request) -> dict:
        _check_auth(request, body_session_id=body.session_id, require_ownership=True)
        _validate_model_override(body.provider, body.model)
        tool_llm = tool_llm_factory(
            *_mcfg(body.session_id, body.provider, body.model, body.api_key))
        ts = _treasury(body.session_id)
        reply, sources, calls = treasury_agent.review(
            tool_llm, body.session_id, ts,
            _treasury_kb(body.session_id), bank_for(body.session_id), store, settings)
        chain_validator.validate(store, body.session_id, ts.attacker_account)
        result: dict = {"sources": sources, "tool_calls": _present_tool_calls(calls)}
        if reply.startswith("<error:"):
            result["reply"] = reply
        return result

    return app
