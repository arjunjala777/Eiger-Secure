"""Authenticated per-request delegation between the application and MCP services.

The service token authenticates the application. A signed, short-lived envelope
binds its verified user context to the exact method, target and request bytes.
Neither identity nor internal flags are accepted inside tool arguments.
"""

import base64
import hashlib
import hmac
import json
import secrets
import threading
import time
import os

import httpx

from halcyon.security.context import SecurityContext, authenticated_context

_LOCAL_DELEGATION_SECRET = secrets.token_hex(32)


def delegation_key(audience: str = ""):
    key_env = {
        "core_banking": "HALCYON_MCP_CORE_DELEGATION_SECRET",
        "crm": "HALCYON_MCP_CRM_DELEGATION_SECRET",
    }.get(audience, "")
    key = os.getenv(key_env) if key_env else None
    hardened = (
        os.getenv("HALCYON_PROFILE") == "production"
        or os.getenv("HALCYON_MODE", "vulnerable") == "secure"
    )
    if not key and hardened:
        raise ValueError(f"Secure/production requires a distinct delegation secret for {audience or 'MCP'}")
    if not key:
        key = os.getenv("HALCYON_MCP_DELEGATION_SECRET")
    key = key or _LOCAL_DELEGATION_SECRET
    if hardened and len(key) < 32:
        raise ValueError("Secure/production MCP delegation secrets must contain at least 32 characters")
    return key


class DelegationAuth(httpx.Auth):
    requires_request_body = True

    def __init__(
        self, token: str, audience: str, context: SecurityContext, signing_key: str | None = None
    ):
        if not token or not context.is_authenticated():
            raise ValueError("MCP transport requires credentials and authenticated context")
        self.token, self.audience, self.context = token, audience, context
        self.signing_key = signing_key or delegation_key(audience)
        if self.signing_key == token:
            raise ValueError("Service and delegation credentials must be distinct")

    def auth_flow(self, request):
        claims = {
            "principal": self.context.principal,
            "tenant": self.context.tenant,
            "request_id": self.context.request_id,
            "audience": self.audience,
            "expiry": int(time.time()) + 30,
            "nonce": secrets.token_hex(16),
            "method": request.method,
            "target": request.url.raw_path.decode("ascii"),
            "body": hashlib.sha256(request.content).hexdigest(),
        }
        encoded = base64.urlsafe_b64encode(
            json.dumps(claims, sort_keys=True, separators=(",", ":")).encode()
        ).decode()
        request.headers["Authorization"] = f"Bearer {self.token}"
        request.headers["X-Eiger-Context"] = encoded
        request.headers["X-Eiger-Signature"] = hmac.new(
            self.signing_key.encode(), b"eiger-delegation-v1:" + encoded.encode(), hashlib.sha256
        ).hexdigest()
        yield request


class DelegationVerifier:
    def __init__(self, token: str, audience: str, signing_key: str | None = None):
        self.token, self.audience = token, audience
        self.signing_key = signing_key or delegation_key(audience)
        if self.signing_key == token:
            raise ValueError("Service and delegation credentials must be distinct")
        self._seen = {}
        self._lock = threading.Lock()

    def verify(self, scope, body: bytes) -> SecurityContext:
        headers = dict(scope.get("headers", []))
        auth = headers.get(b"authorization", b"").decode("latin1")
        if not hmac.compare_digest(auth, f"Bearer {self.token}"):
            raise ValueError("Invalid service credential")
        encoded = headers.get(b"x-eiger-context", b"")
        signature = headers.get(b"x-eiger-signature", b"")
        if not encoded or len(encoded) > 4096:
            raise ValueError("Verified user delegation required")
        expected = (
            hmac.new(self.signing_key.encode(), b"eiger-delegation-v1:" + encoded, hashlib.sha256)
            .hexdigest()
            .encode()
        )
        if not hmac.compare_digest(signature, expected):
            raise ValueError("Invalid delegation signature")
        try:
            claims = json.loads(base64.urlsafe_b64decode(encoded))
            now = time.time()
            expiry = claims["expiry"]
            target = scope.get("raw_path", scope["path"].encode()).decode("ascii")
            if scope.get("query_string"):
                target += "?" + scope["query_string"].decode("ascii")
            if (
                type(expiry) is not int
                or not now <= expiry <= now + 35
                or claims["audience"] != self.audience
                or claims["method"] != scope["method"]
                or claims["target"] != target
                or claims["body"] != hashlib.sha256(body).hexdigest()
                or not isinstance(claims["nonce"], str)
                or len(claims["nonce"]) != 32
                or not isinstance(claims["principal"], str)
                or not 0 < len(claims["principal"]) <= 256
                or not isinstance(claims["tenant"], str)
                or not claims["tenant"]
            ):
                raise ValueError("Invalid delegation claims")
            with self._lock:
                self._seen = {nonce: exp for nonce, exp in self._seen.items() if exp >= now}
                if claims["nonce"] in self._seen or len(self._seen) >= 10000:
                    raise ValueError("Replayed delegation or capacity exceeded")
                self._seen[claims["nonce"]] = expiry
            context = authenticated_context(
                claims["principal"], "bearer_token", tenant=claims["tenant"]
            )
            return SecurityContext(
                **{**context.__dict__, "request_id": str(claims["request_id"])[:128]}
            )
        except (KeyError, TypeError, json.JSONDecodeError, UnicodeError) as exc:
            raise ValueError("Malformed delegation") from exc
