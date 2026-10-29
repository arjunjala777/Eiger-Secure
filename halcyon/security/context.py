"""
Trusted Request Context for Eiger AI Banking.

Provides an immutable, tamper-evident security context capturing validated
transport credentials, principal identity, tenant, and policy versions.
"""

from __future__ import annotations

import uuid
from contextvars import ContextVar
from dataclasses import dataclass, field


@dataclass(frozen=True)
class SecurityContext:
    """
    Immutable trusted security context.
    Must ONLY be constructed from validated transport credentials (cryptographic
    HMAC session cookies, verified service tokens, or system-internal callers).
    Never construct from user- or model-supplied payload arguments.
    """

    principal: str
    tenant: str = "default"
    roles: tuple[str, ...] = ("user",)
    grants: tuple[str, ...] = field(default_factory=tuple)
    request_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    auth_method: str = "unauthenticated"
    policy_version: str = "2026-10-26"
    client_ip: str | None = None

    def has_role(self, role: str) -> bool:
        return role in self.roles

    def has_grant(self, grant: str) -> bool:
        return grant in self.grants or "admin" in self.roles

    def is_authenticated(self) -> bool:
        return self.auth_method in (
            "session_cookie",
            "bearer_token",
            "system_internal",
            "admin_key",
        ) and bool(self.principal)


def anonymous_context(client_ip: str | None = None) -> SecurityContext:
    """Construct an unauthenticated context with no grants."""
    return SecurityContext(
        principal="",
        tenant="public",
        roles=("anonymous",),
        grants=(),
        auth_method="unauthenticated",
        client_ip=client_ip,
    )


# Transport-owned context. Never read identity from tool arguments.
request_context: ContextVar[SecurityContext | None] = ContextVar(
    "eiger_request_context", default=None
)


def internal_context(principal: str) -> SecurityContext:
    """For server-owned adapters only; web entry points bind verified context first."""
    current = request_context.get()
    if current is not None:
        if current.principal != principal or not current.is_authenticated():
            raise ValueError("Request identity does not match tool principal")
        return current
    return authenticated_context(principal, "system_internal")


def authenticated_context(
    principal: str,
    auth_method: str,
    tenant: str = "default",
    roles: tuple[str, ...] = ("user",),
    grants: tuple[str, ...] = (),
    client_ip: str | None = None,
    policy_version: str = "2026-10-26",
) -> SecurityContext:
    """Construct a verified authenticated context from validated transport credentials."""
    if not principal:
        raise ValueError("Authenticated SecurityContext requires non-empty principal")
    if auth_method not in ("session_cookie", "bearer_token", "system_internal", "admin_key"):
        raise ValueError(f"Invalid auth_method: {auth_method}")

    return SecurityContext(
        principal=principal,
        tenant=tenant,
        roles=tuple(roles),
        grants=tuple(grants),
        auth_method=auth_method,
        client_ip=client_ip,
        policy_version=policy_version,
    )
