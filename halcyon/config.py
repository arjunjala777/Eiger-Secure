import ipaddress
import secrets
import urllib.parse
from collections.abc import Mapping
from dataclasses import dataclass, replace
from typing import Any

from halcyon.session_state import SessionState

_TRUE = {"1", "true", "on", "yes"}


def _flag(env: Mapping[str, str], name: str, default: bool) -> bool:
    raw = env.get(name)
    if raw is None:
        return default
    return raw.strip().lower() in _TRUE


@dataclass(frozen=True)
class Settings:
    mode: str
    sec_system_prompt_hardening: bool
    sec_input_filter: bool
    sec_output_encoding: bool
    sec_rag_provenance: bool
    sec_artifact_verification: bool
    sec_tool_scope_enforcement: bool
    sec_mcp_desc_pinning: bool
    sec_mcp_token_scoping: bool
    sec_inter_agent_auth: bool
    sec_guardrails: bool
    sec_secret_scanning: bool
    ollama_url: str
    ollama_model: str
    database_url: str
    default_provider: str
    expose_openapi: bool
    lock_security_levels: bool = False
    disable_lab_endpoints: bool = False
    cookie_secure: bool = False
    admin_api_key: str = ""
    profile: str = "lab"
    session_secret: str = "eiger-sec-session-token-3894"
    guard_mode: str = "observe"
    guard_model: str = "llama-guard3:1b"
    guard_timeout: float = 3.0
    trusted_ollama_url: str | None = None
    ollama_gateway_token: str = ""
    oidc_issuer: str = ""
    oidc_audience: str = ""
    oidc_jwks_url: str = ""
    allowed_origins: tuple[str, ...] = ()
    rag_approved_sources_only: bool = False


APPROVED_MODELS = {
    ("local", "llama3.1:8b"),
    ("remote", "gpt-4o"),
    ("openai", "gpt-4o"),
    ("anthropic", "claude-haiku-4-5"),
}


def is_model_approved(provider: str | None, model: str | None, default_provider: str = "local", default_model: str = "llama3.1:8b") -> bool:
    prov = str(provider or default_provider).strip()
    mod = str(model or default_model).strip()
    if (prov, mod) in APPROVED_MODELS:
        return True
    if prov == "local" and mod == default_model:
        return True
    return False


def validate_provider_destination(url_or_host: str, provider: str = "local", trusted_local_url: str | None = None) -> tuple[bool, str]:
    """P1 SSRF Prevention: Restricts provider destinations, protocols, hosts, and internal subnets."""
    raw = url_or_host.strip()
    if not raw.startswith("http://") and not raw.startswith("https://"):
        raw = f"http://{raw}"
    parsed = urllib.parse.urlparse(raw)
    scheme = parsed.scheme.lower()
    host = (parsed.hostname or "").lower()
    port = parsed.port

    if provider == "local":
        if trusted_local_url and raw.rstrip("/") == trusted_local_url.rstrip("/"):
            if parsed.scheme == "http" and parsed.hostname and not parsed.username and not parsed.password and not parsed.fragment:
                return True, "administrator-pinned local endpoint"
        if scheme != "http":
            return False, "local provider must use http scheme"
        if host not in ("127.0.0.1", "localhost"):
            return False, f"local provider destination must be loopback (127.0.0.1 or localhost), got {host}"
        if port not in (11434, None):
            return False, f"local provider port must be 11434, got {port}"
        return True, "valid"

    # Remote provider checks
    if scheme != "https":
        return False, "remote provider must use https scheme"
    if host in ("169.254.169.254", "metadata.google.internal", "instance-data"):
        return False, "access to cloud metadata endpoints prohibited"

    try:
        ip = ipaddress.ip_address(host)
        if ip.is_private or ip.is_loopback or ip.is_link_local:
            return False, f"access to private/local IP {host} prohibited"
    except ValueError:
        pass

    allowed_remote = {"api.openai.com", "api.anthropic.com"}
    if host not in allowed_remote:
        return False, f"unapproved remote destination host: {host}"
    return True, "valid"


def load_settings(env: Mapping[str, str]) -> Settings:
    mode = env.get("HALCYON_MODE", "vulnerable").strip().lower()
    if mode not in ("vulnerable", "secure"):
        raise ValueError(
            f"HALCYON_MODE must be 'vulnerable' or 'secure', got {mode!r}"
        )
    profile = env.get("HALCYON_PROFILE", "lab").strip().lower()
    if profile not in ("lab", "production"):
        raise ValueError("HALCYON_PROFILE must be lab or production")
    guard_mode = env.get(
        "EIGER_GUARD_MODE",
        "enforce" if profile == "production" else ("observe" if mode == "secure" else "off"),
    )
    if guard_mode not in ("off", "observe", "enforce") or (profile == "production" and guard_mode == "off"):
        raise ValueError("Invalid or disabled production guard mode")
    if profile == "production" and guard_mode != "enforce":
        raise ValueError("Production profile requires EIGER_GUARD_MODE=enforce")

    # High / Critical: Production configuration validation & lockout
    oidc_issuer = env.get("OIDC_ISSUER", "").strip()
    oidc_audience = env.get("OIDC_AUDIENCE", "").strip()
    oidc_jwks_url = env.get("OIDC_JWKS_URL", "").strip()
    if profile == "production":
        if mode != "secure":
            raise ValueError(
                "Production profile requires HALCYON_MODE=secure; vulnerable mode is prohibited in production."
            )
        session_secret = env.get("HALCYON_SESSION_SECRET", "")
        if not session_secret or session_secret == "eiger-sec-session-token-3894":
            raise ValueError(
                "Production profile requires a non-default, secure HALCYON_SESSION_SECRET."
            )
        if len(session_secret) < 32:
            raise ValueError("Production HALCYON_SESSION_SECRET must contain at least 32 characters")
        if not oidc_issuer or not oidc_audience or not oidc_jwks_url:
            raise ValueError("Production profile requires OIDC_ISSUER, OIDC_AUDIENCE, and OIDC_JWKS_URL")
        issuer = urllib.parse.urlparse(oidc_issuer)
        jwks = urllib.parse.urlparse(oidc_jwks_url)
        if (
            issuer.scheme != "https" or not issuer.hostname or issuer.username or issuer.password
            or issuer.query or issuer.fragment or jwks.scheme != "https" or not jwks.hostname
            or jwks.username or jwks.password or jwks.fragment
            or jwks.hostname.lower() != issuer.hostname.lower()
        ):
            raise ValueError("OIDC issuer and JWKS URL must use HTTPS on the same trusted host")
    else:
        if mode == "secure":
            session_secret = env.get("HALCYON_SESSION_SECRET") or secrets.token_urlsafe(48)
        else:
            session_secret = env.get("HALCYON_SESSION_SECRET", "eiger-sec-session-token-3894")

    secure = mode == "secure"
    is_prod = profile == "production"

    def security_flag(name: str) -> bool:
        # Secure Lab and Production controls cannot be disabled through
        # environment overrides. Vulnerable-mode lab exercises may still turn
        # individual controls on for teaching.
        return True if secure or is_prod else _flag(env, name, False)

    origins = tuple(
        value.strip().rstrip("/")
        for value in env.get(
            "EIGER_ALLOWED_ORIGINS",
            "https://localhost" if is_prod else "http://127.0.0.1:8000,http://localhost:8000",
        ).split(",")
        if value.strip()
    )
    parsed_origins = [urllib.parse.urlparse(origin) for origin in origins]
    if any(
        origin == "*" or parsed.scheme not in ("http", "https") or not parsed.netloc
        or parsed.path not in ("", "/") or parsed.query or parsed.fragment
        for origin, parsed in zip(origins, parsed_origins)
    ):
        raise ValueError("EIGER_ALLOWED_ORIGINS must contain explicit HTTP(S) origins, never '*'")
    if is_prod and any(not origin.startswith("https://") for origin in origins):
        raise ValueError("Production EIGER_ALLOWED_ORIGINS must all use HTTPS")

    return Settings(
        mode=mode,
        sec_system_prompt_hardening=security_flag("SEC_SYSTEM_PROMPT_HARDENING"),
        sec_input_filter=security_flag("SEC_INPUT_FILTER"),
        sec_output_encoding=security_flag("SEC_OUTPUT_ENCODING"),
        sec_rag_provenance=security_flag("SEC_RAG_PROVENANCE"),
        rag_approved_sources_only=security_flag("EIGER_RAG_APPROVED_SOURCES_ONLY"),
        sec_artifact_verification=security_flag("SEC_ARTIFACT_VERIFICATION"),
        sec_tool_scope_enforcement=security_flag("SEC_TOOL_SCOPE_ENFORCEMENT"),
        sec_mcp_desc_pinning=security_flag("SEC_MCP_DESC_PINNING"),
        sec_mcp_token_scoping=security_flag("SEC_MCP_TOKEN_SCOPING"),
        sec_inter_agent_auth=security_flag("SEC_INTER_AGENT_AUTH"),
        sec_guardrails=security_flag("SEC_GUARDRAILS"),
        sec_secret_scanning=security_flag("SEC_SECRET_SCANNING"),
        ollama_url=env.get("OLLAMA_URL", "http://localhost:11434"),
        ollama_model=env.get("OLLAMA_MODEL", "llama3.1:8b"),
        database_url=env.get("DATABASE_URL", ""),
        default_provider=env.get("DEFAULT_PROVIDER", "local"),
        expose_openapi=_flag(env, "EIGER_EXPOSE_OPENAPI", False),
        lock_security_levels=True if is_prod else _flag(env, "HALCYON_LOCK_SECURITY_LEVELS", False),
        disable_lab_endpoints=True if is_prod else _flag(env, "HALCYON_DISABLE_LAB_ENDPOINTS", False),
        cookie_secure=True if (secure or is_prod) else _flag(env, "HALCYON_COOKIE_SECURE", False),
        admin_api_key=env.get("HALCYON_ADMIN_API_KEY", ""),
        profile=profile,
        session_secret=session_secret,
        guard_mode=guard_mode,
        guard_model=env.get("LLAMA_GUARD_MODEL", "llama-guard3:1b"),
        guard_timeout=float(env.get("EIGER_GUARD_TIMEOUT", "3")),
        trusted_ollama_url=env.get("EIGER_TRUSTED_OLLAMA_URL"),
        ollama_gateway_token=env.get("EIGER_OLLAMA_GATEWAY_TOKEN", ""),
        oidc_issuer=oidc_issuer,
        oidc_audience=oidc_audience,
        oidc_jwks_url=oidc_jwks_url,
        allowed_origins=origins,
    )


MODULE_FLAGS: dict[str, tuple[str, ...]] = {
    "m1": ("sec_system_prompt_hardening", "sec_input_filter"),
    "m2": ("sec_output_encoding", "sec_system_prompt_hardening"),
    "m3": ("sec_rag_provenance",),
    "m5": ("sec_tool_scope_enforcement",),
    "m6": ("sec_mcp_desc_pinning", "sec_mcp_token_scoping"),
    "m7": ("sec_inter_agent_auth",),
    "m8": ("sec_guardrails",),
}


def effective_settings(
    base: Settings, session_state: "SessionState", session_id: str, module: str
) -> Settings:
    """Overlay a session's per-module L1/L2 level onto the base Settings."""
    if base.lock_security_levels:
        return base
    level = session_state.get_level(session_id, module)
    flags = MODULE_FLAGS.get(module)
    if level is None or not flags:
        return base
    value = level == "L2"
    changes: dict[str, Any] = {name: value for name in flags}
    return replace(base, **changes)
