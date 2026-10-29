import os
from contextlib import asynccontextmanager

from mcp.server.lowlevel import Server
from mcp.server.streamable_http_manager import StreamableHTTPSessionManager
from starlette.applications import Starlette
from starlette.responses import JSONResponse
from starlette.routing import Route
from starlette.types import Receive, Scope, Send

from halcyon import bank_fixtures, crm_fixtures
from halcyon.bank import Bank
from halcyon.mcp_servers.core_banking import build_core_banking_server
from halcyon.mcp_servers.crm import build_crm_server
from halcyon.mcp_vault import SERVER_CORE, SERVER_CRM, TokenVault
from halcyon.security.context import request_context
from halcyon.security.transport import DelegationVerifier


def _asgi(server: Server, required_token: str | None = None, audience: str = SERVER_CORE) -> Starlette:
    is_prod = os.environ.get("HALCYON_PROFILE") == "production"
    is_secure = os.environ.get("HALCYON_MODE") == "secure"
    if not required_token or not required_token.strip():
        raise ValueError("MCP deployment in secure/production mode requires a non-empty authentication token")
    if (is_prod or is_secure) and required_token in ("core-token-dev", "crm-token-dev"):
        raise ValueError("Secure/production MCP credentials must not use development defaults")
    if (is_prod or is_secure) and len(required_token) < 32:
        raise ValueError("Secure/production MCP credentials must contain at least 32 characters")
    verifier = DelegationVerifier(required_token, audience)

    mgr = StreamableHTTPSessionManager(app=server, stateless=True, json_response=True)

    async def handle(scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] == "http":
            body = bytearray()
            while True:
                message = await receive()
                if message["type"] == "http.disconnect":
                    return
                body.extend(message.get("body", b""))
                if len(body) > 1024 * 1024:
                    await JSONResponse({"error": "Request too large"}, status_code=413)(scope, receive, send)
                    return
                if not message.get("more_body", False):
                    break
            try:
                context = verifier.verify(scope, bytes(body))
            except (ValueError, TypeError):
                await JSONResponse({"error": "unauthorized: valid service and user delegation required"}, status_code=401)(scope, receive, send)
                return
            delivered = False
            original_receive = receive
            async def replay_receive():
                nonlocal delivered
                if not delivered:
                    delivered = True
                    return {"type": "http.request", "body": bytes(body), "more_body": False}
                return await original_receive()
            marker = request_context.set(context)
            try:
                await mgr.handle_request(scope, replay_receive, send)
            finally:
                request_context.reset(marker)
            return
    @asynccontextmanager
    async def lifespan(app: Starlette):  # type: ignore[no-untyped-def]
        async with mgr.run():
            yield

    class Transport:
        async def __call__(self, scope, receive, send):
            await handle(scope, receive, send)

    async def health(_request):
        return JSONResponse({"status": "ok"})

    return Starlette(
        routes=[
            Route("/health", endpoint=health, methods=["GET"]),
            Route("/mcp", endpoint=Transport(), methods=["POST", "GET", "DELETE"]),
        ],
        lifespan=lifespan,
    )


def core_banking_app(bank: Bank, vault: TokenVault) -> Starlette:
    return _asgi(build_core_banking_server(bank, vault), vault.own_token(SERVER_CORE))


def crm_app(bank: Bank, vault: TokenVault, customers: dict) -> Starlette:
    return _asgi(build_crm_server(bank, vault, customers), vault.own_token(SERVER_CRM), SERVER_CRM)


def _seeded_bank() -> Bank:
    if os.environ.get("HALCYON_PROFILE") == "production":
        from halcyon.security.ledger import PostgresBank, init_ledger_schema
        dsn = os.environ.get("DATABASE_URL", "")
        init_ledger_schema(dsn)
        return PostgresBank(dsn)
    bank = Bank()
    bank.seed(bank_fixtures.seed_for("demo"))
    return bank


def _vault(server: str) -> TokenVault:
    hardened = (
        os.environ.get("HALCYON_PROFILE") == "production"
        or os.environ.get("HALCYON_MODE", "vulnerable") == "secure"
    )
    env_name, default = (
        ("HALCYON_MCP_CORE_TOKEN", "core-token-dev")
        if server == SERVER_CORE else ("HALCYON_MCP_CRM_TOKEN", "crm-token-dev")
    )
    token = os.environ.get(env_name, "" if hardened else default)
    if not token or (hardened and (token == default or len(token) < 32)):
        raise ValueError(f"Secure/production requires a non-default token for {server}")
    return TokenVault({server: token})


class _ServiceASGI:
    """Initialize only the selected service, with its own credentials."""

    def __init__(self, service: str):
        self.service = service
        self.app = None

    async def __call__(self, scope, receive, send):
        if self.app is None:
            bank, vault = _seeded_bank(), _vault(self.service)
            self.app = (
                core_banking_app(bank, vault)
                if self.service == SERVER_CORE
                else crm_app(bank, vault, crm_fixtures.SEED)
            )
        await self.app(scope, receive, send)


CORE_ASGI = _ServiceASGI(SERVER_CORE)
CRM_ASGI = _ServiceASGI(SERVER_CRM)
