from collections.abc import AsyncIterator
from contextlib import AsyncExitStack, asynccontextmanager
from dataclasses import dataclass

from mcp import ClientSession
from mcp.client.streamable_http import streamablehttp_client
from mcp.shared.memory import create_connected_server_and_client_session as _connect
from mcp.types import TextContent

from halcyon import audit, guards
from halcyon.bank import Bank
from halcyon.config import Settings
from halcyon.mcp_servers.core_banking import build_core_banking_server
from halcyon.mcp_servers.crm import build_crm_server
from halcyon.mcp_vault import SERVER_CORE, SERVER_CRM, TokenVault
from halcyon.store import Store
from halcyon.security.context import internal_context, authenticated_context
from halcyon.security.policy import APPROVED_TOOLS, tool_schema, validate_param_types
from halcyon.security.transport import DelegationAuth

MODULE = "m6"
_SENSITIVE = {"get_account_details"}  # core-banking tools that leak data


@dataclass
class ToolInfo:
    server: str
    name: str
    description: str
    input_schema: dict

    @property
    def qualified(self) -> str:
        return f"{self.server}__{self.name}"


class MCPHost:
    def __init__(self, sessions: dict[str, ClientSession], vault: TokenVault,
                 store: Store, settings: Settings, session_id: str) -> None:
        self._sessions = sessions           # {SERVER_CORE: s, SERVER_CRM: s}
        self._vault = vault
        self._store = store
        self._settings = settings
        self._session_id = session_id
        self._context = authenticated_context(session_id, "system_internal") if settings.mode == "vulnerable" else internal_context(session_id)
        self._pinned: dict[str, str] = {}
        self._served_poison = False

    async def _list(self, server: str) -> list[ToolInfo]:
        res = await self._sessions[server].list_tools()
        return [ToolInfo(server, t.name, t.description or "", t.inputSchema) for t in res.tools]

    async def list_tools(self) -> list[ToolInfo]:
        out: list[ToolInfo] = []
        for server in (SERVER_CORE, SERVER_CRM):
            out.extend(await self._list(server))
        return out

    def approve(self, tools: list[ToolInfo]) -> None:
        if self._settings.sec_mcp_desc_pinning:
            self._pinned = {ti.qualified: guards.desc_hash(ti.description) for ti in tools}

    async def schemas_for_llm(self) -> list[dict]:
        tools = await self.list_tools()
        self._served_poison = False
        schemas: list[dict] = []
        for ti in tools:
            if self._settings.mode == "secure" or self._settings.profile == "production":
                spec = APPROVED_TOOLS.get(ti.name)
                if spec is None or spec.service != ti.server or ti.input_schema != tool_schema(spec):
                    continue
            desc = ti.description
            if self._settings.sec_mcp_desc_pinning:
                pinned = self._pinned.get(ti.qualified)
                if pinned is not None and guards.desc_hash(desc) != pinned:
                    desc = ""  # mutated since approval — drop the untrusted delta
                desc = guards.quarantine_description(desc)
            else:
                if guards.looks_poisoned(desc):
                    self._served_poison = True
                    if ti.name == "get_notes":  # a benign tool now carrying injected text == rug pull
                        audit.record(self._store, self._session_id, MODULE,
                                     audit.MCP_DESC_MUTATION_ACCEPTED, ti.server, {"tool": ti.name})
            schemas.append({"name": ti.qualified, "description": desc, "parameters": ti.input_schema})
        return schemas

    async def call(self, qualified: str, args: dict) -> str:
        server, _, name = qualified.partition("__")
        audit.record(self._store, self._session_id, MODULE, audit.TOOL_CALL,
                     self._session_id, {"tool": qualified, "argument_names": list(args)})
        secure = self._settings.mode == "secure" or self._settings.profile == "production"
        if name == "get_integration_token" and secure:
            return "denied: credentials are not available to agents"
        if name == "get_integration_token":
            service = str(args.get("service", ""))
            if not service or service == SERVER_CRM:
                return self._vault.own_token(SERVER_CRM)
            if service not in (SERVER_CORE, SERVER_CRM):
                return "unknown service"
            if not guards.authorize_token_access(SERVER_CRM, service, self._settings):
                return "access denied"
            audit.record(self._store, self._session_id, MODULE, audit.TOKEN_READ,
                         SERVER_CRM, {"target": service})
            return self._vault.own_token(service)
        # Attribution is deliberately coarse: in vulnerable mode, any served
        # poisoned description arms the *next* sensitive core-tool call, not
        # necessarily the one the poison referenced. This is mechanism-based
        # (model-word-independent) rather than reading the model's intent;
        # the live e2e test proves a real model actually follows the description.
        if server == SERVER_CORE and name in _SENSITIVE and self._served_poison:
            audit.record(self._store, self._session_id, MODULE,
                         audit.MCP_POISONED_INVOCATION, self._session_id,
                         {"tool": qualified, "argument_names": list(args)})

        # MCP Security Gateway Ingress Inspection
        from halcyon.security.mcp_gateway import MCPSecurityGateway
        if not hasattr(self, "_gateway"):
            self._gateway = MCPSecurityGateway()
        if secure:
            spec = APPROVED_TOOLS.get(name)
            if spec is None or spec.service != server:
                return "denied: tool is not approved for this service"
            is_allowed, err = self._gateway.inspect_request(qualified, args, session_id=self._session_id, caller=self._session_id)
        else:
            is_allowed, err = True, None
        if not is_allowed:
            return f"Error: {err}"

        call_args = dict(args)
        res = await self._sessions[server].call_tool(name, call_args)
        first = res.content[0] if res.content else None
        raw_text = first.text if isinstance(first, TextContent) else ""

        # MCP Security Gateway Egress DLP Sanitization
        return self._gateway.inspect_response(name, raw_text, session_id=self._session_id) if secure else raw_text


@asynccontextmanager
async def in_memory_host(bank: Bank, vault: TokenVault, customers: dict,
                         store: Store, settings: Settings,
                         session_id: str) -> AsyncIterator[MCPHost]:
    context = authenticated_context(session_id, "system_internal") if settings.mode == "vulnerable" else internal_context(session_id)
    async with AsyncExitStack() as stack:
        core = await stack.enter_async_context(_connect(build_core_banking_server(bank, vault, context_provider=lambda: context, settings=settings, store=store)))
        crm = await stack.enter_async_context(_connect(build_crm_server(bank, vault, customers, context_provider=lambda: context, settings=settings, store=store)))
        await core.initialize()
        await crm.initialize()
        yield MCPHost({SERVER_CORE: core, SERVER_CRM: crm}, vault, store, settings, session_id)


@asynccontextmanager
async def http_host(core_url: str, crm_url: str, vault: TokenVault,
                     store: Store, settings: Settings,
                     session_id: str) -> AsyncIterator[MCPHost]:
    """Same host, real transport: connects to the deployed mcp-core-banking
    and mcp-crm containers over streamable-HTTP instead of in-memory pipes."""
    core_headers = {"Authorization": f"Bearer {vault.own_token(SERVER_CORE)}"}
    crm_headers = {"Authorization": f"Bearer {vault.own_token(SERVER_CRM)}"}
    async with AsyncExitStack() as stack:
        core_r, core_w, _ = await stack.enter_async_context(streamablehttp_client(core_url, auth=DelegationAuth(vault.own_token(SERVER_CORE), SERVER_CORE, internal_context(session_id))))
        core = await stack.enter_async_context(ClientSession(core_r, core_w))
        crm_r, crm_w, _ = await stack.enter_async_context(streamablehttp_client(crm_url, auth=DelegationAuth(vault.own_token(SERVER_CRM), SERVER_CRM, internal_context(session_id))))
        crm = await stack.enter_async_context(ClientSession(crm_r, crm_w))
        await core.initialize()
        await crm.initialize()
        yield MCPHost({SERVER_CORE: core, SERVER_CRM: crm}, vault, store, settings, session_id)
