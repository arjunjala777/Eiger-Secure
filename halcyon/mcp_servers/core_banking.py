"""Banking MCP service with transport-owned identity and shared execution policy."""
import json
import mcp.types as t
from mcp.server.lowlevel import Server
from halcyon.bank import Bank
from halcyon.config import load_settings
from halcyon.mcp_vault import TokenVault
from halcyon.security.context import anonymous_context, request_context
from halcyon.security.executor import SecurityExecutor
from halcyon.security.policy import APPROVED_TOOLS, tool_schema
from halcyon.store import InMemoryStore


def build_core_banking_server(bank: Bank, vault: TokenVault, *, context_provider=None, settings=None, store=None) -> Server:
    settings = settings or load_settings({"HALCYON_MODE": "secure"})
    executor = SecurityExecutor(bank, store or InMemoryStore(), settings)
    srv = Server("mcp-core-banking")

    @srv.list_tools()
    async def _list():
        if settings.mode == "vulnerable" and settings.profile == "lab":
            move = {"type": "object", "properties": {"to_account": {"type": "string"}, "amount": {"type": "integer"}}, "required": ["to_account", "amount"]}
            return [t.Tool(name=s.name, description=s.name, inputSchema=move if s.name in ("transfer_funds", "issue_refund") else tool_schema(s))
                    for s in APPROVED_TOOLS.values() if s.service == "core_banking"]
        return [t.Tool(name=s.name, description=s.name.replace("_", " "), inputSchema=tool_schema(s))
                for s in APPROVED_TOOLS.values() if s.service == "core_banking"]

    @srv.call_tool()
    async def _call(name: str, args: dict):
        if settings.mode == "vulnerable" and settings.profile == "lab":
            return await _legacy_call(name, args)
        context = context_provider() if context_provider else request_context.get()
        result = executor.execute(context or anonymous_context(), "core_banking__" + name, args)
        return [t.TextContent(type="text", text=json.dumps(result))]

    async def _legacy_call(name: str, args: dict) -> list[t.TextContent]:
        def text(s: str) -> list[t.TextContent]:
            return [t.TextContent(type="text", text=s)]
        caller = str(args.get("_caller_session") or args.get("session_id") or "").strip()
        if name in ("get_balance", "get_account_details"):
            acct = str(args.get("account", "")).strip()
            a = bank.get(acct)
            if a is None:
                return text("no such account")
            if caller and not bank.owns(caller, acct):
                return text(f"denied: caller does not own account {acct}")
            if name == "get_balance":
                return text(f"balance: {a.balance}")
            return text(f"account {a.id}: email={a.email} balance={a.balance}")
        if name in ("transfer_funds", "issue_refund"):
            to = str(args.get("to_account", "")).strip()
            raw_amount = args.get("amount")
            if isinstance(raw_amount, bool) or raw_amount is None:
                return text(f"{name}: invalid amount")
            try:
                amount = int(raw_amount)
            except (TypeError, ValueError):
                return text(f"{name}: invalid amount")
            if type(amount) is not int or isinstance(amount, bool) or amount <= 0:
                return text(f"{name}: invalid amount")
            if not to:
                return text(f"{name}: missing to_account")
            if bank.get(to) is not None:
                if name == "issue_refund":
                    if caller and not bank.owns(caller, to):
                        return text(f"{name}: denied: unowned destination account {to}")
                    tx_id = str(args.get("original_tx_id") or f"tx-seed-{to}")
                    res = bank.issue_refund(tx_id, amount, to, session_id=caller if caller else None)
                    if not res:
                        return text(f"{name}: denied: {res.error}")
                else:
                    from_acct = str(args.get("from_account") or "").strip()
                    if not from_acct and caller:
                        from_acct = bank.primary_account_for(caller) or ""
                    if caller and (not from_acct or not bank.owns(caller, from_acct)):
                        return text(f"{name}: denied: caller does not own source account {from_acct}")
                    if not from_acct:
                        return text(f"{name}: missing from_account")
                    res = bank.transfer(from_account=from_acct, to_account=to, amount=amount, session_id=caller if caller else None)
                    if not res:
                        return text(f"{name}: transfer failed")
            return text(f"{name}: moved {amount} to {to}")
        if name == "update_email":
            acct = str(args.get("account", "")).strip()
            if caller and not bank.owns(caller, acct):
                return text(f"denied: caller does not own account {acct}")
            if bank.get(acct) is not None:
                bank.set_email(acct, str(args.get("email", "")))
            return text(f"update_email: {acct}")
        return text(f"unknown tool: {name}")

    return srv
