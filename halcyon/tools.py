from halcyon import audit, guards
from halcyon.bank import Bank
from halcyon.config import Settings
from halcyon.store import Store

SCHEMAS: list[dict] = [
    {"name": "get_balance", "description": "Get an account balance",
     "parameters": {"type": "object", "properties": {"account": {"type": "string"}},
                    "required": ["account"]}},
    {"name": "get_account_details", "description": "Look up an account's details",
     "parameters": {"type": "object", "properties": {"account": {"type": "string"}},
                    "required": ["account"]}},
    {"name": "transfer_funds", "description": "Transfer money to an account",
     "parameters": {"type": "object", "properties": {
         "to_account": {"type": "string"}, "amount": {"type": "integer"}},
         "required": ["to_account", "amount"]}},
    {"name": "issue_refund", "description": "Issue a refund to an account",
     "parameters": {"type": "object", "properties": {
         "to_account": {"type": "string"}, "amount": {"type": "integer"}},
         "required": ["to_account", "amount"]}},
    {"name": "update_email", "description": "Update an account's email",
     "parameters": {"type": "object", "properties": {
         "account": {"type": "string"}, "email": {"type": "string"}},
         "required": ["account", "email"]}},
]

TOOLS = SCHEMAS


def execute(name: str, session_id: str, args: dict, bank: Bank,
            store: Store, settings: Settings) -> str:
    if settings.mode == "secure" or settings.profile == "production":
        import json
        from halcyon.security.context import internal_context
        from halcyon.security.executor import SecurityExecutor
        from halcyon.security.mcp_gateway import MCPSecurityGateway
        gateway = MCPSecurityGateway()
        allowed, reason = gateway.inspect_request("core_banking__" + name, args, session_id=session_id)
        if not allowed:
            return "denied: " + str(reason)
        result = SecurityExecutor(bank, store, settings).execute(internal_context(session_id), "core_banking__" + name, args)
        return gateway.inspect_response(name, json.dumps(result), session_id=session_id)
    audit.record(store, session_id, "m5", audit.TOOL_CALL, session_id,
                 {"tool": name, "args": args})
    if not guards.authorize_tool_call(session_id, name, args, bank, settings):
        return f"denied: {name} requires authorization / human approval"
    if name == "get_balance":
        a = bank.get(str(args.get("account", "")))
        return f"balance: {a.balance}" if a else "no such account"
    if name == "get_account_details":
        a = bank.get(str(args.get("account", "")))
        return f"account {a.id}: email={a.email} balance={a.balance}" if a else "no such account"
    if name in ("transfer_funds", "issue_refund"):
        to = str(args.get("to_account", ""))
        if not to:
            return f"{name}: missing to_account"
        raw_amount = args.get("amount")
        if isinstance(raw_amount, bool) or raw_amount is None:
            return f"{name}: invalid amount"
        try:
            amount = int(raw_amount)
        except (TypeError, ValueError):
            return f"{name}: invalid amount"
        if type(amount) is not int or isinstance(amount, bool) or amount <= 0:
            return f"{name}: invalid amount"
        if not bank.owns(session_id, to):
            audit.record(store, session_id, "m5", audit.UNAUTHORIZED_TOOL_CALL,
                         session_id, {"tool": name, "to_account": to, "amount": amount})
        if bank.get(to) is not None:
            if settings.mode == "secure" or settings.profile == "production":
                if name == "issue_refund":
                    if not bank.owns(session_id, to):
                        return f"denied: unowned destination account {to}"
                    tx_id = str(args.get("original_tx_id") or f"tx-seed-{to}")
                    res = bank.issue_refund(tx_id, amount, to, session_id=session_id)
                    if not res:
                        return f"denied: refund failed: {res.error}"
                else:
                    from_acct = str(args.get("from_account") or "").strip()
                    if not from_acct:
                        from_acct = bank.primary_account_for(session_id) or ""
                    if not from_acct or not bank.owns(session_id, from_acct):
                        return f"denied: caller does not own source account {from_acct}"
                    res = bank.transfer(from_account=from_acct, to_account=to, amount=amount, session_id=session_id)
                    if not res:
                        return f"denied: transfer failed"
            else:
                bank.credit(to, amount)
        return f"{name}: moved {amount} to {to}"
    if name == "update_email":
        acct = str(args.get("account", ""))
        email = str(args.get("email", ""))
        if not acct:
            return "update_email: missing account"
        if not bank.owns(session_id, acct):
            audit.record(store, session_id, "m5", audit.UNAUTHORIZED_ACCOUNT_MODIFICATION,
                         session_id, {"account": acct, "email": email})
        if bank.get(acct) is not None:
            bank.set_email(acct, email)
        return f"update_email: {acct} -> {email}"
    return f"unknown tool: {name}"

from halcyon.security.policy import APPROVED_TOOLS, tool_schema
SECURE_SCHEMAS = [{"name": s.name, "description": s.name.replace("_", " "), "parameters": tool_schema(s)}
                  for s in APPROVED_TOOLS.values() if s.service == "core_banking"]
