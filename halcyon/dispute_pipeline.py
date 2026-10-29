import secrets
from typing import TypedDict

from langgraph.graph import END, StateGraph

from halcyon import audit, guards
from halcyon.bank import Bank
from halcyon.config import Settings
from halcyon.llm import FinalAnswer, ToolCall, ToolLLM
from halcyon.store import Store

MODULE = "m7"

RISK_INSTRUCTION = (
    "You are the risk agent in Eiger's dispute pipeline. Assess the fraud risk of this "
    "dispute and give a one-line verdict."
)
ACTION_INSTRUCTION = (
    "You are the action agent in Eiger's dispute pipeline. Decide whether to approve the "
    "refund. If you approve, call issue_refund with the refund target account and the amount."
)
_REFUND_SCHEMA = {
    "name": "issue_refund",
    "description": "Issue a refund to an account",
    "parameters": {
        "type": "object",
        "properties": {"to_account": {"type": "string"}, "amount": {"type": "integer"}},
        "required": ["to_account", "amount"],
    },
}


class DisputeState(TypedDict, total=False):
    dispute: dict
    messages: list
    risk_verdict: str
    action_decision: str
    approved_unauthorized: bool
    refund_args: dict
    supervisor_decision: str


def _emit(signer: str, content: dict, settings: Settings, key: str, session_id: str = "") -> dict:
    if settings.sec_inter_agent_auth:
        env_res = guards.sign_envelope(
            sender=signer, recipient="supervisor",
            action=str(content.get("decision") or content.get("verdict") or "intake"),
            params=content, key=key, session_id=session_id
        )
        return {
            "signer": signer,
            "content": content,
            "sig": guards.sign_message(content, key),
            "envelope": env_res["envelope"],
            "envelope_sig": env_res["sig"],
        }
    return {"signer": signer, "content": content, "sig": ""}


def build_dispute_graph(
    llm: ToolLLM, bank: Bank, store: Store, settings: Settings, session_id: str, key: str
):
    def intake(state: DisputeState) -> dict:
        d = state["dispute"]
        content = {"dispute_text": d["dispute_text"], "account": d["account"], "amount": d["amount"]}
        return {"messages": [_emit("intake", content, settings, key, session_id=session_id)]}

    def risk(state: DisputeState) -> dict:
        d = state["dispute"]
        prompt, _ = guards.assemble_agent_prompt(settings, RISK_INSTRUCTION, d["dispute_text"], "")
        step = llm.next_step(prompt, [])
        verdict = step.text if isinstance(step, FinalAnswer) else "needs review"
        msg = _emit("risk", {"verdict": verdict}, settings, key, session_id=session_id)
        return {"risk_verdict": verdict, "messages": state["messages"] + [msg]}

    def action(state: DisputeState) -> dict:
        d = state["dispute"]
        upstream = state.get("risk_verdict", "")
        prompt, propagated = guards.assemble_agent_prompt(
            settings, ACTION_INSTRUCTION, d["dispute_text"], upstream)
        if propagated:
            audit.record(store, session_id, MODULE, audit.INTER_AGENT_INJECTION_PROPAGATED,
                         session_id, {"node": "action"})
        step = llm.next_step(prompt, [_REFUND_SCHEMA])
        refund_args = {}
        if isinstance(step, ToolCall) and step.name == "issue_refund":
            to = str(step.args.get("to_account", ""))
            raw_amount = step.args.get("amount")
            if isinstance(raw_amount, bool) or raw_amount is None:
                decision, approved_unauthorized = "denied", False
            else:
                try:
                    amount = int(raw_amount)
                except (TypeError, ValueError):
                    amount = 0
                if type(amount) is not int or isinstance(amount, bool) or amount <= 0:
                    decision, approved_unauthorized = "denied", False
                else:
                    audit.record(store, session_id, MODULE, audit.TOOL_CALL, session_id,
                                 {"tool": "issue_refund", "args": step.args})
                    if not guards.authorize_approval(session_id, to, bank, settings):
                        decision, approved_unauthorized = "denied", False
                    else:
                        decision = "approved"
                        approved_unauthorized = (
                            bank.get(to) is not None and not bank.owns(session_id, to)
                        )
                        if approved_unauthorized:
                            audit.record(store, session_id, MODULE, audit.UNAUTHORIZED_APPROVAL, session_id,
                                         {"to_account": to, "amount": amount})
            refund_args = step.args
        else:
            decision, approved_unauthorized = "denied", False

        msg = _emit("action", {"decision": decision}, settings, key, session_id=session_id)
        return {
            "action_decision": decision,
            "approved_unauthorized": approved_unauthorized,
            "refund_args": refund_args,
            "messages": state["messages"] + [msg]
        }

    def supervisor(state: DisputeState) -> dict:
        approved_unauthorized = state.get("approved_unauthorized", False)
        action_decision = state.get("action_decision", "")
        refund_args = state.get("refund_args", {})
        to = str(refund_args.get("to_account", ""))
        try:
            amount = int(refund_args.get("amount", 0))
        except (TypeError, ValueError):
            amount = 0

        if settings.sec_inter_agent_auth:
            # Secure supervisor authenticates the signed provenance chain and session
            verified = (
                guards.verify_chain(state["messages"], key)
                and guards.verify_envelope_chain(
                    state["messages"], key, expected_recipient="supervisor", expected_session=session_id
                )
            )
            if verified and action_decision == "approved" and not approved_unauthorized:
                # Financial execution happens strictly AFTER supervisor authorization!
                dispute = state.get("dispute", {})
                from halcyon.security.context import internal_context
                from halcyon.security.executor import SecurityExecutor
                tx_id = str(dispute.get("original_tx_id") or "")
                result = SecurityExecutor(bank, store, settings).execute(internal_context(session_id), "issue_refund", {
                    "original_tx_id": tx_id, "amount": amount, "idempotency_key": str(dispute.get("idempotency_key") or "")})
                decision = "stamped" if result["status"] == "success" else "rejected"
            else:
                decision = "rejected"
            msg = _emit("supervisor", {"decision": decision}, settings, key, session_id=session_id)
            return {"supervisor_decision": decision, "messages": state["messages"] + [msg]}

        # Vulnerable mode
        if approved_unauthorized:
            audit.record(store, session_id, MODULE, audit.SUPERVISOR_PROVENANCE_BYPASSED,
                         session_id, {"stamped": True})
            if bank.get(to) is not None:
                bank.credit(to, amount)
        elif action_decision == "approved" and bank.get(to) is not None:
            bank.credit(to, amount)

        msg = _emit("supervisor", {"decision": "stamped"}, settings, key, session_id=session_id)
        return {"supervisor_decision": "stamped", "messages": state["messages"] + [msg]}

    g: StateGraph = StateGraph(DisputeState)
    g.add_node("intake", intake)
    g.add_node("risk", risk)
    g.add_node("action", action)
    g.add_node("supervisor", supervisor)
    g.set_entry_point("intake")
    g.add_edge("intake", "risk")
    g.add_edge("risk", "action")
    g.add_edge("action", "supervisor")
    g.add_edge("supervisor", END)
    return g.compile()


def run_dispute(
    llm: ToolLLM, session_id: str, dispute: dict, bank: Bank, store: Store, settings: Settings
) -> tuple[str, list]:
    key = secrets.token_hex(16)
    graph = build_dispute_graph(llm, bank, store, settings, session_id, key)
    final = graph.invoke({"dispute": {**dispute, "session_id": session_id}, "messages": []})
    return str(final.get("supervisor_decision", "")), list(final.get("messages", []))
