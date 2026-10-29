"""LiteLLM-backed LLM / ToolLLM providers.

One code path for every provider (local Ollama + BYOK Anthropic/OpenAI/Gemini/xAI).
litellm consumes OpenAI-format messages and normalizes them per provider, so the tool
path reuses the same internal->OpenAI translation the hand-rolled OpenAI provider used.

`litellm` is imported lazily (inside the methods) so the Stub-based test suite never
pays its heavy import cost.
"""
import json

from halcyon.llm import FinalAnswer, ToolCall


def to_litellm_model(provider: str | None, model: str | None, ollama_model: str) -> str:
    p = (provider or "").lower()
    if p == "anthropic":
        return "anthropic/" + (model or "claude-haiku-4-5")
    if p in ("openai", "remote"):
        return "openai/" + (model or "gpt-4o")
    if p in ("gemini", "google"):
        return "gemini/" + (model or "gemini-2.5-flash")
    if p in ("xai", "grok"):
        return "xai/" + (model or "grok-4.3")
    # ollama_chat/ maps to Ollama's /api/chat, which correctly feeds tool
    # results back on multi-turn tool calls. The plain ollama/ prefix uses the
    # legacy completion route and loops (model never sees the tool result).
    return "ollama_chat/" + (model or ollama_model)  # local / default


def _to_openai_messages(messages: list[dict]) -> list[dict]:
    """Our internal agent-loop message shape -> OpenAI format (litellm's input format)."""
    out: list[dict] = []
    for m in messages:
        role = m.get("role")
        if role == "assistant" and "tool_calls" in m:
            out.append({
                "role": "assistant",
                "content": None,
                "tool_calls": [
                    {"id": c["id"], "type": "function",
                     "function": {"name": c["name"], "arguments": json.dumps(c["args"])}}
                    for c in m["tool_calls"]
                ],
            })
        elif role == "tool":
            out.append({"role": "tool", "tool_call_id": m.get("tool_call_id"),
                        "content": m.get("content", "")})
        else:
            out.append(m)
    return out


class LiteLLMChat:
    """LLM.chat via litellm.completion."""

    def __init__(self, model: str, api_key: str = "", api_base: str | None = None) -> None:
        self._model = model
        self._api_key = api_key
        self._api_base = api_base

    def chat(self, messages: list[dict]) -> str:
        import litellm

        kwargs: dict = {"model": self._model, "messages": messages}
        if self._api_key:
            kwargs["api_key"] = self._api_key
        if self._api_base:
            kwargs["api_base"] = self._api_base
        resp = litellm.completion(**kwargs)
        return resp.choices[0].message.content or ""


class LiteLLMTool:
    """ToolLLM.next_step via litellm.completion (OpenAI-format tools)."""

    def __init__(self, model: str, api_key: str = "", api_base: str | None = None) -> None:
        self._model = model
        self._api_key = api_key
        self._api_base = api_base

    def next_step(self, messages: list[dict], tools: list[dict]) -> "ToolCall | FinalAnswer":
        import litellm

        kwargs: dict = {
            "model": self._model,
            "messages": _to_openai_messages(messages),
            "tools": [{"type": "function", "function": s} for s in tools],
        }
        if self._api_key:
            kwargs["api_key"] = self._api_key
        if self._api_base:
            kwargs["api_base"] = self._api_base
        try:
            resp = litellm.completion(**kwargs)
            msg = resp.choices[0].message
            calls = getattr(msg, "tool_calls", None)
            if calls:
                fn = calls[0].function
                args = json.loads(fn.arguments or "{}")
                return ToolCall(str(fn.name), dict(args))
            return FinalAnswer(msg.content or "")
        except Exception as exc:  # noqa: BLE001 - surface as a final answer for the agent loop
            return FinalAnswer(f"<error: {exc}>")
