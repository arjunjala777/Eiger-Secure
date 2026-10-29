from halcyon.config import load_settings
from halcyon.llm import StubLLM, build_llm
from halcyon.provider_litellm import LiteLLMChat, to_litellm_model


def test_stub_returns_fixed_reply_and_captures_messages():
    llm = StubLLM("hello")
    out = llm.chat([{"role": "user", "content": "hi"}])
    assert out == "hello"
    assert llm.last_messages == [{"role": "user", "content": "hi"}]


def test_build_llm_defaults_to_local_ollama():
    s = load_settings({})
    llm = build_llm(s)
    assert isinstance(llm, LiteLLMChat)
    assert llm._model.startswith("ollama")   # ollama_chat/ (see to_litellm_model)


def test_build_llm_remote_requires_key():
    s = load_settings({})
    import pytest

    with pytest.raises(ValueError):
        build_llm(s, provider="remote", model="gpt-4o", api_key="")


def test_build_llm_anthropic_uses_a_claude_default_model():
    s = load_settings({})
    llm = build_llm(s, provider="anthropic", api_key="k")
    assert "claude" in llm._model


def test_to_litellm_model_maps_each_provider():
    assert to_litellm_model("anthropic", None, "llama3.1:8b") == "anthropic/claude-haiku-4-5"
    assert to_litellm_model("openai", None, "llama3.1:8b") == "openai/gpt-4o"
    assert to_litellm_model("gemini", None, "llama3.1:8b").startswith("gemini/")
    assert to_litellm_model("xai", None, "llama3.1:8b").startswith("xai/")
    assert to_litellm_model("local", None, "llama3.1:8b") == "ollama_chat/llama3.1:8b"
    assert to_litellm_model("xai", "grok-4.5", "x") == "xai/grok-4.5"
