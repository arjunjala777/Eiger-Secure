"""mcp.json is the source of truth for MCP server discovery; env vars override per server."""
import json

from halcyon.mcp_config import config_path, load_mcp_servers
from halcyon.mcp_servers.core_banking import build_core_banking_server
from halcyon.mcp_servers.crm import build_crm_server


def _write(tmp_path, obj):
    p = tmp_path / "mcp.json"
    p.write_text(json.dumps(obj))
    return p


def test_reads_urls_from_file(tmp_path):
    p = _write(tmp_path, {"mcpServers": {
        "mcp-core-banking": {"url": "http://core:9001/mcp"},
        "mcp-crm": {"url": "http://crm:9002/mcp"},
    }})
    servers = load_mcp_servers({"MCP_CONFIG": str(p)})
    assert servers == {
        "mcp-core-banking": "http://core:9001/mcp",
        "mcp-crm": "http://crm:9002/mcp",
    }


def test_env_overrides_file_per_server(tmp_path):
    p = _write(tmp_path, {"mcpServers": {
        "mcp-core-banking": {"url": "http://core:9001/mcp"},
        "mcp-crm": {"url": "http://crm:9002/mcp"},
    }})
    servers = load_mcp_servers({"MCP_CONFIG": str(p), "MCP_CRM_URL": "http://override:9/mcp"})
    assert servers["mcp-core-banking"] == "http://core:9001/mcp"  # untouched
    assert servers["mcp-crm"] == "http://override:9/mcp"  # env wins


def test_missing_file_falls_back_to_env(tmp_path):
    servers = load_mcp_servers({
        "MCP_CONFIG": str(tmp_path / "nope.json"),
        "MCP_CORE_URL": "http://c:1/mcp",
        "MCP_CRM_URL": "http://r:2/mcp",
    })
    assert servers == {"mcp-core-banking": "http://c:1/mcp", "mcp-crm": "http://r:2/mcp"}


def test_missing_file_and_no_env_is_empty(tmp_path):
    assert load_mcp_servers({"MCP_CONFIG": str(tmp_path / "nope.json")}) == {}


def test_default_config_path_is_repo_root_mcp_json():
    # the app reads <repo-root>/mcp.json by default (baked into the image at /app/mcp.json)
    assert config_path({}).name == "mcp.json"


def test_shipped_config_keys_match_server_literals():
    """The declared server names MUST equal the Server("...") literals, or the scanner's
    join (config servers <-> source tools) silently finds nothing."""
    shipped = json.loads(config_path({}).read_text())
    declared = set(shipped["mcpServers"])
    core = build_core_banking_server(_DummyBank(), _DummyVault())
    crm = build_crm_server(_DummyBank(), _DummyVault(), {})
    assert declared == {core.name, crm.name} == {"mcp-core-banking", "mcp-crm"}


class _DummyBank:
    def get(self, *a, **k):
        return None

    def owns(self, *a, **k):
        return False


class _DummyVault:
    def own_token(self, *a, **k):
        return "t"
