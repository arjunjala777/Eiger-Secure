"""Discover MCP servers from `mcp.json` — the way real MCP clients (Claude Desktop,
Cursor, VS Code) do — instead of bespoke per-server env vars.

`mcp.json` at the repo root is the source of truth: its `mcpServers` keys declare the
servers, and each `url` says where to reach it. Adding a third server is a config edit,
not a code + compose change.

Precedence per server: env override (`MCP_CORE_URL` / `MCP_CRM_URL`) > `mcp.json` url.
The keys MUST match the `Server("...")` literals in `halcyon/mcp_servers/*` — an external
scanner joins these declared names against the tools it finds in source (normalising both
sides), so a mismatch makes that join silently find nothing.
"""
import json
import os
from collections.abc import Mapping
from pathlib import Path

# repo root = the parent of the halcyon/ package (i.e. /app in the container image)
_DEFAULT_CONFIG = Path(__file__).resolve().parent.parent / "mcp.json"

# Optional per-server env overrides -> the server name they override.
_ENV_OVERRIDES = {
    "MCP_CORE_URL": "mcp-core-banking",
    "MCP_CRM_URL": "mcp-crm",
}


def config_path(env: Mapping[str, str] = os.environ) -> Path:
    """Where the app reads MCP config from (override with MCP_CONFIG)."""
    override = env.get("MCP_CONFIG")
    return Path(override) if override else _DEFAULT_CONFIG


def load_mcp_servers(env: Mapping[str, str] = os.environ) -> dict[str, str]:
    """Return {server_name: url}. `mcp.json` is the base; env vars override per server."""
    servers: dict[str, str] = {}
    path = config_path(env)
    if path.is_file():
        data = json.loads(path.read_text())
        for name, spec in (data.get("mcpServers") or {}).items():
            url = (spec or {}).get("url")
            if url:
                servers[name] = url
    # env overrides win, and can also supply a server the file omitted (compose/CI convenience)
    for var, name in _ENV_OVERRIDES.items():
        if env.get(var):
            servers[name] = env[var]
    return servers
