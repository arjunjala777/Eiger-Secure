# Repo 2 local deployment

The updated repo 2 application, RAG source boundary, MCP services, and digest-checking inference gateway are deployed as local Windows processes. This is the Secure Lab deployment, not the production Docker topology.

| Service | Local endpoint | Process ID at verification |
|---|---|---|
| Repo 2 application | http://localhost:8002 | 38184 |
| Repo 2 Core MCP | http://127.0.0.1:9101/mcp | 24408 |
| Repo 2 CRM MCP | http://127.0.0.1:9102/mcp | 32200 |
| Repo 2 inference gateway | http://127.0.0.1:11435 | 11012 |

Ports 8000, 8012, 9001 and 9002 belonged to benchmark/scratch processes, so they were not stopped or repurposed. Their process IDs remained unchanged. The shared Ollama daemon on port 11434 also remained unchanged. Repo 1 files were not modified.

## Verified after deployment

- `/health`: 200, secure mode, Ollama/database/MCP up.
- `/ready`: 200, model inventory and NeMo checks passed, database available. Guard mode is `observe`; deterministic RAG/authorization controls are enforced independently.
- Unauthenticated gateway and Core/CRM MCP calls: 401.
- Standard launcher probes passed for authentication, CSRF/origin restrictions, session URL rejection, ingestion limits, model policy, MCP authentication and disabled gateway management routes.
- Six real HTTP/live-model RAG checks passed: semantic 24/7 poison, fake official tags, zero-width poison, legitimate PIN reset, restricted memo query and legitimate dispute-window query.
- The three poison documents were accepted into the caller's notes but did not change the official-hours answers. This verifies behavior beyond rejecting known attack strings at ingestion.
- The restricted memo was not disclosed. All six validation responses were core fail/stretch fail. Legitimate queries returned valid bank information.
- The disposable verification session was reset afterward; no customer/benchmark session was reset.

Detailed responses and timestamp: [m3-deployment-verification.json](m3-deployment-verification.json).

## Launch procedure

From `C:\Users\Arjun Jala\eiger repo 2`, with these repo 2 ports free:

```powershell
& .\scripts\security\run_local_secure.ps1 -AppPort 8002 -CorePort 9101 -CrmPort 9102 -GatewayPort 11435
```

The launcher creates ephemeral service/session credentials and leaves services running independently after successful probes. Credentials are not written to this report. The first attempt exceeded the 45-second startup allowance and cleaned up its own processes; the launcher now allows 120 seconds for cold startup. This is not an automatic Windows boot service. Process IDs can change after a restart; identify current repo 2 processes before stopping them.

The repository environment used for deployment has aiohttp 3.14.5 and PyJWT 2.15.1. It imports the new source policy from repo 2. No dependency reinstallation was necessary for the RAG patch. Changes remain uncommitted.

## Remaining boundary

The shared raw Ollama listener remains locally accessible outside the gateway. This deployment does not claim to close that host-level exposure. Production Docker isolation, immutable model storage, external OIDC/TLS/SIEM and full production validation remain separate tasks. Existing manifest digests were used without silently changing or approving new model artifacts.
