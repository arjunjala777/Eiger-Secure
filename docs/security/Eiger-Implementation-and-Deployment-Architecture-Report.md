# EIGER AI BANKING PLATFORM: IMPLEMENTATION & DEPLOYMENT ARCHITECTURE SPECIFICATION

**Comprehensive Technical Delineation of Subsystem Implementations and Multi-Tier Deployment Topologies**

- **Document Version:** 1.0 (Production Hardened)
- **Hardened Repository:** `eiger repo 2` on `security-hardening`
- **Baseline Reference:** `eiger` on `m3-submission` (Clean benchmark)
- **Evaluation Date:** 27 October 2026
- **Test Suite Record:** **448 Passed**, 0 Failed, 35 Negative Security Tests

---

## 1. Executive Overview & Security Engineering Philosophy

This architectural specification provides an exhaustive, code-level exposition of exactly how the Eiger AI Banking Platform has been hardened and where each constituent component is deployed across both containerized production and local runtime environments.

> **Fundamental Engineering Principle: Deterministic Defense Over Probabilistic Alignment.** In an agentic banking environment, probabilistic safety controls can be subverted through novel prompt injections. Therefore, in the hardened architecture, financial authorization, balance invariants, session authentication, and inter-process delegation are enforced by deterministic, non-bypassable software boundaries. AI safety classifiers (NeMo and Llama Guard) provide defense-in-depth screening, but the core financial state remains cryptographically and transactionally immutable to model manipulation.

## 2. Granular Implementation Architecture (How It Has Been Implemented)

### 2.1 Web Identity, Authentication & Session Engine (`halcyon/web.py`)
- **OIDC JWKS Signature Verification:** Unsigned bearer strings rejected; incoming tokens cryptographically validated against configured JWKS.
- **Mint-Only Session Lifecycle:** Client URL parameters (`?session=alice`) ignored; server mints cryptographically signed random `eiger-{hex}` sessions.
- **Hardened Cookie Policy:** Cookies enforce `Secure; HttpOnly; SameSite=Strict; Max-Age=86400` (24h expiry).
- **Origin Matching & CSRF Token Guard:** Sensitive POST routes validate Origin/Referer headers against whitelist plus session-bound CSRF token.
- **OWASP Deny-by-Default:** Route decorators default to `require_ownership=True`.
- **Public View Pseudonymization:** Scoreboard IDs anonymized to `Participant-XXXXXX`.
- **Production Endpoint Lockdown:** Lab routes (`/reset/*`, `/validate/*`, `/source`) return HTTP 403 Forbidden.

### 2.2 Financial Integrity, Invariants & Transactional Persistence (`halcyon/bank.py`, `halcyon/security/ledger.py`, `halcyon/tools.py`)
- **Double-Entry Balance Conservation:** `transfer_funds(from_account=None)` synthetic credit logic completely eliminated; credits mandate verified debits.
- **Elimination of Merchant Fallbacks:** Removed `acct-merchant` exemptions; caller must own source account via `bank.owns()`.
- **Strict Numeric Schema Validation:** Enforces `type(amount) is int and amount > 0`; booleans (`True`/`False`) and floats rejected.
- **Atomic Refund Pipeline:** Refunds validate original purchase ID, derive destination from purchase, and enforce cumulative caps.
- **PostgreSQL ACID Transactional Storage:** Process-local dictionaries replaced with PostgreSQL transactions using row locks (`SELECT ... FOR UPDATE`).
- **Treasury Replay & Idempotency Binding:** Disbursements bound to server-generated payment ID and bank idempotency keys.

### 2.3 Model Control Plane, Reverse Proxy Gateway & SSRF Boundary (`halcyon/ollama_gateway.py`, `halcyon/llm.py`)
- **Ollama Reverse Proxy Gateway:** Bearer-authenticated reverse proxy mediating all model communications (`EIGER_OLLAMA_GATEWAY_TOKEN`).
- **Strict Path Whitelisting:** Forwards only `/api/chat` and `/api/generate`; blocks management routes (`create`, `delete`, `pull`) with 403.
- **Per-Request Digest Verification:** Validates upstream SHA-256 model digests against `config/models.json` manifest.
- **Network SSRF Boundary Guard:** Blocks link-local metadata (`169.254.169.254`), RFC 3927, and RFC 1918 subnets.

### 2.4 MCP Tool Execution, Dual Transport & DLP Gateway (`halcyon/security/transport.py`, `halcyon/security/mcp_gateway.py`)
- **Dual Transport Authentication:** Service bearer token plus signed user delegation envelope (`X-Eiger-Delegation-Signature`) binding caller identity to payload.
- **Inter-Service Credential Isolation:** Banking daemon strictly rejects CRM service credentials.
- **In-Daemon Permission Enforcement:** Tool handlers verify `bank.owns(caller, account)` on reads and mutations.
- **Lasso-Style MCP Security Gateway:** Ingress schema typing and egress DLP masking credit cards, SSNs, and tokens.

### 2.5 Knowledge Base Architecture & Surface Minimization (`halcyon/sqlite_kb.py`)
- **ChromaDB Dependency Removal:** ChromaDB completely eliminated from code, dependencies, and Compose files.
- **Deterministic SQLite Lexical Retrieval:** Parameterized SQL with pre-clearance tenant filtering.
- **Context Prompt Isolation:** Knowledge chunks isolated with XML boundary tags and regex escaping.

### 2.6 AI Safety Guardrails & Probabilistic Screening (`halcyon/security/runtime.py`)
- **NeMo Guardrails Colang Flows:** Dialogue policies enforcing topical focus and blocking prompt injections.
- **Meta Llama Guard 3-1B Classifier:** 13-category safety taxonomy (`S13 = Elections`).
- **Fail-Closed Contract:** Errors or timeouts return `UNAVAILABLE` rather than defaulting to safe.

### 2.7 SIEM Observability & Audit Spooling (`halcyon/security/wazuh_logger.py`)
- **Structured JSON Audit Logging:** OSSEC/Wazuh compliant versioned JSON security events.
- **HMAC Actor Pseudonymization:** User IDs hashed to `actor-{sha256}`.
- **Bounded Disk Spooling:** 10 MB rotating file spool (`.json.1`).
- **Custom Decoders & Rules:** Mapped alert levels 6 through 14 in `wazuh/decoders/` and `wazuh/rules/`.

## 3. Deployment Topologies (Where It Has Been Deployed)

### 3.1 Three-Tier Micro-Segmented Docker Topology (`docker-compose.blue-team.yml`)

| Network Segment | Network Driver | Internal Only | Connected Services |
| :--- | :--- | :--- | :--- |
| `ingress` | bridge | No (Port 8000 exposed) | `eiger-app` |
| `backend` | bridge | Yes (`internal: true`) | `eiger-app`, `mcp-core`, `mcp-crm`, `ollama-gateway`, `postgres` |
| `models` | bridge | Yes (`internal: true`) | `ollama-gateway`, `ollama` |

#### Production Service Matrix

| Service Name | Base / Digest | Host Binding | Internal Port | Hardening Profile |
| :--- | :--- | :--- | :--- | :--- |
| `eiger-app` | `eiger-blue-team:local` | `127.0.0.1:8000` | 8000 | non-root, read-only root, cap_drop: [ALL], mem_limit: 3g |
| `mcp-core` | `eiger-blue-team:local` | None (Blocked) | 9001 | non-root, read-only root, cap_drop: [ALL], mem_limit: 3g |
| `mcp-crm` | `eiger-blue-team:local` | None (Blocked) | 9002 | non-root, read-only root, cap_drop: [ALL], mem_limit: 3g |
| `ollama-gateway` | `eiger-blue-team:local` | None (Blocked) | 11435 | non-root, read-only root, cap_drop: [ALL], mem_limit: 512m |
| `ollama` | `ollama/ollama@sha256:...` | None (Blocked) | 11434 | read-only root, cap_drop: [ALL], mem_limit: 10g |
| `postgres` | `postgres@sha256:...` | None (Blocked) | 5432 | Row-level locking ledger, persistent `ledger_data` volume |

### 3.2 Enterprise SIEM & SOC Cluster Deployment (`docker-compose.wazuh.yml`)
- **Shared Volume:** Shared `eiger_logs` volume at `/app/logs/wazuh_security_events.json`.
- **Wazuh Cluster:** Manager, Indexer, and Dashboard ingesting spooled events with custom rules.

### 3.3 Local Developer & Testing Deployment (`scripts/security/run_local_secure.ps1`)
- **Loopback Enforcement:** Validates Ollama is bound exclusively to `127.0.0.1:11434`.
- **Ephemeral CSPRNG Secrets:** Generates 48-byte random secrets per session with zero hardcoded fallbacks.
- **Port Bindings:** Gateway on 11435, Banking on 9001, CRM on 9002, Web on 8000.

## 4. Mandatory Security Environment Variables

| Variable Name | Expected Format | Target Component | Security Purpose |
| :--- | :--- | :--- | :--- |
| `HALCYON_MODE` | `secure` | All Components | Enforces secure mode; disables insecure demo fallbacks. |
| `HALCYON_PROFILE` | `production` / `lab` | Web / Banking | production permanently disables `/reset/*` and `/source`. |
| `HALCYON_SESSION_SECRET` | CSPRNG 48-byte Base64 | `halcyon/web.py` | Keys HMAC-SHA256 session cookie signatures. |
| `HALCYON_MCP_CORE_TOKEN` | CSPRNG 48-byte Base64 | `mcp_deploy.py` (CORE) | Bearer authentication secret for Core Banking daemon. |
| `HALCYON_MCP_CRM_TOKEN` | CSPRNG 48-byte Base64 | `mcp_deploy.py` (CRM) | Bearer authentication secret for CRM daemon. |
| `HALCYON_MCP_CORE_DELEGATION_SECRET` | CSPRNG 48-byte Base64 | `halcyon/security/transport.py` | Keys user delegation HMAC-SHA256 signatures. |
| `EIGER_OLLAMA_GATEWAY_TOKEN` | CSPRNG 48-byte Base64 | `halcyon/ollama_gateway.py` | Bearer token authenticating web app to Ollama gateway. |
| `DATABASE_URL` | PostgreSQL URL | `halcyon/security/ledger.py` | Connection string for ACID transactional ledger. |

## 5. Empirical Verification & Test Suite Metrics

- **Full Test Suite:** **448 passed**, 8 skipped, 12 deselected with 0 failures in 45.55s.
- **Negative Security Suite:** 35 dedicated test invariants passing 100% in `tests/test_negative_security.py`.
- **Ollama Gateway Security Suite:** 4 focused gateway tests passing in `tests/test_ollama_gateway.py`.
- **MCP Scanner Probes:** Grade **A+** (100/100, 4/4 empirical probes passed in `scripts/security/mcp_scanner.py`).
- **Dependency & Supply Chain Audits:** Zero vulnerabilities via `pip-audit --local`; CycloneDX 1.6 AI BOM (`ai-bom.json`).
