# EIGER AI BANKING PLATFORM: SECURITY IMPROVEMENTS REPORT

**Comprehensive Comparison Between the Vulnerable Benchmark Application and the Hardened Architecture**

- **Benchmark Repository:** `eiger` on `m3-submission` (Clean baseline reference)
- **Hardened Repository:** `eiger repo 2` on `security-hardening`
- **Evaluation Date:** 27 October 2026
- **Test Suite Record:** 448 Passed, 0 Failed, 35 Dedicated Negative Security Tests

## 1. Executive Summary & Assessment Methodology

This engineering report provides an exhaustive, finding-by-finding differential analysis of every security improvement, architectural boundary, and defense-in-depth safeguard implemented in the hardened application (`eiger repo 2`) compared against the original baseline benchmark application (`eiger`). The benchmark repository has been strictly preserved in a clean, untouched state.

### Core Architectural Qualification: Software Persistence vs. Deployment Restrictions
> **Important:** Documenting a database requirement in documentation is a deployment restriction, not implemented software persistence. In the benchmark application, process-local in-memory dictionaries allowed arbitrary demo balances and total state loss on restart. The hardened platform implements a true transactional PostgreSQL ACID ledger with row-level locks (`SELECT ... FOR UPDATE`), atomic audit outbox commits, and crash-resilient idempotency.

## 2. Master Comparative Analysis Matrix

| Domain / Asset | Benchmark State (`eiger`) | Hardened State (`eiger repo 2`) | Key Files Changed | Defensive Control | Finding Ref |
| :--- | :--- | :--- | :--- | :--- | :---: |
| **Web Authentication** | Accepts unsigned/unverified bearer strings; fallback accepts raw session tokens. | **Strict OIDC JWKS cryptographic verification; unverified tokens rejected with 401/403.** | `halcyon/web.py` | OIDC Cryptographic Auth | **VAPT-026, Critical** |
| **Session Fixation** | GET /chat?session=alice sets production cookie for alice; legacy 2-part cookies accepted. | **Caller-selected URL sessions rejected; server mints cryptographically signed random eiger-{hex} IDs.** | `halcyon/web.py` | Server-Minted Sessions | **VAPT-021, High** |
| **Cookie Security** | Cookies lack Secure, HttpOnly, and SameSite attributes; infinite session lifetime. | **Hardened profile enforces Secure, HttpOnly, SameSite=Strict, and 24h Max-Age (86400).** | `halcyon/web.py` | Hardened Cookie Policy | **VAPT-035, Medium** |
| **CSRF Protections** | Sensitive POST endpoints (/api/profile, /api/kb) lack origin validation and CSRF tokens. | **Enforces strict Origin/Referer matching against host and session-bound CSRF token validation.** | `halcyon/web.py` | Origin & CSRF Token Validation | **VAPT-010, High** |
| **Route Authorization** | Routes default to require_ownership=False; anonymous profile and KB modification. | **OWASP Deny-by-Default: require_ownership=True enforced across all protected stateful routes.** | `halcyon/web.py` | OWASP Deny-by-Default | **VAPT-012, High** |
| **Scoreboard Privacy** | Public /board and scoreboard leak raw learner session IDs and balances. | **All participant IDs anonymized to Participant-XXXXXX hashes; raw identifiers strictly omitted.** | `halcyon/web.py` | Identifier Pseudonymization | **VAPT-023, 040, Med** |
| **Lab Endpoint Lockout** | Production deployments expose /reset/*, /validate/*, and /source endpoints. | **Production profile hardens and disables all lab/reset routes with HTTP 403 Forbidden.** | `halcyon/web.py, config.py` | Environment Gating | **VAPT-015, 021, High** |
| **Money Creation** | transfer_funds(from_account=None) creates synthetic credits without debiting a source. | **Strict conservation of money supply: requires caller-owned source account with verified balance.** | `halcyon/bank.py, tools.py` | Double-Entry Balance Conservation | **VAPT-038, Critical** |
| **Merchant Theft** | tools.py exempted acct-merchant from ownership, permitting unauthorized 250-unit debits. | **Removed merchant fallback and exemption; caller must own source account via bank.owns().** | `halcyon/tools.py` | Principal Account Binding | **Critical Probe** |
| **Refund Ledger Bypass** | dispute_pipeline and tools call bank.credit() directly, minting refunds without records. | **Unified refund ledger routing: requires original transaction ID, validates limit, derives destination.** | `halcyon/bank.py, dispute.py` | Atomic Refund Invariant | **VAPT-017, Critical** |
| **Numeric Validation** | Accepts booleans (True coerced to 1 unit), negative numbers, and floating-point amounts. | **Strict schema validation: type(amount) is int and amount > 0; booleans & floats rejected.** | `halcyon/bank.py, policy.py` | Strict Type & Value Guard | **VAPT-036, Critical** |
| **Financial Persistence** | Process-local in-memory dictionary; balances vanish on restart; no row concurrency. | **Production PostgreSQL ACID transactions with row-level locks (SELECT FOR UPDATE) and rollback.** | `halcyon/security/ledger.py` | Transactional Storage Engine | **VAPT-037, Critical** |
| **Treasury Release** | Transfers execute repeatedly on duplicate scenario review (45,000 -> 90,000). | **Server-controlled payment ID bound to bank idempotency key; replay returns cached result.** | `halcyon/treasury_agent.py` | Idempotency State Binding | **VAPT-024, High** |
| **Model Control Plane** | Unauthenticated loopback Ollama (:11434); exposes /api/create, /api/delete, /api/pull. | **Bearer-authenticated Ollama Gateway; whitelists inference paths and rejects control routes.** | `halcyon/ollama_gateway.py` | Model Gateway Firewall | **VAPT-002, Critical** |
| **Model Tampering** | Local process can overwrite approved model with rogue prompt-injection template. | **Per-request SHA-256 digest validation against reviewed config/models.json manifest.** | `halcyon/ollama_gateway.py` | Model Digest Verification | **VAPT-002, High** |
| **Provider SSRF** | Model config accepts arbitrary endpoints; SSRF to cloud metadata (169.254.169.254). | **Strict IP parser blocks link-local metadata (RFC 3927) and private subnets (RFC 1918).** | `halcyon/llm.py, config.py` | SSRF IP Boundary Validation | **VAPT-003, Critical** |
| **MCP Authentication** | Ports 9001/9002 expose unauthenticated SSE; startup fails open on empty token. | **Mandatory Bearer token authentication; startup fails closed immediately if token is empty.** | `halcyon/mcp_deploy.py` | Fail-Closed Daemon Auth | **VAPT-007, High** |
| **MCP Service Isolation** | Banking MCP daemon accepted CRM service token; cross-service tool invocation. | **Distinct token secrets per MCP daemon; Banking daemon strictly rejects CRM tokens.** | `halcyon/mcp_deploy.py, vault.py` | Service Token Scoping | **VAPT-008, Critical** |
| **MCP User Delegation** | Tools executed without user identity; service credential allowed cross-user theft. | **Dual authentication: service bearer token plus signed user delegation envelope bound to body.** | `halcyon/security/transport.py` | Dual Auth & Delegation | **OWASP Auth, High** |
| **MCP Security Gateway** | No gateway between agent and tools; raw arguments dispatch directly to tools. | **Lasso-style MCP Gateway: validates types, blocks SQL/scripts, and applies egress DLP.** | `halcyon/security/mcp_gateway.py` | Lasso MCP Gateway Layer | **Agent Defense** |
| **Data Loss Prevention** | Tool outputs expose credit card numbers, SSNs, and internal API tokens to LLM context. | **Egress DLP sanitizer masks payment cards, SSNs, and tokens while preserving account IDs.** | `halcyon/security/mcp_gateway.py` | Context DLP Masking | **OWASP LLM06, Med** |
| **Vector DB Dependency** | ChromaDB embedded dependency introduced heavy footprint and known CVE exposures. | **Complete removal of ChromaDB; replaced with persistent SQLite KB with access filtering.** | `halcyon/sqlite_kb.py` | Dependency Surface Reduction | **VAPT-003, Med** |
| **Vulnerable Packages** | aiohttp 3.14.1 and PyJWT 2.13.0 with known public vulnerability advisories. | **Upgraded to aiohttp 3.14.5 and PyJWT 2.15.1; pip-audit confirms zero known vulnerabilities.** | `pyproject.toml, uv.lock` | Automated Package Patching | **VAPT-018, 029, 034** |
| **Pickle Deserialization** | M4 bundle distributed executable pickle (community_model.pkl) triggering RCE. | **Removed executable pickle; replaced with quarantine record; disabled pickle deserialization.** | `halcyon/artifacts.py` | Pickle RCE Elimination | **VAPT-001, Critical** |
| **AI Safety Guardrails** | No runtime guardrails; model vulnerable to direct prompt injection and jailbreaks. | **NVIDIA NeMo Guardrails (Colang dialog rails) and Meta Llama Guard 3-1B classifier.** | `halcyon/security/runtime.py` | NeMo & Llama Guard Rails | **Runtime Defense** |
| **Classifier Taxonomy** | Proposed classifier conflated injection with elections; returned safe on failure. | **Official 13-category taxonomy (S13=Elections); explicit UNAVAILABLE fail-closed contract.** | `halcyon/security/contracts.py` | Standard 13-Cat Taxonomy | **Classifier Standard** |
| **SIEM Observability** | Ephemeral console logging; unformatted and unmonitored security decisions. | **Wazuh SIEM structured JSON audit logger with keyed pseudonyms and bounded rotation.** | `halcyon/security/wazuh_logger.py` | Structured SIEM Integration | **Observability** |
| **Supply-Chain Scans** | Static source-text regex searching without empirical runtime validation. | **Evidence-based MCP scanner with isolated probes (Grade A+) and CycloneDX 1.6 AI BOM.** | `scripts/security/mcp_scanner.py` | Evidence-Based Scanning | **Supply Chain** |
| **Container Hardening** | Root execution, writable container filesystems, exposed daemon ports. | **Non-root user, read-only root filesystems, dropped capabilities, isolated bridge networks.** | `docker-compose.blue-team.yml` | Least-Privilege Containers | **Container Security** |

## 3. Detailed Technical Delineation by Security Domain

### 3.1 Web Identity, Authentication & Session Architecture
- **OIDC Cryptographic Verification:** Benchmark evaluated `verified or token`, accepting unverified tokens. Hardened platform strictly validates JWKS signatures.
- **Elimination of Session Fixation:** Benchmark `/chat?session=alice` issued cookies for attacker-chosen identities. Hardened platform mints random server-generated `eiger-{hex}` IDs.
- **Cookie Hardening Attributes:** Enforced `Secure`, `HttpOnly`, `SameSite=Strict`, and `Max-Age=86400` (24h expiry).
- **CSRF & Origin Enforcement:** Enforces strict Origin/Referer matching against host and session-bound CSRF tokens on stateful mutations.
- **OWASP Deny-by-Default:** Protected routes default to `require_ownership=True`, blocking anonymous access.

### 3.2 Financial Integrity, Ledgers & Transactional Persistence
- **Conservation of Money Supply:** Transfers require caller-owned source accounts with verified available balance; credits out of thin air are blocked.
- **Elimination of Merchant Fallbacks:** Removed `acct-merchant` ownership exemptions and automatic source fallbacks in `tools.py`.
- **Strict Refund Derivation & Limits:** Refunds require original transaction ID, derive destination from purchase, and enforce cumulative caps.
- **Strict Numeric Type Safety:** Explicitly rejects Python booleans (`True`/`False`), floats, and negative values before execution.
- **PostgreSQL ACID Ledger:** Replaced in-memory dictionaries with PostgreSQL transactions and `SELECT ... FOR UPDATE` row locks.
- **Treasury Idempotency:** Server-controlled payment IDs prevent duplicate scenario disbursements.

### 3.3 Model Control Plane, Gateway & SSRF Protections
- **Ollama Bearer Gateway:** Bearer-authenticated gateway (`halcyon/ollama_gateway.py`) whitelists inference paths and rejects management routes (`create`, `delete`, `pull`).
- **Per-Request Digest Verification:** Compares model digests against `config/models.json` before forwarding inference.
- **Cloud Metadata SSRF Blocking:** Rejects loopback, link-local metadata (`169.254.169.254`), and RFC 1918 private subnets.
- **Read-Only Model Storage:** Pinned read-only model volumes in Docker Compose unexposed to the host.

### 3.4 MCP Tool Execution, Gateway & Data Minimization
- **Dual Transport Authentication:** Service bearer token plus signed user delegation envelope bound to request body.
- **Token Isolation:** Banking daemon strictly rejects CRM service credentials.
- **Account-Level Tool Authorization:** Tool handlers verify `bank.owns(caller, account)` for reads and mutations.
- **Lasso-Style MCP Gateway:** Ingress parameter schema enforcement and egress DLP masking credit cards, SSNs, and tokens.

### 3.5 Knowledge Base Architecture & Dependency Reduction
- **Complete ChromaDB Removal:** ChromaDB eliminated from codebase, dependencies, and Compose services.
- **Persistent SQLite Lexical Retrieval:** Replaced with `halcyon/sqlite_kb.py` featuring pre-clearance tenant filtering.
- **Dependency Upgrades:** `aiohttp` upgraded to 3.14.5 and `PyJWT` to 2.15.1; zero vulnerabilities in `pip-audit`.
- **Context Delimiter Isolation:** XML boundary tags and regex neutralization prevent prompt injection breakouts.

### 3.6 Supply Chain, Serialization & Artifact Safety
- **Pickle Deserialization Elimination:** Application pickle loading disabled; executable pickles replaced with quarantine records.
- **Safe Bytecode Inspection:** Non-executing `pickletools.genops` inspection in `halcyon/scan_artifact.py`.
- **CycloneDX 1.6 AI BOM:** Validated `ai-bom.json` separating models, components, and services.

### 3.7 Layered AI Guardrails & Probabilistic Safety
- **NVIDIA NeMo Guardrails:** Colang dialog rules intercepting jailbreaks and unauthorized financial commitments.
- **Meta Llama Guard 3-1B Classifier:** Official 13-category taxonomy (`S13 = Elections`) and distinct Eiger policy codes.
- **Fail-Closed Contracts:** Timeouts, errors, and malformed outputs yield `UNAVAILABLE`, never false `safe`.
- **Phased Rollout:** `observe_only` telemetry mode maintains deterministic authority.

### 3.8 Enterprise Observability & Wazuh SIEM Integration
- **Wazuh Structured JSON Logging:** Standardized security events with keyed actor pseudonyms (`actor-{sha256}`).
- **Bounded Spooling & Rotation:** 10 MB segment rotation (`.json.1`) prevents disk exhaustion.
- **Custom XML Rules & Decoders:** Alert levels 6 to 14 mapped in `wazuh/decoders/` and `wazuh/rules/`.

### 3.9 Production Containerization & Deployment Hardening
- **Unprivileged Execution:** Non-root application user, read-only root filesystems, dropped Linux capabilities.
- **Internal Network Isolation:** Private bridge networks for backend services without exposed host ports.
- **Environment Secrets:** Mandatory environment variable configuration without hardcoded fallbacks.

## 4. Empirical Verification & Test Suite Metrics

- **Latest Full Regression:** **448 passed**, 8 skipped, 12 deselected with zero failures in 45.55s.
- **Negative Security Suite:** 35 dedicated test invariants passing 100%.
- **Ollama Gateway Suite:** 4 focused gateway tests passing.
- **MCP Posture Scanner:** Grade **A+** (100/100, 4/4 empirical probes passed).
- **Local Environment Audit:** Zero vulnerabilities detected via `pip-audit --local`.
