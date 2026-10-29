# Eiger Security Mitigation Report

**Report date:** 27 October 2026  
**Scope:** `C:\Users\Arjun Jala\eiger repo 2`  
**Branch:** `security-hardening`  
**Current committed HEAD:** `74eb102`  
**Delivery state:** Working-tree changes remain uncommitted. HEAD alone does not contain the mitigations described below.

## 1. Executive assessment

The remediation work strengthened application authorization, financial execution, MCP transport, model access, session handling, dependency management, artifact handling, and security telemetry. The benchmark repository, `C:\Users\Arjun Jala\eiger`, was not modified by this work.

The latest full regression run recorded **446 passed, 8 skipped, and 12 deselected**. A separate signed MCP HTTP integration test passed. Following that full run, additional Ollama integrity protections were implemented and verified with **four focused gateway tests**; the full suite was not rerun after those final changes.

This report distinguishes source changes from deployed controls. In particular, the final digest enforcement and read-only model deployment changes are **not deployed**. The shared local Ollama management listener remains a residual exposure. No claim of complete vulnerability closure or production readiness is made.

## 2. Status of the six recently raised findings

| Finding | Mitigation implemented | Evidence and remaining boundary |
|---|---|---|
| VAPT-002: unauthenticated Ollama control plane | Added bearer-authenticated inference gateway, exact model/path allowlists, management-route rejection, and per-request model digest verification against a reviewed manifest. Production configuration isolates Ollama and makes its model storage read-only. | Gateway authentication and management-route rejection passed local probes. Four focused tests cover gateway behavior and digest replacement. Final digest/storage changes are not deployed. Direct local access to port 11434 remains possible. **Partial closure.** |
| VAPT-003: ChromaDB dependency exposure | Removed ChromaDB from the application dependency set, runtime implementation, and Compose services. Replaced retrieval with persistent SQLite collections and access filtering before ranking. | Recorded environment and generated AI BOM excluded ChromaDB. Old images/environments must be replaced separately. Retrieval is now lexical rather than embedding-based. |
| VAPT-018: High dependency advisories | Updated the dependency set and lockfile, including aiohttp 3.14.5 and PyJWT 2.15.1; removed ChromaDB and reduced its transitive dependency footprint. | Recorded installed-environment `pip-audit --local` reported no known vulnerabilities. This is not a finding-by-finding validation of all original Trivy advisories or an audit of the final container image. |
| VAPT-029: Medium dependency advisories | Same dependency refresh and runtime reduction; regenerated the production-environment AI BOM. | Exact closure of the historical advisory list requires matching the original scanner evidence against the final deployed packages and image. |
| VAPT-034: aiohttp advisories | Updated aiohttp from the reported 3.14.1 version to 3.14.5. | Updated version and clean recorded environment audit provide remediation evidence. This report does not independently validate the supplied CVE identifiers or affected-version ranges. |
| VAPT-035: session cookie missing Secure | Secure-profile cookies now use `Secure`, `HttpOnly`, `SameSite=Strict`, and a 24-hour lifetime. Added session-bound CSRF checks and origin restrictions. | Live response showed `Max-Age=86400` and the stated flags. Production HTTPS ingress remains a deployment requirement. No claim is made here that a `__Host-` cookie prefix or privilege-change rotation was added. |

## 3. Implemented mitigations

### 3.1 Ollama gateway and model integrity

**Files:** `halcyon/ollama_gateway.py`, `scripts/security/run_local_secure.ps1`, `docker-compose.blue-team.yml`, `tests/test_ollama_gateway.py`.

- Gateway access requires a bearer credential; credentials shorter than the configured minimum are rejected.
- Only explicitly permitted inference and inventory operations are forwarded. Model create, delete, pull, push, and copy operations are not exposed through the gateway.
- Requests must select an allowlisted model. Inventory responses exclude other model names.
- Before forwarding a POST operation, the gateway loads the selected model's approved SHA-256 digest and compares it with the upstream inventory. Missing or malformed pins, missing models, and mismatches block forwarding; upstream failures do not become an approval.
- Request size is bounded while receiving the body.
- The local launcher requires a manifest, defaulting to `config/models.json`. It does not automatically approve the current model inventory.
- Production Compose mounts the gateway manifest and Ollama model volume read-only, leaves the raw model service without a published port, and connects it only to the private model network. Runtime model updates require a separate maintenance procedure.

**Residual limitation:** The existing Windows Ollama daemon still accepts direct local management traffic on port 11434. A gateway cannot protect requests that bypass it. Checking inventory before inference also leaves a check/use race if another process can mutate the model concurrently. Network isolation and immutable runtime storage are necessary together. Host and Docker administrators remain trusted. Existing model artifacts were not deleted or independently approved during this work.

### 3.2 MCP authentication and execution authorization

**Files:** `halcyon/mcp_deploy.py`, `halcyon/mcp_host.py`, `halcyon/security/transport.py`, `halcyon/security/context.py`, `halcyon/security/executor.py`, and MCP server modules.

- MCP HTTP calls require the service credential and a short-lived, signed user delegation bound to the request body and target audience.
- Core Banking and CRM use distinct service tokens and delegation keys. Secure/production startup rejects development defaults and inadequate credentials.
- Verified transport identity populates the security context; model-generated or payload-supplied identity does not grant authority.
- Tool execution validates the authoritative schema, account ownership, allowed parameters, and financial amount types. Credential-returning tools are excluded from secure discovery.
- Response projection and DLP reduce model-visible output to authorized fields.
- Fixed service startup so each ASGI entry point initializes only its own service, allowing separate containers to receive only their respective credentials.

**Evidence:** Separate-service subprocess tests, the signed MCP HTTP integration test, and live rejection of unauthenticated/default-token-only requests passed. Pattern-based DLP is not a guarantee of detecting every secret or indirect prompt injection.

### 3.3 Financial integrity and persistence

**Files:** `halcyon/bank.py`, `halcyon/security/ledger.py`, `halcyon/security/executor.py`, `halcyon/tools.py`, `halcyon/dispute_pipeline.py`, `halcyon/treasury_agent.py`.

- Secure native and MCP tool execution share deterministic authorization checks.
- Financial operations reject invalid amount types and unauthorized account access; idempotency is scoped to the authenticated operation.
- Refund execution uses the original transaction, derives the destination, and enforces cumulative limits.
- Treasury releases remain subject to deterministic beneficiary and amount policy; model proposals do not authorize payments.
- Production uses a PostgreSQL ledger with transactional financial state, persistent idempotency, and audit records. Audit failure rolls back the payment.
- Production startup and treasury reads do not create demonstration balances.

**Evidence boundary:** Earlier live PostgreSQL tests exercised persistence, concurrent idempotency, and rollback. Those results are recorded separately from the final default suite and do not establish a fully deployed production stack or high-throughput capacity.

### 3.4 Web identity, sessions, and route privacy

**Files:** `halcyon/web.py`, `halcyon/config.py`, `run_eiger.py`, `halcyon/main.py`.

- Production bearer identity validates OIDC signature, issuer, audience, expiry, and subject using configured JWKS.
- Signed session cookies expire after 24 hours and use Secure/HttpOnly/Strict attributes in hardened profiles.
- Cookie-authenticated mutations require a session-bound CSRF token and origin validation.
- Protected stateful routes enforce authenticated ownership; session identities supplied through URL parameters are rejected on protected paths.
- Secure Lab boards expose caller-scoped progress; production disables lab routes. Secure/production M4 bundle access returns 404.
- Ingestion size, per-session quotas, and rate limits constrain abuse.
- Secure/production configuration prevents environment overrides from disabling platform security flags.

**Evidence boundary:** Local probes verified authorization failures, CSRF/origin rejection, cookie flags, ingestion bounds, and restricted routes. A real external OIDC provider and production TLS ingress have not been validated end to end.

### 3.5 Knowledge retrieval and dependency reduction

**Files:** `halcyon/sqlite_kb.py`, `halcyon/config.py`, application startup modules, `pyproject.toml`, `uv.lock`, `ai-bom.json`.

ChromaDB was removed and persistent SQLite retrieval introduced. Access and ownership filtering occurs before ranking, reducing cross-session retrieval and candidate-displacement exposure. This changes retrieval semantics to lexical matching; it is not a claim of equivalent semantic search quality. Dependency inventory was regenerated from a production-style environment.

### 3.6 Artifact safety

**Files:** `halcyon/artifacts.py`, `halcyon/scan_artifact.py`, `labs/m4/`, M4 tests and teaching documentation.

- Removed the executable teaching pickle and its builder from the current working tree.
- Retained a data-only quarantine record containing the historical digest and static findings.
- Removed application pickle deserialization; pickle formats are rejected in every profile. Secure artifact admission also requires approved safetensors hashes.
- Updated the lab bundle, teaching content, and tests to use the quarantine record. Production build context excludes lab artifacts.
- Static scanning does not deserialize inspected artifacts.

**Boundary:** Removing files from the working tree does not erase copies in Git history, old archives, or prior images. A static scan or matching digest does not certify arbitrary content as universally safe.

### 3.7 Guardrails, telemetry, and supply-chain assurance

**Files:** `halcyon/security/runtime.py`, classifier/NeMo modules, `halcyon/security/wazuh_logger.py`, `scripts/security/`, `schemas/`, `wazuh/`.

- Integrated input/output assessments into model-facing execution paths and actual NeMo Colang actions.
- Malformed or unavailable classifier results are represented as unavailable, not safe. Production requires enforcement mode; local Secure Lab uses observation mode while deterministic authorization remains active.
- Added sanitized, correlated audit events, keyed actor pseudonyms, bounded rotation, and a persistent SQLite retry queue. Queue exhaustion fails closed; file delivery is at least once and can duplicate after a crash.
- Corrected scanner admission/error behavior and validated the AI BOM against the vendored CycloneDX 1.6 schema.
- Provided Wazuh manager rules and an optional enrollment overlay with manager identity and enrollment-secret configuration.

**Boundary:** Prior Wazuh rule-engine testing does not prove external event delivery, indexing, or operational alerting. Two recorded live classifier samples do not establish general detection accuracy or latency under load.

### 3.8 Deployment and operational corrections

**Files:** `Dockerfile`, Compose files, `scripts/security/run_local_secure.ps1`, `scripts/security/live_secure_probe.py`.

- Hardened container configuration includes a non-root application user, read-only application filesystems, dropped capabilities, resource limits, and isolated service networks.
- Corrected MCP and gateway healthchecks to target their own ports. Gateway liveness indicates credential configuration, not model readiness.
- Local launcher generates ephemeral credentials, starts hidden service processes, waits for startup, and runs security probes. Failed startup triggers cleanup of its own processes.
- Removed obsolete Chroma cache setup from the image build and avoided retained dependency download cache.

**Deployment status:** The final Docker image has not been rebuilt and the latest production topology has not been runtime-tested. Earlier successful image tests apply only to their earlier source snapshots.

## 4. Verification record

| Check | Recorded result | Applicable scope |
|---|---|---|
| Latest full regression | 446 passed, 8 skipped, 12 deselected; 3 deprecation warnings; 31.30 seconds | Snapshot before the final Ollama digest/storage patch |
| Signed MCP HTTP integration | 1 passed; 2 deprecation warnings | After separate-service startup correction |
| Local Secure Lab startup probes | Passed | Authentication/CSRF, session URL rejection, ingestion cap, model policy, MCP authentication, gateway management restrictions; before final digest patch |
| Latest gateway-focused tests | 4 passed | Includes approved-tag digest replacement rejection and manifest handling |
| Latest gateway lint | Passed | Gateway source and gateway tests |
| Recorded installed-environment dependency audit | No known vulnerabilities found | Installed blue-team environment at scan time; not the final container image |
| Earlier PostgreSQL tests | 5 passed | Earlier adapter/store integration snapshot |
| Final production deployment | Not verified | New image, isolation, immutable model runtime, external OIDC/TLS/SIEM remain outstanding |

Skipped and deselected tests are not counted as passes. Focused gateway tests overlap with the suite and must not be added to the full-suite count as if they were an independent complete regression run. No new execution or dependency scan was performed solely to produce this report.

## 5. Remaining actions before production closure

1. Review model digests against independently trusted artifacts and provision the manifest. Do not automatically trust an inventory from a potentially modified daemon.
2. Build the current image and deploy the private model topology with immutable model storage. Verify that permitted inference still works and model mutation fails.
3. Retire or isolate the raw host listener used by repo 2 after checking dependencies on that shared daemon. Confirm untrusted callers cannot bypass the gateway.
4. Replay original attacks against the deployed configuration and rescan the final image. Reconcile each dependency advisory with package/version/reachability evidence.
5. Validate real OIDC authentication, HTTPS ingress, external SIEM receipt, outage handling, database restore, and representative model workloads.
6. Review and commit the repo 2 working-tree changes, retaining release-specific test and image evidence. Keep the benchmark repository unchanged.

## 6. Evidence source

This report consolidates the implementation and execution evidence in [blue-team-validation.md](blue-team-validation.md), the repository changes, and recorded tool outputs from the remediation session. It supersedes blanket statements that all vulnerabilities are closed; it does not replace a deployment-specific penetration test or certify regulatory compliance.
