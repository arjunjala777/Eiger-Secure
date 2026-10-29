# Blue-team implementation correction and validation

Date: 2026-10-26. Scope: `eiger repo 2`, branch `security-hardening`, reviewed against starting commit `74eb102`. Changes are local and uncommitted. The benchmark repository was not modified. This record supersedes claims that merely creating security classes or passing mocked tests proves production integration.

> **Implementation follow-up:** the runtime and deployment statements below describe the earlier validation snapshot. The 2026-10-26 follow-up at the end of this document records the current code, tests, and active-service restart; where the two differ, the follow-up is authoritative.

## Corrected execution boundaries

- Direct MCP HTTP services require both their scoped bearer credential and a short-lived, body-bound delegation signature containing the authenticated principal. A separate production delegation secret prevents possession of a service token alone from granting user authority. Unsigned calls, body identity claims, cross-user operations and replayed envelopes are denied. The host and service both validate the authoritative tool registry.
- Secure native tools and MCP services use the same deterministic executor. Unexpected properties (including underscore-prefixed properties), boolean/invalid amounts and unauthorized accounts are rejected. Financial calls require scoped idempotency keys. Refunds require the original transaction, derive its destination and enforce cumulative limits. Secure tool discovery excludes credential-returning tools.
- Production uses PostgreSQL, not process-local bank state. A locked namespace row serializes financial changes and stores idempotency records across workers/restarts. The same database transaction commits a ledger revision and audit digest; audit failure rolls back the payment. This correctness-first adapter is not a high-throughput accounting system. Production startup and treasury reads do not mint demonstration balances.
- Verified web identity is bound to a request context, propagated to tools and correlated audit events. Input/output assessments now execute on model-facing web routes. NeMo uses actual installed Colang action rails. Llama Guard uses Ollama's native chat template and the native 13-category taxonomy. Mixed/malformed verdicts are unavailable, never safe.
- Response projection and DLP run on actual execution paths. These minimize model-visible fields; pattern matching is not a complete PII or prompt-injection detector. Classifiers never grant financial authority.
- Audit export uses sanitized JSON Lines, keyed pseudonyms, request correlation, bounded segments and a durable SQLite retry queue. Cross-process exporters serialize via SQLite. Delivery to the local file is at least once; duplicates can occur after a crash. Manager receipt/indexing is a separate operational check. Queue exhaustion fails closed. The PostgreSQL financial audit is independent of SIEM delivery.
- Unknown/unapproved artifacts fail admission; scanner failures return nonzero. Pickle inspection never executes artifacts. The AI BOM is checked against the complete vendored CycloneDX 1.6 schema, including references. Configured model names are distinguished from verified artifact digests. No static scan certifies a model's behavior or arbitrary serialized content as universally safe.
- The current Compose profiles use an internal, inference-only Ollama gateway and a persistent SQLite KB; the Chroma dependency and HTTP service have been removed. MCP tokens and delegation keys are distinct per service. Wazuh enrollment remains a separate optional overlay requiring manager CA and enrollment-password files. Rules belong on the manager, not the agent.

## Evidence obtained

| Check | Result | Meaning and limits |
|---|---|---|
| Prior default suite | **417 passed, 9 skipped, 18 deselected**, 25.09 seconds | Historical result for the earlier code snapshot; see the follow-up for current results. |
| Explicit localhost SDK HTTP tests | **3 passed** | One secure transport/payment test plus two explicitly vulnerable teaching demonstrations. Secure production defaults are not weakened to preserve those demonstrations. |
| Live PostgreSQL | **5 passed** | Three ledger tests (adapter recreation, concurrent idempotency, audit rollback) and two existing store tests, using a disposable database. |
| Focused integration additions | **16 passed**, also included above | Direct HTTP auth, payload spoofing, strict schemas, refund, malformed verdicts, real web guard invocation, scanner exit codes, log retry/redaction and schema rejection. |
| Real local Llama Guard 3-1B samples | Benign request ALLOW; robbery request BLOCK/S2 | Two samples only. Cold latency 20.63 seconds; warm latency 0.87 seconds. No broad accuracy or sub-second cold-start claim. |
| Wazuh 4.14.9 manager rule engine | Synthetic unauthorized-financial event matched rule 100401, level 14 | Actual decoder/rule validation. External agent enrollment, indexing, dashboards and alert delivery were not verified. |
| Ruff | Passed for security modules, scripts and new integration tests | No claim that the entire pre-existing repository is lint-clean. |
| Compose configuration | Base plus Wazuh overlay validated with placeholder inputs | Syntax/interpolation only, not service readiness. |
| Prior Docker image | **Built and smoke-tested before the follow-up** | That image included the old Chroma-based KB and is not evidence for the current SQLite/gateway image. |
| Prior production image | **Passed for the earlier snapshot** | Must not be used as verification of the current OIDC, per-service MCP delegation, SQLite KB, and inference gateway changes. |
| Current full deployment | **See follow-up status** | Full production-model/SIEM workload testing remains separate from unit and local service probes. |

Three default-suite deprecation warnings remain (Starlette/httpx and NeMo configuration). Skips include opt-in HTTP and PostgreSQL tests; the explicitly run tests above provide separate evidence. Calibration tests remain deselected. Reproduce the default suite with `.venv\Scripts\python.exe -B -m pytest -q`; set `RUN_SECURITY_HTTP_TESTS=1` for the new live HTTP test. Live ledger tests use `SECURITY_TEST_DATABASE_URL`; existing store tests use `TEST_DATABASE_URL`. Use an isolated test database: the fixtures create/reset their own data.

## Runtime policy and rollout

`EIGER_GUARD_MODE=observe` runs and logs assessments without enforcing classifier decisions. It does not mean the detector is enforcing. Deterministic authorization remains mandatory. In `enforce`, blocked assessments return 403 and unavailable/review assessments return 503. Production requires `enforce` and rejects both `observe` and `off`; the Secure Lab launch uses `observe` while deterministic authorization remains active.

The default inference deadline is three seconds; cold starts can exceed it. Warm approved models, measure p50/p95 latency and capacity under realistic traffic, evaluate benign banking requests and adversarial requests, then choose the deadline and enforcement policy. A readiness check verifies expected model digests and NeMo initialization; it does not establish model accuracy or guarantee a warm model under memory pressure. Do not silently convert outages into ALLOW. Evaluate input and output false positives before turning on classifier enforcement.

## Deployment procedure still requiring validation

1. Set independent random session, OIDC, MCP service, per-service delegation, inference-gateway, and URL-safe PostgreSQL credentials outside Git. Production requires OIDC issuer/audience/JWKS configuration, HTTPS browser origins, and `EIGER_GUARD_MODE=enforce`. Configure real account ownership and authorized opening ledger state through a controlled administrative process; demo accounts are not created automatically.
2. The previous image/database smoke checks do not validate the current image. Rebuild after the SQLite KB and inference-gateway migration; verify the complete Compose topology and signed MCP requests. Backend/model ports remain unpublished in the production Compose profile.
3. Provision reviewed model artifacts to the Ollama service through an operator-only maintenance path. Runtime application traffic goes through the inference-only gateway; it cannot create, delete, pull, or push models. The provisioner uses `OLLAMA_MANAGEMENT_URL` for local operator access and records digests without asserting model provenance.
4. Review and retain `/app/config/models.json` with release evidence. Start the application and check `/ready`; missing or mismatched model digests fail readiness. Configure traffic routing to honor readiness.
5. For SIEM, set `WAZUH_MANAGER`, `WAZUH_MANAGER_CA_FILE` and `WAZUH_ENROLLMENT_PASSWORD_FILE`; use both Compose files. Configure manager-side password-protected enrollment and a certificate matching the manager identity. Install `wazuh/rules/eiger_rules.xml` on the existing manager and validate with `wazuh-logtest`. The agent consumes JSON using Wazuh's built-in decoder. Enroll it, inject a synthetic event and verify delivery, correlation and alerting at the manager. See [manager identity verification](https://documentation.wazuh.com/current/user-manual/agent/agent-enrollment/security-options/manager-identity-verification.html) and [password enrollment](https://documentation.wazuh.com/current/user-manual/agent/agent-enrollment/security-options/using-password-authentication.html).
6. Configure durable log storage, restricted file permissions, collector retention/acknowledgement and an alert for export backlog. Do not delete rotated segments before collection is confirmed. Exercise disk-full, model outage, PostgreSQL outage and restart scenarios. Back up/restore the ledger and test restore integrity. Do not use Redis locks as a substitute for database transaction guarantees.

A full container rollout, external SIEM receipt and workload-specific model evaluation are outstanding release gates, not application unit-test failures. No claim of complete prompt-injection prevention, regulatory compliance or production readiness is made.

## Docker recovery and cleanup

Docker Desktop logs identified a containerd SIGBUS crash, with the Docker WSL distribution stopped. A normal Desktop restart timed out; terminating the stuck Desktop processes and relaunching recovered Docker 29.6.1. C: had roughly 2.5 GB free, so storage remains constrained; disk pressure was observed, but not proven to be the crash cause.

The failed review build's specific 1.093 GB cache record and the disposable Wazuh manager test image were removed. Other repositories, images and containers were preserved. The Dockerfile now disables uv's retained download cache and installs dependencies separately from application source. The successful image is `eiger-repo2-security-test:74eb102`, image manifest digest `sha256:30b8f47525ae6fa38a31107223ef8ebd70940158eda4bf0b70141b6b99fca936` (the tag names the starting review commit, not a new committed release).

Both original disposable test containers were confirmed absent after recovery. The subsequent isolated image/PostgreSQL smoke network and containers were removed in a label-checked cleanup. No review test containers remain. Changes remain local and uncommitted on `security-hardening` in repo 2.

## Implementation follow-up — 2026-10-26

This section supersedes the Chroma deployment and older runtime statements above.

- **Vector store/dependency:** removed `chromadb` and its HTTP service from the application and both Compose profiles. Runtime RAG now uses persistent SQLite collections with access/owner filters applied before ranking. The current runtime and AI BOM do not contain ChromaDB; the SQLite retrieval behavior is lexical rather than embedding-based. This removes the vulnerable Chroma endpoint and package from the shipped runtime instead of labeling an affected package “not affected.”
- **Python advisories:** upgraded `aiohttp` to 3.14.5 and PyJWT to 2.15.1. A fresh `pip-audit --local` of the installed blue-team environment reported no known vulnerabilities.
- **Ollama:** application and classifier traffic now uses a bearer-authenticated inference gateway. It permits approved inference/readiness operations, filters model inventory, and rejects management paths such as create/delete/pull/push. Docker networking keeps Ollama on a private model network. In the local Secure Lab, the existing Ollama daemon remains bound to loopback for operator maintenance; it is not remotely exposed, and its installed models were not altered.
- **MCP:** Secure/production startup rejects development defaults. Banking and CRM use separate service tokens and separate delegation keys; HTTP requests require a short-lived, signed, audience-bound delegation. The local services were restarted from the current repository source.
- **Identity and route privacy:** production bearer authentication validates OIDC JWT signature, issuer, audience, expiry, and subject against the configured JWKS. Session cookies are versioned/signed, expire after 24 hours, and use Secure/HttpOnly/SameSite=Strict in secure/production modes. Cookie mutations require a session-bound CSRF token and allowed Origin. Secure Lab board routes return only the caller's progress; production lab routes are disabled. The armed M4 bundle is unavailable in secure/production mode.
- **Other corrections:** removed the internal archive hostname from the served template; added per-session ingestion quotas/rate limits; the Docker image has a liveness healthcheck. The executable M4 pickle and builder were removed, the loader rejects pickle in every profile, and the lab bundle now carries only a static quarantine record. VAPT-033 remains tracked as dead-code cleanup, not as an independently exploitable vulnerability.
- **Current regression suite:** `uv run --extra blue-team pytest` — **446 passed, 8 skipped, 12 deselected** (31.30 seconds). The opt-in signed MCP HTTP integration test also passed separately (**1 passed**). Skips/deselections are recorded rather than counted as passing tests.
- **Current local live stack:** the older `run_eiger.py` and MCP processes were stopped and replaced from repo 2. `/health` reports secure mode with Ollama gateway, database, and MCP up. Live probes confirmed: unauthenticated session changes return 401; board access without a session returns 401; secure M4 bundle returns 404; default-token-only MCP calls return 401; unauthenticated Ollama gateway calls return 401; management routes return 404; hostile CORS origins return 403. The launcher's signed-cookie/CSRF, ingestion-size, model-policy, and cleanup probes passed before it remained running.

The full production Docker rollout, a real external OIDC provider, production TLS ingress, external SIEM delivery, and live-model quality evaluation remain deployment gates. These results do not establish that the application is “completely secure.”


## Final startup correction and handoff

- Each MCP ASGI entry point now initializes only its own service. Separate Core and CRM processes start with only their own token and delegation key; two subprocess regression tests verify this isolation and unauthenticated rejection.
- Compose healthchecks target the correct Core (9001), CRM (9002), and inference gateway (11435) ports. Gateway health reports credential configuration, not upstream model readiness. Removed the obsolete Chroma cache directory from the Dockerfile.
- Final regression: 446 passed, 8 skipped, 12 deselected, 3 deprecation warnings. The opt-in signed MCP HTTP integration test separately passed (1 test).
- The current local launcher completed successfully and all built-in live security probes passed. Services run at http://localhost:8000 with ephemeral credentials; no benchmark repository changes were made.
- Current Docker image rebuild and full production topology validation remain outstanding. Earlier image results are historical, not validation of this source snapshot.
- The raw local Ollama maintenance listener on loopback port 11434 remains accessible to local processes without gateway authentication. The inference gateway does not eliminate that host-local trust boundary; production requires the documented network isolation.
- Changes remain uncommitted in repo 2. External OIDC, TLS ingress, SIEM receipt, and representative live-model evaluation remain release gates.


## Ollama integrity follow-up

Gateway POST operations now require a reviewed SHA-256 manifest and compare the selected model against the upstream inventory before forwarding inference. Missing pins, mismatches, and unavailable inventory fail closed. Four gateway tests passed, including replacement of an approved tag. Request bodies are bounded while receiving them.

Production Compose mounts both the gateway manifest and Ollama model storage read-only; Ollama remains on the private models network without a published port. Provisioning must occur in a separate operator-controlled maintenance environment before starting this topology. Runtime downloads and model updates are intentionally unavailable. These new container settings have not been deployed or runtime-validated.

The local launcher now requires EIGER_MODEL_MANIFEST (default config/models.json). Recording the current inventory does not establish trustworthy provenance: review digests against independently trusted model artifacts before accepting them. No manifest was automatically approved, and existing running services were not restarted with this change.

This does not close the shared host Ollama listener. A process with access to port 11434 can still modify that daemon, and an inventory check followed by inference has a race if another process can mutate models between requests. Read-only model storage and network isolation are required together. Host administrators or Docker administrators remain trusted. Production closure requires deploying the isolated topology and demonstrating denied direct access and failed model mutation there.
