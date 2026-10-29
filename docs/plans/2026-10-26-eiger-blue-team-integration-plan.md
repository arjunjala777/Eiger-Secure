# Eiger blue team security integration plan

## Purpose and decision

Build a self-hosted defensive stack that limits what an AI agent can access and execute, records its security decisions, and measures the effectiveness of probabilistic detection. Deterministic application and banking-service authorization remains the authority for every operation, even when a safety model returns safe or an observability service is unavailable.

All implementation belongs in `eiger repo 2` on `security-hardening`. Repo 1 is the read-only benchmark. This plan does not authorize deployment, model downloads, service installation, or changes to existing untracked implementation files.

The reviewed repository HEAD is `f453cab`. The blue-team modules, scanner scripts, Wazuh configuration, and Compose blueprint are currently untracked prototypes. Preserve them while implementing this plan in reviewable commits. Establish fresh test and bypass results at this HEAD; earlier results at `b4771bb` do not automatically apply.

## Corrections to the existing proposal

- Meta's Llama Guard 3-1B model card describes 13 categories. S13 is Elections, not prompt injection, and this model does not define the proposed S14 financial-fraud label. Keep native model labels unchanged and define separate Eiger policy codes for injection, unauthorized finance, cross-tenant access, and data disclosure. A content-safety verdict cannot authorize a financial transaction.
- The classifier prototype currently reports safe for HTTP errors, exceptions, and empty results. Introduce an explicit unavailable or invalid result; never translate missing evidence into safe.
- NeMo initialization and execution errors currently fall back to substring checks. Report the active engine and degraded state explicitly. Verify the pinned Colang configuration against NeMo 0.24.1 and use structured rail outcomes instead of searching generated text for refusal phrases.
- The MCP gateway prototype accepts floats for amounts and does not enforce a registry of per-tool schemas or trusted user identity. It must enforce exact integer minor units and operation-specific authorization. Keyword scanning cannot establish SQL or command safety.
- The Compose gateway command runs a Python module containing a class but no serving application. Start with an integrated gateway; add a separate service only after implementing and testing a real protocol endpoint and backend network isolation.
- Compose currently supplies predictable secret defaults, uses mutable images, names token variables differently from the existing application, and uses `OLLAMA_HOST` where the primary application reads `OLLAMA_URL`. Container service DNS names also need an explicit trusted endpoint policy compatible with SSRF restrictions.
- Wazuh custom rules and decoders run on the manager. The application-side collector needs enrollment, a localfile configuration, transport security, and log rotation handling. A JSON file and an agent container alone do not establish alert delivery.
- The scanner prototypes use source-string checks and unsupported-format fallbacks. They provide observations, not proof of authorization or artifact safety. The artifact scanner imports `inspect_pickle` from a module that does not define it.
- The BOM generator hardcodes inventory and an invalid UUID serial number and places service records among components. Generate inventory from installed and deployed artifacts and validate the complete output against the chosen CycloneDX schema.

## Architecture and trust boundaries

```text
Client
  -> TLS ingress, request limits, authentication and CSRF checks
  -> trusted request context and deterministic route policy
  -> content safety and injection assessment, subject to endpoint policy
  -> application LLM and tenant-filtered RAG
  -> mandatory tool execution gateway
  -> banking or CRM service authorization
  -> transactional business operation and audit outbox
  -> structured result projection and DLP
  -> final answer checks and client response

Security events -> bounded local spool / collector -> Wazuh manager
               -> manager rules -> alerts -> indexer and dashboard

CI admission checks -> pinned application, models, tools, policy and image inventory
```

RAG documents, tool descriptions, tool results, user messages, and model outputs are untrusted data. They cannot modify authenticated identity, grants, policy version, secret selection, or the approved tool registry. Classifier inputs and outputs remain untrusted too.

Use NeMo as the orchestration adapter for selected rails and Llama Guard as one content-safety detector. Avoid running two complete generation pipelines or duplicating identical classification calls. Keep the business executor independent of the orchestration framework.

## Phase 0 Establish the security baseline

1. Record HEAD, dirty/untracked files, dependency lock hashes, enabled profiles, tool inventory, and current test selections without modifying repo 1.
2. Replay the previous merchant-source, anonymous-dispute, MCP ownership, and duplicate-treasury probes against current HEAD. Include both in-process and HTTP paths.
3. Define assets, principals, cross-session boundaries, permitted side effects, and adversary-controlled inputs. Separate simulated lab exceptions from production requirements.
4. Write the mandatory invariants: every debit has an authorized funded source; every refund references a permitted original payment; each pending treasury payment executes once; cross-tenant reads and writes are denied; denial causes no business side effect.

Exit gate: reproducible baseline evidence and no unresolved violation of a mandatory invariant in the intended deployment profile. Adding AI detectors is not remediation for a failing invariant.

## Phase 1 Implement one deterministic execution contract

Proposed additions are `halcyon/security/context.py`, `contracts.py`, `policy.py`, and a shared executor used by native tools and MCP adapters.

- Create immutable trusted context containing principal, tenant, grants, request ID, authentication method and policy version. Populate it from validated transport credentials. Never trust a `_caller_session` field supplied in model arguments.
- Register each tool by service, name, approved schema digest, allowed operation and response projection. Reject unknown tools, unapproved schema changes, extra properties, missing fields, booleans as integers, fractional amounts and non-finite numbers. Bound nesting, strings, arrays and total request size.
- Bind all financial parameters, including currency, original payment and beneficiary, to a server-side operation record. Scope idempotency to principal and operation plus a canonical parameter digest. Reject changed parameters on replay.
- Recheck current authorization at execution. Add server-side approval bound to the complete operation for policy-defined sensitive actions. A model confirmation is not approval.
- Enforce the same checks inside banking and CRM services. Gateway compromise or direct backend access must not grant unrestricted data or money movement.
- Use durable transactions for production balances, refund limits, idempotency, payment completion and audit outbox records. Single-process fixtures may remain available under an explicitly limited lab profile. A distributed lock does not provide persistence for process-local dictionaries.
- Propagate deadlines and cancellation. After an uncertain network result, reconcile using the stable operation ID rather than submitting another payment under a new key.

Exit gate: hostile model and tool outputs cannot violate the invariants. Tests cover concurrent duplicates, different parameter reuse, stale approvals, backend restarts and ambiguous timeouts.

## Phase 2 Integrate a mandatory gateway and data minimization

Implement `mcp_gateway.py` initially as a library called by the common executor and MCP host. Cover special host handlers and native tool paths, not just the ordinary MCP dispatch branch.

- Inspect every tool call before dispatch. Apply the registered schema, trusted context, permission and budget policy. Enforce per-principal rate, tool-call count, execution time, response size and concurrency limits.
- Prefer parameterized database operations and fixed executable interfaces in the backend. Detecting strings such as SQL keywords or shell commands is supplementary.
- Return only authorized, task-relevant fields. Apply DLP to structured results before converting them to model-visible text. Use field rules plus targeted detectors; avoid treating every long account ID as a payment-card number.
- Never return service tokens, private signing keys or authentication session credentials as tool results. Log only redaction counts and detector IDs, not the original secret.
- Preserve MCP result types, error flags and structured payloads. Define behavior for multiple content blocks, nested JSON, resource links, unsupported content and streams. Inspect sensitive output before any chunk is emitted.
- Preserve provenance on external text. Quarantine suspicious content without silently transforming its meaning into approved policy.

Exit gate: every relevant dispatch path is covered; denied requests execute zero backend operations; sensitive fixtures do not appear in model-visible output or telemetry; legitimate authorized reads retain their required fields.

If later introducing a network gateway, implement the MCP transport explicitly, authenticate both hops, and permit backend ingress only from the gateway. Validate initialization, discovery, resources, prompts, tool calls, session handling, cancellation and streaming before replacing the library integration. Keep backend authorization in place.

## Phase 3 Add measured model-based guardrails

- Declare NeMo and inference dependencies in a reproducible dependency group or extra and commit the lockfile changes. Frozen container builds must install that declared group.
- Pin the exact classifier artifact, tokenizer/template, quantization and policy configuration. Use the serving artifact's documented formatting; do not mix instruction formats from different Llama generations.
- Use a strict result contract: `allow`, `block`, `review`, or `unavailable`, with detector ID, native categories, policy mapping, model digest, policy version and latency. Invalid output is unavailable. Do not fabricate confidence scores that the classifier does not produce.
- Evaluate direct injection separately from content safety. Include indirect injection in RAG, CRM records, tool descriptions and tool outputs. Treat detectors as evidence, not execution authority.
- Use a shared asynchronous inference client with deadlines, bounded queues, admission control and resource limits. Isolate or reserve guard inference capacity so a long application generation cannot starve the detector. Benchmark cold start, warm requests and saturation on the actual hardware before committing to a latency target.
- Wire NeMo at explicit input, retrieval, execution and output boundaries. Use checks or structured outcomes around the existing application generation path. Prevent hidden external model calls, embedding downloads and telemetry in the offline deployment.

Begin in observe-only mode for probabilistic detections while deterministic policies remain enforced. Promote individual detector policies after reviewing a held-out benign and adversarial corpus, including representative English and Hindi requests. Measure false blocks, missed detections, task completion and latency by endpoint and language. Proposed initial benign false-block target is at most 1 percent; latency and attack-detection targets must be approved from measured results before enforcement.

Exit gate: documented evaluation, correct native taxonomy, strict output parsing, tested outage behavior, and measured resource requirements. No claim of universal jailbreak prevention or guaranteed sub-second inference.

## Failure behavior

| Condition | Required behavior |
| --- | --- |
| Identity, permission, schema or policy validation fails | Deny before model or tool work; record the reason without sensitive payloads. |
| Required guard model unavailable, times out or returns malformed output | Return a temporary failure or queue for review for protected agent workflows. Never label the request safe. |
| Public low-risk FAQ detector unavailable | Allow only an explicitly configured deterministic fallback using public approved facts and no tool permissions; otherwise return unavailable. |
| Gateway or banking policy service unavailable | Deny mutations; never connect directly to bypass the gateway. |
| DLP or authorized response projection fails | Withhold sensitive output; do not return the original response. |
| Wazuh manager unavailable | Spool bounded sanitized events locally, expose degraded health and retry delivery. Keep authorization enforced. |
| Durable business audit/outbox unavailable before commit | Reject financial mutation. Commit the operation and its audit record atomically. |
| Spool full or collector stalled | Alert through a separate health channel; preserve mandatory audit and apply a documented endpoint degradation policy. Never silently discard required financial evidence. |

## Phase 4 Establish useful Wazuh observability

- Use versioned Eiger event fields rather than impersonating Wazuh's own agent or rule metadata: event ID, UTC time, trace ID, pseudonymous actor, tenant reference, operation ID, tool, decision, reason code, policy version, detector/model version and latency.
- Exclude raw prompts, document bodies, customer identifiers, session credentials and tool responses by default. Use keyed pseudonyms for correlation; avoid high-cardinality customer data in metrics. Restrict log permissions, retention and operator access.
- Emit JSON Lines or structured stdout through a collector that handles concurrent writers, restarts, rotation, backpressure and delivery errors. Protect the security spool from application tampering where practical. Business evidence belongs in durable audit storage, not only a writable application log.
- Configure the agent's localfile collection and authenticated manager enrollment. Install custom rules and any necessary decoders on the manager. Start with Wazuh's JSON decoder and verify the actual decoded fields before writing regex decoders.
- Separate suspicious input, denied operation and confirmed successful unauthorized activity. Tune severity accordingly. Correlate repeated cross-tenant denials, payment replays, guard outages and tool-manifest changes instead of making every blocked phrase a critical alert.
- Verify rules with `wazuh-logtest`, then prove end-to-end arrival at the manager and alert index. An emitted file or a passing rule simulation is not sufficient delivery evidence.

Exit gate: a synthetic denial produces a traceable alert; expected benign events do not flood high-severity alerts; loss, rotation and disk-full drills produce visible degraded health without leaking data.

## Phase 5 Make supply-chain admission verifiable

- Replace source-text security grades with structured findings tied to evidence. Inspect live tool manifests and run positive and negative authorization probes against isolated fixtures. Report checks that could not execute as not assessed, not passed.
- Use maintained dependency and image vulnerability scanners alongside Eiger-specific checks. Restrict runtime probes to explicitly configured lab targets. Never let a scan mutate a live banking environment.
- Scan model and serialized artifacts in a restricted job without deserializing untrusted pickle. Verify approved provenance, hashes, licenses, supported formats and bounded archive extraction. Hashing an unknown artifact establishes identity, not trust. Unsupported, malformed or unscannable artifacts are unknown and cannot pass admission.
- Generate the software inventory from the lockfile and built image, model records from exact deployed manifests, and tool/RAG records from approved configuration. Represent services using CycloneDX services and validate model-card fields and UUIDs against the pinned 1.6 schema. Keep credentials and internal customer content out of inventory.
- Pin image and model digests, policy hashes and tool-schema hashes. Sign release manifests and retain the scanned inventory with the release. Scanner exceptions need an owner, reason, expiry and constrained deployment scope.

Exit gate: malformed BOMs and unapproved artifacts fail CI; inventory matches the deployed release; scanner failures cannot yield a clean report.

## Phase 6 Produce a deployable topology

- Separate Compose profiles for the application, local guard inference, collection and optional full SIEM. The manager may be external; the plan must declare which topology is being validated.
- Provide PostgreSQL and the RAG store through explicit services or validated external endpoints. Remove secret defaults and use mounted secrets or an approved secret provider. Match variable names to the code that consumes them.
- Keep MCP, model inference, database and collector interfaces internal by default. Expose only the intended TLS ingress. Use separate networks and narrow service credentials; avoid host networking and Docker socket mounts.
- Reconcile trusted container DNS endpoints with SSRF policy using immutable administrator-configured endpoints. User or model input cannot select arbitrary container hosts or private-network destinations.
- Pin compatible images, validate architecture support, run non-root where supported, drop capabilities, use read-only filesystems with explicit writable mounts, and set memory, CPU, PID and log-size limits. Validate any collector privileges separately.
- Add liveness and capability-specific readiness checks, one-time verified model provisioning, startup dependencies and persistent storage. Readiness must report missing model weights, invalid rails, broken policy loading and absent credentials.
- Use an independently controlled mutation kill switch. Rolling back a detector may restore observe-only mode; it must not disable route, ledger or tool authorization. Review database migrations and restoration procedures separately from application rollback.

Exit gate: render/validate Compose, build from the locked dependencies, perform a fresh isolated startup, and demonstrate operation without unexpected internet downloads or exposed backend ports.

## Verification and rollout gates

1. Baseline regression: preserve intended authorized behavior. Updating a test that depended on unauthorized behavior is expected; retaining every old assertion is not an acceptance criterion.
2. Deterministic security tests: identity and tenant boundaries; native and MCP parity; parameter tampering; source ownership; refunds; one-time treasury execution; currency binding; repeated and concurrent idempotency; no side effects after denial.
3. Guardrail tests: valid and malformed model outputs, unsupported categories, detector outage, cancellation, multilingual benign cases, direct and indirect injection, truncated context, encoded data and classifier saturation. Keep live-model evaluations separate from offline unit tests and record actual versions.
4. Operational tests: direct backend attempts, missing secrets, invalid rails, Wazuh outage, disk full, concurrent log writes, process restart, model cold start and two application workers sharing durable state.
5. Supply-chain tests: known dangerous fixtures, unsupported formats, parser errors, invalid BOM schema, changed tool schemas and unexpected image/model digests.
6. Stage deterministic enforcement first. Run detectors in observe-only mode, then enforce selected policies in a limited rollout. Monitor false blocks, missed attacks, p50/p95/p99 latency, queue depth, audit lag and legitimate banking task completion.

Release requires zero known deterministic invariant violations, successful mandatory integration checks, an evaluated detector policy, an evidence-backed operational runbook, and explicit disposition of skipped tests. A passing pytest count is regression evidence, not a guarantee of security or compatibility.

## Suggested implementation commits

1. Baseline evidence, request context and explicit security result contracts.
2. Shared deterministic executor, service authorization and durable operation semantics.
3. Gateway coverage, structured output minimization and DLP.
4. Correct classifier adapter and validated NeMo rails, initially observe-only.
5. Durable audit export, Wazuh collection, manager rules and delivery tests.
6. Evidence-based scanners, schema-validated inventory and pinned admission policy.
7. Compose hardening, outage/load drills and staged enforcement evidence.

Each commit includes relevant tests and updates the control-to-evidence matrix. Do not commit existing untracked prototypes wholesale before their behavior has been reviewed.

## Primary references

- Meta Llama Guard 3-1B model card: https://github.com/meta-llama/PurpleLlama/blob/main/Llama-Guard3/1B/MODEL_CARD.md
- NVIDIA NeMo Guardrails 0.24.1 rail types: https://docs.nvidia.com/nemo/guardrails/v0.24.1/about-nemo-guardrails-library/rail-types
- Wazuh JSON decoder: https://documentation.wazuh.com/current/user-manual/ruleset/decoders/json-decoder.html
- Wazuh rule testing: https://documentation.wazuh.com/current/user-manual/ruleset/testing.html
- Wazuh log collection: https://documentation.wazuh.com/current/user-manual/capabilities/log-data-collection/how-it-works.html
- CycloneDX 1.6 schema: https://github.com/CycloneDX/specification/blob/master/schema/bom-1.6.schema.json
- PostgreSQL transactions: https://www.postgresql.org/docs/current/tutorial-transactions.html
