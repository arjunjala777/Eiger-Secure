# S10 — Kill-Chain Capstone: a real, coupled, end-to-end compromise

**Status:** Design approved (2026-08-06). Next step: `writing-plans` → implementation plan under `docs/plans/`.
**Author context:** Brainstormed with KK after Batch-2. This is a *new* Eiger capability, not a change to M1–M8.

---

## 1. Motivation

Today Eiger's modules **do not chain**. Each `validators/m*.py` checks only its own module's audit events; the M5/M7 authz gates read only `bank.owns()`, never the M1 honeytoken. The Day-2 "AI vs AI" finale *narrates* a kill chain but enforces it via a **leaderboard loot-gate**, not code. Eiger also has **no** secret-leak, misconfiguration, or self-serve-RCE surface (M4 is scan-only; real RCE is instructor-only in a throwaway container).

KK wants a capstone that **mirrors a real-world breach**: a leaked secret → a misconfiguration → prompt injection → an easily-exploitable supply-chain issue → **final compromise (RCE + crown-jewel exfiltration)** — where each link is **genuinely required** for the next, enforced server-side.

## 2. Decisions locked

| Decision | Choice |
|---|---|
| **Shape** | A **new self-contained kill-chain capstone** that reuses Eiger's machinery. M1–M8 stay as the teaching ladder. |
| **Coupling** | **Real, code-enforced** — each stage's loot is the literal key to the next. Not a loot-gate. |
| **Finale** | **Real code execution**, but confined to a disposable sandbox (see §5). Not host RCE. |
| **Secret-leak delivery** | **In-app simulated repo/source browser** (deterministic, resettable, per-session). Not a real external GitHub repo. |

Non-negotiable Eiger invariants this must honour (see root `CLAUDE.md`): mechanism validation via append-only audit log (never model-output string match); one build + `SEC_*` flags (the vulnerable→secure diff is the lesson); deterministic + resettable + self-service; RCE isolated per-participant.

## 3. The chain — one campaign, five real links

Attacker goal: **RCE on Eiger's backend + exfiltrate the vault master secret.**

| # | Stage (real-world technique) | Eiger surface (new unless noted) | Loot it yields | Why the next stage needs it |
|---|---|---|---|---|
| **1** | Leaked secret in git | Read-only **"Source" tab** — mock `eiger-platform` repo + commit history; a **CI/deploy token** buried in a reverted commit / `.env.sample` | `EIGER_CI_TOKEN` (per session) | Stage 2's endpoint rejects every request without it |
| **2** | Misconfig / over-permissive CI | Internal `POST /internal/deploy` — network-exposed *and* trusts the CI token for more than it should | Trusted-source **write access** + ability to set the **artifact URL** the worker loads | Stage 3's injection only survives because you can now write to a channel provenance won't quarantine |
| **3** | Prompt injection via a *trusted* channel | The privileged **ops-agent** reads that trusted source as authoritative and obeys → triggers a deploy/build action | The agent **fetches + loads** the artifact registered in stage 2 | Stage 4 only fires because the agent was made to pull it |
| **4** | Easily-exploitable supply chain | The artifact (poisoned pickle model / typosquatted dep) the **worker** actually loads → attacker code runs (extends M4, made live) | Code execution in the sandbox | Stage 5's secret is reachable only via code exec |
| **5** | Final compromise | Payload reads the per-session **vault master secret** (no API exposes it) and exfiltrates to the session-scoped callback | `rce_confirmed` + the crown-jewel secret | — the "domain admin" moment |

**Real coupling (enforced in code, not a gate):** S2 auth-checks the S1 token; S3's injection only lands via S2's *trusted* write (a normal user-KB write stays quarantined by `SEC_RAG_PROVENANCE`); S4 loads only what S3's agent fetched; S5's secret exists only behind S4's code exec. Skip a link → the chain dead-ends in code.

**Kill-chain framing (credibility):** MITRE ATT&CK — Valid Accounts (leaked creds) → Exploitation of Remote Services (misconfig) → … → Execution (supply chain). Aligns with the OWASP GenAI/LLM Top 10 **2026** emphasis (LLM03 Excessive Agency now #3; LLM04 Supply Chain covers "a promoted artifact is not what it claims to be").

## 4. New surfaces / components (design level)

- **Source browser** — read-only mock repo + commit-history view; per-session seeded leak. (New tab + endpoint, e.g. `GET /source/...`.)
- **`POST /internal/deploy`** — the misconfigured CI endpoint; validates the CI token (over-scoped in vulnerable mode); registers artifact URL + trusted-source write.
- **Ops-agent** — a privileged internal agent variant that reads the trusted source and has a `deploy(artifact_url)` tool. (May reuse the existing agent/LangGraph plumbing with a distinct system prompt + tool.)
- **Build worker** — the ephemeral sandbox that loads the artifact (§5).
- **`POST /chain/callback`** — the single allow-listed egress target the worker's payload reports to.
- **Chain validator** — `GET /validate/chain` (§7).
- **Fixtures** — per-session CI token, vault master secret, seeded repo/leak, poisoned-artifact scaffolding.

## 5. RCE isolation architecture (security-critical)

"Real RCE" = **real deserialization → real arbitrary code**, confined to a **disposable sandbox**, *not* the host. Blast radius = a throwaway container holding one fake per-session secret and no network.

When the ops-agent (S3) calls `deploy(artifact_url)`, the app spawns a short-lived **build worker** to "load" the artifact — attacker code executes there, confined by:

| Control | Purpose |
|---|---|
| **No network egress** except one allow-listed callback (`/chain/callback`) | RCE can't reach the internet, other participants, or anything real — only report back |
| **No host access** — non-root, read-only FS, dropped caps, `no-new-privileges`, seccomp, no docker socket/mounts | Code can't escape the container |
| **Resource + time bounds** (CPU/mem/pids, ~30s hard timeout → killed) | No fork bombs / hangs / noisy-neighbour at 32× |
| **Ephemeral + per-session** — spawned per run, destroyed after | Nothing persists; reset re-provisions clean |
| **Prize = per-session secret only** (`vault_master`, mounted only in the worker) | Reading it proves code exec but is worthless elsewhere |

**Rejected:** in-process sandboxes (seccomp/restricted-exec) — a real pickle escapes them; not safe enough. **v1** = ephemeral worker **container** (above). **Hardening path** = gVisor / Firecracker microVM for kernel-level isolation (optional, Phase 4).

## 6. Audit events (append-only; mechanism validation)

Ordered chain events, one per stage, plus the proof:
```
secret_leak_discovered  → misconfig_exploited → trusted_injection_fired
    → malicious_artifact_loaded → rce_confirmed  (+ exfiltrated secret == session vault_master)
```
All are server-emitted on the exploited path. The final proof is deterministic even though RCE isn't: the per-session secret (reachable only via code exec) either arrived at the callback or it didn't.

## 7. Chain validator

`GET /validate/chain?session=…` → `{core: pass|fail, ...}`:
- All five events present for the session, **in order** (checked against append-only log IDs, as defence against forged events — though code-gating already prevents legitimate out-of-order).
- `rce_confirmed`'s reported secret **equals** the session's `vault_master`.

`POST /reset/chain` → regenerate CI token + vault secret, re-seed the leak, destroy any lingering worker, clear chain events.

## 8. Secure-flip flags — break *any one* link, kill the chain

| Flag | Breaks | Effect |
|---|---|---|
| `SEC_SECRET_SCANNING` | S1 | leak scrubbed / secret rotated out of history → nothing to find |
| `SEC_CI_LEAST_PRIV` | S2 | CI token scoped + endpoint network-isolated → S2 denied |
| `SEC_TRUSTED_SOURCE_AUTH` | S3 | writes to the trusted source require signing/authz → injection quarantined |
| `SEC_ARTIFACT_VERIFICATION` *(exists)* | S4 | worker refuses non-safetensors / unpinned-hash → never deserialized |
| `SEC_WORKER_SANDBOX` | S5 | egress blocked + secret not mounted → code may run but can't exfil (defense-in-depth) |

**The lesson:** flip *one* → the chain validator fails at that link. You don't have to fix everything; you have to break one link.

## 9. Phased build plan

- **Phase 0 — Spec (this doc) + a dedicated threat model *of the sandbox itself*.** A broken sandbox = real RCE on shared infra; it gets its own adversarial review before exposure.
- **Phase 1 — Whole chain, *stubbed* exec.** All 5 stages, real coupling, validator, all secure-flips — but S4/S5 run a *constrained* payload (read-secret + callback only). Curriculum + grading fully playable and reviewable **without** the risky infra.
- **Phase 2 — Real sandbox** (ephemeral egress-locked worker) swapped in behind the same interface.
- **Phase 3 — Fleet ops** — per-participant provisioning + nuke/reprovision (the long-deferred container-per-participant fleet, now on the critical path).
- **Phase 4 (optional) — gVisor/Firecracker** hardening.

## 10. Dependencies & risks

- **The sandbox is the crux** and is security-sensitive; **must get an adversarial review** before 32 people touch it. Phase 1's stub lets everything else proceed in parallel.
- **Forces the container-per-participant fleet** (deferred since day one) onto the critical path.
- **Determinism:** real RCE is less deterministic than string checks, but the validator keys on the per-session-secret exfil, which is binary (arrived or not).
- **Artifact hosting** (open question, §11) must not become a way to serve real malware off Eiger's infra — payloads run only in the no-egress sandbox and are per-session.

## 11. Open questions (resolve during writing-plans)

1. **Artifact delivery:** does the participant *upload* a poisoned pickle to a per-session "package registry," or *point* the deploy at a pre-seeded malicious artifact and only control the trigger? (Upload = more realistic; more to sandbox.)
2. **Ops-agent identity:** reuse the existing agent/LangGraph with a new system prompt + `deploy` tool, or a distinct agent? Keyless vs BYOK for this agent.
3. **Worker runtime:** Docker-in-Docker vs a sibling container via the host daemon vs a pre-warmed worker pool (latency at 32×).
4. **Trusted-source channel:** which concrete store is the "trusted" write target (a `trusted`-provenance KB doc? an ops runbook the agent reads?).
5. **Where the capstone sits in the run-of-show** (replaces / follows the current "AI vs AI" finale?).
6. **Reset semantics** for a mid-run worker (participant abandons after S4).

## 12. References

- Root `CLAUDE.md` (four hard rules, flag registry, validation backbone).
- Existing scan-only supply chain: `docs/specs/2026-07-12-halcyon-s4-m4-supply-chain-design.md`, `docs/m4-instructor-demo.md`.
- OWASP GenAI/LLM Top 10 **2026** (agentic + supply-chain emphasis).
- MITRE ATT&CK kill-chain mapping.
