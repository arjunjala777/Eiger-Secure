# M4 Supply-Chain Audit — Current Safe Flow

**Updated:** 2026-10-26
**Branch:** `security-hardening`

## Artifact disposition

The historical `community_model.pkl` contained a `posix.system` reduction chain. Its bytes and builder script have been removed. `labs/m4/artifacts/community_model.quarantine.json` retains the SHA-256 and static finding summary as data only. The M4 exercise no longer distributes a pickle.

`halcyon.artifacts.load_artifact()` rejects `.pkl` and `.pickle` in every mode. `test_artifacts.py` checks that refusal; scanner unit tests generate any malicious test pickle only inside a temporary directory and never load it.

## M4 checks

1. In an isolated teaching deployment only, inspect the quarantine record and submit its historical SHA-256. Submit the vulnerable dependency pin for the stretch objective.
2. Confirm `/submit/m4` grades both submissions and `/validate/m4` records the expected lab progress.
3. Confirm `/api/m4/bundle` returns 404 in Secure Lab and Production. Production also disables all lab endpoints.
4. Confirm the production Docker build context excludes `labs/` and the production environment does not install ChromaDB.

Never recreate or deserialize the quarantined artifact. The `vulnerable` mode is an explicit, isolated teaching profile; it is not a deployment mode for a service exposed to untrusted users.
