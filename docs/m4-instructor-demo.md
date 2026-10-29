# M4 Instructor Notes — Quarantined Artifact Record

**Status:** The historical `community_model.pkl` exploit has been removed from the repository. Do not regenerate, deserialize, or distribute it. `halcyon.artifacts.load_artifact` rejects pickle formats in every profile, and the secure application disables the M4 bundle route.

## Safe classroom flow

The M4 bundle now contains `artifacts/community_model.quarantine.json`, a static incident record with the historical digest and opcode summary, plus the safe tensor-format sample and dependency exercise. The record contains no pickle bytes and scanning it does not execute code.

1. Inspect `labs/m4/artifacts/community_model.quarantine.json`.
2. Submit its recorded SHA-256 through the M4 panel while using the isolated vulnerable teaching profile.
3. Submit the vulnerable dependency pin from `labs/m4/requirements-vulnerable.txt`.
4. Verify that the loader refuses a pickle path even when `HALCYON_MODE=vulnerable`.

`tests/test_artifacts.py` covers the all-profile pickle refusal. `tests/test_m4_answers.py` verifies the quarantine record matches the historical digest, and `tests/test_scan_artifact.py` creates a disposable test-only malicious pickle in a temporary directory to exercise the static scanner. The test fixture is never shipped with the app or bundle.

## Deployment boundaries

- Secure Lab and Production return 404 for `/api/m4/bundle`.
- Production disables all lab endpoints.
- Docker build context excludes `labs/`; the production image does not contain the historical fixture.
- M4's dependency-pin challenge describes a lab fixture only. It is not the runtime dependency set.
