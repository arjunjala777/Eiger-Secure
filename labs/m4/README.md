# M4 — Supply Chain Audit

This lab contains a safe quarantine record for a historically poisoned ML
artifact and dependency pins. The executable pickle was removed from the
repository and is never included in a bundle.

## What's here

- `artifacts/community_model.quarantine.json` — the original digest and static
  finding summary; it contains no executable artifact bytes.
- `artifacts/embedding_model.safetensors` — an embedding model checkpoint.
- `requirements-vulnerable.txt` — the pinned dependencies for this pipeline.

## How to audit

1. Review the quarantine record:

   ```bash
   python -m json.tool labs/m4/artifacts/community_model.quarantine.json
   ```

   The original artifact was statically found to contain `posix.system`,
   `STACK_GLOBAL`, and `REDUCE`. The bytes were removed; use the recorded SHA-256
   for the exercise. Do not reconstruct or load the historic pickle.

2. Audit the dependency pins for known CVEs:

   ```bash
   pip-audit -r labs/m4/requirements-vulnerable.txt
   ```

   (No `pip-audit`? Look up each pin manually against the NVD/OSV database.)

3. Submit the quarantined artifact's recorded sha256 and the vulnerable
   dependency pin via the M4 panel.
