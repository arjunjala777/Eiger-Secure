"""Explicit operator-run provisioning; normal startup never downloads weights."""

import argparse
import json
import os
from pathlib import Path
import httpx

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", default=os.getenv("EIGER_MODEL_MANIFEST", "models.json"))
    parser.add_argument("--warm", action="store_true")
    args = parser.parse_args()
    # Operator-only maintenance endpoint. Runtime application traffic uses the
    # inference gateway, which intentionally has no model mutation routes.
    url = os.getenv("OLLAMA_MANAGEMENT_URL", "http://127.0.0.1:11434").rstrip("/")
    from urllib.parse import urlparse
    parsed = urlparse(url)
    if (
        parsed.scheme != "http" or parsed.hostname not in ("127.0.0.1", "localhost")
        or parsed.port != 11434 or parsed.username or parsed.password or parsed.fragment
    ):
        raise SystemExit("OLLAMA_MANAGEMENT_URL must target the loopback admin listener on port 11434")
    required = [
        os.getenv("OLLAMA_MODEL", "llama3.1:8b"),
        os.getenv("LLAMA_GUARD_MODEL", "llama-guard3:1b"),
    ]
    with httpx.Client(timeout=120, trust_env=False) as client:
        response = client.get(url + "/api/tags")
        response.raise_for_status()
        available = {m["name"]: m["digest"] for m in response.json()["models"]}
        if any(name not in available for name in required):
            raise SystemExit(
                "Required weights are missing; provision the approved artifacts before creating the inventory"
            )
        if args.warm:
            for name in required:
                response = client.post(
                    url + "/api/generate",
                    json={
                        "model": name,
                        "stream": False,
                        "keep_alive": "30m",
                        "options": {"num_predict": 0},
                    },
                )
                response.raise_for_status()
        path = Path(args.output)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps({name: available[name] for name in required}, indent=2))
        print(
            "Recorded exact local model digests; review and retain this manifest with the release"
        )
