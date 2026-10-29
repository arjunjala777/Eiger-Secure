"""Generate inventory and validate against the vendored official CycloneDX 1.6 schema."""

import importlib.metadata
import json
import os
from pathlib import Path
import uuid
from datetime import datetime, timezone
from urllib.parse import quote
from jsonschema import Draft7Validator
from referencing import Registry, Resource

SCHEMAS = Path(__file__).resolve().parents[2] / "schemas" / "cyclonedx-1.6"


def validate_bom(bom):
    registry = Registry()
    for path in SCHEMAS.glob("*.json"):
        schema = json.loads(path.read_text(encoding="utf-8"))
        resource = Resource.from_contents(schema)
        for uri in (
            path.name,
            "http://cyclonedx.org/schema/" + path.name,
            schema.get("$id", path.as_uri()),
        ):
            registry = registry.with_resource(uri, resource)
    schema = json.loads((SCHEMAS / "bom-1.6.schema.json").read_text())
    Draft7Validator(schema, registry=registry).validate(bom)


def generate_ai_bom(output_path="ai-bom.json", model_manifest=None):
    components = []
    installed = sorted(
        importlib.metadata.distributions(), key=lambda d: d.metadata.get("Name", "").lower()
    )
    seen = set()
    for dist in installed:
        name = dist.metadata.get("Name")
        if not name or name.lower() in seen:
            continue
        seen.add(name.lower())
        components.append(
            {
                "type": "library",
                "name": name,
                "version": dist.version,
                "purl": "pkg:pypi/"
                + quote(name.lower().replace("_", "-"))
                + "@"
                + quote(dist.version),
            }
        )
    models = model_manifest or {
        os.getenv("OLLAMA_MODEL", "llama3.1:8b"): None,
        os.getenv("LLAMA_GUARD_MODEL", "llama-guard3:1b"): None,
    }
    for name, digest in models.items():
        component = {
            "type": "machine-learning-model",
            "name": name,
            "properties": [
                {
                    "name": "eiger:inventory-state",
                    "value": "verified-artifact" if digest else "configured-unresolved",
                }
            ],
            "modelCard": {
                "modelParameters": {
                    "task": "content-safety-classification"
                    if "guard" in name
                    else "text-generation",
                    "inputs": [{"format": "text/plain"}],
                    "outputs": [{"format": "text/plain"}],
                }
            },
        }
        if digest:
            component["hashes"] = [{"alg": "SHA-256", "content": digest.removeprefix("sha256:")}]
        components.append(component)
    bom = {
        "$schema": "http://cyclonedx.org/schema/bom-1.6.schema.json",
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "serialNumber": "urn:uuid:" + str(uuid.uuid4()),
        "version": 1,
        "metadata": {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "component": {
                "type": "application",
                "name": "Eiger",
                "version": importlib.metadata.version("halcyon"),
            },
        },
        "components": components,
        "services": [
            {
                "name": "core_banking_mcp",
                "authenticated": True,
                "endpoints": [os.getenv("MCP_CORE_URL", "http://mcp-core:9001/mcp")],
            },
            {
                "name": "crm_mcp",
                "authenticated": True,
                "endpoints": [os.getenv("MCP_CRM_URL", "http://mcp-crm:9002/mcp")],
            },
        ],
    }
    validate_bom(bom)
    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(bom, indent=2), encoding="utf-8")
    return bom


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser()
    parser.add_argument("--output", default="ai-bom.json")
    parser.add_argument("--model-manifest")
    args = parser.parse_args()
    generate_ai_bom(
        args.output,
        json.loads(Path(args.model_manifest).read_text()) if args.model_manifest else None,
    )
