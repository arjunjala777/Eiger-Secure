"""
Tests for Supply-Chain Admission & Inventory Validation.

Validates CycloneDX 1.6 AI BOM schema adherence, empirical probe verification,
and artifact scanner admission decisions.
"""

import json
import uuid
from pathlib import Path
import pytest
import anyio

from scripts.security.generate_ai_bom import generate_ai_bom
from scripts.security.mcp_scanner import run_mcp_probes
from scripts.security.supply_chain_scanner import scan_artifacts


def test_ai_bom_cyclonedx_schema_compliance(tmp_path: Path):
    bom_file = tmp_path / "test_ai_bom.json"
    bom = generate_ai_bom(bom_file)

    assert bom["bomFormat"] == "CycloneDX"
    assert bom["specVersion"] == "1.6"
    assert bom["serialNumber"].startswith("urn:uuid:")

    # Validate UUID syntax
    raw_uuid = bom["serialNumber"].replace("urn:uuid:", "")
    parsed_uuid = uuid.UUID(raw_uuid)
    assert parsed_uuid.version == 4

    # Validate services array is separated from components
    assert "services" in bom
    assert len(bom["services"]) >= 2
    service_names = [s["name"] for s in bom["services"]]
    assert "core_banking_mcp" in service_names
    assert "crm_mcp" in service_names

    # Validate components array contains models
    assert "components" in bom
    comp_names = [c["name"] for c in bom["components"]]
    assert "llama3.1:8b" in comp_names
    assert "llama-guard3:1b" in comp_names


def test_mcp_scanner_empirical_admission_pass():
    async def main():
        report = await run_mcp_probes()
        assert report["admission_status"] == "PASS"
        assert report["probes_executed"] >= 8
        assert report["probes_passed"] == report["probes_executed"]
        assert len(report["findings"]) == 0

    anyio.run(main)


def test_supply_chain_scanner_on_empty_and_valid_dir(tmp_path: Path):
    # Empty dir
    empty_rep = scan_artifacts(tmp_path)
    assert empty_rep["scanned_count"] == 0
    assert empty_rep["admission_verdict"] == "FAIL"

    # Benign file
    safe_file = tmp_path / "model.json"
    safe_file.write_text('{"weights": [0.1, 0.2]}', encoding="utf-8")
    import hashlib
    rep = scan_artifacts(tmp_path, {hashlib.sha256(safe_file.read_bytes()).hexdigest()})
    assert rep["scanned_count"] == 1
    assert rep["admission_verdict"] == "PASS"
    assert rep["results"][0]["status"] == "APPROVED"  # not a pickle stream
