import json
from pathlib import Path

from halcyon import m4_answers, scan_artifact


def test_quarantine_record_matches_historical_artifact_hash_and_contains_no_payload():
    record_path = Path("labs/m4/artifacts/community_model.quarantine.json")
    record = json.loads(record_path.read_text(encoding="utf-8"))
    assert record["sha256"] == m4_answers.QUARANTINED_ARTIFACT_SHA256
    assert record["status"] == "removed"
    assert not Path("labs/m4/artifacts/community_model.pkl").exists()
    assert scan_artifact.scan(record_path)["malicious"] is False


def test_normalizers():
    assert m4_answers.normalize_package("PyYAML==5.3.1") == "pyyaml==5.3.1"
    assert m4_answers.normalize_hash("SHA256:ABCD") == "abcd"


def test_stretch_requires_version_pin():
    from halcyon import m4_answers

    assert m4_answers.normalize_package("pyyaml") != m4_answers.VULNERABLE_PACKAGE       # bare fails
    assert m4_answers.normalize_package("PyYAML==5.3.1") == m4_answers.VULNERABLE_PACKAGE  # pin passes
