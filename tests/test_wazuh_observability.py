"""
Tests for Wazuh SIEM Security Event Logger.

Validates schema formatting, pseudonymous hashing, bounded spooling,
and concurrent thread-safe writes.
"""

import json
import threading
from pathlib import Path
import pytest

from halcyon.security.wazuh_logger import WazuhSecurityLogger, _pseudonymize


def test_wazuh_logger_event_schema(tmp_path: Path):
    log_file = tmp_path / "test_wazuh.json"
    logger = WazuhSecurityLogger(log_path=log_file)

    event = logger.log(
        event_type="prompt_injection_detected",
        severity="critical",
        rule_id=100101,
        action="input_validation",
        decision="BLOCK",
        session_id="user_alice_secret",
        target_resource="chat_endpoint",
        reason_code="EIGER_PROMPT_INJECTION",
        message="Intercepted injection payload",
        details={"matched_rule": "ignore_instructions"},
    )

    # Verify event structure
    assert event["app"] == "eiger-banking"
    assert event["rule"]["id"] == 100101
    assert event["rule"]["level"] == 14  # Critical maps to Wazuh level 14
    assert event["security"]["decision"] == "BLOCK"
    assert event["security"]["event_type"] == "prompt_injection_detected"

    # Data minimization: pseudonymized actor
    assert event["security"]["actor_pseudonym"].startswith("actor-")
    assert "user_alice_secret" not in event["security"]["actor_pseudonym"]

    # File persisted as valid JSON Line
    assert log_file.exists()
    line = log_file.read_text(encoding="utf-8").strip()
    parsed = json.loads(line)
    assert parsed["event_id"] == event["event_id"]


def test_wazuh_logger_bounded_rotation(tmp_path: Path):
    log_file = tmp_path / "rotate_test.json"
    # Small max_bytes to trigger rotation quickly
    logger = WazuhSecurityLogger(log_path=log_file, max_bytes=500)

    for i in range(10):
        logger.log(
            event_type="mcp_gateway_block",
            severity="high",
            rule_id=100201,
            action="test_action",
            decision="BLOCK",
            message=f"Iteration message {i}",
        )

    # Backup file must exist due to rotation
    backup_file = log_file.with_suffix(".json.1")
    assert backup_file.exists()
    assert log_file.exists()


def test_wazuh_logger_thread_safety(tmp_path: Path):
    log_file = tmp_path / "concurrent_wazuh.json"
    logger = WazuhSecurityLogger(log_path=log_file)

    def worker(worker_id: int):
        for i in range(20):
            logger.log(
                event_type="heartbeat",
                severity="low",
                rule_id=100001,
                action="concurrent_test",
                decision="ALLOW",
                message=f"Worker {worker_id} msg {i}",
            )

    threads = [threading.Thread(target=worker, args=(i,)) for i in range(5)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    # All 100 lines must be valid JSON Lines
    lines = [line.strip() for line in log_file.read_text(encoding="utf-8").splitlines() if line.strip()]
    assert len(lines) == 100
    for line in lines:
        data = json.loads(line)
        assert data["app"] == "eiger-banking"
