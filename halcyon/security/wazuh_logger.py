"""Sanitized JSON Lines export with a bounded, durable local retry queue.

Delivery is at least once to the local collector; Wazuh receipt must be checked
at the manager. Business ledger audit is committed with financial state.
"""

import hashlib
import hmac
import json
import logging
import os
from pathlib import Path
import secrets
import sqlite3
import threading
import uuid
from datetime import datetime, timezone
from halcyon.security.context import request_context

DEFAULT_LOG_PATH = Path(os.getenv("EIGER_WAZUH_LOG_PATH", "logs/wazuh_security_events.json"))
MAX_LOG_BYTES = 10 * 1024 * 1024
_LOCK = threading.RLock()
_LOGGER = logging.getLogger("eiger.wazuh")
_PSEUDONYM_KEY = os.getenv(
    "EIGER_AUDIT_HMAC_KEY", os.getenv("HALCYON_SESSION_SECRET", "")
).encode() or secrets.token_bytes(32)
_ALLOWED_DETAILS = {
    "tool",
    "ownership_param",
    "native_categories",
    "eiger_policy_codes",
    "latency_ms",
    "observe_only",
    "status_code",
    "timeout_seconds",
    "model",
    "engine",
    "rule",
    "redactions",
    "detector",
    "degraded",
}


class AuditUnavailable(RuntimeError):
    pass


def _pseudonymize(identifier):
    if not identifier or identifier == "anonymous":
        return "anonymous"
    return (
        "actor-"
        + hmac.new(_PSEUDONYM_KEY, str(identifier).encode(), hashlib.sha256).hexdigest()[:24]
    )


class WazuhSecurityLogger:
    def __init__(
        self,
        log_path=DEFAULT_LOG_PATH,
        max_bytes=MAX_LOG_BYTES,
        max_spool_bytes=10 * 1024 * 1024,
        max_segments=8,
    ):
        self.log_path = Path(log_path)
        self.max_bytes, self.max_spool_bytes, self.max_segments = (
            max_bytes,
            max_spool_bytes,
            max_segments,
        )
        self.last_error = None

    def _connect(self):
        self.log_path.parent.mkdir(parents=True, exist_ok=True)
        conn = sqlite3.connect(str(self.log_path) + ".spool.sqlite", timeout=5)
        conn.execute(
            "CREATE TABLE IF NOT EXISTS pending (id INTEGER PRIMARY KEY, payload TEXT NOT NULL)"
        )
        return conn

    def _export(self, conn):
        # SQLite serializes exporters across processes as well as local threads.
        conn.execute("BEGIN IMMEDIATE")
        try:
            for seq, line in conn.execute("SELECT id,payload FROM pending ORDER BY id").fetchall():
                size = self.log_path.stat().st_size if self.log_path.exists() else 0
                if size and size + len(line.encode()) + 1 > self.max_bytes:
                    next_name = None
                    for n in range(1, self.max_segments + 1):
                        candidate = self.log_path.with_suffix(".json." + str(n))
                        if not candidate.exists():
                            next_name = candidate
                            break
                    if next_name is None:
                        raise OSError(
                            "Audit segment capacity reached; collector acknowledgement required"
                        )
                    self.log_path.rename(next_name)
                with self.log_path.open("a", encoding="utf-8") as stream:
                    stream.write(line + "\n")
                    stream.flush()
                    os.fsync(stream.fileno())
                conn.execute("DELETE FROM pending WHERE id=?", (seq,))
            conn.commit()
        except Exception:
            conn.rollback()  # A crash may duplicate events, but cannot silently lose them.
            raise

    def log(
        self,
        event_type,
        severity,
        rule_id,
        action,
        decision,
        session_id=None,
        actor="anonymous",
        target_resource=None,
        reason_code="",
        detector_id="eiger_security_core",
        latency_ms=None,
        details=None,
        message="",
    ):
        context = request_context.get()
        # Never persist free text, raw arguments, exception messages or arbitrary details.
        safe_details = {}
        for key, value in (details or {}).items():
            if key in _ALLOWED_DETAILS:
                if isinstance(value, (bool, int, float)) or value is None:
                    safe_details[key] = value
                elif key in ("native_categories", "eiger_policy_codes"):
                    safe_details[key] = [str(v)[:64] for v in value][:16]
                else:
                    safe_details[key] = (
                        str(value)[:128]
                        if key in ("tool", "ownership_param", "engine", "rule", "detector")
                        else _pseudonymize(str(value))
                    )
        # Event types/actions are code identifiers, never content supplied by the model.
        import re

        def clean(v):
            return (
                str(v)[:80]
                if re.fullmatch(r"[A-Za-z0-9_.:-]{1,80}", str(v))
                else "invalid_event_identifier"
            )

        event = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "event_id": str(uuid.uuid4()),
            "trace_id": context.request_id if context else str(uuid.uuid4()),
            "app": "eiger-banking",
            "policy_version": context.policy_version if context else "2026-10-26",
            "rule": {
                "id": int(rule_id),
                "level": self._severity_to_wazuh_level(severity),
                "description": "Eiger " + clean(event_type),
            },
            "security": {
                "event_type": clean(event_type),
                "severity": clean(severity),
                "decision": clean(decision),
                "action": clean(action),
                "actor_pseudonym": _pseudonymize(session_id or actor),
                "target_resource": _pseudonymize(target_resource),
                "reason_code": clean(reason_code or event_type.upper()),
                "detector_id": clean(detector_id),
                "latency_ms": latency_ms,
                "details": safe_details,
            },
        }
        line = json.dumps(event)
        if len(line.encode()) > 16384:
            raise AuditUnavailable("Audit event exceeds size limit")
        with _LOCK:
            try:
                with self._connect() as conn:
                    current = conn.execute(
                        "SELECT COALESCE(SUM(length(CAST(payload AS BLOB))),0) FROM pending"
                    ).fetchone()[0]
                    if current + len(line.encode()) > self.max_spool_bytes:
                        raise AuditUnavailable("Durable audit queue capacity exceeded")
                    conn.execute("INSERT INTO pending(payload) VALUES (?)", (line,))
                    conn.commit()  # Persist before attempting export.
                    try:
                        self._export(conn)
                        self.last_error = None
                    except OSError as exc:
                        self.last_error = type(exc).__name__
                        _LOGGER.error("Audit export degraded; event retained in durable queue")
            except (OSError, sqlite3.Error) as exc:
                self.last_error = type(exc).__name__
                raise AuditUnavailable("Durable audit storage unavailable") from exc
        return event

    @staticmethod
    def _severity_to_wazuh_level(severity):
        return {"critical": 14, "high": 12, "medium": 8, "low": 4, "info": 2}.get(
            severity.lower(), 5
        )


_GLOBAL_LOGGER = WazuhSecurityLogger()


def log_security_event(*args, **kwargs):
    return _GLOBAL_LOGGER.log(*args, **kwargs)
