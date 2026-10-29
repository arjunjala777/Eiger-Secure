"""Persistent, network-free knowledge store.

This deliberately avoids running the Chroma HTTP API. The deployed Chroma
server version had no upstream fix for its remote-model code-execution
advisories; using SQLite here removes that reachable server surface entirely.
Retrieval is lexical (term overlap), with authorization applied in SQL before
ranking and limiting results.
"""

from __future__ import annotations

import hashlib
import os
import re
import sqlite3
import threading
import uuid
from pathlib import Path

from halcyon.kb import Chunk

_TOKEN = re.compile(r"[a-z0-9]+")


class SQLiteKB:
    def __init__(self, collection: str = "halcyon", db_path: str | None = None) -> None:
        self._name = collection
        self._lock = threading.RLock()
        self._seq = 0
        path = db_path or os.getenv("EIGER_KB_PATH", ":memory:")
        if path != ":memory:":
            Path(path).parent.mkdir(parents=True, exist_ok=True)
        self._conn = sqlite3.connect(path, timeout=10, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._conn.execute("PRAGMA busy_timeout=10000")
        if path != ":memory:":
            self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.execute(
            """CREATE TABLE IF NOT EXISTS eiger_kb_chunks (
                collection TEXT NOT NULL,
                id TEXT NOT NULL,
                text TEXT NOT NULL,
                provenance TEXT NOT NULL,
                access TEXT NOT NULL,
                owner_session TEXT NOT NULL DEFAULT '',
                PRIMARY KEY (collection, id)
            )"""
        )
        self._conn.execute(
            "CREATE INDEX IF NOT EXISTS eiger_kb_acl_idx "
            "ON eiger_kb_chunks(collection, access, owner_session)"
        )
        self._conn.commit()

    def add(
        self, text: str, provenance: str, access: str = "public", owner_session: str = ""
    ) -> Chunk:
        if not isinstance(text, str):
            raise TypeError("document text must be a string")
        chunk_id = "u-" + uuid.uuid4().hex
        with self._lock, self._conn:
            self._conn.execute(
                "INSERT INTO eiger_kb_chunks VALUES (?, ?, ?, ?, ?, ?)",
                (self._name, chunk_id, text, provenance, access, owner_session or ""),
            )
        return Chunk(chunk_id, text, provenance, access, owner_session or "")

    def retrieve(
        self, query: str, session_id: str, k: int = 3, include_restricted: bool = True,
        trusted_only: bool = False,
    ) -> list[Chunk]:
        if k <= 0:
            return []
        sql = (
            "SELECT id, text, provenance, access, owner_session "
            "FROM eiger_kb_chunks WHERE collection = ?"
        )
        params: list[object] = [self._name]
        if trusted_only:
            sql += " AND provenance = 'trusted'"
        if not include_restricted:
            sql += " AND (access = 'public' OR (access = 'restricted' AND owner_session = ? AND ? != ''))"
            params.extend([session_id, session_id])
        # Authorization is applied by the database before candidate scoring,
        # so restricted records cannot consume the top-k result budget.
        with self._lock:
            rows = self._conn.execute(sql, params).fetchall()
        query_terms = set(_TOKEN.findall(query.lower()))
        scored: list[tuple[int, sqlite3.Row]] = []
        for row in rows:
            score = len(query_terms.intersection(_TOKEN.findall(row["text"].lower())))
            if score:
                scored.append((score, row))
        scored.sort(key=lambda pair: (-pair[0], pair[1]["id"]))
        return [
            Chunk(row["id"], row["text"], row["provenance"], row["access"], row["owner_session"])
            for _, row in scored[:k]
        ]

    def seed(self, fixtures: list[dict]) -> None:
        with self._lock, self._conn:
            for fixture in fixtures:
                text = fixture["text"]
                chunk_id = "seed-" + hashlib.sha256(text.encode("utf-8")).hexdigest()
                self._conn.execute(
                    "INSERT OR REPLACE INTO eiger_kb_chunks VALUES (?, ?, ?, ?, ?, ?)",
                    (
                        self._name,
                        chunk_id,
                        text,
                        fixture.get("provenance", "trusted"),
                        fixture.get("access", "public"),
                        fixture.get("owner_session", ""),
                    ),
                )

    def clear(self) -> None:
        with self._lock, self._conn:
            self._conn.execute(
                "DELETE FROM eiger_kb_chunks WHERE collection = ?", (self._name,)
            )
        self._seq = 0

    def list_own(self, session_id: str) -> list[Chunk]:
        with self._lock:
            rows = self._conn.execute(
                "SELECT id, text, access FROM eiger_kb_chunks "
                "WHERE collection = ? AND provenance = 'user' AND owner_session = ? "
                "ORDER BY rowid",
                (self._name, session_id),
            ).fetchall()
        return [Chunk(r["id"], r["text"], "user", r["access"], session_id) for r in rows]

    def delete_own(self, session_id: str, chunk_id: str) -> bool:
        with self._lock, self._conn:
            result = self._conn.execute(
                "DELETE FROM eiger_kb_chunks WHERE collection = ? AND id = ? "
                "AND provenance = 'user' AND owner_session = ?",
                (self._name, chunk_id, session_id),
            )
            return result.rowcount == 1

    def close(self) -> None:
        with self._lock:
            self._conn.close()
