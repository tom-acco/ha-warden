"""Tamper-evident storage layer for Security Logger.

Design notes (see docs/ARCHITECTURE.md for the full rationale):

- Storage is a dedicated SQLite database, separate from Home Assistant's own
  recorder database, so wiping/restoring the HA config does not also wipe
  the security log.
- Every row is hash-chained: hash(row_n) = SHA256(prev_hash + canonical_json(row_n_fields)).
  This makes silent edits or deletions of historical rows detectable by
  recomputing the chain (see verify_chain()). It is NOT a substitute for
  proper file permissions / backups - it only gives you tamper *evidence*,
  not tamper *prevention*.
- All blocking sqlite3 calls are wrapped so they run in the executor thread
  pool via hass.async_add_executor_job from calling code - this module itself
  is synchronous by design and should never be called directly from the
  event loop.
"""
from __future__ import annotations

import hashlib
import json
import sqlite3
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional

GENESIS_HASH = "0" * 64

SCHEMA = """
CREATE TABLE IF NOT EXISTS events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts REAL NOT NULL,
    category TEXT NOT NULL,
    event_type TEXT NOT NULL,
    user_id TEXT,
    source_ip TEXT,
    entity_id TEXT,
    domain TEXT,
    outcome TEXT,
    data TEXT NOT NULL,
    prev_hash TEXT NOT NULL,
    row_hash TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_events_ts ON events (ts);
CREATE INDEX IF NOT EXISTS idx_events_category ON events (category);
CREATE INDEX IF NOT EXISTS idx_events_entity ON events (entity_id);
CREATE INDEX IF NOT EXISTS idx_events_user ON events (user_id);
"""


@dataclass
class LogEvent:
    """A single security log entry, prior to hashing/storage."""

    category: str
    event_type: str
    data: dict[str, Any] = field(default_factory=dict)
    ts: float = field(default_factory=time.time)
    user_id: Optional[str] = None
    source_ip: Optional[str] = None
    entity_id: Optional[str] = None
    domain: Optional[str] = None
    outcome: Optional[str] = None


def _canonical(payload: dict[str, Any]) -> str:
    """Deterministic JSON encoding so hashing is stable across runs."""
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str)


class SecurityStorage:
    """Synchronous SQLite-backed, hash-chained event store.

    Every public method here does blocking I/O and is meant to be invoked
    via `await hass.async_add_executor_job(storage.method, ...)` from the
    integration's async code - never awaited directly.
    """

    def __init__(self, db_path: str | Path) -> None:
        self.db_path = str(db_path)
        self._conn: Optional[sqlite3.Connection] = None
        # Serializes access to the single shared connection. HA's executor is
        # a multi-threaded pool and we open with check_same_thread=False, so
        # two writes can otherwise run concurrently. For append() specifically
        # that is a correctness bug, not just a sqlite-threading one: the
        # read-last-hash -> insert sequence is a read-modify-write, and two
        # interleaved appends would read the same prev_hash and fork the
        # chain, making verify_chain() report tampering that never happened.
        self._lock = threading.Lock()

    # -- lifecycle ------------------------------------------------------
    def open(self) -> None:
        Path(self.db_path).parent.mkdir(parents=True, exist_ok=True)
        self._conn = sqlite3.connect(self.db_path, check_same_thread=False)
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.execute("PRAGMA foreign_keys=ON")
        self._conn.executescript(SCHEMA)
        self._conn.commit()

    def close(self) -> None:
        if self._conn is not None:
            self._conn.close()
            self._conn = None

    # -- writes -----------------------------------------------------------
    def _last_hash(self) -> str:
        assert self._conn is not None
        cur = self._conn.execute(
            "SELECT row_hash FROM events ORDER BY id DESC LIMIT 1"
        )
        row = cur.fetchone()
        return row[0] if row else GENESIS_HASH

    def append(self, event: LogEvent) -> int:
        """Append one event to the chain. Returns the new row id.

        The whole read-last-hash -> hash -> insert -> commit sequence is held
        under self._lock so it is atomic with respect to other appends; see
        __init__ for why forking the chain would otherwise be possible.
        """
        assert self._conn is not None
        with self._lock:
            prev_hash = self._last_hash()
            payload = {
                "ts": event.ts,
                "category": event.category,
                "event_type": event.event_type,
                "user_id": event.user_id,
                "source_ip": event.source_ip,
                "entity_id": event.entity_id,
                "domain": event.domain,
                "outcome": event.outcome,
                "data": event.data,
            }
            row_hash = hashlib.sha256(
                (prev_hash + _canonical(payload)).encode("utf-8")
            ).hexdigest()

            cur = self._conn.execute(
                """
                INSERT INTO events
                    (ts, category, event_type, user_id, source_ip, entity_id,
                     domain, outcome, data, prev_hash, row_hash)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    event.ts,
                    event.category,
                    event.event_type,
                    event.user_id,
                    event.source_ip,
                    event.entity_id,
                    event.domain,
                    event.outcome,
                    _canonical(event.data),
                    prev_hash,
                    row_hash,
                ),
            )
            self._conn.commit()
            return cur.lastrowid

    # -- reads --------------------------------------------------------------
    def query(
        self,
        category: Optional[str] = None,
        entity_id: Optional[str] = None,
        user_id: Optional[str] = None,
        since: Optional[float] = None,
        until: Optional[float] = None,
        limit: int = 200,
        outcome: Optional[str] = None,
    ) -> list[dict[str, Any]]:
        assert self._conn is not None
        clauses = []
        params: list[Any] = []
        if category:
            clauses.append("category = ?")
            params.append(category)
        if entity_id:
            clauses.append("entity_id = ?")
            params.append(entity_id)
        if user_id:
            clauses.append("user_id = ?")
            params.append(user_id)
        if outcome:
            clauses.append("outcome = ?")
            params.append(outcome)
        if since is not None:
            clauses.append("ts >= ?")
            params.append(since)
        if until is not None:
            clauses.append("ts <= ?")
            params.append(until)

        where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
        sql = f"""
            SELECT id, ts, category, event_type, user_id, source_ip,
                   entity_id, domain, outcome, data
            FROM events
            {where}
            ORDER BY ts DESC
            LIMIT ?
        """
        params.append(limit)
        with self._lock:
            cur = self._conn.execute(sql, params)
            cols = [c[0] for c in cur.description]
            rows = cur.fetchall()
        results = []
        for row in rows:
            record = dict(zip(cols, row))
            record["data"] = json.loads(record["data"])
            results.append(record)
        return results

    # -- integrity ----------------------------------------------------------
    def verify_chain(self) -> dict[str, Any]:
        """Recompute the hash chain and report the first break, if any.

        Returns a dict: {"ok": bool, "checked": int, "broken_at_id": int|None}
        """
        assert self._conn is not None
        with self._lock:
            cur = self._conn.execute(
                """
                SELECT id, ts, category, event_type, user_id, source_ip,
                       entity_id, domain, outcome, data, prev_hash, row_hash
                FROM events ORDER BY id ASC
                """
            )
            rows = cur.fetchall()
        expected_prev = GENESIS_HASH
        checked = 0
        for row in rows:
            (
                row_id, ts, category, event_type, user_id, source_ip,
                entity_id, domain, outcome, data, prev_hash, row_hash,
            ) = row
            if prev_hash != expected_prev:
                return {"ok": False, "checked": checked, "broken_at_id": row_id}
            payload = {
                "ts": ts,
                "category": category,
                "event_type": event_type,
                "user_id": user_id,
                "source_ip": source_ip,
                "entity_id": entity_id,
                "domain": domain,
                "outcome": outcome,
                "data": json.loads(data),
            }
            recomputed = hashlib.sha256(
                (prev_hash + _canonical(payload)).encode("utf-8")
            ).hexdigest()
            if recomputed != row_hash:
                return {"ok": False, "checked": checked, "broken_at_id": row_id}
            expected_prev = row_hash
            checked += 1
        return {"ok": True, "checked": checked, "broken_at_id": None}

    # -- maintenance ----------------------------------------------------------
    def purge_older_than(self, cutoff_ts: float) -> int:
        """Delete events older than cutoff_ts.

        NOTE: this necessarily breaks the hash chain's ability to verify
        from genesis, since it removes rows. If you need long-term audit
        retention alongside pruning, export+archive (with its own hash of
        the exported blob) before purging rather than relying on purge
        alone. Left as an explicit, documented tradeoff rather than hidden
        behavior - see docs/ARCHITECTURE.md.
        """
        assert self._conn is not None
        with self._lock:
            cur = self._conn.execute("DELETE FROM events WHERE ts < ?", (cutoff_ts,))
            self._conn.commit()
            return cur.rowcount
