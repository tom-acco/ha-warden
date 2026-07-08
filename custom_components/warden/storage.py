"""Tamper-evident storage layer for Warden.

Design notes (see docs/ARCHITECTURE.md for the full rationale):

- Storage is a dedicated SQLite database, separate from Home Assistant's own
  recorder database, so wiping/restoring the HA config does not also wipe
  the security log.
- Rows are hash-chained *per category*: hash(row_n) =
  SHA256(prev_hash + canonical_json(row_n_fields)), where prev_hash is the
  row_hash of the previous row *in the same category*. A single global chain
  would mean deleting old, high-volume `device_state` rows from the middle of
  the chain breaks the prev_hash link for every later row of every category -
  so selective/tiered retention (keep auth+anomalies long, expire noisy
  device_state fast) would be incompatible with tamper-evidence. Per-category
  chains let each category be verified and purged independently: expiring old
  device_state only re-anchors the device_state chain, leaving the auth chain
  fully verifiable. This is tamper *evidence*, not tamper *prevention* - pair
  it with file permissions and backups.
- verify_chain() reports the *verifiable range* per category rather than a
  bare pass/fail, and whether each chain still anchors to genesis. After a
  legitimate purge the earliest surviving row no longer links to genesis;
  that is expected and is reported as `anchored_to_genesis: False`, not as
  tampering. Purges are themselves recorded as `maintenance`/`purge` events
  so they are auditable rather than looking like silent deletions.
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

# Category used for the integration's own audit records (currently purge
# events). Kept here so this module stays free of any other-module imports;
# const.CATEGORY_MAINTENANCE mirrors it for the rest of the integration.
MAINTENANCE_CATEGORY = "maintenance"

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
-- Supports both the per-category last-hash lookup on write and per-category
-- ordered scans on verify.
CREATE INDEX IF NOT EXISTS idx_events_cat_id ON events (category, id);
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
    """Synchronous SQLite-backed, per-category hash-chained event store.

    Every public method here does blocking I/O and is meant to be invoked
    via `await hass.async_add_executor_job(storage.method, ...)` from the
    integration's async code - never awaited directly.
    """

    # How many oldest rows to delete per iteration when enforcing the size cap.
    _SIZE_PRUNE_CHUNK = 1000

    def __init__(self, db_path: str | Path) -> None:
        self.db_path = str(db_path)
        self._conn: Optional[sqlite3.Connection] = None
        # Serializes access to the single shared connection. HA's executor is
        # a multi-threaded pool and we open with check_same_thread=False, so
        # two writes could otherwise run concurrently. For the write path that
        # is a correctness bug, not just a sqlite-threading one: appending is a
        # read-last-hash -> insert read-modify-write, and two interleaved
        # appends would read the same prev_hash and fork the chain, making
        # verify_chain() report tampering that never happened. All public
        # methods acquire this; the `_locked` helpers assume it is held.
        self._lock = threading.Lock()

    # -- lifecycle ------------------------------------------------------
    def open(self) -> None:
        Path(self.db_path).parent.mkdir(parents=True, exist_ok=True)
        self._conn = sqlite3.connect(self.db_path, check_same_thread=False)
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.execute("PRAGMA foreign_keys=ON")
        # INCREMENTAL auto_vacuum lets us actually return freed pages to the OS
        # after a purge (plain DELETE only marks pages free). The setting only
        # takes effect on a fresh DB or after a VACUUM, so apply one if this DB
        # wasn't already in INCREMENTAL mode (2).
        current_auto_vacuum = self._conn.execute("PRAGMA auto_vacuum").fetchone()[0]
        self._conn.execute("PRAGMA auto_vacuum=INCREMENTAL")
        self._conn.executescript(SCHEMA)
        if current_auto_vacuum != 2:
            self._conn.execute("VACUUM")
        self._conn.commit()

    def close(self) -> None:
        if self._conn is not None:
            self._conn.close()
            self._conn = None

    # -- writes -----------------------------------------------------------
    def _last_hash(self, category: str) -> str:
        """row_hash of the most recent row in `category`, or GENESIS if none.

        Reads the current connection, so within an uncommitted batch it sees
        rows inserted earlier in the same batch - which is exactly what chains
        successive same-category events together correctly.
        """
        assert self._conn is not None
        cur = self._conn.execute(
            "SELECT row_hash FROM events WHERE category = ? ORDER BY id DESC LIMIT 1",
            (category,),
        )
        row = cur.fetchone()
        return row[0] if row else GENESIS_HASH

    @staticmethod
    def _payload(event: LogEvent) -> dict[str, Any]:
        return {
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

    def _insert_locked(self, event: LogEvent) -> int:
        """Insert one event, chained to its category's last row. No commit.

        Caller must hold self._lock and commit afterwards.
        """
        assert self._conn is not None
        prev_hash = self._last_hash(event.category)
        payload = self._payload(event)
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
        return cur.lastrowid

    def append(self, event: LogEvent) -> int:
        """Append one event and commit. Returns the new row id."""
        with self._lock:
            row_id = self._insert_locked(event)
            self._conn.commit()
            return row_id

    def append_batch(self, events: list[LogEvent]) -> int:
        """Append many events in a single transaction. Returns the count.

        This is the path the integration's write buffer uses: one commit for
        the whole batch instead of one commit (and fsync) per event, which is
        the point of buffering. Each event is still chained correctly to the
        prior same-category row - including other events earlier in this same
        batch - because _last_hash reads uncommitted rows on this connection.
        """
        if not events:
            return 0
        with self._lock:
            for event in events:
                self._insert_locked(event)
            self._conn.commit()
            return len(events)

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
        """Recompute the per-category hash chains and report each one's state.

        Returns:
            {
              "ok": bool,          # every category chain internally consistent
              "chains": {
                 <category>: {
                    "checked": int,
                    "first_id": int, "last_id": int,
                    "anchored_to_genesis": bool,  # False after a purge - expected
                    "ok": bool,
                    "broken_at_id": int | None,
                 }, ...
              }
            }

        "ok"/"broken_at_id" reflect *internal* consistency of the surviving
        rows: any edit, insert, or deletion within a chain breaks a link and
        is caught. What this cannot detect is deletion of the oldest
        (prefix) rows - the surviving sub-chain stays self-consistent - which
        is why `anchored_to_genesis` is reported separately and why purges are
        logged as their own events.
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

        chains: dict[str, dict[str, Any]] = {}
        for row in rows:
            (
                row_id, ts, category, event_type, user_id, source_ip,
                entity_id, domain, outcome, data, prev_hash, row_hash,
            ) = row
            state = chains.get(category)
            if state is None:
                # First surviving row of this category: it anchors the chain we
                # can verify from here on. We can't verify its link to whatever
                # came before (possibly purged), so seed expected_prev with its
                # own stored prev_hash and record whether that is genesis.
                state = chains[category] = {
                    "checked": 0,
                    "first_id": row_id,
                    "last_id": row_id,
                    "anchored_to_genesis": prev_hash == GENESIS_HASH,
                    "ok": True,
                    "broken_at_id": None,
                    "_expected_prev": prev_hash,
                }
            if not state["ok"]:
                continue
            if prev_hash != state["_expected_prev"]:
                state["ok"] = False
                state["broken_at_id"] = row_id
                continue
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
                state["ok"] = False
                state["broken_at_id"] = row_id
                continue
            state["_expected_prev"] = row_hash
            state["last_id"] = row_id
            state["checked"] += 1

        clean = {
            category: {k: v for k, v in state.items() if not k.startswith("_")}
            for category, state in chains.items()
        }
        return {"ok": all(c["ok"] for c in clean.values()), "chains": clean}

    # -- maintenance ----------------------------------------------------------
    def _record_purge_locked(self, reason: str, detail: dict[str, Any]) -> None:
        """Log a maintenance/purge event so a deletion is itself auditable.
        Caller holds the lock; does not commit."""
        self._insert_locked(
            LogEvent(
                category=MAINTENANCE_CATEGORY,
                event_type="purge",
                outcome=reason,
                data=detail,
            )
        )

    def _reclaim_locked(self) -> None:
        """Checkpoint the WAL and return freed pages to the OS. Best-effort:
        incremental_vacuum only frees pages when auto_vacuum is INCREMENTAL
        (guaranteed for DBs opened by open())."""
        assert self._conn is not None
        try:
            self._conn.execute("PRAGMA wal_checkpoint(TRUNCATE)")
            self._conn.execute("PRAGMA incremental_vacuum")
            self._conn.commit()
        except sqlite3.Error:
            pass

    def _db_size_bytes(self) -> int:
        total = 0
        for suffix in ("", "-wal", "-shm"):
            path = Path(self.db_path + suffix)
            if path.exists():
                total += path.stat().st_size
        return total

    def enforce_retention(
        self, policy: dict[str, int], default_days: Optional[int] = None
    ) -> dict[str, int]:
        """Delete rows older than a per-category age limit.

        `policy` maps category -> retention days; categories absent from it
        fall back to `default_days`. A value of None (in policy or as the
        default) means "keep forever". Returns {category: rows_deleted} for
        categories that actually lost rows. Per-category deletion is safe for
        the chains precisely because each category has its own chain.
        """
        assert self._conn is not None
        now = time.time()
        with self._lock:
            categories = [
                r[0] for r in self._conn.execute(
                    "SELECT DISTINCT category FROM events"
                ).fetchall()
            ]
            deleted: dict[str, int] = {}
            for category in categories:
                days = policy.get(category, default_days)
                if days is None:
                    continue
                cutoff = now - days * 86400
                cur = self._conn.execute(
                    "DELETE FROM events WHERE category = ? AND ts < ?",
                    (category, cutoff),
                )
                if cur.rowcount:
                    deleted[category] = cur.rowcount
            if deleted:
                self._record_purge_locked(
                    "retention", {"deleted_by_category": deleted}
                )
                self._conn.commit()
                self._reclaim_locked()
            else:
                self._conn.commit()
            return deleted

    def enforce_size_cap(self, max_bytes: int) -> int:
        """Hard backstop against disk fill: if the DB exceeds max_bytes, delete
        the oldest rows (globally, oldest-first) until it's back under the cap.

        Oldest-first means this can evict security-relevant rows during a flood
        of noise - it's a safety net, not the primary policy (that's
        enforce_retention). `max_bytes <= 0` disables it. Returns rows deleted.
        """
        assert self._conn is not None
        if max_bytes <= 0:
            return 0
        with self._lock:
            deleted_total = 0
            prev_size: Optional[int] = None
            for _ in range(10_000):  # safety bound on iterations
                size = self._db_size_bytes()
                if size <= max_bytes:
                    break
                if prev_size is not None and size >= prev_size:
                    # Not shrinking (e.g. auto_vacuum couldn't reclaim) - stop
                    # rather than delete everything to no effect.
                    break
                prev_size = size
                ids = [
                    r[0] for r in self._conn.execute(
                        "SELECT id FROM events ORDER BY id ASC LIMIT ?",
                        (self._SIZE_PRUNE_CHUNK,),
                    ).fetchall()
                ]
                if not ids:
                    break
                placeholders = ",".join("?" * len(ids))
                self._conn.execute(
                    f"DELETE FROM events WHERE id IN ({placeholders})", ids
                )
                self._conn.commit()
                deleted_total += len(ids)
                self._reclaim_locked()
            if deleted_total:
                self._record_purge_locked(
                    "size_cap", {"deleted": deleted_total, "max_bytes": max_bytes}
                )
                self._conn.commit()
                self._reclaim_locked()
            return deleted_total

    def purge_older_than(self, cutoff_ts: float) -> int:
        """Delete all events older than cutoff_ts, across every category.

        Used by the manual `purge_old` service. Records the purge as its own
        event and reclaims freed space. As with any purge, this re-anchors the
        affected chains (verify_chain will report the surviving rows as no
        longer anchored to genesis); see the class docstring.
        """
        assert self._conn is not None
        with self._lock:
            cur = self._conn.execute("DELETE FROM events WHERE ts < ?", (cutoff_ts,))
            deleted = cur.rowcount
            if deleted:
                self._record_purge_locked(
                    "manual", {"deleted": deleted, "cutoff_ts": cutoff_ts}
                )
            self._conn.commit()
            self._reclaim_locked()
            return deleted
