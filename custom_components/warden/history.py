"""Reconstructing anomaly-baseline observations from the persisted log.

Kept free of any Home Assistant imports (depends only on storage + const) so
it can be unit-tested standalone and so the reconstruction logic lives next
to nothing else. See docs/ARCHITECTURE.md ("Why anomaly detection is a
z-score baseline") and __init__.py for how the result is used on startup.
"""
from __future__ import annotations

import time

from .const import ANOMALY_HISTORY_LOOKBACK_DAYS, CATEGORY_STATE
from .storage import SecurityStorage


def reconstruct_hourly_observations(
    storage: SecurityStorage, lookback_days: int = ANOMALY_HISTORY_LOOKBACK_DAYS
) -> list[tuple[str, int, int]]:
    """Rebuild the per-clock-hour event counts the live tick would have
    produced, from persisted device_state history, so baselines can be warmed
    on startup.

    Returns a list of (entity_id, hour_of_day, count) in chronological order.
    Mirrors the live tick's semantics: one observation per entity per hour it
    had at least one event (hours with zero events are simply not observed,
    exactly as in the live path). The current, still-incomplete clock hour is
    excluded so a partial count can't bias the baseline - the live tick will
    record it once it finishes.

    Runs blocking sqlite via storage.query; call it on the executor.
    """
    since = time.time() - lookback_days * 86400
    rows = storage.query(category=CATEGORY_STATE, since=since, limit=1_000_000)

    current_hour_index = int(time.time() // 3600)
    per_hour: dict[tuple[str, int], int] = {}
    for row in rows:
        entity_id = row.get("entity_id")
        if not entity_id:
            continue
        hour_index = int(row["ts"] // 3600)
        if hour_index >= current_hour_index:
            continue  # skip the in-progress hour
        per_hour[(entity_id, hour_index)] = per_hour.get((entity_id, hour_index), 0) + 1

    # Sort by hour_index so baselines are fed chronologically.
    ordered = sorted(per_hour.items(), key=lambda kv: kv[0][1])
    return [
        (entity_id, time.localtime(hour_index * 3600).tm_hour, count)
        for (entity_id, hour_index), count in ordered
    ]
