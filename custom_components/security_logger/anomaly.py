"""Baseline / anomaly detection for device behaviour.

This is intentionally the simplest thing that can work: a per-entity,
per-hour-of-day rolling frequency baseline with z-score based outlier
detection. It is NOT machine learning, and that is a deliberate choice for
v1 - it's auditable, explainable ("this fired because door sensor X had
14 events in this hour vs. a baseline of 1.2 +/- 0.8"), and cheap to run on
a Raspberry Pi. See docs/ROADMAP.md for where a heavier model could plug in
later without changing the storage schema.
"""
from __future__ import annotations

import math
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Iterable, Optional


@dataclass
class _Bucket:
    """Running (count, mean, M2) per hour-of-day bucket - Welford's algorithm
    so we never have to store the full event history in memory."""

    n: int = 0
    mean: float = 0.0
    m2: float = 0.0

    def update(self, x: float) -> None:
        self.n += 1
        delta = x - self.mean
        self.mean += delta / self.n
        delta2 = x - self.mean
        self.m2 += delta * delta2

    @property
    def stddev(self) -> float:
        if self.n < 2:
            return 0.0
        return math.sqrt(self.m2 / (self.n - 1))

    def z_score(self, x: float) -> float:
        sd = self.stddev
        if sd == 0:
            # Zero observed variance so far (e.g. this hour has always seen
            # exactly 1 event, every day). A plain division by zero would
            # crash; silently returning 0 would mean a perfectly stable
            # baseline could NEVER be flagged no matter how far off a new
            # observation is - which is exactly the case ("always 1, then
            # suddenly 50") you most want caught. Instead, fall back to an
            # absolute-deviation check: if the new value differs at all
            # from a rock-solid baseline, treat that as a large z-score.
            if x == self.mean:
                return 0.0
            return 6.0 if x > self.mean else -6.0
        return (x - self.mean) / sd


@dataclass
class EntityBaseline:
    """Per-entity baseline: one _Bucket per hour-of-day (0-23)."""

    entity_id: str
    buckets: dict[int, _Bucket] = field(
        default_factory=lambda: defaultdict(_Bucket)
    )

    def observe_count(self, hour_of_day: int, count_in_period: float) -> float:
        """Record this period's event count for this hour-of-day and return
        the z-score of that count against the baseline *before* this update
        (so the current observation doesn't dilute its own anomaly score)."""
        bucket = self.buckets[hour_of_day]
        z = bucket.z_score(count_in_period)
        bucket.update(count_in_period)
        return z


class AnomalyEngine:
    """Holds baselines for all monitored entities and flags outliers."""

    def __init__(self, z_threshold: float = 3.0, min_samples: int = 8) -> None:
        self.z_threshold = z_threshold
        self.min_samples = min_samples
        self._baselines: dict[str, EntityBaseline] = {}

    def _get_baseline(self, entity_id: str) -> EntityBaseline:
        if entity_id not in self._baselines:
            self._baselines[entity_id] = EntityBaseline(entity_id=entity_id)
        return self._baselines[entity_id]

    def warm_from_history(
        self, observations: Iterable[tuple[str, int, int]]
    ) -> int:
        """Seed baselines from past (entity_id, hour_of_day, count)
        observations *without* flagging anything, and return how many were
        applied.

        Baselines live only in memory, so without this every Home Assistant
        restart reset them to cold - and with min_samples=8 that means ~8
        days of uptime before anything can be flagged again. Since HA is
        commonly restarted more often than that, detection would in practice
        almost never fire. Rehydrating from the persisted event log on
        startup (see __init__.py) closes that gap. Feed observations in
        chronological order so the rolling baseline matches the live path.
        """
        applied = 0
        for entity_id, hour_of_day, count in observations:
            self._get_baseline(entity_id).observe_count(hour_of_day, float(count))
            applied += 1
        return applied

    def record_period(
        self, entity_id: str, hour_of_day: int, count_in_period: int
    ) -> Optional[dict]:
        """Feed one period's observation (e.g. "6 events between 2-3am").

        Returns an anomaly dict if this observation is flagged, else None.
        Requires `min_samples` prior observations for that hour-of-day
        before it will flag anything, to avoid false positives while the
        baseline is still cold.
        """
        baseline = self._get_baseline(entity_id)
        bucket = baseline.buckets[hour_of_day]
        samples_before = bucket.n
        z = baseline.observe_count(hour_of_day, float(count_in_period))

        if samples_before < self.min_samples:
            return None
        if abs(z) >= self.z_threshold:
            return {
                "entity_id": entity_id,
                "hour_of_day": hour_of_day,
                "observed_count": count_in_period,
                "baseline_mean": round(bucket.mean, 3),
                "baseline_stddev": round(bucket.stddev, 3),
                "z_score": round(z, 3),
            }
        return None
