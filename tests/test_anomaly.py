"""Anomaly engine + baseline-rehydration tests. Pure stdlib + the anomaly,
history and storage modules (no Home Assistant runtime).
"""
import os
import sys
import tempfile

sys.path.insert(0, os.path.dirname(__file__))
import conftest  # noqa: F401,E402  (registers the warden package)

from warden.anomaly import AnomalyEngine  # noqa: E402
from warden.history import reconstruct_hourly_observations  # noqa: E402
from warden.storage import SecurityStorage, LogEvent  # noqa: E402


def test_cold_engine_will_not_flag_before_min_samples():
    engine = AnomalyEngine(z_threshold=3.0, min_samples=8)
    # A big spike on a cold bucket must not flag - baseline isn't trusted yet.
    assert engine.record_period("lock.front", 3, 99) is None


def test_warmed_engine_flags_spike_immediately():
    """The point of rehydration: after a restart, a warmed baseline should be
    able to flag on the very next observation instead of waiting ~8 days."""
    engine = AnomalyEngine(z_threshold=3.0, min_samples=8)
    # 10 historical days where hour 3 always saw ~1 event.
    history = [("lock.front", 3, 1) for _ in range(10)]
    applied = engine.warm_from_history(history)
    assert applied == 10

    # A sudden spike in that hour is flagged straight away.
    result = engine.record_period("lock.front", 3, 40)
    assert result is not None
    assert result["entity_id"] == "lock.front"
    assert result["observed_count"] == 40
    assert result["z_score"] >= 3.0


def test_reconstruct_hourly_observations_from_log():
    db = os.path.join(tempfile.mkdtemp(), "hist.db")
    storage = SecurityStorage(db)
    storage.open()

    hour = 3600
    now_hour_index = int(__import__("time").time() // hour)
    # Three complete past hours for one entity, with 2 / 3 / 1 events.
    plan = {now_hour_index - 5: 2, now_hour_index - 4: 3, now_hour_index - 3: 1}
    for hour_index, count in plan.items():
        for _ in range(count):
            storage.append(
                LogEvent(
                    category="device_state",
                    event_type="state_changed",
                    entity_id="binary_sensor.door",
                    ts=hour_index * hour + 10,
                    data={},
                )
            )
    # Two events in the *current* (incomplete) hour - must be excluded.
    for _ in range(2):
        storage.append(
            LogEvent(
                category="device_state",
                event_type="state_changed",
                entity_id="binary_sensor.door",
                data={},  # ts defaults to now
            )
        )
    # An event in a different category - must be ignored.
    storage.append(
        LogEvent(category="user_action", event_type="call_service",
                 entity_id="binary_sensor.door", ts=(now_hour_index - 4) * hour, data={})
    )

    obs = reconstruct_hourly_observations(storage, lookback_days=30)
    # Counts, in chronological order, current hour excluded.
    assert [count for (_e, _h, count) in obs] == [2, 3, 1]
    assert all(entity == "binary_sensor.door" for (entity, _h, _c) in obs)
    storage.close()


if __name__ == "__main__":
    test_cold_engine_will_not_flag_before_min_samples()
    test_warmed_engine_flags_spike_immediately()
    test_reconstruct_hourly_observations_from_log()
    print("all anomaly tests passed")
