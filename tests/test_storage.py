"""Storage-layer tests. Pure stdlib + the storage module (no Home Assistant
runtime needed), so these run with a bare `pytest` or `python -m pytest`.

Covers the per-category hash chains, batch append, range-based verify, and
the retention / size-cap machinery, plus the concurrency regression guard for
the write race (append is a read-last-hash -> insert read-modify-write driven
from a multi-threaded executor over a single shared connection).
"""
import os
import sys
import tempfile
import time
from concurrent.futures import ThreadPoolExecutor

sys.path.insert(0, os.path.dirname(__file__))
import conftest  # noqa: F401,E402  (registers the warden package)

from warden.storage import SecurityStorage, LogEvent, GENESIS_HASH  # noqa: E402


def _fresh_storage() -> SecurityStorage:
    db = os.path.join(tempfile.mkdtemp(), "test.db")
    storage = SecurityStorage(db)
    storage.open()
    return storage


def test_append_and_verify_roundtrip():
    storage = _fresh_storage()
    for i in range(50):
        storage.append(LogEvent(category="device_state", event_type="x", data={"i": i}))
    result = storage.verify_chain()
    assert result["ok"] is True
    chain = result["chains"]["device_state"]
    assert chain["checked"] == 50
    assert chain["anchored_to_genesis"] is True
    assert chain["broken_at_id"] is None
    storage.close()


def test_verify_detects_tampering():
    storage = _fresh_storage()
    for i in range(10):
        storage.append(LogEvent(category="device_state", event_type="x", data={"i": i}))
    # Edit a row's data out from under the chain.
    storage._conn.execute("UPDATE events SET data = ? WHERE id = 5", ('{"i":999}',))
    storage._conn.commit()
    result = storage.verify_chain()
    assert result["ok"] is False
    assert result["chains"]["device_state"]["broken_at_id"] == 5
    storage.close()


def test_categories_have_independent_chains():
    """A break in one category must not falsely implicate another."""
    storage = _fresh_storage()
    for i in range(5):
        storage.append(LogEvent(category="device_state", event_type="x", data={"i": i}))
        storage.append(LogEvent(category="auth_attempt", event_type="x", outcome="failure"))
    # Tamper with a device_state row only.
    storage._conn.execute(
        "UPDATE events SET data = ? WHERE id = "
        "(SELECT id FROM events WHERE category = 'device_state' ORDER BY id LIMIT 1)",
        ('{"i":42}',),
    )
    storage._conn.commit()
    result = storage.verify_chain()
    assert result["ok"] is False
    assert result["chains"]["device_state"]["ok"] is False
    assert result["chains"]["auth_attempt"]["ok"] is True
    storage.close()


def test_batch_append_chains_correctly():
    storage = _fresh_storage()
    batch = [
        LogEvent(category="device_state", event_type="x", entity_id=f"e{i}", data={"i": i})
        for i in range(30)
    ] + [
        LogEvent(category="auth_attempt", event_type="x", outcome="failure")
        for _ in range(10)
    ]
    assert storage.append_batch(batch) == 40
    result = storage.verify_chain()
    assert result["ok"] is True
    assert result["chains"]["device_state"]["checked"] == 30
    assert result["chains"]["auth_attempt"]["checked"] == 10
    storage.close()


def test_query_filters_by_outcome():
    storage = _fresh_storage()
    storage.append(LogEvent(category="auth_attempt", event_type="x", outcome="failure"))
    storage.append(LogEvent(category="auth_attempt", event_type="x", outcome="failure"))
    storage.append(LogEvent(category="auth_attempt", event_type="x", outcome="success"))

    failures = storage.query(category="auth_attempt", outcome="failure")
    assert len(failures) == 2
    assert all(row["outcome"] == "failure" for row in failures)
    assert len(storage.query(category="auth_attempt")) == 3
    storage.close()


def test_enforce_retention_is_per_category():
    storage = _fresh_storage()
    now = time.time()
    old = now - 10 * 86400  # 10 days ago
    for _ in range(5):
        storage.append(LogEvent(category="device_state", event_type="x", ts=old))
        storage.append(LogEvent(category="auth_attempt", event_type="x", ts=old, outcome="failure"))
    storage.append(LogEvent(category="device_state", event_type="x", ts=now))

    # device_state kept 1 day, auth kept 365, maintenance kept forever.
    deleted = storage.enforce_retention(
        {"device_state": 1, "auth_attempt": 365}, default_days=None
    )
    assert deleted.get("device_state") == 5  # the 5 old ones
    assert "auth_attempt" not in deleted     # all within 365d

    remaining_ds = storage.query(category="device_state", limit=100)
    remaining_auth = storage.query(category="auth_attempt", limit=100)
    assert len(remaining_ds) == 1            # only the fresh one
    assert len(remaining_auth) == 5

    # The surviving device_state chain is still internally consistent, just no
    # longer anchored to genesis; auth is untouched and still anchored.
    result = storage.verify_chain()
    assert result["ok"] is True
    assert result["chains"]["device_state"]["anchored_to_genesis"] is False
    assert result["chains"]["auth_attempt"]["anchored_to_genesis"] is True
    # The purge was recorded as an auditable maintenance event.
    assert len(storage.query(category="maintenance", limit=10)) == 1
    storage.close()


def test_enforce_size_cap_shrinks_and_deletes():
    storage = _fresh_storage()
    blob = {"payload": "x" * 512}
    for i in range(4000):
        storage.append(LogEvent(category="device_state", event_type="x", data=dict(blob, i=i)))
    initial = storage._db_size_bytes()
    cap = initial // 2
    deleted = storage.enforce_size_cap(cap)
    final = storage._db_size_bytes()
    assert deleted > 0
    assert final < initial
    storage.close()


def test_size_cap_disabled_when_zero():
    storage = _fresh_storage()
    for i in range(10):
        storage.append(LogEvent(category="device_state", event_type="x", data={"i": i}))
    assert storage.enforce_size_cap(0) == 0
    assert len(storage.query(category="device_state", limit=100)) == 10
    storage.close()


def test_query_offset_and_count():
    storage = _fresh_storage()
    for i in range(25):
        storage.append(LogEvent(category="device_state", event_type="x", data={"i": i}))
    assert storage.count(category="device_state") == 25
    page1 = storage.query(category="device_state", limit=10, offset=0)
    page2 = storage.query(category="device_state", limit=10, offset=10)
    assert len(page1) == 10 and len(page2) == 10
    # Newest-first, non-overlapping pages.
    assert {r["id"] for r in page1}.isdisjoint({r["id"] for r in page2})
    assert page1[0]["id"] > page2[0]["id"]
    storage.close()


def test_search_and_count_match():
    storage = _fresh_storage()
    storage.append(LogEvent(category="device_state", event_type="state_changed", entity_id="lock.front"))
    storage.append(LogEvent(category="device_state", event_type="state_changed", entity_id="lock.back"))
    storage.append(LogEvent(category="user_action", event_type="call_service", entity_id="light.kitchen"))
    assert storage.count(search="lock") == 2
    rows = storage.query(search="lock", limit=50)
    assert len(rows) == 2
    assert all("lock" in r["entity_id"] for r in rows)
    storage.close()


def test_concurrent_appends_keep_chain_intact():
    storage = _fresh_storage()
    n = 2000

    def writer(i: int) -> None:
        storage.append(
            LogEvent(
                category="device_state",
                event_type="state_changed",
                entity_id=f"lock.front_{i % 5}",
                data={"i": i},
            )
        )

    with ThreadPoolExecutor(max_workers=16) as pool:
        list(pool.map(writer, range(n)))

    result = storage.verify_chain()
    assert result["ok"] is True, result
    assert result["chains"]["device_state"]["checked"] == n
    storage.close()


if __name__ == "__main__":
    test_append_and_verify_roundtrip()
    test_verify_detects_tampering()
    test_categories_have_independent_chains()
    test_batch_append_chains_correctly()
    test_query_filters_by_outcome()
    test_enforce_retention_is_per_category()
    test_enforce_size_cap_shrinks_and_deletes()
    test_size_cap_disabled_when_zero()
    test_query_offset_and_count()
    test_search_and_count_match()
    test_concurrent_appends_keep_chain_intact()
    print("all storage tests passed")
