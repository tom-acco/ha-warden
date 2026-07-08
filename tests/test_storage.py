"""Storage-layer tests. Pure stdlib + the storage module (no Home Assistant
runtime needed), so these run with a bare `pytest` or `python -m pytest`.

The concurrency test is a regression guard for the hash-chain write race:
append() is a read-last-hash -> insert read-modify-write, and HA drives it
from a multi-threaded executor over a single shared connection. Without
serialization, interleaved appends fork the chain and verify_chain() then
reports tampering that never happened.
"""
import os
import sys
import tempfile
from concurrent.futures import ThreadPoolExecutor

sys.path.insert(0, os.path.dirname(__file__))
import conftest  # noqa: F401,E402  (registers the security_logger package)

from security_logger.storage import SecurityStorage, LogEvent  # noqa: E402


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
    assert result == {"ok": True, "checked": 50, "broken_at_id": None}
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
    assert result["broken_at_id"] == 5
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
    assert result["checked"] == n
    storage.close()


if __name__ == "__main__":
    test_append_and_verify_roundtrip()
    test_verify_detects_tampering()
    test_query_filters_by_outcome()
    test_concurrent_appends_keep_chain_intact()
    print("all storage tests passed")
