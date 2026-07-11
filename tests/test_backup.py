"""Backup handler tests. The HA-facing subscribe/setup is lazy-imported, so
the handler logic (_make_handler) is testable with fake event objects - we
only rely on the event class *name* and its `state`/`reason` attributes.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(__file__))
import conftest  # noqa: F401,E402  (registers the warden package)

from warden.backup_listener import _make_handler  # noqa: E402


# Fakes whose class __name__ matches what the manager delivers.
class CreateBackupEvent:
    def __init__(self, state=None, reason=None):
        self.state = state
        self.reason = reason


class RestoreBackupEvent:
    pass


class IdleEvent:
    pass


def test_create_flow_logs_start_once_then_failure():
    events = []
    handler = _make_handler(events.append)

    handler(CreateBackupEvent(state="in_progress"))
    handler(CreateBackupEvent(state="in_progress"))  # progress tick: no dupe
    assert [e.event_type for e in events] == ["backup_create_started"]

    handler(CreateBackupEvent(state="failed", reason="agent_error"))
    assert events[-1].event_type == "backup_create_failed"
    assert events[-1].outcome == "failure"
    assert events[-1].data["reason"] == "agent_error"

    # A fresh flow after idle logs start again.
    handler(IdleEvent())
    handler(CreateBackupEvent(state="in_progress"))
    assert events[-1].event_type == "backup_create_started"


def test_successful_create_does_not_log_failure():
    events = []
    handler = _make_handler(events.append)
    handler(CreateBackupEvent(state="in_progress"))
    handler(CreateBackupEvent(state="completed"))
    handler(IdleEvent())
    assert [e.event_type for e in events] == ["backup_create_started"]


def test_restore_logs_start_once():
    events = []
    handler = _make_handler(events.append)
    handler(RestoreBackupEvent())
    handler(RestoreBackupEvent())
    assert [e.event_type for e in events] == ["backup_restore_started"]


if __name__ == "__main__":
    test_create_flow_logs_start_once_then_failure()
    test_successful_create_does_not_log_failure()
    test_restore_logs_start_once()
    print("all backup tests passed")
