"""Backup create/restore capture.

Backups are high-value for a security log: downloading a backup is config
*exfiltration*, and restoring an old one is a classic way to *cover tracks*.
But the backup integration is awkward to observe (verified against HA 2026-07):
it fires no bus event, its create message is DEBUG-only (so our WARNING-level
log handler can't see it), and restore isn't logged at all. The one workable
hook is the backup manager's own event stream: `async_get_manager(hass)` ->
`manager.async_subscribe_events(cb)`, which delivers dataclass events including
`CreateBackupEvent` / `RestoreBackupEvent` / `IdleEvent`.

Those events carry only `manager_state` / `stage` / `state` / `reason` - NOT
the backup id, name, or protection flag (there's nothing to enrich with there).
So we match on the event *type name* (stable) and log the *start* of each
create/restore flow, plus - best-effort, from the `state` string - a
`backup_create_failed` when a create fails (a failed backup is itself worth
knowing). Restore is logged at start because a restore restarts HA, so we'd
never see it complete.

Everything is wrapped defensively: if the backup integration or this internal
API isn't present/changes, backup capture silently disables itself rather than
breaking Warden. HA imports are lazy so this module (and its handler logic)
stays importable and unit-testable without Home Assistant.
"""
from __future__ import annotations

import logging
from typing import Callable

from .const import AUTH_FAILURE, CATEGORY_SYSTEM
from .storage import LogEvent

_LOGGER = logging.getLogger(__name__)


def _state_str(event: object) -> str | None:
    """Lower-cased string of the event's `state` (a StrEnum or plain value),
    or None. Read via getattr so an event without `state` is fine."""
    state = getattr(event, "state", None)
    if state is None:
        return None
    return str(getattr(state, "value", state)).lower()


def _make_handler(enqueue: Callable[[LogEvent], None]) -> Callable[[object], None]:
    # The manager emits many progress events per operation; we log the start of
    # a create/restore flow once, plus a create failure once, and reset on idle.
    flow = {"create": False, "restore": False, "create_failed": False}

    def _on_event(event: object) -> None:
        name = type(event).__name__
        if name == "CreateBackupEvent":
            if not flow["create"]:
                flow["create"] = True
                enqueue(LogEvent(category=CATEGORY_SYSTEM, event_type="backup_create_started"))
            state = _state_str(event)
            if state and "fail" in state and not flow["create_failed"]:
                flow["create_failed"] = True
                enqueue(
                    LogEvent(
                        category=CATEGORY_SYSTEM,
                        event_type="backup_create_failed",
                        outcome=AUTH_FAILURE,
                        data={"reason": getattr(event, "reason", None)},
                    )
                )
        elif name == "RestoreBackupEvent":
            if not flow["restore"]:
                flow["restore"] = True
                enqueue(LogEvent(category=CATEGORY_SYSTEM, event_type="backup_restore_started"))
        elif name == "IdleEvent":
            flow["create"] = False
            flow["restore"] = False
            flow["create_failed"] = False

    return _on_event


def setup_backup_capture(hass, enqueue: Callable[[LogEvent], None]) -> Callable[[], None]:
    """Subscribe to the backup manager's events. Returns an unsubscribe.

    The manager may load after us, so if it isn't ready yet we retry once HA
    has fully started.
    """
    from homeassistant.const import EVENT_HOMEASSISTANT_STARTED

    unsubs: list[Callable[[], None]] = []
    handler = _make_handler(enqueue)

    def _subscribe(_event=None) -> None:
        try:
            from homeassistant.components.backup import async_get_manager

            manager = async_get_manager(hass)
            unsubs.append(manager.async_subscribe_events(handler))
        except Exception as err:  # noqa: BLE001 - never let backup break setup
            _LOGGER.debug("Warden: backup capture unavailable: %s", err)

    if hass.is_running:
        _subscribe()
    else:
        unsubs.append(
            hass.bus.async_listen_once(EVENT_HOMEASSISTANT_STARTED, _subscribe)
        )

    def _remove() -> None:
        for unsub in unsubs:
            unsub()

    return _remove
