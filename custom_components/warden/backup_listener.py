"""Backup create/restore capture.

Backups are high-value for a security log: downloading a backup is config
*exfiltration*, and restoring an old one is a classic way to *cover tracks*.
But the backup integration is awkward to observe (verified against HA 2026-07):
it fires no bus event, its create message is DEBUG-only (so our WARNING-level
log handler can't see it), and restore isn't logged at all. The one workable
hook is the backup manager's own event stream: `async_get_manager(hass)` ->
`manager.async_subscribe_events(cb)`, which delivers dataclass events including
`CreateBackupEvent` / `RestoreBackupEvent`.

We match on the event *type name* (stable) rather than its internal state/stage
enums (less so), and log the *start* of each create/restore flow - which is
what a security log wants ("someone initiated a backup/restore"), not progress
ticks. Everything is wrapped defensively: if the backup integration or this
internal API isn't present/changes, backup capture silently disables itself
rather than breaking Warden.
"""
from __future__ import annotations

import logging
from typing import Callable

from homeassistant.const import EVENT_HOMEASSISTANT_STARTED
from homeassistant.core import HomeAssistant

from .const import CATEGORY_SYSTEM
from .storage import LogEvent

_LOGGER = logging.getLogger(__name__)


def _make_handler(enqueue: Callable[[LogEvent], None]) -> Callable[[object], None]:
    # One event per flow: the manager emits many progress events; we log only
    # the transition into a create/restore flow and reset on the idle event.
    flow = {"create": False, "restore": False}

    def _on_event(event: object) -> None:
        name = type(event).__name__
        if name == "CreateBackupEvent":
            if not flow["create"]:
                flow["create"] = True
                enqueue(LogEvent(category=CATEGORY_SYSTEM, event_type="backup_create_started"))
        elif name == "RestoreBackupEvent":
            if not flow["restore"]:
                flow["restore"] = True
                enqueue(LogEvent(category=CATEGORY_SYSTEM, event_type="backup_restore_started"))
        elif name == "IdleEvent":
            flow["create"] = False
            flow["restore"] = False

    return _on_event


def setup_backup_capture(
    hass: HomeAssistant, enqueue: Callable[[LogEvent], None]
) -> Callable[[], None]:
    """Subscribe to the backup manager's events. Returns an unsubscribe.

    The manager may load after us, so if it isn't ready yet we retry once HA
    has fully started.
    """
    unsubs: list[Callable[[], None]] = []

    def _subscribe(_event=None) -> None:
        try:
            from homeassistant.components.backup import async_get_manager

            manager = async_get_manager(hass)
            unsubs.append(manager.async_subscribe_events(_make_handler(enqueue)))
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
