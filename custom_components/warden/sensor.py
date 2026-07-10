"""Simple sensors so the log's headline numbers (and a small recent-events
window) show up on a dashboard without opening the full Warden panel. Full
history/search lives in the panel (see docs/PANEL.md) or the
warden.query_events service.
"""
from __future__ import annotations

import logging
import time
from datetime import timedelta

from homeassistant.components.sensor import SensorEntity
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant
from homeassistant.helpers.entity_platform import AddEntitiesCallback
from homeassistant.helpers.update_coordinator import CoordinatorEntity, DataUpdateCoordinator

from .const import (
    AUTH_FAILURE,
    CATEGORY_ACTION,
    CATEGORY_ANOMALY,
    CATEGORY_AUTH,
    DATA_STORAGE,
    DOMAIN,
)
from .storage import SecurityStorage

_LOGGER = logging.getLogger(__name__)

SCAN_INTERVAL = timedelta(minutes=5)

# How many recent rows the "Recent Events" sensor exposes for a dashboard card.
# Kept small: it rides in a state attribute, and large attributes bloat HA's
# recorder (the attribute itself is excluded from recording, see the sensor).
RECENT_EVENTS_LIMIT = 20


def _compact(row: dict) -> dict:
    """Trim a stored row to the small, scalar fields a table card shows -
    never the full `data` blob, to keep the attribute tiny."""
    return {
        "time": time.strftime("%m-%d %H:%M:%S", time.localtime(row.get("ts", 0))),
        "category": row.get("category"),
        "type": row.get("event_type"),
        "entity": row.get("entity_id"),
        "user": row.get("user_id"),
        "outcome": row.get("outcome"),
    }


async def async_setup_entry(
    hass: HomeAssistant, entry: ConfigEntry, async_add_entities: AddEntitiesCallback
) -> None:
    storage: SecurityStorage = hass.data[DOMAIN][entry.entry_id][DATA_STORAGE]

    async def _update():
        now = time.time()
        day_ago = now - 86400

        def _compute():
            # Count only failures for the "Failed Auth" tile; once successful
            # logins are captured (Phase 2) they share CATEGORY_AUTH and would
            # otherwise inflate this number.
            failed_auth = storage.query(
                category=CATEGORY_AUTH, outcome=AUTH_FAILURE,
                since=day_ago, until=now, limit=10000,
            )
            anomalies = storage.query(category=CATEGORY_ANOMALY, since=day_ago, until=now, limit=10000)
            actions = storage.query(category=CATEGORY_ACTION, since=day_ago, until=now, limit=10000)
            recent = storage.query(limit=RECENT_EVENTS_LIMIT)  # newest first, all categories
            return {
                "failed_auth_24h": len(failed_auth),
                "anomalies_24h": len(anomalies),
                "actions_24h": len(actions),
                "recent_events": [_compact(r) for r in recent],
            }

        return await hass.async_add_executor_job(_compute)

    coordinator = DataUpdateCoordinator(
        hass,
        logger=_LOGGER,
        config_entry=entry,
        name=f"{DOMAIN}_counts",
        update_method=_update,
        update_interval=SCAN_INTERVAL,
    )
    await coordinator.async_config_entry_first_refresh()

    async_add_entities(
        [
            SecurityCountSensor(coordinator, "failed_auth_24h", "Failed Auth Attempts (24h)", "mdi:account-alert"),
            SecurityCountSensor(coordinator, "anomalies_24h", "Detected Anomalies (24h)", "mdi:alert-octagon"),
            SecurityCountSensor(coordinator, "actions_24h", "User Actions (24h)", "mdi:account-check"),
            WardenRecentEventsSensor(coordinator),
        ]
    )


class SecurityCountSensor(CoordinatorEntity, SensorEntity):
    """A simple rolling-24h count sensor backed by the coordinator."""

    def __init__(self, coordinator, key: str, name: str, icon: str) -> None:
        super().__init__(coordinator)
        self._key = key
        self._attr_name = f"Warden {name}"
        self._attr_unique_id = f"{DOMAIN}_{key}"
        self._attr_icon = icon
        self._attr_native_unit_of_measurement = "events"

    @property
    def native_value(self):
        return self.coordinator.data.get(self._key) if self.coordinator.data else None


class WardenRecentEventsSensor(CoordinatorEntity, SensorEntity):
    """Exposes the most recent log rows as a state attribute so a dashboard
    card can render them. The full log stays in SQLite (query via the
    warden.query_events action); this is just a small rolling window.
    """

    # Keep the (potentially chunky) event list out of HA's recorder - it's a
    # live view, not history, and recording it every refresh would bloat the
    # recorder DB.
    _unrecorded_attributes = frozenset({"events"})

    def __init__(self, coordinator) -> None:
        super().__init__(coordinator)
        self._attr_name = "Warden Recent Events"
        self._attr_unique_id = f"{DOMAIN}_recent_events"
        self._attr_icon = "mdi:clipboard-text-clock"

    @property
    def native_value(self):
        # State is the number of rows in the window; the rows themselves are in
        # the `events` attribute.
        data = self.coordinator.data or {}
        return len(data.get("recent_events") or [])

    @property
    def extra_state_attributes(self):
        data = self.coordinator.data or {}
        return {"events": data.get("recent_events") or []}
