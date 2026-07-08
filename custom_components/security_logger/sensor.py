"""Simple sensors so the log's headline numbers show up on a dashboard
without needing a custom frontend panel yet (that's Phase 2 - see
docs/ROADMAP.md). Full history/search still goes through the
security_logger.query_events service.
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


async def async_setup_entry(
    hass: HomeAssistant, entry: ConfigEntry, async_add_entities: AddEntitiesCallback
) -> None:
    storage: SecurityStorage = hass.data[DOMAIN][entry.entry_id][DATA_STORAGE]

    async def _update():
        now = time.time()
        day_ago = now - 86400

        def _counts():
            # Count only failures for the "Failed Auth" tile; once successful
            # logins are captured (Phase 2) they share CATEGORY_AUTH and would
            # otherwise inflate this number.
            failed_auth = storage.query(
                category=CATEGORY_AUTH, outcome=AUTH_FAILURE,
                since=day_ago, until=now, limit=10000,
            )
            anomalies = storage.query(category=CATEGORY_ANOMALY, since=day_ago, until=now, limit=10000)
            actions = storage.query(category=CATEGORY_ACTION, since=day_ago, until=now, limit=10000)
            return {
                "failed_auth_24h": len(failed_auth),
                "anomalies_24h": len(anomalies),
                "actions_24h": len(actions),
            }

        return await hass.async_add_executor_job(_counts)

    coordinator = DataUpdateCoordinator(
        hass,
        logger=_LOGGER,
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
        ]
    )


class SecurityCountSensor(CoordinatorEntity, SensorEntity):
    """A simple rolling-24h count sensor backed by the coordinator."""

    def __init__(self, coordinator, key: str, name: str, icon: str) -> None:
        super().__init__(coordinator)
        self._key = key
        self._attr_name = f"Security Logger {name}"
        self._attr_unique_id = f"{DOMAIN}_{key}"
        self._attr_icon = icon
        self._attr_native_unit_of_measurement = "events"

    @property
    def native_value(self):
        return self.coordinator.data.get(self._key) if self.coordinator.data else None
