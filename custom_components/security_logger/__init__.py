"""Security Logger - structured, tamper-evident security event logging
for Home Assistant.

See docs/ARCHITECTURE.md for the full design rationale. Summary of what
this integration does on setup:

  1. Opens a dedicated SQLite database (separate from HA's own recorder).
  2. Attaches listeners for service calls and monitored state changes,
     using HA's existing Context (user_id) for attribution.
  3. Attaches a log handler to HA's ban logger to capture failed auth
     attempts (source IP, requested URL).
  4. Optionally runs a lightweight anomaly engine over monitored entities.
  5. Registers services to query the log and verify its integrity.
"""
from __future__ import annotations

import logging
import time
from datetime import timedelta
from pathlib import Path

import voluptuous as vol
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant, ServiceCall, ServiceResponse, SupportsResponse
from homeassistant.exceptions import HomeAssistantError
from homeassistant.helpers import config_validation as cv
from homeassistant.helpers.event import async_track_time_interval

from .anomaly import AnomalyEngine
from .auth_listener import setup_ban_log_capture
from .const import (
    CATEGORY_ANOMALY,
    CATEGORY_STATE,
    CONF_ANOMALY_ENABLED,
    CONF_ANOMALY_Z_THRESHOLD,
    CONF_DB_PATH,
    CONF_MONITORED_DEVICE_CLASSES,
    CONF_MONITORED_DOMAINS,
    CONF_RETENTION_DAYS,
    DATA_STORAGE,
    DATA_UNSUB_LISTENERS,
    DEFAULT_ANOMALY_Z_THRESHOLD,
    DEFAULT_MONITORED_DEVICE_CLASSES,
    DEFAULT_MONITORED_DOMAINS,
    DEFAULT_RETENTION_DAYS,
    DOMAIN,
    SERVICE_PURGE_OLD,
    SERVICE_QUERY_EVENTS,
    SERVICE_VERIFY_INTEGRITY,
)
from .event_listener import setup_action_listener, setup_state_listener
from .history import reconstruct_hourly_observations
from .storage import LogEvent, SecurityStorage

_LOGGER = logging.getLogger(__name__)

PLATFORMS: list[str] = ["sensor"]

QUERY_EVENTS_SCHEMA = vol.Schema(
    {
        vol.Optional("category"): str,
        vol.Optional("entity_id"): str,
        vol.Optional("user_id"): str,
        vol.Optional("since"): cv.datetime,
        vol.Optional("until"): cv.datetime,
        vol.Optional("limit", default=200): vol.Coerce(int),
    }
)


async def async_setup_entry(hass: HomeAssistant, entry: ConfigEntry) -> bool:
    """Set up Security Logger from a config entry."""
    options = {**entry.data, **entry.options}

    db_path = Path(hass.config.path(options.get(CONF_DB_PATH, "security_logger.db")))
    storage = SecurityStorage(db_path)
    await hass.async_add_executor_job(storage.open)

    anomaly_enabled = options.get(CONF_ANOMALY_ENABLED, True)
    anomaly_engine = AnomalyEngine(
        z_threshold=options.get(CONF_ANOMALY_Z_THRESHOLD, DEFAULT_ANOMALY_Z_THRESHOLD)
    )

    hass.data.setdefault(DOMAIN, {})
    hass.data[DOMAIN][entry.entry_id] = {
        DATA_STORAGE: storage,
        "anomaly_engine": anomaly_engine,
    }

    def enqueue(event: LogEvent) -> None:
        """Write an event without blocking the event loop.

        Fire-and-forget from listener callbacks: schedule the blocking
        sqlite write on the executor. If you need back-pressure handling
        for very high event volumes, put a bounded asyncio.Queue in front
        of this - left simple here since typical home security event
        volume is low (see docs/ARCHITECTURE.md, "Scaling considerations").

        The write future is otherwise discarded, so a failed append would
        vanish silently (a dropped event in a *security* log). Attach a
        callback that logs any exception instead.
        """
        future = hass.async_add_executor_job(storage.append, event)

        def _log_write_error(fut) -> None:
            exc = fut.exception()
            if exc is not None:
                _LOGGER.error(
                    "Security Logger: failed to persist %s/%s event: %s",
                    event.category, event.event_type, exc,
                )

        future.add_done_callback(_log_write_error)

    unsub_listeners: list = []
    unsub_listeners.append(setup_action_listener(hass, enqueue))
    unsub_listeners.append(
        setup_state_listener(
            hass,
            enqueue,
            monitored_domains=options.get(
                CONF_MONITORED_DOMAINS, DEFAULT_MONITORED_DOMAINS
            ),
            monitored_device_classes=options.get(
                CONF_MONITORED_DEVICE_CLASSES, DEFAULT_MONITORED_DEVICE_CLASSES
            ),
        )
    )
    unsub_listeners.append(setup_ban_log_capture(enqueue))

    if anomaly_enabled:
        # Baselines are in-memory; warm them from persisted history so a
        # restart doesn't reset detection to cold. See _reconstruct_hourly_
        # observations and AnomalyEngine.warm_from_history.
        observations = await hass.async_add_executor_job(
            reconstruct_hourly_observations, storage
        )
        applied = anomaly_engine.warm_from_history(observations)
        if applied:
            _LOGGER.debug(
                "Security Logger: warmed anomaly baselines from %d historical "
                "hourly observations",
                applied,
            )
        unsub_listeners.append(
            _setup_anomaly_polling(hass, storage, anomaly_engine, enqueue)
        )

    hass.data[DOMAIN][entry.entry_id][DATA_UNSUB_LISTENERS] = unsub_listeners

    _register_services(hass)
    await hass.config_entries.async_forward_entry_setups(entry, PLATFORMS)
    return True


async def async_unload_entry(hass: HomeAssistant, entry: ConfigEntry) -> bool:
    """Unload a config entry: detach listeners, close the DB."""
    unloaded = await hass.config_entries.async_unload_platforms(entry, PLATFORMS)
    if not unloaded:
        return False

    data = hass.data[DOMAIN].pop(entry.entry_id)
    for unsub in data[DATA_UNSUB_LISTENERS]:
        unsub()
    await hass.async_add_executor_job(data[DATA_STORAGE].close)

    # Services are registered once and shared across entries; tear them down
    # when the last entry unloads so a stale service call can't dereference a
    # storage that no longer exists.
    if not hass.data[DOMAIN]:
        for service in (SERVICE_QUERY_EVENTS, SERVICE_VERIFY_INTEGRITY, SERVICE_PURGE_OLD):
            hass.services.async_remove(DOMAIN, service)

    return True


def _setup_anomaly_polling(hass, storage: SecurityStorage, engine: AnomalyEngine, enqueue):
    """Every hour, tally per-entity event counts for the hour just finished
    and feed them to the anomaly engine. Simple and auditable; see
    anomaly.py for why this isn't ML-based in v1."""

    async def _tick(_now) -> None:
        now = time.time()
        hour_ago = now - 3600
        hour_of_day = time.localtime(hour_ago).tm_hour

        def _tally() -> dict[str, int]:
            rows = storage.query(category=CATEGORY_STATE, since=hour_ago, until=now, limit=10000)
            counts: dict[str, int] = {}
            for row in rows:
                eid = row.get("entity_id")
                if eid:
                    counts[eid] = counts.get(eid, 0) + 1
            return counts

        counts = await hass.async_add_executor_job(_tally)
        for entity_id, count in counts.items():
            result = engine.record_period(entity_id, hour_of_day, count)
            if result is not None:
                _LOGGER.warning(
                    "Security Logger: anomalous activity on %s - %s",
                    entity_id,
                    result,
                )
                enqueue(
                    LogEvent(
                        category=CATEGORY_ANOMALY,
                        event_type="anomalous_frequency",
                        entity_id=entity_id,
                        data=result,
                    )
                )

    return async_track_time_interval(hass, _tick, timedelta(hours=1))


def _get_storage(hass: HomeAssistant) -> SecurityStorage:
    """Return the storage for the (typically only) loaded entry.

    Services are global, but state lives per-entry; with a single entry - the
    normal case - this is unambiguous. Raise a clear error rather than a bare
    StopIteration if called with no entry loaded (e.g. a service call racing a
    reload).
    """
    entries = hass.data.get(DOMAIN, {})
    if not entries:
        raise HomeAssistantError("Security Logger is not loaded")
    entry_id = next(iter(entries))
    return entries[entry_id][DATA_STORAGE]


def _register_services(hass: HomeAssistant) -> None:
    if hass.services.has_service(DOMAIN, SERVICE_QUERY_EVENTS):
        return  # already registered by a previous entry

    async def _query_events(call: ServiceCall) -> ServiceResponse:
        storage = _get_storage(hass)

        since = call.data.get("since")
        until = call.data.get("until")
        results = await hass.async_add_executor_job(
            storage.query,
            call.data.get("category"),
            call.data.get("entity_id"),
            call.data.get("user_id"),
            since.timestamp() if since else None,
            until.timestamp() if until else None,
            call.data.get("limit", 200),
        )
        return {"events": results}

    async def _verify_integrity(call: ServiceCall) -> ServiceResponse:
        storage = _get_storage(hass)
        result = await hass.async_add_executor_job(storage.verify_chain)
        return result

    async def _purge_old(call: ServiceCall) -> ServiceResponse:
        storage = _get_storage(hass)
        retention_days = call.data.get("retention_days", DEFAULT_RETENTION_DAYS)
        cutoff = time.time() - retention_days * 86400
        deleted = await hass.async_add_executor_job(storage.purge_older_than, cutoff)
        return {"deleted": deleted}

    hass.services.async_register(
        DOMAIN,
        SERVICE_QUERY_EVENTS,
        _query_events,
        schema=QUERY_EVENTS_SCHEMA,
        supports_response=SupportsResponse.ONLY,
    )
    hass.services.async_register(
        DOMAIN,
        SERVICE_VERIFY_INTEGRITY,
        _verify_integrity,
        supports_response=SupportsResponse.ONLY,
    )
    hass.services.async_register(
        DOMAIN,
        SERVICE_PURGE_OLD,
        _purge_old,
        schema=vol.Schema({vol.Optional("retention_days"): vol.Coerce(int)}),
        supports_response=SupportsResponse.ONLY,
    )
