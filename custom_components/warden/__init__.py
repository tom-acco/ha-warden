"""Warden - structured, tamper-evident security event logging
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
from homeassistant.components import frontend, panel_custom
from homeassistant.components.http import StaticPathConfig
from homeassistant.config_entries import ConfigEntry
from homeassistant.const import EVENT_HOMEASSISTANT_STARTED, EVENT_HOMEASSISTANT_STOP
from homeassistant.core import HomeAssistant, ServiceCall, ServiceResponse, SupportsResponse
from homeassistant.exceptions import HomeAssistantError
from homeassistant.helpers import config_validation as cv
from homeassistant.helpers.event import async_track_time_interval

from .anomaly import AnomalyEngine
from .auth_listener import setup_ban_log_capture
from .auth_poller import AuthTokenTracker, async_poll as async_poll_auth
from .buffer import WriteBuffer
from .const import (
    AUTH_POLL_INTERVAL_SECONDS,
    CATEGORY_ANOMALY,
    CATEGORY_STATE,
    CATEGORY_SYSTEM,
    CONF_ACTIVITY_RETENTION_DAYS,
    CONF_ANOMALY_ENABLED,
    CONF_ANOMALY_Z_THRESHOLD,
    CONF_BUFFER_FLUSH_SECONDS,
    CONF_BUFFER_MAX_EVENTS,
    CONF_DB_PATH,
    CONF_MAX_DB_SIZE_MB,
    CONF_MONITORED_DEVICE_CLASSES,
    CONF_MONITORED_DOMAINS,
    CONF_SECURITY_RETENTION_DAYS,
    DATA_BUFFER,
    DATA_GLOBALS,
    DATA_STORAGE,
    DATA_UNSUB_LISTENERS,
    DEFAULT_ACTIVITY_RETENTION_DAYS,
    DEFAULT_ANOMALY_Z_THRESHOLD,
    DEFAULT_BUFFER_FLUSH_SECONDS,
    DEFAULT_BUFFER_MAX_EVENTS,
    DEFAULT_DB_FILENAME,
    DEFAULT_MAX_DB_SIZE_MB,
    DEFAULT_MONITORED_DEVICE_CLASSES,
    DEFAULT_MONITORED_DOMAINS,
    DEFAULT_RETENTION_DAYS,
    DEFAULT_SECURITY_RETENTION_DAYS,
    DOMAIN,
    PANEL_ASSET_VERSION,
    PANEL_ICON,
    PANEL_JS_FILENAME,
    PANEL_STATIC_URL,
    PANEL_TITLE,
    PANEL_URL_PATH,
    PANEL_WEBCOMPONENT,
    RETENTION_TIERS,
    SERVICE_PURGE_OLD,
    SERVICE_QUERY_EVENTS,
    SERVICE_VERIFY_INTEGRITY,
)
from .event_listener import (
    setup_account_listener,
    setup_action_listener,
    setup_state_listener,
)
from .history import reconstruct_hourly_observations
from .storage import LogEvent, SecurityStorage
from .websocket import async_register_websocket_commands

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
    """Set up Warden from a config entry."""
    options = {**entry.data, **entry.options}

    db_path = Path(hass.config.path(options.get(CONF_DB_PATH, DEFAULT_DB_FILENAME)))
    storage = SecurityStorage(db_path)
    await hass.async_add_executor_job(storage.open)

    anomaly_enabled = options.get(CONF_ANOMALY_ENABLED, True)
    anomaly_engine = AnomalyEngine(
        z_threshold=options.get(CONF_ANOMALY_Z_THRESHOLD, DEFAULT_ANOMALY_Z_THRESHOLD)
    )

    # Buffer writes: rather than one executor job + commit per event, events
    # accumulate and flush in batches (by count or time). See buffer.py for the
    # throughput-vs-durability tradeoff. `enqueue` is the fire-and-forget hook
    # the listeners call.
    buffer = WriteBuffer(
        hass,
        storage,
        max_events=options.get(CONF_BUFFER_MAX_EVENTS, DEFAULT_BUFFER_MAX_EVENTS),
        flush_seconds=options.get(
            CONF_BUFFER_FLUSH_SECONDS, DEFAULT_BUFFER_FLUSH_SECONDS
        ),
    )
    buffer.start()
    enqueue = buffer.add

    hass.data.setdefault(DOMAIN, {})
    hass.data[DOMAIN][entry.entry_id] = {
        DATA_STORAGE: storage,
        DATA_BUFFER: buffer,
        "anomaly_engine": anomaly_engine,
    }

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
    unsub_listeners.append(await _async_setup_auth_polling(hass, enqueue))
    unsub_listeners.append(setup_account_listener(hass, enqueue))
    unsub_listeners.append(_setup_lifecycle_listeners(hass, enqueue, buffer))

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
                "Warden: warmed anomaly baselines from %d historical "
                "hourly observations",
                applied,
            )
        unsub_listeners.append(
            _setup_anomaly_polling(hass, storage, anomaly_engine, enqueue)
        )

    unsub_listeners.append(_setup_retention(hass, storage, options))

    hass.data[DOMAIN][entry.entry_id][DATA_UNSUB_LISTENERS] = unsub_listeners

    # Reload when options change, so edits to retention / monitored entities /
    # buffer thresholds take effect without an HA restart. Without this the
    # options flow saves but appears to do nothing until the next restart.
    entry.async_on_unload(entry.add_update_listener(_async_reload_on_update))

    _register_services(hass)
    await _async_register_frontend(hass)
    await hass.config_entries.async_forward_entry_setups(entry, PLATFORMS)
    return True


async def _async_register_frontend(hass: HomeAssistant) -> None:
    """Register the WS commands, serve the panel JS, and add the sidebar item.

    The WS commands and static path are once-per-HA-process (they can't be
    unregistered), so they're guarded by a persistent flag. The sidebar panel
    is added here and removed when the last entry unloads, so it survives a
    reload cleanly.
    """
    globals_ = hass.data.setdefault(DATA_GLOBALS, {})

    if not globals_.get("assets"):
        panel_dir = str(Path(__file__).parent / "panel")
        await hass.http.async_register_static_paths(
            [StaticPathConfig(PANEL_STATIC_URL, panel_dir, False)]
        )
        async_register_websocket_commands(hass)
        globals_["assets"] = True

    if not globals_.get("panel"):
        await panel_custom.async_register_panel(
            hass,
            frontend_url_path=PANEL_URL_PATH,
            webcomponent_name=PANEL_WEBCOMPONENT,
            module_url=f"{PANEL_STATIC_URL}/{PANEL_JS_FILENAME}?v={PANEL_ASSET_VERSION}",
            sidebar_title=PANEL_TITLE,
            sidebar_icon=PANEL_ICON,
            require_admin=True,
        )
        globals_["panel"] = True


async def _async_reload_on_update(hass: HomeAssistant, entry: ConfigEntry) -> None:
    """Update listener: reload the entry so new options are applied."""
    await hass.config_entries.async_reload(entry.entry_id)


async def async_unload_entry(hass: HomeAssistant, entry: ConfigEntry) -> bool:
    """Unload a config entry: detach listeners, close the DB."""
    unloaded = await hass.config_entries.async_unload_platforms(entry, PLATFORMS)
    if not unloaded:
        return False

    data = hass.data[DOMAIN].pop(entry.entry_id)
    for unsub in data[DATA_UNSUB_LISTENERS]:
        unsub()
    # Flush anything still buffered before the DB goes away, or those events
    # are lost.
    await data[DATA_BUFFER].async_shutdown()
    await hass.async_add_executor_job(data[DATA_STORAGE].close)

    # Services and the sidebar panel are shared across entries; tear them down
    # when the last entry unloads so nothing dereferences a storage that no
    # longer exists. (The WS commands and static path can't be unregistered and
    # are harmless - they just report "not loaded" until an entry returns.)
    if not hass.data[DOMAIN]:
        for service in (SERVICE_QUERY_EVENTS, SERVICE_VERIFY_INTEGRITY, SERVICE_PURGE_OLD):
            hass.services.async_remove(DOMAIN, service)
        globals_ = hass.data.get(DATA_GLOBALS, {})
        if globals_.get("panel"):
            frontend.async_remove_panel(hass, PANEL_URL_PATH)
            globals_["panel"] = False

    return True


def _setup_lifecycle_listeners(hass: HomeAssistant, enqueue, buffer: WriteBuffer):
    """Log HA start/stop so the audit trail records its own gaps.

    On stop we also flush the buffer: a normal HA shutdown does NOT call
    async_unload_entry, so this is the buffer's only flush opportunity on a
    restart - otherwise the last few seconds of events (and the stop event
    itself) would be lost.
    """
    unsubs = []

    def _on_start(_event) -> None:
        enqueue(LogEvent(category=CATEGORY_SYSTEM, event_type="homeassistant_started"))

    unsubs.append(hass.bus.async_listen(EVENT_HOMEASSISTANT_STARTED, _on_start))

    async def _on_stop(_event) -> None:
        enqueue(LogEvent(category=CATEGORY_SYSTEM, event_type="homeassistant_stop"))
        await buffer.async_flush()

    unsubs.append(hass.bus.async_listen_once(EVENT_HOMEASSISTANT_STOP, _on_stop))

    def _remove() -> None:
        for unsub in unsubs:
            unsub()

    return _remove


async def _async_setup_auth_polling(hass: HomeAssistant, enqueue):
    """Capture successful logins by polling refresh tokens. The initial poll
    seeds a silent baseline (existing sessions aren't re-logged); the interval
    then catches new sessions, new long-lived tokens, and known tokens used
    from a new IP. See auth_poller.py / docs/ARCHITECTURE.md."""
    tracker = AuthTokenTracker()
    await async_poll_auth(hass, tracker, enqueue)  # baseline; emits nothing

    async def _tick(_now) -> None:
        await async_poll_auth(hass, tracker, enqueue)

    return async_track_time_interval(
        hass, _tick, timedelta(seconds=AUTH_POLL_INTERVAL_SECONDS)
    )


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
                    "Warden: anomalous activity on %s - %s",
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


def _setup_retention(hass: HomeAssistant, storage: SecurityStorage, options: dict):
    """Enforce retention once a day: per-category age limits (two tiers) plus a
    hard size-cap backstop. This is what actually bounds disk growth - without
    it retention_days was only a default for the manual purge service and the
    DB grew unbounded. See docs/ARCHITECTURE.md ("Retention")."""
    activity_days = options.get(
        CONF_ACTIVITY_RETENTION_DAYS, DEFAULT_ACTIVITY_RETENTION_DAYS
    )
    security_days = options.get(
        CONF_SECURITY_RETENTION_DAYS, DEFAULT_SECURITY_RETENTION_DAYS
    )
    policy = {
        category: (activity_days if tier == "activity" else security_days)
        for category, tier in RETENTION_TIERS.items()
    }
    max_bytes = (
        options.get(CONF_MAX_DB_SIZE_MB, DEFAULT_MAX_DB_SIZE_MB) * 1024 * 1024
    )

    async def _tick(_now) -> None:
        def _run():
            # Keep unknown categories to the longer (security) window rather
            # than deleting data we don't have a rule for.
            by_age = storage.enforce_retention(policy, default_days=security_days)
            by_size = storage.enforce_size_cap(max_bytes)
            return by_age, by_size

        by_age, by_size = await hass.async_add_executor_job(_run)
        if by_age or by_size:
            _LOGGER.info(
                "Warden retention: %s purged by age, %d by size cap",
                by_age or "nothing",
                by_size,
            )

    return async_track_time_interval(hass, _tick, timedelta(days=1))


def _get_storage(hass: HomeAssistant) -> SecurityStorage:
    """Return the storage for the (typically only) loaded entry.

    Services are global, but state lives per-entry; with a single entry - the
    normal case - this is unambiguous. Raise a clear error rather than a bare
    StopIteration if called with no entry loaded (e.g. a service call racing a
    reload).
    """
    entries = hass.data.get(DOMAIN, {})
    if not entries:
        raise HomeAssistantError("Warden is not loaded")
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
