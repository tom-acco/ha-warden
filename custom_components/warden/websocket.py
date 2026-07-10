"""WebSocket API backing the Warden panel.

Every command is admin-only (a security audit log must not be a non-admin
read) and runs the blocking SQLite work on the executor. The panel
(panel/warden-panel.js) is the only intended caller, but these are ordinary
WS commands and are usable from any authenticated admin client.
"""
from __future__ import annotations

import time
from typing import Any

import voluptuous as vol
from homeassistant.components import websocket_api
from homeassistant.core import HomeAssistant, callback
from homeassistant.exceptions import HomeAssistantError

from .const import (
    AUTH_FAILURE,
    CATEGORY_ACTION,
    CATEGORY_ANOMALY,
    CATEGORY_AUTH,
    DATA_STORAGE,
    DOMAIN,
)
from .storage import SecurityStorage


def _storage(hass: HomeAssistant) -> SecurityStorage:
    """The storage for the (single, normal case) loaded entry. Mirrors
    __init__._get_storage but kept here to avoid importing __init__ (cycle)."""
    entries = hass.data.get(DOMAIN, {})
    if not entries:
        raise HomeAssistantError("Warden is not loaded")
    return next(iter(entries.values()))[DATA_STORAGE]


@callback
def async_register_websocket_commands(hass: HomeAssistant) -> None:
    """Register the panel's WS commands. Caller ensures this runs once per HA
    instance (WS commands persist for the process lifetime and can't be
    unregistered)."""
    websocket_api.async_register_command(hass, ws_stats)
    websocket_api.async_register_command(hass, ws_query)
    websocket_api.async_register_command(hass, ws_verify)


@websocket_api.require_admin
@websocket_api.websocket_command({vol.Required("type"): "warden/stats"})
@websocket_api.async_response
async def ws_stats(
    hass: HomeAssistant, connection: websocket_api.ActiveConnection, msg: dict[str, Any]
) -> None:
    """Headline numbers for the panel's stat tiles."""
    try:
        storage = _storage(hass)
    except HomeAssistantError as err:
        connection.send_error(msg["id"], "not_loaded", str(err))
        return

    def _run() -> dict[str, Any]:
        now = time.time()
        day_ago = now - 86400
        return {
            "failed_auth_24h": storage.count(
                category=CATEGORY_AUTH, outcome=AUTH_FAILURE, since=day_ago, until=now
            ),
            "anomalies_24h": storage.count(
                category=CATEGORY_ANOMALY, since=day_ago, until=now
            ),
            "actions_24h": storage.count(
                category=CATEGORY_ACTION, since=day_ago, until=now
            ),
            "total_events": storage.count(),
            "db_size_bytes": storage.db_size_bytes(),
        }

    connection.send_result(msg["id"], await hass.async_add_executor_job(_run))


@websocket_api.require_admin
@websocket_api.websocket_command(
    {
        vol.Required("type"): "warden/query",
        vol.Optional("category"): vol.Any(str, None),
        vol.Optional("entity_id"): vol.Any(str, None),
        vol.Optional("user_id"): vol.Any(str, None),
        vol.Optional("outcome"): vol.Any(str, None),
        vol.Optional("search"): vol.Any(str, None),
        vol.Optional("since"): vol.Any(float, int, None),
        vol.Optional("until"): vol.Any(float, int, None),
        vol.Optional("limit", default=50): vol.All(int, vol.Range(min=1, max=1000)),
        vol.Optional("offset", default=0): vol.All(int, vol.Range(min=0)),
    }
)
@websocket_api.async_response
async def ws_query(
    hass: HomeAssistant, connection: websocket_api.ActiveConnection, msg: dict[str, Any]
) -> None:
    """A filtered, paginated page of events plus the matching total."""
    try:
        storage = _storage(hass)
    except HomeAssistantError as err:
        connection.send_error(msg["id"], "not_loaded", str(err))
        return

    limit = msg["limit"]
    offset = msg["offset"]
    filters = dict(
        category=msg.get("category"),
        entity_id=msg.get("entity_id"),
        user_id=msg.get("user_id"),
        outcome=msg.get("outcome"),
        search=msg.get("search"),
        since=msg.get("since"),
        until=msg.get("until"),
    )

    def _run() -> tuple[list[dict[str, Any]], int]:
        return (
            storage.query(limit=limit, offset=offset, **filters),
            storage.count(**filters),
        )

    events, total = await hass.async_add_executor_job(_run)

    # Resolve user_id -> display name so the panel can show who did something
    # rather than an opaque UUID. Cheap (few users); only when a page has any.
    if any(e.get("user_id") for e in events):
        names = {u.id: u.name for u in await hass.auth.async_get_users()}
        for event in events:
            uid = event.get("user_id")
            if uid:
                event["user_name"] = names.get(uid)

    connection.send_result(
        msg["id"], {"events": events, "total": total, "limit": limit, "offset": offset}
    )


@websocket_api.require_admin
@websocket_api.websocket_command({vol.Required("type"): "warden/verify"})
@websocket_api.async_response
async def ws_verify(
    hass: HomeAssistant, connection: websocket_api.ActiveConnection, msg: dict[str, Any]
) -> None:
    """Per-category hash-chain integrity report."""
    try:
        storage = _storage(hass)
    except HomeAssistantError as err:
        connection.send_error(msg["id"], "not_loaded", str(err))
        return

    connection.send_result(
        msg["id"], await hass.async_add_executor_job(storage.verify_chain)
    )
