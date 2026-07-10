"""Event bus listeners: user actions and monitored device state changes.

HA already attaches a `Context` to every state change and service call,
carrying `user_id` (who/what triggered it) and `parent_id`/`id` (so you can
trace a chain: user pressed a dashboard button -> service call ->
automation -> state change, all linked by context id). We piggyback on
that existing mechanism rather than re-inventing attribution.
"""
from __future__ import annotations

import logging
from typing import Any, Callable

from homeassistant.const import EVENT_CALL_SERVICE, EVENT_STATE_CHANGED
from homeassistant.core import Event, HomeAssistant, State

from .const import CATEGORY_ACCOUNT, CATEGORY_ACTION, CATEGORY_STATE
from .storage import LogEvent

# HA's AuthManager fires these on the bus with data {"user_id": ...} (values
# defined in homeassistant/auth/__init__.py; using the literal event names so
# we match the bus regardless of where the constant lives).
_USER_EVENT_TYPES = ("user_added", "user_updated", "user_removed")

_LOGGER = logging.getLogger(__name__)


def _entity_matches_filters(
    state: State, monitored_domains: list[str], monitored_device_classes: list[str]
) -> bool:
    domain = state.domain
    if domain in monitored_domains:
        return True
    device_class = state.attributes.get("device_class")
    if device_class in monitored_device_classes:
        return True
    return False


def setup_action_listener(
    hass: HomeAssistant,
    enqueue: Callable[[LogEvent], None],
) -> Callable[[], None]:
    """Log every service call, attributing it to the calling user/context."""

    def _handle(event: Event) -> None:
        data = event.data
        context = event.context
        log_event = LogEvent(
            category=CATEGORY_ACTION,
            event_type="call_service",
            user_id=context.user_id if context else None,
            domain=data.get("domain"),
            data={
                "service": data.get("service"),
                "service_data": _redact(data.get("service_data", {})),
                "context_id": context.id if context else None,
                "parent_id": context.parent_id if context else None,
            },
        )
        enqueue(log_event)

    return hass.bus.async_listen(EVENT_CALL_SERVICE, _handle)


def setup_account_listener(
    hass: HomeAssistant,
    enqueue: Callable[[LogEvent], None],
) -> Callable[[], None]:
    """Log user-account changes (created / updated / removed). Account
    management is high-value audit material and low volume."""

    def _handle(event: Event) -> None:
        context = event.context
        enqueue(
            LogEvent(
                category=CATEGORY_ACCOUNT,
                event_type=event.event_type,  # user_added / user_updated / user_removed
                user_id=event.data.get("user_id"),
                data={"context_id": context.id if context else None},
            )
        )

    unsubs = [hass.bus.async_listen(t, _handle) for t in _USER_EVENT_TYPES]

    def _remove() -> None:
        for unsub in unsubs:
            unsub()

    return _remove


def setup_state_listener(
    hass: HomeAssistant,
    enqueue: Callable[[LogEvent], None],
    monitored_domains: list[str],
    monitored_device_classes: list[str],
) -> Callable[[], None]:
    """Log state changes for entities we care about (locks, doors, alarm
    panel, cameras, motion sensors, etc.) with before/after state."""

    def _handle(event: Event) -> None:
        new_state: State | None = event.data.get("new_state")
        old_state: State | None = event.data.get("old_state")
        if new_state is None:
            return
        if not _entity_matches_filters(
            new_state, monitored_domains, monitored_device_classes
        ):
            return

        context = event.context
        log_event = LogEvent(
            category=CATEGORY_STATE,
            event_type="state_changed",
            user_id=context.user_id if context else None,
            entity_id=new_state.entity_id,
            domain=new_state.domain,
            data={
                "old_state": old_state.state if old_state else None,
                "new_state": new_state.state,
                "attributes": dict(new_state.attributes),
                "context_id": context.id if context else None,
            },
        )
        enqueue(log_event)

    return hass.bus.async_listen(EVENT_STATE_CHANGED, _handle)


# Keys we never want to persist verbatim even from our own service-call
# logging, in case a service call itself contains a secret (e.g. a code
# passed to alarm_control_panel.alarm_disarm).
_REDACT_KEYS = {"code", "password", "pin", "token", "api_key"}
_REDACTED = "***REDACTED***"


def _redact(value: Any) -> Any:
    """Recursively redact secret-shaped keys anywhere in the structure.

    Service data can nest (e.g. a dict/list under some key), so a top-level-
    only pass would leak a secret one level down. Any key matching
    _REDACT_KEYS has its value replaced wholesale; other values are walked.
    """
    if isinstance(value, dict):
        return {
            k: (_REDACTED if isinstance(k, str) and k.lower() in _REDACT_KEYS
                else _redact(v))
            for k, v in value.items()
        }
    if isinstance(value, (list, tuple)):
        return [_redact(v) for v in value]
    return value
