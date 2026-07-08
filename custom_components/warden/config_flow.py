"""Config flow for Warden.

Minimal single-step flow: ask where to put the database and which domains
to monitor by default. Everything here is also editable later via the
Options flow, which just re-uses the same schema.
"""
from __future__ import annotations

from typing import Any

import voluptuous as vol
from homeassistant import config_entries
from homeassistant.core import callback
from homeassistant.helpers import selector

from .const import (
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
    DEFAULT_ACTIVITY_RETENTION_DAYS,
    DEFAULT_ANOMALY_Z_THRESHOLD,
    DEFAULT_BUFFER_FLUSH_SECONDS,
    DEFAULT_BUFFER_MAX_EVENTS,
    DEFAULT_DB_FILENAME,
    DEFAULT_MAX_DB_SIZE_MB,
    DEFAULT_MONITORED_DEVICE_CLASSES,
    DEFAULT_MONITORED_DOMAINS,
    DEFAULT_SECURITY_RETENTION_DAYS,
    DOMAIN,
)


def _multi_select(options: list[str]) -> selector.SelectSelector:
    """A multi-select that also lets the user type in values not in the
    suggested list (custom_value=True), returning a real list[str].

    The previous schema used vol.All(vol.Coerce(list)), which HA renders as a
    single text field and which turns a typed string like "lock" into
    ['l','o','c','k'] - so editing these via the UI produced garbage filters.
    """
    return selector.SelectSelector(
        selector.SelectSelectorConfig(
            options=options,
            multiple=True,
            custom_value=True,
            mode=selector.SelectSelectorMode.DROPDOWN,
        )
    )


def _schema(defaults: dict[str, Any]) -> vol.Schema:
    # Suggested options = the built-in defaults; custom_value=True means users
    # aren't limited to these.
    domain_options = sorted(
        set(DEFAULT_MONITORED_DOMAINS) | set(defaults.get(CONF_MONITORED_DOMAINS, []))
    )
    device_class_options = sorted(
        set(DEFAULT_MONITORED_DEVICE_CLASSES)
        | set(defaults.get(CONF_MONITORED_DEVICE_CLASSES, []))
    )
    return vol.Schema(
        {
            vol.Required(
                CONF_DB_PATH, default=defaults.get(CONF_DB_PATH, DEFAULT_DB_FILENAME)
            ): str,
            vol.Required(
                CONF_MONITORED_DOMAINS,
                default=defaults.get(CONF_MONITORED_DOMAINS, DEFAULT_MONITORED_DOMAINS),
            ): _multi_select(domain_options),
            vol.Required(
                CONF_MONITORED_DEVICE_CLASSES,
                default=defaults.get(
                    CONF_MONITORED_DEVICE_CLASSES, DEFAULT_MONITORED_DEVICE_CLASSES
                ),
            ): _multi_select(device_class_options),
            vol.Required(
                CONF_ANOMALY_ENABLED, default=defaults.get(CONF_ANOMALY_ENABLED, True)
            ): bool,
            vol.Required(
                CONF_ANOMALY_Z_THRESHOLD,
                default=defaults.get(
                    CONF_ANOMALY_Z_THRESHOLD, DEFAULT_ANOMALY_Z_THRESHOLD
                ),
            ): vol.Coerce(float),
            # Retention: two tiers (activity = high-volume/low-value, expire
            # fast; security = keep long) plus a hard size-cap backstop.
            vol.Required(
                CONF_ACTIVITY_RETENTION_DAYS,
                default=defaults.get(
                    CONF_ACTIVITY_RETENTION_DAYS, DEFAULT_ACTIVITY_RETENTION_DAYS
                ),
            ): vol.All(vol.Coerce(int), vol.Range(min=1)),
            vol.Required(
                CONF_SECURITY_RETENTION_DAYS,
                default=defaults.get(
                    CONF_SECURITY_RETENTION_DAYS, DEFAULT_SECURITY_RETENTION_DAYS
                ),
            ): vol.All(vol.Coerce(int), vol.Range(min=1)),
            vol.Required(
                CONF_MAX_DB_SIZE_MB,
                default=defaults.get(CONF_MAX_DB_SIZE_MB, DEFAULT_MAX_DB_SIZE_MB),
            ): vol.All(vol.Coerce(int), vol.Range(min=0)),  # 0 disables
            # Write buffer (throughput vs. durability): flush when either the
            # event count or the interval is hit.
            vol.Required(
                CONF_BUFFER_MAX_EVENTS,
                default=defaults.get(
                    CONF_BUFFER_MAX_EVENTS, DEFAULT_BUFFER_MAX_EVENTS
                ),
            ): vol.All(vol.Coerce(int), vol.Range(min=1)),
            vol.Required(
                CONF_BUFFER_FLUSH_SECONDS,
                default=defaults.get(
                    CONF_BUFFER_FLUSH_SECONDS, DEFAULT_BUFFER_FLUSH_SECONDS
                ),
            ): vol.All(vol.Coerce(int), vol.Range(min=1)),
        }
    )


class WardenConfigFlow(config_entries.ConfigFlow, domain=DOMAIN):
    """Handle the initial setup UI flow."""

    VERSION = 1

    async def async_step_user(
        self, user_input: dict[str, Any] | None = None
    ) -> config_entries.FlowResult:
        errors: dict[str, str] = {}

        if user_input is not None:
            return self.async_create_entry(title="Warden", data=user_input)

        return self.async_show_form(
            step_id="user", data_schema=_schema({}), errors=errors
        )

    @staticmethod
    @callback
    def async_get_options_flow(
        config_entry: config_entries.ConfigEntry,
    ) -> "WardenOptionsFlow":
        return WardenOptionsFlow()


class WardenOptionsFlow(config_entries.OptionsFlow):
    """Allow changing monitored domains / thresholds after setup.

    Note: no __init__ reassigning self.config_entry - the base OptionsFlow
    provides it as a property, and assigning it is deprecated (HA 2024.11+).
    """

    async def async_step_init(
        self, user_input: dict[str, Any] | None = None
    ) -> config_entries.FlowResult:
        if user_input is not None:
            return self.async_create_entry(title="", data=user_input)

        current = {**self.config_entry.data, **self.config_entry.options}
        return self.async_show_form(
            step_id="init", data_schema=_schema(current)
        )
