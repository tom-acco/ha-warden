"""Config flow for Security Logger.

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
    CONF_ANOMALY_ENABLED,
    CONF_ANOMALY_Z_THRESHOLD,
    CONF_DB_PATH,
    CONF_MONITORED_DEVICE_CLASSES,
    CONF_MONITORED_DOMAINS,
    CONF_RETENTION_DAYS,
    DEFAULT_ANOMALY_Z_THRESHOLD,
    DEFAULT_DB_FILENAME,
    DEFAULT_MONITORED_DEVICE_CLASSES,
    DEFAULT_MONITORED_DOMAINS,
    DEFAULT_RETENTION_DAYS,
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
            vol.Required(
                CONF_RETENTION_DAYS,
                default=defaults.get(CONF_RETENTION_DAYS, DEFAULT_RETENTION_DAYS),
            ): vol.Coerce(int),
        }
    )


class SecurityLoggerConfigFlow(config_entries.ConfigFlow, domain=DOMAIN):
    """Handle the initial setup UI flow."""

    VERSION = 1

    async def async_step_user(
        self, user_input: dict[str, Any] | None = None
    ) -> config_entries.FlowResult:
        errors: dict[str, str] = {}

        if user_input is not None:
            return self.async_create_entry(title="Security Logger", data=user_input)

        return self.async_show_form(
            step_id="user", data_schema=_schema({}), errors=errors
        )

    @staticmethod
    @callback
    def async_get_options_flow(
        config_entry: config_entries.ConfigEntry,
    ) -> "SecurityLoggerOptionsFlow":
        return SecurityLoggerOptionsFlow(config_entry)


class SecurityLoggerOptionsFlow(config_entries.OptionsFlow):
    """Allow changing monitored domains / thresholds after setup."""

    def __init__(self, config_entry: config_entries.ConfigEntry) -> None:
        self.config_entry = config_entry

    async def async_step_init(
        self, user_input: dict[str, Any] | None = None
    ) -> config_entries.FlowResult:
        if user_input is not None:
            return self.async_create_entry(title="", data=user_input)

        current = {**self.config_entry.data, **self.config_entry.options}
        return self.async_show_form(
            step_id="init", data_schema=_schema(current)
        )
