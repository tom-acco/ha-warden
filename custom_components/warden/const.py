"""Constants for the Warden integration."""
from __future__ import annotations

DOMAIN = "warden"

# --- Config / options keys -------------------------------------------------
CONF_DB_PATH = "db_path"
CONF_MONITORED_DOMAINS = "monitored_domains"
CONF_MONITORED_DEVICE_CLASSES = "monitored_device_classes"
CONF_ANOMALY_ENABLED = "anomaly_enabled"
CONF_ANOMALY_Z_THRESHOLD = "anomaly_z_threshold"
CONF_RETENTION_DAYS = "retention_days"
# Two-tier automatic retention: high-volume/low-value activity vs. low-volume/
# high-value security events. See RETENTION_TIERS below and docs/ARCHITECTURE.
CONF_ACTIVITY_RETENTION_DAYS = "activity_retention_days"
CONF_SECURITY_RETENTION_DAYS = "security_retention_days"
CONF_MAX_DB_SIZE_MB = "max_db_size_mb"
# Write buffer: flush accumulated events when either threshold is hit first.
CONF_BUFFER_MAX_EVENTS = "buffer_max_events"
CONF_BUFFER_FLUSH_SECONDS = "buffer_flush_seconds"

DEFAULT_DB_FILENAME = "warden.db"
DEFAULT_MONITORED_DOMAINS = ["lock", "alarm_control_panel", "camera"]
DEFAULT_MONITORED_DEVICE_CLASSES = ["door", "window", "motion", "garage_door"]
DEFAULT_ANOMALY_Z_THRESHOLD = 3.0
DEFAULT_RETENTION_DAYS = 365  # default for the manual purge_old service
DEFAULT_ACTIVITY_RETENTION_DAYS = 90
DEFAULT_SECURITY_RETENTION_DAYS = 365
DEFAULT_MAX_DB_SIZE_MB = 500  # 0 disables the size-cap backstop
DEFAULT_BUFFER_MAX_EVENTS = 100
DEFAULT_BUFFER_FLUSH_SECONDS = 5

# How far back to replay device_state history to warm anomaly baselines on
# startup. 30 days gives well over the engine's min_samples (8) per
# hour-of-day bucket while bounding the reconstruction scan.
ANOMALY_HISTORY_LOOKBACK_DAYS = 30

# --- Internal hass.data keys -------------------------------------------------
DATA_STORAGE = "storage"
DATA_BUFFER = "buffer"
DATA_UNSUB_LISTENERS = "unsub_listeners"

# --- Event categories stored in the log table -------------------------------
CATEGORY_AUTH = "auth_attempt"
CATEGORY_ACTION = "user_action"
CATEGORY_STATE = "device_state"
CATEGORY_ANOMALY = "anomaly"
# Integration's own audit records (purge events). Must match
# storage.MAINTENANCE_CATEGORY.
CATEGORY_MAINTENANCE = "maintenance"

# Which retention tier each category falls in. "activity" = high-volume,
# low individual value (expire fast); "security" = low-volume, high value
# (keep long). Purge records live in the security tier so they aren't the
# first thing culled.
RETENTION_TIERS = {
    CATEGORY_STATE: "activity",
    CATEGORY_ACTION: "activity",
    CATEGORY_AUTH: "security",
    CATEGORY_ANOMALY: "security",
    CATEGORY_MAINTENANCE: "security",
}

# --- Auth outcomes -----------------------------------------------------------
AUTH_SUCCESS = "success"
AUTH_FAILURE = "failure"

# --- Services exposed by this integration ------------------------------------
SERVICE_QUERY_EVENTS = "query_events"
SERVICE_VERIFY_INTEGRITY = "verify_integrity"
SERVICE_PURGE_OLD = "purge_old"

# The logger HA's own HTTP ban middleware writes to. We attach a logging
# handler to this logger to recover failed-auth attempts, since HA does not
# currently fire a bus event for them (see docs/ARCHITECTURE.md).
HA_BAN_LOGGER_NAME = "homeassistant.components.http.ban"
HA_AUTH_LOGGER_NAME = "homeassistant.components.http.auth"
