"""Constants for the Security Logger integration."""
from __future__ import annotations

DOMAIN = "security_logger"

# --- Config / options keys -------------------------------------------------
CONF_DB_PATH = "db_path"
CONF_MONITORED_DOMAINS = "monitored_domains"
CONF_MONITORED_DEVICE_CLASSES = "monitored_device_classes"
CONF_ANOMALY_ENABLED = "anomaly_enabled"
CONF_ANOMALY_Z_THRESHOLD = "anomaly_z_threshold"
CONF_RETENTION_DAYS = "retention_days"

DEFAULT_DB_FILENAME = "security_logger.db"
DEFAULT_MONITORED_DOMAINS = ["lock", "alarm_control_panel", "camera"]
DEFAULT_MONITORED_DEVICE_CLASSES = ["door", "window", "motion", "garage_door"]
DEFAULT_ANOMALY_Z_THRESHOLD = 3.0
DEFAULT_RETENTION_DAYS = 365

# How far back to replay device_state history to warm anomaly baselines on
# startup. 30 days gives well over the engine's min_samples (8) per
# hour-of-day bucket while bounding the reconstruction scan.
ANOMALY_HISTORY_LOOKBACK_DAYS = 30

# --- Internal hass.data keys -------------------------------------------------
DATA_STORAGE = "storage"
DATA_UNSUB_LISTENERS = "unsub_listeners"

# --- Event categories stored in the log table -------------------------------
CATEGORY_AUTH = "auth_attempt"
CATEGORY_ACTION = "user_action"
CATEGORY_STATE = "device_state"
CATEGORY_ANOMALY = "anomaly"

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
