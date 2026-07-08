# Security Logger for Home Assistant

A Home Assistant custom integration for structured, tamper-evident security
event logging: failed/successful auth attempts, who-did-what user action
attribution, and anomalous device behaviour detection - things the built-in
Logbook doesn't give you.

> **Status: early scaffold.** This is a working v0.1 skeleton, not a
> finished product. It compiles, the storage/anomaly logic is unit-tested
> in isolation, but it has not been run inside a live Home Assistant
> instance yet. See `docs/ROADMAP.md` for what's implemented vs. planned,
> and `docs/ARCHITECTURE.md` for the reasoning behind the design choices.

## What this does today

- **User action logging** - every service call is logged with the calling
  user's ID (via HA's built-in `Context` object), the service, and a
  redacted copy of the service data.
- **Device state logging** - state changes for entities you configure
  (by domain, e.g. `lock`, `alarm_control_panel`, or device_class, e.g.
  `door`, `window`, `motion`) are logged with before/after state.
- **Failed auth attempts** - captured by attaching a log handler to HA's
  existing ban-log warnings, giving you source IP and requested URL.
- **Anomaly detection** - a simple, explainable per-entity/per-hour
  frequency baseline that flags statistically unusual activity.
- **Tamper-evident storage** - every log row is hash-chained; a
  `verify_integrity` service recomputes the chain and tells you if/where
  it's been altered.
- Three sensors (`Failed Auth Attempts (24h)`, `Detected Anomalies (24h)`,
  `User Actions (24h)`) and three services (`query_events`,
  `verify_integrity`, `purge_old`) for interacting with the log.

## What this does NOT do yet

- **Successful login capture.** HA doesn't expose this today without
  deeper hooks into the auth provider. This is flagged explicitly in
  `auth_listener.py` and tracked as a Phase 2 item - don't assume it works.
- **A dedicated frontend panel/dashboard.** For now, use the
  `security_logger.query_events` service (Developer Tools -> Actions) or
  build a Lovelace card around it. A proper panel is Phase 2.
- Long-term archival/export tooling beyond the raw SQLite file.

## Repository layout

```
custom_components/security_logger/   The actual HA integration
  __init__.py        Setup/teardown, listener wiring, service registration
  manifest.json       HA integration manifest
  const.py             Config keys, defaults, event category constants
  config_flow.py       UI setup + options flow
  storage.py            Hash-chained SQLite storage layer
  anomaly.py            Per-entity baseline / z-score anomaly detection
  history.py            Rebuilds anomaly baselines from the log on startup
  event_listener.py    Service-call + state-change listeners (user actions, device state)
  auth_listener.py      Failed-auth capture via HA's ban logger
  sensor.py              Rolling 24h count sensors
  services.yaml          Service definitions (shows up in HA's UI)
  strings.json / translations/en.json   Config flow UI text
tests/                  Pure-Python tests for storage/anomaly/history
                        (no HA runtime needed: `pytest tests/`)
docs/
  ARCHITECTURE.md      Design rationale, tradeoffs, what's log-scraped vs. API-based
  ROADMAP.md           Phased plan, what's done / next / later
  SETUP.md              How to install this for local development against a real HA instance
hacs.json               Makes this repo installable via HACS as a custom repository
```

## Quick install (for testing against a real Home Assistant instance)

1. Copy `custom_components/security_logger/` into your HA config's
   `custom_components/` directory (or add this repo to HACS as a custom
   repository - see `docs/SETUP.md`).
2. Restart Home Assistant.
3. Settings -> Devices & Services -> Add Integration -> "Security Logger".
4. Choose which domains/device classes to monitor.
5. Try it: Developer Tools -> Actions -> `security_logger.query_events`.

See `docs/SETUP.md` for the full local development workflow, including
running against a local HA instance in a virtualenv/devcontainer.

## Security design notes (read before relying on this)

- **We do not log entered passwords**, even for failed attempts. Logging
  failed-password contents risks capturing a legitimate user's real
  password when they mistype it, turning the security log itself into a
  thing worth attacking. See `docs/ARCHITECTURE.md`.
- The hash chain gives you **tamper evidence, not tamper prevention** -
  it tells you if historical rows were altered after the fact; it does not
  stop someone with filesystem access from editing the DB. Pair it with
  normal file permission hygiene and backups.
- `purge_old` intentionally breaks the from-genesis verifiability of the
  chain for remaining rows once older ones are deleted. If you need both
  pruning and long-term audit retention, export+archive before purging.

## License

Pick one before publishing - MIT or Apache-2.0 are the norm for HACS
integrations. Not included yet.
