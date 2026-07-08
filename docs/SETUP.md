# Local development setup

## Option A - fastest: symlink into an existing HA config

If you already have a Home Assistant instance (HA OS, Container, or Core)
running somewhere you control:

```bash
# from your HA config directory
mkdir -p custom_components
ln -s /path/to/this/repo/custom_components/security_logger \
      custom_components/security_logger
```

Restart HA, then Settings -> Devices & Services -> Add Integration ->
search "Security Logger".

For HA OS/Supervised installs where you can't easily symlink (e.g. no
shell access to the underlying filesystem), just copy the folder in via
Samba/SSH add-on instead of symlinking, and re-copy after each edit.

## Option B - isolated dev environment (recommended for actual development)

This keeps you from experimenting against a HA instance you rely on daily.

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install homeassistant

# Create a throwaway config dir
mkdir -p ~/ha-dev-config/custom_components
ln -s "$(pwd)/custom_components/security_logger" \
      ~/ha-dev-config/custom_components/security_logger

hass -c ~/ha-dev-config
```

First run will generate a default `configuration.yaml` etc. in
`~/ha-dev-config`. Visit http://localhost:8123, complete onboarding, then
add the integration via the UI as above.

Note: `homeassistant` is a large dependency with a lot of optional extras;
installing the full package can take a while and pulls in many libraries
you won't need for this integration alone. If you want a lighter loop,
HA's own `script/setup` dev-container workflow (documented in HA core's
own repo) is the officially supported path for core/integration
development and is worth switching to once you're doing this regularly.

## Running the standalone unit checks (no HA required)

`storage.py` and `anomaly.py` have no dependency on the `homeassistant`
package - they're plain Python + stdlib (`sqlite3`, `hashlib`, `json`,
`math`). You can sanity-check them in isolation without a full HA install:

```bash
cd custom_components/security_logger
python3 - <<'EOF'
from storage import SecurityStorage, LogEvent
from anomaly import AnomalyEngine

s = SecurityStorage("/tmp/test_security_logger.db")
s.open()
s.append(LogEvent(category="auth_attempt", event_type="http_auth_failed",
                   source_ip="1.2.3.4", outcome="failure",
                   data={"requested_url": "/api/x"}))
print(s.query(category="auth_attempt"))
print(s.verify_chain())
EOF
rm -f /tmp/test_security_logger.db
```

The two files that DO import `homeassistant` (`__init__.py`,
`event_listener.py`, `auth_listener.py`'s handler registration,
`config_flow.py`, `sensor.py`) need a real or stubbed HA environment to
exercise beyond a syntax check (`python3 -m py_compile <file>.py`).

## Installing via HACS (once published)

1. HACS -> Integrations -> the "..." menu -> Custom repositories.
2. Add this repo's URL, category "Integration".
3. Install "Security Logger", restart HA, add the integration via the UI.

`hacs.json` at the repo root is already set up for this - update the
`homeassistant` minimum version field there as you find the actual
minimum version this works against (currently a placeholder).

## Suggested next steps once you're in your own workspace

1. Get Option B running and confirm the integration loads at all -
   this scaffold has not yet been run inside a live HA instance.
2. Trigger a few real events (lock/unlock a demo lock entity, call a
   service, deliberately fail a login) and confirm they show up via
   `security_logger.query_events`.
3. Verify the ban-log regex in `auth_listener.py` against the exact log
   line your HA version emits - grep your `home-assistant.log` for
   "invalid authentication" after a deliberate failed login.
4. Pick up Phase 1 items in `docs/ROADMAP.md`.
