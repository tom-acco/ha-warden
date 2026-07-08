"""Auth attempt capture.

IMPORTANT / HONEST STATUS (read this before building on it):

Home Assistant does not currently fire a structured event-bus event for
either failed or successful login attempts. What exists today:

  * FAILED attempts: the `homeassistant.components.http.ban` logger emits a
    WARNING-level log record of the form:
        "Login attempt or request with invalid authentication from
         {ip} ({ip}). Requested URL: '...'"
    This module attaches a logging.Handler to that logger and parses the IP
    out of the message. This is what's implemented below and it works today,
    but it is scraping a log string, not consuming a stable API - a future
    HA release could change that message format and quietly break the
    regex. Treat CURRENT_BAN_MSG_RE as something to re-verify against the
    HA release you're targeting.

  * SUCCESSFUL logins: there is no equivalent log line or event by default.
    Getting real success-side data (which user, which auth provider, from
    which IP) requires wrapping/subclassing HA's auth provider
    (`homeassistant.auth.providers.homeassistant.HassAuthProvider` or the
    relevant provider class for your auth backend) and hooking
    `async_validate_login`, or patching the `homeassistant.components.auth`
    login_flow view. That's a deeper, more version-sensitive integration
    than a log-scraping shim, and is left as `AuthProviderHookNotImplemented`
    below so this fact isn't hidden - it's flagged as Phase 2 in
    docs/ROADMAP.md rather than papered over with something that looks like
    it works but doesn't.

Deliberately NOT captured: raw password contents. Only whether an attempt
succeeded/failed, the username presented (not the password), and source IP
are logged. See docs/ARCHITECTURE.md ("Why we don't log credential
contents") for the reasoning - logging failed passwords risks capturing
real passwords when a legitimate user mistypes, turning the security log
itself into a credential store worth attacking.
"""
from __future__ import annotations

import logging
import re
from typing import Callable

from .const import AUTH_FAILURE, CATEGORY_AUTH, HA_BAN_LOGGER_NAME
from .storage import LogEvent

# Matches: "Login attempt or request with invalid authentication from
# 192.168.1.5 (192.168.1.5). Requested URL: '/api/...'"
# Re-verify this against the HA version you support - see module docstring.
CURRENT_BAN_MSG_RE = re.compile(
    r"invalid authentication from ([0-9a-fA-F:.]+)"
    r"(?:\s*\(([0-9a-fA-F:.]+)\))?"
    r"(?:\.\s*Requested URL:\s*'([^']+)')?"
)


class BanLogHandler(logging.Handler):
    """A logging.Handler that turns HA's ban-log WARNING records into
    structured LogEvents and hands them to `enqueue`."""

    def __init__(self, enqueue: Callable[[LogEvent], None]) -> None:
        super().__init__(level=logging.WARNING)
        self._enqueue = enqueue

    def emit(self, record: logging.LogRecord) -> None:
        try:
            message = record.getMessage()
        except Exception:  # pragma: no cover - defensive, logging must not raise
            return

        match = CURRENT_BAN_MSG_RE.search(message)
        if not match:
            return

        source_ip = match.group(1)
        requested_url = match.group(3)

        event = LogEvent(
            category=CATEGORY_AUTH,
            event_type="http_auth_failed",
            source_ip=source_ip,
            outcome=AUTH_FAILURE,
            data={
                "requested_url": requested_url,
                "raw_message": message,
            },
        )
        self._enqueue(event)


def setup_ban_log_capture(enqueue: Callable[[LogEvent], None]) -> Callable[[], None]:
    """Attach the BanLogHandler to HA's ban logger. Returns a callable that
    detaches it (call from async_unload_entry)."""
    handler = BanLogHandler(enqueue)
    target_logger = logging.getLogger(HA_BAN_LOGGER_NAME)
    target_logger.addHandler(handler)

    def _remove() -> None:
        target_logger.removeHandler(handler)

    return _remove


class AuthProviderHookNotImplemented(Exception):
    """Raised by the (currently unimplemented) successful-login hook.

    Placeholder so the gap is visible in code, not just documentation.
    See the module docstring and docs/ROADMAP.md ("Phase 2: successful
    auth capture") for the intended approach before implementing this.
    """
