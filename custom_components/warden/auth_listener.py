"""Auth attempt capture.

IMPORTANT / HONEST STATUS (read this before building on it):

Home Assistant does not currently fire a structured event-bus event for
either failed or successful login attempts. What exists today:

  * FAILED attempts: the `homeassistant.components.http.ban` logger emits a
    WARNING-level log record. As of HA dev (verified 2026-07) the format is:
        "Login attempt or request with invalid authentication from
         {host} ({ip}). Requested URL: '...'. ({user_agent})"
    This module attaches a logging.Handler to that logger and parses the IP
    out of the message. This is what's implemented below and it works today,
    but it is scraping a log string, not consuming a stable API - a future
    HA release could change that message format and quietly break the
    regex. Treat CURRENT_BAN_MSG_RE as something to re-verify against the
    HA release you're targeting. NOTE the trailing "({user_agent})" is newer
    than this module's original regex; CURRENT_BAN_MSG_RE stops at the URL
    so it still matches, but the user-agent is a useful fingerprint we're
    currently dropping - see ROADMAP Phase 2.

  * SUCCESSFUL logins: now captured by polling refresh tokens - see
    auth_poller.py. The original plan here (hook the auth provider) was NOT
    the path taken; the reasoning, verified against HA 2026-07, is below.
      - `homeassistant.components.http.ban.process_success_login` logs only
        at DEBUG and carries no user identity - not a usable scrape target.
      - `homeassistant.components.auth.login_flow` is where success actually
        happens (user + credential + client + request IP are in scope) but
        it fires no bus event and writes no structured log.
      - `AuthManager` fires user add/update/remove events but nothing for
        login or refresh-token creation/use.
      - The "supervisor.auth: Successful login for 'x'" INFO line lives in
        the Supervisor process, not HA core, so an in-process log handler
        can't see it and it doesn't exist on Container/Core installs. The
        popular `system_log_event` automation recipe relies on it and is
        therefore fragile and install-type-dependent.
    Wrapping/subclassing an auth provider's `async_validate_login` (the
    `AuthProviderHookNotImplemented` stub below) would give exact,
    at-the-moment capture with IP, but means monkeypatching private,
    provider-specific internals - poor footing for a security integration.
    The recommended approach instead is to poll refresh tokens via the
    stable-ish public API: `hass.auth.async_get_users()` -> each
    `User.refresh_tokens` (dict[str, RefreshToken]). RefreshToken exposes
    `user`, `client_name`, `token_type` (normal / system /
    long_lived_access_token), `created_at`, `last_used_at`, `last_used_ip`.
    A new `normal` token == an interactive session was established; a new
    `long_lived_access_token` == an API token was minted (worth alerting
    on); a known token used from a not-previously-seen `last_used_ip` ==
    session activity from a new location. This measures session/token
    issuance rather than per-request logins (source IP arrives on first
    use, latency bounded by the poll interval), which is honest and
    sufficient. Implemented in auth_poller.py.

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

# Matches (HA 2026.x, verified against a live 2026.5 capture):
#   "Login attempt or request with invalid authentication from
#    10.1.102.50 (10.1.102.50). Requested URL: '/auth/login_flow/...'.
#    (Mozilla/5.0 ... Chrome/150.0.0.0 Safari/537.36)"
# Groups: 1=source ip, 3=requested url, 4=user-agent (the trailing parenthesised
# UA is newer than the original format; the greedy .+ before \) captures it
# including its own inner parens). Re-verify against the HA version you target.
CURRENT_BAN_MSG_RE = re.compile(
    r"invalid authentication from ([0-9a-fA-F:.]+)"
    r"(?:\s*\(([0-9a-fA-F:.]+)\))?"
    r"(?:\.\s*Requested URL:\s*'([^']+)')?"
    r"(?:\.\s*\((.+)\))?"
)

# The escalation: HA banned an IP after too many failed attempts. It's a
# WARNING on the *same* logger we already tap, so we only need to recognise
# it. The ban is arguably the most important auth event - repeated failures
# crossed the threshold and the IP is now locked out.
BAN_APPLIED_RE = re.compile(r"Banned IP (\S+) for too many login attempts")


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

        ban_match = BAN_APPLIED_RE.search(message)
        if ban_match:
            self._enqueue(
                LogEvent(
                    category=CATEGORY_AUTH,
                    event_type="ip_banned",
                    source_ip=ban_match.group(1),
                    outcome=AUTH_FAILURE,
                    data={"raw_message": message},
                )
            )
            return

        match = CURRENT_BAN_MSG_RE.search(message)
        if not match:
            return

        source_ip = match.group(1)
        requested_url = match.group(3)
        user_agent = match.group(4)

        event = LogEvent(
            category=CATEGORY_AUTH,
            event_type="http_auth_failed",
            source_ip=source_ip,
            outcome=AUTH_FAILURE,
            data={
                "requested_url": requested_url,
                "user_agent": user_agent,
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
    """Placeholder for the auth-provider-hook style of successful-login
    capture, kept so the gap is visible in code, not just documentation.

    Note (2026-07): the module docstring now recommends refresh-token
    polling over this provider-hook approach - the hook gives exact,
    at-the-moment capture but requires monkeypatching private,
    provider-specific internals, which is poor footing for a security
    integration. This stub is retained only as the "instant/exact"
    enhancement option, not the primary planned path. See the module
    docstring and docs/ROADMAP.md ("Phase 2") before building either.
    """
