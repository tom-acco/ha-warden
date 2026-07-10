"""Successful-auth capture by polling refresh tokens.

Home Assistant fires no event for a successful login and its only in-process
"success" log line is a userless DEBUG record (see auth_listener.py and
docs/ARCHITECTURE.md). The one clean, API-based signal is the refresh-token
store: `hass.auth.async_get_users()` -> each `User.refresh_tokens`. A
RefreshToken carries the user, client, type, creation time, and last-used
IP, so watching that store surfaces the security-relevant transitions:

  * a new `normal` token  -> an interactive session was established (a login);
  * a new `long_lived_access_token` -> an API token was minted (worth noting);
  * a known token used from a not-previously-seen IP -> the session is active
    from a new location.

This measures session/token *issuance*, not per-request logins: the source IP
arrives on first use, and detection latency is bounded by the poll interval.
That's honest and sufficient - see docs/ARCHITECTURE.md for why this beats
monkeypatching the auth provider.

The diff logic (AuthTokenTracker) is kept free of Home Assistant imports so it
is unit-testable; async_poll() is the thin HA-facing fetch that feeds it.
"""
from __future__ import annotations

from typing import Any, Callable

from .const import AUTH_SUCCESS, CATEGORY_AUTH
from .storage import LogEvent

# RefreshToken.token_type values (homeassistant.auth.models). Hardcoded rather
# than imported so this module stays HA-free and testable; they are stable.
TOKEN_TYPE_NORMAL = "normal"
TOKEN_TYPE_LONG_LIVED = "long_lived_access_token"

EVENT_SESSION_STARTED = "session_started"
EVENT_LONG_LIVED_TOKEN_CREATED = "long_lived_token_created"
EVENT_SESSION_NEW_IP = "session_new_ip"
EVENT_SESSION_ENDED = "session_ended"


class AuthTokenTracker:
    """Diffs successive refresh-token snapshots into successful-auth events.

    The first snapshot is a silent baseline (existing tokens are recorded, not
    logged - otherwise every restart would re-log every current session). After
    that, newly-appearing tokens and new source IPs on known tokens are
    emitted. State is in-memory: a restart re-baselines, so a login that
    happened while HA was down isn't retroactively logged (inherent to
    polling; documented).
    """

    def __init__(self) -> None:
        self._seeded = False
        # token_id -> {"user_id", "token_type", "client_name", "ips": set}
        self._tokens: dict[str, dict[str, Any]] = {}

    @staticmethod
    def _record(t: dict[str, Any]) -> dict[str, Any]:
        return {
            "user_id": t["user_id"],
            "token_type": t["token_type"],
            "client_name": t.get("client_name"),
            "ips": {t["last_used_ip"]} if t["last_used_ip"] else set(),
        }

    def process(self, snapshot: list[dict[str, Any]]) -> list[LogEvent]:
        """Given the current token snapshot, return events to log."""
        current_ids = {t["token_id"] for t in snapshot}
        events: list[LogEvent] = []

        if not self._seeded:
            for t in snapshot:
                self._tokens[t["token_id"]] = self._record(t)
            self._seeded = True
            return events

        for t in snapshot:
            tid = t["token_id"]
            ip = t["last_used_ip"]
            rec = self._tokens.get(tid)
            if rec is None:
                self._tokens[tid] = self._record(t)
                events.append(self._token_event(t))
            elif ip and rec["ips"] and ip not in rec["ips"]:
                # A genuinely new location for a token we've already seen used.
                rec["ips"].add(ip)
                events.append(self._ip_event(t))
            elif ip and not rec["ips"]:
                # First IP for a token that was created before it was used -
                # record it silently (it's the origin, not a *new* location).
                rec["ips"].add(ip)

        # A token that vanished was revoked / logged out / expired -> the
        # session ended. Emit that (closing the login->logout lifecycle) and
        # forget it so the map can't grow without bound.
        for tid in list(self._tokens):
            if tid not in current_ids:
                events.append(self._ended_event(self._tokens.pop(tid)))

        return events

    @staticmethod
    def _token_event(t: dict[str, Any]) -> LogEvent:
        is_llt = t["token_type"] == TOKEN_TYPE_LONG_LIVED
        return LogEvent(
            category=CATEGORY_AUTH,
            event_type=EVENT_LONG_LIVED_TOKEN_CREATED if is_llt else EVENT_SESSION_STARTED,
            outcome=AUTH_SUCCESS,
            user_id=t["user_id"],
            source_ip=t["last_used_ip"],
            data={
                "client_name": t.get("client_name"),
                "token_type": t["token_type"],
                "created_at": t.get("created_at"),
            },
        )

    @staticmethod
    def _ip_event(t: dict[str, Any]) -> LogEvent:
        return LogEvent(
            category=CATEGORY_AUTH,
            event_type=EVENT_SESSION_NEW_IP,
            outcome=AUTH_SUCCESS,
            user_id=t["user_id"],
            source_ip=t["last_used_ip"],
            data={
                "client_name": t.get("client_name"),
                "token_type": t["token_type"],
            },
        )

    @staticmethod
    def _ended_event(rec: dict[str, Any]) -> LogEvent:
        # Not a success/failure - it's the session closing - so outcome is left
        # unset (it must not count toward the "failed auth" tile).
        return LogEvent(
            category=CATEGORY_AUTH,
            event_type=EVENT_SESSION_ENDED,
            user_id=rec["user_id"],
            data={
                "client_name": rec["client_name"],
                "token_type": rec["token_type"],
            },
        )


async def async_poll(hass, tracker: AuthTokenTracker, enqueue: Callable[[LogEvent], None]) -> None:
    """Build a snapshot from hass.auth and feed it to the tracker.

    Filters to human/API tokens: skips system-generated users and `system`
    tokens (churned by integrations/Supervisor), which are noise, not logins.
    """
    snapshot: list[dict[str, Any]] = []
    for user in await hass.auth.async_get_users():
        if user.system_generated:
            continue
        for token in user.refresh_tokens.values():
            if token.token_type not in (TOKEN_TYPE_NORMAL, TOKEN_TYPE_LONG_LIVED):
                continue
            snapshot.append(
                {
                    "token_id": token.id,
                    "user_id": user.id,
                    "token_type": token.token_type,
                    "client_name": token.client_name,
                    "created_at": token.created_at.isoformat() if token.created_at else None,
                    "last_used_ip": token.last_used_ip,
                }
            )
    for event in tracker.process(snapshot):
        enqueue(event)
