"""Auth capture tests: the ban-log regex (incl. the user-agent group) and the
refresh-token session tracker. Both modules are HA-free, so these run with no
Home Assistant install.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(__file__))
import conftest  # noqa: F401,E402  (registers the warden package)

from warden.auth_listener import CURRENT_BAN_MSG_RE  # noqa: E402
from warden.auth_poller import (  # noqa: E402
    AuthTokenTracker,
    EVENT_LONG_LIVED_TOKEN_CREATED,
    EVENT_SESSION_NEW_IP,
    EVENT_SESSION_STARTED,
    TOKEN_TYPE_LONG_LIVED,
    TOKEN_TYPE_NORMAL,
)

# The exact WARNING captured live on HA 2026.5 (see the panel screenshot).
REAL_MSG = (
    "Login attempt or request with invalid authentication from "
    "10.1.102.50 (10.1.102.50). Requested URL: "
    "'/auth/login_flow/2c702620348a746a51a071a4145962cc'. "
    "(Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/150.0.0.0 Safari/537.36)"
)


def test_ban_regex_extracts_ip_url_and_user_agent():
    m = CURRENT_BAN_MSG_RE.search(REAL_MSG)
    assert m is not None
    assert m.group(1) == "10.1.102.50"
    assert m.group(3) == "/auth/login_flow/2c702620348a746a51a071a4145962cc"
    # The greedy UA group must span its own inner parens.
    assert m.group(4).startswith("Mozilla/5.0 (Macintosh;")
    assert m.group(4).endswith("Safari/537.36")


def test_ban_regex_without_user_agent_still_matches():
    msg = ("Login attempt or request with invalid authentication from "
           "192.168.1.5 (192.168.1.5). Requested URL: '/api/x'")
    m = CURRENT_BAN_MSG_RE.search(msg)
    assert m.group(1) == "192.168.1.5"
    assert m.group(3) == "/api/x"
    assert m.group(4) is None


def _tok(tid, uid="u1", ttype=TOKEN_TYPE_NORMAL, ip=None, client="Chrome"):
    return {
        "token_id": tid, "user_id": uid, "token_type": ttype,
        "client_name": client, "created_at": None, "last_used_ip": ip,
    }


def test_tracker_seeds_silently_then_flags_new_session():
    tr = AuthTokenTracker()
    assert tr.process([_tok("a", ip="1.1.1.1")]) == []  # baseline: no events
    events = tr.process([_tok("a", ip="1.1.1.1"), _tok("b", ip="2.2.2.2")])
    assert len(events) == 1
    assert events[0].event_type == EVENT_SESSION_STARTED
    assert events[0].user_id == "u1"
    assert events[0].source_ip == "2.2.2.2"
    assert events[0].outcome == "success"


def test_tracker_flags_long_lived_token():
    tr = AuthTokenTracker()
    tr.process([])  # seed empty
    events = tr.process([_tok("llt", ttype=TOKEN_TYPE_LONG_LIVED, ip="3.3.3.3")])
    assert len(events) == 1
    assert events[0].event_type == EVENT_LONG_LIVED_TOKEN_CREATED


def test_tracker_flags_new_ip_for_known_token():
    tr = AuthTokenTracker()
    tr.process([_tok("a", ip="1.1.1.1")])           # baseline with an ip
    assert tr.process([_tok("a", ip="1.1.1.1")]) == []   # same ip: nothing
    events = tr.process([_tok("a", ip="9.9.9.9")])       # new location
    assert len(events) == 1
    assert events[0].event_type == EVENT_SESSION_NEW_IP
    assert events[0].source_ip == "9.9.9.9"


def test_tracker_first_ip_is_silent_when_created_without_one():
    tr = AuthTokenTracker()
    tr.process([])  # seed empty
    started = tr.process([_tok("a", ip=None)])
    assert len(started) == 1 and started[0].source_ip is None
    assert tr.process([_tok("a", ip="1.1.1.1")]) == []   # first ip: origin, silent
    later = tr.process([_tok("a", ip="2.2.2.2")])         # then a genuine new one
    assert len(later) == 1 and later[0].event_type == EVENT_SESSION_NEW_IP


def test_tracker_prunes_revoked_tokens():
    tr = AuthTokenTracker()
    tr.process([_tok("a", ip="1.1.1.1")])  # baseline
    tr.process([])                          # 'a' revoked -> pruned
    events = tr.process([_tok("a", ip="1.1.1.1")])  # reappears -> treated as new
    assert len(events) == 1
    assert events[0].event_type == EVENT_SESSION_STARTED


if __name__ == "__main__":
    for name, fn in sorted(globals().items()):
        if name.startswith("test_") and callable(fn):
            fn()
    print("all auth tests passed")
