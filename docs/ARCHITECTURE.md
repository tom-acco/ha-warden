# Architecture

## Goals, in priority order

1. Capture auth attempts (success + failure, source, outcome) without
   storing credential contents.
2. Attribute user actions ("who did what") using data HA already tracks.
3. Flag anomalous device behaviour with something explainable, not a black
   box.
4. Make the log resistant to *silent* tampering (append-only, hash-chained).
5. Be installable by a normal HA user via HACS, not just a developer.

Everything below explains a design decision and, where relevant, what it
costs you.

## Why a separate SQLite database instead of the HA Recorder

HA's built-in Recorder already stores state history, but:

- It's designed for graphing/history, with purge policies that assume
  you're fine losing detail over time - not for an audit trail.
- If someone compromises or resets HA (or you restore an old backup), the
  Recorder DB goes with it. A security log arguably needs to survive that.
- Structuring auth attempts and anomaly events into the same schema as
  arbitrary sensor state history would make querying (and later, exporting
  for compliance/review) much messier.

Cost: you now own a second database file, its migrations, and its backup
story. That's a real maintenance burden for an open-source project -
budget for it in your release process (see ROADMAP.md).

## Why hash-chaining instead of e.g. signing each row

Hash-chaining (`row_hash = SHA256(prev_hash + row_data)`) is cheap, has no
key-management story, and is enough to answer the question "has this log
been altered since it was written?" - which is the actual threat model for
a home user (someone with access to the HA box editing/deleting
incriminating rows), not "can a third party cryptographically prove this
log's authenticity to someone else" (which would need real signing with a
key HA doesn't hold, and is a different, bigger problem).

**What it does not protect against:** someone with filesystem access
replacing the *entire* database file with a fabricated one that has its
own internally-consistent chain from a fake genesis. Hash-chaining detects
*edits to history*, not *wholesale replacement*. If you need protection
against that too, you'd want to periodically publish/export the latest
`row_hash` somewhere outside the box (e.g. a push to a cloud service or a
notification), so a wholesale replacement is at least detectable by
comparing to that external record. Noted as a Phase 3 idea in ROADMAP.md,
not implemented.

## Why we don't log credential contents

For failed logins specifically: it's tempting to log "what was entered"
for forensic value, but the entered "password" in a failed attempt is
frequently the user's *real* password, mistyped (wrong caps-lock state,
autofill from the wrong site, etc). A log designed to help you detect
intrusions would, in practice, spend most of its life accumulating your own
family's real credentials in more-or-less plaintext. That log then becomes
one of the most attractive files in your entire HA config to steal. The
asymmetry (rare genuine attacker value vs. near-certain accumulation of
real secrets) is why this integration only logs: source IP, whether it
succeeded, and (once Phase 2's provider hook exists) which username was
presented - never the password/PIN/code itself. `event_listener.py`
additionally redacts common secret-shaped keys (`code`, `password`, `pin`,
`token`, `api_key`) out of any service-call data it logs, for the same
reason (e.g. someone calling `alarm_control_panel.alarm_disarm` with a
code).

## Why user attribution rides on HA's existing Context object

Home Assistant already attaches a `Context` (with `user_id`, `id`,
`parent_id`) to every state change and service call. This is the standard
mechanism the frontend, automations, and scripts all use internally to
know "what caused this." Building a separate attribution system would
duplicate something HA already solved, and would drift out of sync with
it. The integration listens on the event bus (`EVENT_CALL_SERVICE`,
`EVENT_STATE_CHANGED`) and just reads `event.context.user_id` - no custom
tracking needed.

Limits: `user_id` is `None` for changes triggered by automations,
integrations, or physical button presses on a device with no associated
HA user - which is most device-initiated state changes. This is a
genuine gap, not a bug: HA's context model wasn't built with security
audit as a goal, and "what user_id is this integration polling under"
is often not a meaningful question. For those, `parent_id`/`id` chains and
the entity/domain of the originating service call are your next-best
attribution signal.

## Why failed-login capture is a logging.Handler on a HA-internal logger

HA does not fire a bus event for failed logins; it only logs a WARNING
string from `homeassistant.components.http.ban`. Attaching a
`logging.Handler` to that logger and parsing the message is the only
current way to get this data without patching HA core. This is explicitly
called out as version-fragile in `auth_listener.py` - a future HA release
changing that log message format would silently stop working. Options if/
when that breaks:

- Update the regex (fastest fix).
- Move to a real hook into the HTTP layer (e.g. a middleware) if HA
  exposes one by the time you need it.
- File an upstream feature request for a proper `auth_attempt` event -
  arguably the right long-term fix, and something worth doing regardless
  since it would benefit everyone building on this, not just this project.

## Why successful-login capture is *not* implemented (yet)

There is no bus event or usable log line for successful logins today
(verified against HA dev, 2026-07):

- `homeassistant.components.http.ban.process_success_login` logs only at
  DEBUG and carries no user identity.
- `homeassistant.components.auth.login_flow` is where success actually
  happens (user + credential + client + request IP are in scope) but fires
  no event and writes nothing structured.
- `AuthManager` fires user add/update/remove events, nothing for login or
  token creation/use.
- The "supervisor.auth: Successful login for 'x'" INFO line is emitted by
  the Supervisor process, not HA core - an in-process log handler can't see
  it, and it doesn't exist on Container/Core installs. The common
  `system_log_event` automation recipe depends on it and is therefore
  fragile and install-type-dependent.

Two real options, deliberately weighed rather than faking it with a proxy
signal (e.g. "person entity changed to home" - that's presence, not
authentication, and would be actively misleading in a security log):

1. **Hook an auth provider's `async_validate_login`** (the
   `AuthProviderHookNotImplemented` stub in `auth_listener.py`). Exact,
   at-the-moment, with IP - but requires monkeypatching private,
   provider-specific internals. Poor footing for a security integration and
   version-fragile.
2. **Poll refresh tokens** via `hass.auth.async_get_users()` -> each
   `User.refresh_tokens`. `RefreshToken` exposes `user`, `client_name`,
   `token_type` (normal / system / long_lived_access_token), `created_at`,
   `last_used_at`, `last_used_ip`. A new `normal` token = a session was
   established; a new `long_lived_access_token` = an API token was minted; a
   known token used from a new `last_used_ip` = activity from a new
   location. This uses stable-ish public API, no monkeypatching, and is
   honest that it measures *session/token issuance* (source IP on first
   use, latency bounded by the poll interval) rather than per-request
   logins.

Option 2 is the recommended path; option 1 is retained only as an optional
"instant/exact" enhancement. Left unimplemented for now, with the gap
visible in code (`AuthProviderHookNotImplemented`) - see docs/ROADMAP.md
Phase 2.

## Why anomaly detection is a z-score baseline, not ML

A per-entity, per-hour-of-day rolling mean/stddev (Welford's algorithm, so
no need to store full event history in memory) is:

- **Explainable** - "this fired because door sensor X saw 14 events this
  hour vs. a baseline of 1.2 +/- 0.8" is something a homeowner can actually
  evaluate and act on. A model that says "0.94 anomaly score" is not.
- **Cheap** - runs fine on a Raspberry Pi, no training pipeline, no model
  file to ship/version.
- **Auditable** - for an open-source security tool, "here is the exact
  arithmetic that produced this alert" matters for trust.

The known edge case (documented and fixed in `anomaly.py`): a baseline
with *zero* observed variance (e.g. a sensor that has fired exactly once,
every day, for weeks) can't compute a real z-score - dividing by a stddev
of 0 either crashes or silently reports "no anomaly," so a rock-solid
baseline could never flag *any* deviation, which is the opposite of the
desired behaviour. The fallback: if variance is 0 and the new observation
differs at all from the mean, treat it as a large fixed z-score rather
than skip the check.

Where a heavier model could plug in later without changing the storage
schema: replace `AnomalyEngine.record_period` internals, keep its
input/output contract (entity_id, hour_of_day, count -> anomaly dict or
None) the same, so `__init__.py`'s polling loop and the `anomaly` log
category don't need to change.

**Baselines survive restarts by replaying the log, not by persisting the
model.** The baseline state (per-entity, per-hour Welford stats) lives only
in memory. If it were left to rebuild from empty on each setup, then with
`min_samples=8` you'd need ~8 days of continuous uptime before anything
could be flagged again - and since HA is restarted more often than that for
most people, detection would in practice almost never fire. Rather than add
a serialization format for the model, `history.reconstruct_hourly_
observations` replays the already-persisted `device_state` events into the
same per-hour observations the live tick makes, and `warm_from_history`
seeds the baselines from them on startup. This keeps a single source of
truth (the log), needs no schema change, and survives a hard crash - not
just a clean unload. The in-progress clock hour is excluded from replay so
a partial count can't bias the baseline; the live tick records it once it
completes.

## Scaling considerations

Typical home security event volume (door/lock/motion/service-calls) is low
- tens to low hundreds of events/day for most homes. The current design
(SQLite, `hass.async_add_executor_job` per write, no in-memory queue) is
sized for that. If you're building for a much larger install (many
cameras firing motion events per minute, commercial deployment, etc.), you
would want to: batch writes, add a bounded `asyncio.Queue` in front of the
executor calls in `__init__.py`'s `enqueue()` so a burst can't back up the
event loop, and consider Postgres over SQLite for concurrent-write
throughput. Not implemented, since it would add complexity most users
don't need - see ROADMAP.md if this becomes a real bottleneck for someone.

## Packaging: integration, not add-on

This ships as a `custom_components/` integration (HACS-installable),
not a Supervisor add-on. Add-ons run as separate Docker containers and are
the right call when you need a runtime/dependency HA's own Python
environment can't provide (a different language, a heavier ML runtime, a
service that needs to keep running independent of HA's process). Nothing
here currently needs that - SQLite and pure-Python stats are fine inside
HA's own process - and integrations have a much lower install-friction
path for end users (a HACS click-to-install vs. add-on store setup). If
Phase 2/3 work (e.g. a heavier anomaly model, or an export/archival
service) needs its own runtime, revisit this decision then rather than
paying the complexity cost now.
