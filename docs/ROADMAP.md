# Roadmap

## Phase 0 - this scaffold (done)

- [x] Hash-chained SQLite storage with integrity verification
- [x] Service-call logging with user_id attribution via HA Context
- [x] Monitored-entity state-change logging (configurable domains/device
      classes)
- [x] Failed-auth capture via ban-log scraping
- [x] Basic z-score anomaly engine + hourly polling loop
- [x] Config flow (UI setup + options)
- [x] `query_events` / `verify_integrity` / `purge_old` services
- [x] Three summary sensors
- [x] Unit-level smoke tests of storage.py and anomaly.py (pure Python,
      no HA dependency needed) - in `tests/`, runnable as `pytest tests/`
      or by running each file directly

## Phase 0.1 - post-review hardening (done)

Findings from a code review of the initial scaffold, fixed in the commits
following it:

- [x] **Hash-chain write race.** `storage.append()` is a read-last-hash ->
      insert read-modify-write, driven from HA's multi-threaded executor
      over one shared connection. Concurrent appends could fork the chain
      and make `verify_integrity` report false tampering. Now serialized
      with a lock; regression-tested with 16 threads / 2000 writes.
- [x] **Config-flow list fields.** `monitored_domains` /
      `monitored_device_classes` used `vol.Coerce(list)`, which HA renders
      as a text box and which shreds a typed string into per-character
      lists. Replaced with a proper multi-select `SelectSelector`.
- [x] **Anomaly baselines reset on every restart.** They lived only in
      memory, so with `min_samples=8` detection effectively never fired for
      anyone who restarts HA weekly. Now rehydrated on startup by replaying
      persisted `device_state` history (no schema change).
- [x] Smaller fixes: recursive secret redaction, surfacing failed-write
      exceptions instead of dropping events, service teardown on unload,
      `outcome` filter so the failed-auth tile counts failures only,
      OptionsFlow deprecation.

## Phase 0.2 - retention & write path (done)

- [x] **Automatic, bounded retention.** Nothing enforced retention before
      this - `retention_days` was only the manual purge default, so the DB
      grew without limit (the biggest risk for a live install). Added a
      daily job with **two-tier per-category** age limits (activity =
      device_state/user_action, expire fast; security = auth/anomaly/
      maintenance, keep long) plus a hard **size-cap backstop**
      (`max_db_size_mb`), with `auto_vacuum=INCREMENTAL` so the file
      actually shrinks.
- [x] **Per-category hash chains.** Required to make selective/tiered
      retention compatible with tamper-evidence: a single global chain
      would break every later row when old device_state rows were deleted
      from the middle. `verify_integrity` now reports per-category range +
      `anchored_to_genesis`, and purges are logged as auditable
      `maintenance` events so a legitimate purge isn't mistaken for
      tampering.
- [x] **Buffered writes.** Events batch in memory and flush by count or
      time (`append_batch`, one commit per flush) instead of one commit per
      event; flushed on unload. Documented durability tradeoff.

**Not yet done, and worth doing before calling this "v1":**
- [ ] Actually run it inside a live HA instance (devcontainer or HA OS VM)
      end to end - this scaffold has been syntax-checked and had its
      storage/anomaly logic unit-tested standalone, but never exercised
      against real HA event bus traffic.
- [ ] Confirm the ban-log regex against the actual HA version(s) you plan
      to support - message format may have shifted release to release.
- [ ] Decide and add a license file.

## Phase 1 - make it trustworthy for real use

- [ ] End-to-end test harness: spin up a real (or minimal-config) HA
      instance in CI, trigger fake service calls/state changes/failed
      logins, assert they land in the log correctly.
- [ ] Config validation: reject nonsensical monitored_domains, surface
      clear errors in the options flow rather than silently no-op'ing.
- [ ] Export tooling: dump a time range to a signed/hashed archive file
      before `purge_old` runs, so retention and long-term audit aren't
      mutually exclusive (see ARCHITECTURE.md's purge_old caveat).
- [ ] Basic Lovelace card (or at least documented YAML) so people don't
      have to hit Developer Tools -> Actions to read their own log.

## Phase 2 - close the known functionality gaps

- [x] **Successful-login capture.** Implemented via refresh-token polling
      (`auth_poller.py`): a snapshot diff emits `session_started`,
      `long_lived_token_created`, and `session_new_ip` events (outcome
      `success`), seeded silently on startup. Closes the biggest gap versus
      the original ask ("auth attempts, both failed and successful"). The
      auth-provider `async_validate_login` hook
      (`AuthProviderHookNotImplemented`) remains an optional "instant/exact"
      enhancement. Not yet exercised in a live HA.
- [x] **Capture the user-agent on failed logins.** `CURRENT_BAN_MSG_RE` now
      has a 4th group for the trailing "({user_agent})"; stored under
      `data.user_agent`. Verified against a live 2026.5 capture.
- [x] Dedicated frontend panel (sidebar item) with a searchable/filterable
      timeline — implemented (M1–M4) as a no-build vanilla web-component panel
      (`panel/warden-panel.js`) over an admin-only WebSocket API
      (`websocket.py`). Stat tiles, filtered/paginated table, row detail, and
      integrity view. See `docs/PANEL.md`. Not yet exercised in a live HA;
      optional M5 (live tail/export) remains.
- [x] **More hookable events (Tier 1).** User-account changes
      (`user_added`/`updated`/`removed` -> `account` category) and HA
      lifecycle (`homeassistant_started`/`stop` -> `system` category, which
      also flushes the write buffer on shutdown). Both in the security
      retention tier.
- [x] **Source-review finds (2026-07).** Reviewing HA source surfaced four
      more captures: **IP bans** (the `Banned IP ...` WARNING on the ban
      logger we already tap - the escalation we'd been dropping); **session
      end** (the token poller already saw tokens vanish - now emits
      `session_ended`, closing login->logout); **backup create/restore** (no
      bus event and DEBUG-only/unlogged, so via the backup manager's
      `async_subscribe_events` stream, defensively); and `core_config_updated`.
      MFA enable/disable has no clean hook (no event) - noted, partially
      covered via `user_updated` / `session_ended`.
- [ ] **More hookable events (Tier 2).** Config-change audit trail:
      integration added/removed (no single bus event - watch
      `EVENT_COMPONENT_LOADED`/config-entries) and entity/device registry
      changes (`EVENT_ENTITY_REGISTRY_UPDATED`/`DEVICE_REGISTRY_UPDATED`,
      logging create/remove, skipping noisy `update`). Deliberately NOT
      hooking automation/script firing (volume) or presence-as-auth
      (misleading).
- [ ] Per-user notification rules (e.g. "notify me only for anomalies on
      exterior door sensors", "notify me for any failed auth from a new
      IP").
- [ ] Multi-instance correlation - if someone runs Frigate/an NVR/a
      separate alarm panel integration, correlate their events into the
      same timeline rather than treating this purely as an HA-internal
      event log.

## Phase 3 - things to consider only if actually needed

- [ ] External hash-checkpoint publishing (push the latest `row_hash`
      somewhere off-box periodically) to detect wholesale database
      replacement, not just row edits - see ARCHITECTURE.md.
- [ ] Postgres backend option for higher write throughput /
      multi-instance setups.
- [ ] Heavier anomaly modeling (e.g. per-entity seasonal decomposition,
      or a small local model) - only if the z-score baseline demonstrably
      misses things people care about in practice. Don't add ML for its
      own sake; see ARCHITECTURE.md's rationale for why v1 deliberately
      avoids it.
- [ ] Bound the write buffer with an explicit overflow policy. The buffer
      (Phase 0.2) batches writes but is unbounded - it warns rather than
      drops, since dropping a security event is worse than the memory cost.
      An adversarial event volume would want a hard cap with a defined
      overflow behaviour (spill to disk? drop with a recorded gap marker?).
      Not needed for typical home volumes; see "Scaling considerations" in
      ARCHITECTURE.md.

## Explicitly out of scope for this project

- Being a general-purpose SIEM. This is scoped to "your Home Assistant
  instance's security-relevant events," not network traffic analysis,
  other services' logs, etc. If you want that, this log's structured
  SQLite output is a reasonable thing to feed *into* a real SIEM later,
  not something that should try to become one.
