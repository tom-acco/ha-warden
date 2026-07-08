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

- [ ] **Successful-login capture.** Implement the auth provider hook
      described in `auth_listener.py`'s docstring
      (`AuthProviderHookNotImplemented`). This is the single biggest
      functionality gap versus the original ask ("auth attempts, both
      failed and successful").
- [ ] Dedicated frontend panel (custom Lovelace panel via HA's panel
      registration API) with a searchable/filterable timeline, replacing
      the "call a service and read the response" workflow.
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
- [ ] Bounded async queue in front of storage writes if a real deployment
      shows event-loop back-pressure under high event volume (see
      "Scaling considerations" in ARCHITECTURE.md) - not needed for
      typical home event volumes.

## Explicitly out of scope for this project

- Being a general-purpose SIEM. This is scoped to "your Home Assistant
  instance's security-relevant events," not network traffic analysis,
  other services' logs, etc. If you want that, this log's structured
  SQLite output is a reasonable thing to feed *into* a real SIEM later,
  not something that should try to become one.
