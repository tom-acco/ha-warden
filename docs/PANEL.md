# Dedicated panel — design & plan

Status: **plan only, not implemented.** This is the Phase 2 "dedicated
frontend panel" item from ROADMAP.md, thought through so the work (and its
tradeoffs) are visible before any code is written.

## Why a panel at all

Today the log is viewable two ways, both limited:

- the `warden.query_events` action (Developer Tools -> Actions) — powerful
  filtering, but it's a developer tool, not somewhere you'd send a household
  member, and the response is raw YAML;
- the `Warden Recent Events` sensor + a Markdown card — dashboard-friendly,
  but it's a fixed 20-row window with no search, sort, or pagination, and it
  refreshes only every 5 minutes.

A security audit log wants a real **timeline you can search, filter, and
drill into**, plus at-a-glance health (counts, integrity, DB size). That's a
full-page UI — a sidebar panel — not a card.

## The big tradeoff to decide first

A panel is the first thing that makes Warden ship **frontend code**. So far
it's pure Python (SQLite + stdlib), which is a deliberate part of its
low-maintenance, auditable ethos (see ARCHITECTURE.md). A panel adds a
JavaScript surface that has to track HA frontend changes over time. That's
the real cost — weigh it before committing.

Three approaches, increasing in effort and capability:

| Approach | Sidebar item? | Ships JS? | Capability | Effort |
| --- | --- | --- | --- | --- |
| **A. Cards only** (today, +docs) | no | no | fixed window, no search | ~none |
| **B. Registered Lovelace dashboard** | yes | no | curated cards, still card-bound | low |
| **C. Custom web-component panel** | yes | yes | real searchable/paginated timeline | high |

**Recommendation: C, but built no-build** — a single hand-authored
vanilla-JS web component (no webpack/rollup toolchain), backed by a small
WebSocket API. It's the only option that delivers the actual goal (a
searchable, paginated, drill-in timeline), and writing the component as one
plain ES module keeps the frontend footprint to *one reviewable file* with
no build pipeline — preserving as much of the "auditable, low-toolchain"
ethos as a frontend can. B is a reasonable stepping stone if we want a
sidebar entry sooner; A stays as the zero-dependency fallback we already
ship.

## How it works (Approach C architecture)

```
  Sidebar "Warden"  ──click──▶  warden-panel  (custom element, this.hass injected)
                                     │
                                     │  hass.connection.sendMessagePromise(...)
                                     ▼
                         WebSocket API commands (Python, admin-only)
                            warden/stats · warden/query · warden/verify
                                     │
                                     ▼
                         SecurityStorage (existing SQLite layer)
```

**Backend (Python, in the integration):**

1. **WebSocket commands** via `homeassistant.components.websocket_api`, each
   `@websocket_api.require_admin` (a security log is admin-only) and run on
   the executor:
   - `warden/stats` → the tile numbers (24h counts) + DB size + last-purge info.
   - `warden/query` → events with **server-side** filters (category, entity,
     user, outcome, time range, free text) **+ offset/limit + total count**
     for pagination. This is the panel's workhorse.
   - `warden/verify` → the per-category `verify_chain()` result.
   - *(later)* `warden/subscribe` → push new events for a live "tail" toggle.
2. **Serve the panel JS** as a static file with
   `hass.http.async_register_static_paths([StaticPathConfig("/warden_static", <dir>, False)])`.
3. **Register the sidebar panel** with
   `panel_custom.async_register_panel(hass, frontend_url_path="warden",
   webcomponent_name="warden-panel", module_url="/warden_static/warden-panel.js",
   sidebar_title="Warden", sidebar_icon="mdi:shield-search", require_admin=True)`.

**Frontend (one JS file):** a `warden-panel` custom element. HA sets
`this.hass` on it; the element calls the WS commands, holds filter/pagination
state, and renders the table + tiles + detail drawer. Written as vanilla
`HTMLElement` + template strings (no build); can migrate to Lit later if the
component grows enough to justify a toolchain.

**Storage additions needed** (small): an `offset` parameter and a `count(...)`
method on `SecurityStorage.query`/a sibling, and a public accessor for
`_db_size_bytes()`. Everything else already exists.

## How it looks

```
┌────────────────────────────────────────────────────────────────────┐
│ 🛡 Warden                                          [ Verify integrity ]│
├────────────────────────────────────────────────────────────────────┤
│ ┌───────────┐ ┌───────────┐ ┌───────────┐ ┌───────────┐            │
│ │Failed auth│ │ Anomalies │ │  Actions  │ │  DB size  │            │
│ │    3   24h│ │   0   24h │ │ 1,204 24h │ │  12.4 MB  │            │
│ └───────────┘ └───────────┘ └───────────┘ └───────────┘            │
├────────────────────────────────────────────────────────────────────┤
│ [ Category ▾ ] [ ⌕ entity/type ] [ User ▾ ] [ Outcome ▾ ] [ 24h ▾ ] │
├────────────────────────────────────────────────────────────────────┤
│ Time            Category      Type              Entity        Outcome│
│ ──────────────────────────────────────────────────────────────────  │
│ 08:14:02  ⚠ auth          http_auth_failed    —             failure │
│ 08:13:55    device_state  state_changed        lock.front    —       │  ← click row
│ 08:13:40    user_action   call_service         —             —       │     to expand
│ 08:10:11  ⚑ anomaly       anomalous_frequency  binary.door   —       │
│ ...                                                                  │
│                                       showing 1–50 of 3,812  ‹ ›     │
├────────────────────────────────────────────────────────────────────┤
│ ▾ 08:13:55  device_state / state_changed         (expanded detail)   │
│    entity: lock.front_door   user: 3b2f…a91   context: 018f… ← 018e… │
│    data: { old_state: "locked", new_state: "unlocked", … }          │
└────────────────────────────────────────────────────────────────────┘
```

Feature set, prioritised:

1. **Stat tiles** — the three 24h counts + DB size (from `warden/stats`).
2. **Event table** — server-paginated, newest first, category icon/colour.
3. **Filters** — category, entity, user, outcome, time range, free text;
   applied server-side so it scales past the in-memory window.
4. **Row detail** — expand to the full `data` blob + the context chain
   (`context_id` ← `parent_id`, the "what caused this" trail) + row hashes.
5. **Integrity view** — "Verify integrity" runs `warden/verify` and shows
   per-category chain status (range, `anchored_to_genesis`, ok / first break).
6. *(later)* **Live tail** toggle, and **Export** current query to JSON/CSV.

## Permissions

Admin-only, enforced in **two** places: `require_admin=True` on the panel
(hides it from non-admins) *and* `@websocket_api.require_admin` on every WS
command (so the data can't be fetched by a non-admin hitting the socket
directly). A security log must not be a privilege-escalation read.

## Milestones

- **M1 — Backend.** WS commands (`stats`, `query`, `verify`) + storage
  `offset`/`count`/size accessor. Testable without any UI via the WS API.
- **M2 — Minimal panel.** Register the sidebar item; render tiles + a
  read-only paginated table. Ship the single JS file via static path.
- **M3 — Filters + row detail.** The filter bar and the expand-to-detail
  drawer, including the context chain.
- **M4 — Integrity view.** Surface `verify_chain` per-category.
- **M5 — (optional) live tail + export.**

M1 is independently useful (better programmatic access) even if the UI
stalls, which de-risks the frontend commitment.

## Risks / open questions

- **Frontend maintenance.** The JS must track HA frontend conventions
  (`this.hass`, theming variables, connection API). Mitigate by keeping it
  one small vanilla file and leaning on CSS variables HA already exposes for
  theming.
- **Verify exact APIs against the target HA release** at implementation time
  (as with the ban-log regex): `panel_custom.async_register_panel` signature,
  `async_register_static_paths`/`StaticPathConfig`, and the
  `websocket_api` decorators — confirmed against 2026-07 dev, but re-check.
- **Theming / mobile.** Should reuse HA's CSS custom properties so it matches
  the user's theme and works on the companion app; needs testing on narrow
  screens.
- **Do we even want live tail?** Push subscriptions add complexity; the 5s
  buffer + a manual refresh may be enough for v1.
