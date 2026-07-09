/*
 * Warden panel — a single, no-build web component.
 *
 * Home Assistant injects `hass` (and narrow/route/panel) onto this element and
 * mounts it full-page when the sidebar item is opened. It talks to the
 * integration's admin-only WebSocket API (warden/stats, warden/query,
 * warden/verify) and renders stat tiles, a filtered + paginated event table
 * with row detail, and an integrity report. Styling uses HA theme CSS
 * variables so it follows the user's theme.
 *
 * Kept deliberately dependency-free and hand-written (no Lit, no bundler) so
 * the frontend surface is one reviewable file. See docs/PANEL.md.
 */

const CATEGORIES = [
  "",
  "auth_attempt",
  "user_action",
  "device_state",
  "anomaly",
  "maintenance",
];

const CATEGORY_COLOR = {
  auth_attempt: "var(--error-color, #db4437)",
  anomaly: "var(--warning-color, #ffa600)",
  device_state: "var(--info-color, #039be5)",
  user_action: "var(--primary-color, #03a9f4)",
  maintenance: "var(--secondary-text-color, #888)",
};

const esc = (value) =>
  String(value ?? "").replace(/[&<>"]/g, (c) => (
    { "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c]
  ));

const fmtTime = (ts) => {
  if (!ts) return "";
  const d = new Date(ts * 1000);
  return d.toLocaleString(undefined, {
    month: "2-digit", day: "2-digit",
    hour: "2-digit", minute: "2-digit", second: "2-digit",
  });
};

const fmtBytes = (n) => {
  if (!n && n !== 0) return "—";
  const units = ["B", "KB", "MB", "GB"];
  let v = n, i = 0;
  while (v >= 1024 && i < units.length - 1) { v /= 1024; i++; }
  return `${v.toFixed(v < 10 && i > 0 ? 1 : 0)} ${units[i]}`;
};

class WardenPanel extends HTMLElement {
  constructor() {
    super();
    this.attachShadow({ mode: "open" });
    this._hass = null;
    this._built = false;
    this._state = {
      stats: null,
      events: [],
      total: 0,
      offset: 0,
      limit: 50,
      filters: {},
      expanded: null,
      error: null,
    };
  }

  set hass(hass) {
    this._hass = hass;
    if (!this._built) {
      this._build();
      this._built = true;
      this._refresh();
    }
  }
  get hass() { return this._hass; }

  async _ws(message) {
    return this._hass.connection.sendMessagePromise(message);
  }

  // -- data ----------------------------------------------------------------
  async _refresh() {
    await Promise.all([this._loadStats(), this._loadEvents()]);
  }

  async _loadStats() {
    try {
      this._state.stats = await this._ws({ type: "warden/stats" });
    } catch (err) {
      this._state.stats = null;
    }
    this._renderTiles();
  }

  async _loadEvents() {
    const s = this._state;
    const msg = { type: "warden/query", limit: s.limit, offset: s.offset };
    for (const [k, v] of Object.entries(s.filters)) {
      if (v !== "" && v != null) msg[k] = v;
    }
    try {
      const res = await this._ws(msg);
      s.events = res.events || [];
      s.total = res.total || 0;
      s.error = null;
    } catch (err) {
      s.events = [];
      s.total = 0;
      s.error = (err && err.message) || "query failed";
    }
    s.expanded = null;
    this._renderTable();
    this._renderPager();
  }

  async _verify() {
    const box = this.shadowRoot.getElementById("verify");
    box.hidden = false;
    box.innerHTML = `<div class="muted">Verifying…</div>`;
    try {
      const res = await this._ws({ type: "warden/verify" });
      const rows = Object.entries(res.chains || {}).map(([cat, c]) => `
        <tr>
          <td>${esc(cat)}</td>
          <td>${c.ok ? "✅ intact" : `❌ broken at id ${esc(c.broken_at_id)}`}</td>
          <td>${esc(c.checked)}</td>
          <td>${c.anchored_to_genesis ? "yes" : "no (purged)"}</td>
        </tr>`).join("");
      box.innerHTML = `
        <div class="verify-head">${res.ok ? "✅ All chains intact" : "❌ Tampering detected"}
          <button class="link" id="verifyClose">close</button></div>
        <table class="mini"><thead><tr>
          <th>Category</th><th>Status</th><th>Rows</th><th>Genesis-anchored</th>
        </tr></thead><tbody>${rows || `<tr><td colspan="4" class="muted">No data yet.</td></tr>`}</tbody></table>`;
      box.querySelector("#verifyClose").onclick = () => { box.hidden = true; };
    } catch (err) {
      box.innerHTML = `<div class="err">Verify failed: ${esc(err && err.message)}</div>`;
    }
  }

  // -- rendering -----------------------------------------------------------
  _build() {
    this.shadowRoot.innerHTML = `
      <style>
        :host { display:block; color:var(--primary-text-color); }
        .wrap { padding:16px; max-width:1100px; margin:0 auto; }
        header { display:flex; align-items:center; gap:8px; margin-bottom:16px; }
        h1 { font-size:20px; font-weight:500; margin:0; }
        .spacer { flex:1; }
        button {
          font:inherit; cursor:pointer; border:1px solid var(--divider-color,#ccc);
          background:var(--card-background-color,#fff); color:var(--primary-text-color);
          border-radius:8px; padding:6px 12px;
        }
        button:hover { border-color:var(--primary-color); }
        button:disabled { opacity:.4; cursor:default; }
        button.link { border:none; background:none; color:var(--primary-color); padding:0 4px; }
        .tiles { display:grid; grid-template-columns:repeat(auto-fit,minmax(150px,1fr)); gap:12px; margin-bottom:16px; }
        .tile { background:var(--card-background-color,#fff); border:1px solid var(--divider-color,#eee);
          border-radius:12px; padding:14px 16px; }
        .tile .n { font-size:26px; font-weight:600; }
        .tile .l { color:var(--secondary-text-color); font-size:13px; margin-top:2px; }
        .filters { display:flex; flex-wrap:wrap; gap:8px; margin-bottom:12px; align-items:center; }
        select, input {
          font:inherit; padding:6px 8px; border-radius:8px;
          border:1px solid var(--divider-color,#ccc);
          background:var(--card-background-color,#fff); color:var(--primary-text-color);
        }
        input { min-width:150px; }
        table { width:100%; border-collapse:collapse; background:var(--card-background-color,#fff);
          border-radius:12px; overflow:hidden; }
        th, td { text-align:left; padding:8px 10px; font-size:13px; border-bottom:1px solid var(--divider-color,#eee); }
        th { color:var(--secondary-text-color); font-weight:500; }
        tbody tr.row { cursor:pointer; }
        tbody tr.row:hover { background:var(--primary-background-color,#f5f5f5); }
        .dot { display:inline-block; width:8px; height:8px; border-radius:50%; margin-right:6px; vertical-align:middle; }
        .mono { font-family:var(--code-font-family,monospace); }
        .muted { color:var(--secondary-text-color); padding:12px; }
        .err { color:var(--error-color,#db4437); padding:12px; }
        .detail { background:var(--primary-background-color,#fafafa); }
        .detail pre { margin:6px 0 0; white-space:pre-wrap; word-break:break-word;
          font-family:var(--code-font-family,monospace); font-size:12px; }
        .pager { display:flex; align-items:center; gap:10px; margin-top:12px; }
        .pager .info { color:var(--secondary-text-color); font-size:13px; margin-right:auto; }
        #verify { background:var(--card-background-color,#fff); border:1px solid var(--divider-color,#eee);
          border-radius:12px; padding:12px 14px; margin-bottom:16px; }
        .verify-head { font-weight:600; margin-bottom:8px; display:flex; align-items:center; gap:8px; }
        table.mini th, table.mini td { border-bottom:none; padding:4px 10px; }
      </style>
      <div class="wrap">
        <header>
          <h1>🛡 Warden</h1>
          <div class="spacer"></div>
          <button id="verifyBtn">Verify integrity</button>
          <button id="refreshBtn">Refresh</button>
        </header>
        <div id="verify" hidden></div>
        <div class="tiles" id="tiles"></div>
        <div class="filters">
          <select id="fCategory">${CATEGORIES.map((c) =>
            `<option value="${c}">${c || "all categories"}</option>`).join("")}</select>
          <input id="fSearch" placeholder="search entity / type…" />
          <input id="fUser" placeholder="user id" />
          <select id="fOutcome">
            <option value="">any outcome</option>
            <option value="success">success</option>
            <option value="failure">failure</option>
          </select>
          <button id="applyBtn">Filter</button>
          <button id="clearBtn">Clear</button>
        </div>
        <table>
          <thead><tr>
            <th>Time</th><th>Category</th><th>Type</th><th>Entity</th><th>User</th><th>Outcome</th>
          </tr></thead>
          <tbody id="tbody"></tbody>
        </table>
        <div class="pager">
          <span class="info" id="pageInfo"></span>
          <button id="prevBtn">‹ Prev</button>
          <button id="nextBtn">Next ›</button>
        </div>
      </div>`;

    const $ = (id) => this.shadowRoot.getElementById(id);
    $("verifyBtn").onclick = () => this._verify();
    $("refreshBtn").onclick = () => this._refresh();
    $("applyBtn").onclick = () => this._applyFilters();
    $("clearBtn").onclick = () => this._clearFilters();
    $("fSearch").addEventListener("keydown", (e) => { if (e.key === "Enter") this._applyFilters(); });
    $("fUser").addEventListener("keydown", (e) => { if (e.key === "Enter") this._applyFilters(); });
    $("prevBtn").onclick = () => this._page(-1);
    $("nextBtn").onclick = () => this._page(1);
    $("tbody").addEventListener("click", (e) => {
      const tr = e.target.closest("tr.row");
      if (tr) this._toggleRow(Number(tr.dataset.id));
    });
  }

  _applyFilters() {
    const $ = (id) => this.shadowRoot.getElementById(id);
    this._state.filters = {
      category: $("fCategory").value,
      search: $("fSearch").value.trim(),
      user_id: $("fUser").value.trim(),
      outcome: $("fOutcome").value,
    };
    this._state.offset = 0;
    this._loadEvents();
  }

  _clearFilters() {
    const $ = (id) => this.shadowRoot.getElementById(id);
    $("fCategory").value = ""; $("fSearch").value = "";
    $("fUser").value = ""; $("fOutcome").value = "";
    this._state.filters = {};
    this._state.offset = 0;
    this._loadEvents();
  }

  _page(dir) {
    const s = this._state;
    const next = s.offset + dir * s.limit;
    if (next < 0 || next >= s.total) return;
    s.offset = next;
    this._loadEvents();
  }

  _toggleRow(id) {
    this._state.expanded = this._state.expanded === id ? null : id;
    this._renderTable();
  }

  _renderTiles() {
    const s = this._state.stats;
    const tile = (n, l) => `<div class="tile"><div class="n">${esc(n)}</div><div class="l">${esc(l)}</div></div>`;
    this.shadowRoot.getElementById("tiles").innerHTML = s
      ? tile(s.failed_auth_24h, "Failed auth · 24h") +
        tile(s.anomalies_24h, "Anomalies · 24h") +
        tile(s.actions_24h, "User actions · 24h") +
        tile(fmtBytes(s.db_size_bytes), `DB size · ${esc(s.total_events)} rows`)
      : `<div class="muted">Loading…</div>`;
  }

  _renderTable() {
    const s = this._state;
    const tbody = this.shadowRoot.getElementById("tbody");
    if (s.error) { tbody.innerHTML = `<tr><td colspan="6" class="err">${esc(s.error)}</td></tr>`; return; }
    if (!s.events.length) { tbody.innerHTML = `<tr><td colspan="6" class="muted">No events.</td></tr>`; return; }

    tbody.innerHTML = s.events.map((e) => {
      const dot = `<span class="dot" style="background:${CATEGORY_COLOR[e.category] || "#999"}"></span>`;
      const outcome = e.outcome === "failure"
        ? `<span style="color:var(--error-color,#db4437)">failure</span>`
        : esc(e.outcome || "");
      const row = `
        <tr class="row" data-id="${e.id}">
          <td class="mono">${esc(fmtTime(e.ts))}</td>
          <td>${dot}${esc(e.category)}</td>
          <td>${esc(e.event_type)}</td>
          <td class="mono">${esc(e.entity_id || "—")}</td>
          <td class="mono">${esc(e.user_id ? e.user_id.slice(-8) : "—")}</td>
          <td>${outcome}</td>
        </tr>`;
      if (s.expanded !== e.id) return row;
      const detail = {
        entity_id: e.entity_id, user_id: e.user_id, source_ip: e.source_ip,
        domain: e.domain, outcome: e.outcome, data: e.data,
      };
      return row + `
        <tr class="detail"><td colspan="6">
          <pre>${esc(JSON.stringify(detail, null, 2))}</pre>
        </td></tr>`;
    }).join("");
  }

  _renderPager() {
    const s = this._state;
    const from = s.total ? s.offset + 1 : 0;
    const to = s.offset + s.events.length;
    this.shadowRoot.getElementById("pageInfo").textContent =
      `showing ${from}–${to} of ${s.total}`;
    this.shadowRoot.getElementById("prevBtn").disabled = s.offset <= 0;
    this.shadowRoot.getElementById("nextBtn").disabled = s.offset + s.limit >= s.total;
  }
}

customElements.define("warden-panel", WardenPanel);
