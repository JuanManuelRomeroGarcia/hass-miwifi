import { LitElement, html, css } from "../vendor/lit.js?v=3.13.2";
import { localize } from "../translations/localize.js?v=3.13.2";

const COLUMNS = [
  ["name", "label_name"], ["state", "nav_status"], ["ip", "ip"],
  ["mac", "mac_address"], ["node", "devices_column_node"],
  ["connection", "devices_column_connection"], ["signal", "signal"],
  ["wifi_protocol", "wifi_protocol"], ["link_tx_rate", "link_tx_rate"], ["link_rx_rate", "link_rx_rate"],
  ["up", "devices_column_upload"], ["down", "devices_column_download"],
  ["last", "last_activity"], ["wan", "wan_access"],
];
const DEFAULT_COLUMNS = ["name", "state", "ip", "node", "connection"];
const PREFERENCE_KEY = "miwifi.device-view.v1";

class MiWiFiDeviceCards extends LitElement {
  static properties = {
    hass: {},
    _showOffline: { state: true },
    _view: { state: true },
    _columns: { state: true },
    _search: { state: true },
    _sort: { state: true },
    _descending: { state: true },
    _wanPending: { state: true },
    _wanError: { state: true },
  };

  constructor() {
    super();
    this._showOffline = false;
    this._view = "cards";
    this._columns = [...DEFAULT_COLUMNS];
    this._search = "";
    this._sort = "name";
    this._descending = false;
    this._wanPending = new Set();
    this._wanError = "";
    try {
      const saved = JSON.parse(localStorage.getItem(PREFERENCE_KEY));
      if (saved && typeof saved === "object") {
        this._view = saved.view === "table" ? "table" : "cards";
        if (Array.isArray(saved.columns)) {
          this._columns = COLUMNS.map(([key]) => key).filter(
            key => key === "name" || saved.columns.includes(key)
          );
        }
        if (COLUMNS.some(([key]) => key === saved.sort)) this._sort = saved.sort;
        this._descending = saved.descending === true;
      }
    } catch { /* Storage may be disabled or contain an older invalid value. */ }
  }

  _savePreferences() {
    try {
      localStorage.setItem(PREFERENCE_KEY, JSON.stringify({
        view: this._view, columns: this._columns,
        sort: this._sort, descending: this._descending,
      }));
    } catch { /* The view remains usable without browser storage. */ }
  }

  _setView(view) {
    this._view = view === "table" ? "table" : "cards";
    this._savePreferences();
  }

  _setColumn(key, checked) {
    if (key === "name" || !COLUMNS.some(([column]) => column === key)) return;
    this._columns = COLUMNS.map(([column]) => column).filter(
      column => column === "name" || (column === key ? checked : this._columns.includes(column))
    );
    this._savePreferences();
  }

  _sortBy(key) {
    this._descending = this._sort === key ? !this._descending : false;
    this._sort = key;
    this._savePreferences();
  }

  _cellValue(device, key, topo) {
    const a = device.attributes || {};
    switch (key) {
      case "name": return a.friendly_name || device.entity_id;
      case "state": return localize(device.state === "home" ? "status_connected"
        : device.state === "not_home" ? "status_disconnected" : "status_unavailable");
      case "node": return a.connected_via_router_name || topo.routersByMac[this._getViaMac(device)] || this._getViaMac(device) || "—";
      case "connection": return this._getConnectionTitle(this._getConnectionKey(a.connection));
      case "signal": return this._getConnectionKey(a.connection) === "lan" || a.signal === "" || a.signal == null ? "—" : `${a.signal} ${a.signal_unit || ""}`.trim();
      case "link_tx_rate":
      case "link_rx_rate": return this._getConnectionKey(a.connection) === "lan" || a[key] == null ? "—" : `${a[key]} Mbps`;
      case "wifi_protocol": return this._getConnectionKey(a.connection) === "lan" ? "—" : a.wifi_protocol || "—";
      case "up": return a.up_speed ?? "—";
      case "down": return a.down_speed ?? "—";
      case "last": return a.last_activity || "—";
      case "wan": return localize(a.internet_blocked ? "wan_blocked" : "wan_allowed");
      default: return a[key] || "—";
    }
  }

  _visibleDevices(devices, topo) {
    const query = this._search.trim().toLocaleLowerCase();
    const filtered = query ? devices.filter(device =>
      ["name", "ip", "mac", "node", "connection"].some(key =>
        String(this._cellValue(device, key, topo)).toLocaleLowerCase().includes(query)
      )
    ) : [...devices];
    const collator = new Intl.Collator(this.hass?.language || undefined, { numeric: true, sensitivity: "base" });
    return filtered.sort((a, b) => {
      const av = this._sortValue(a, topo), bv = this._sortValue(b, topo);
      const comparison = typeof av === "number" && typeof bv === "number"
        ? av - bv : collator.compare(String(av), String(bv));
      return (comparison || collator.compare(a.entity_id, b.entity_id)) * (this._descending ? -1 : 1);
    });
  }

  _sortValue(device, topo) {
    const value = this._cellValue(device, this._sort, topo);
    if (["up", "down"].includes(this._sort)) {
      const match = String(value).match(/^([\d.]+)\s*([KMGT]?)B\/s$/i);
      if (match && Number.isFinite(Number(match[1]))) {
        return Number(match[1]) * 1024 ** (" KMGT".indexOf(match[2].toUpperCase() || " "));
      }
    }
    return value;
  }

  _renderToolbar() {
    return html`
      <div class="toolbar">
        <div class="view-buttons" role="group" aria-label=${localize("devices_view")}>
          <button aria-pressed=${this._view === "cards"} @click=${() => this._setView("cards")}>${localize("devices_view_cards")}</button>
          <button aria-pressed=${this._view === "table"} @click=${() => this._setView("table")}>${localize("devices_view_table")}</button>
        </div>
        <label class="search">${localize("devices_search")}
          <input type="search" .value=${this._search} @input=${event => { this._search = event.target.value; }}>
        </label>
      </div>
      ${this._view === "table" ? html`
        <details class="column-picker">
          <summary>${localize("devices_columns")}</summary>
          <div class="column-options">${COLUMNS.map(([key, label]) => html`
            <label><input type="checkbox" .checked=${this._columns.includes(key)} ?disabled=${key === "name"}
              @change=${event => this._setColumn(key, event.target.checked)}>${localize(label)}</label>
          `)}</div>
        </details>
        <p class="table-hint">${localize("devices_table_hint")}</p>
      ` : ""}
      ${this._wanError ? html`<p role="alert">${this._wanError}</p>` : ""}
    `;
  }

  _renderTable(devices, topo) {
    const columns = COLUMNS.filter(([key]) => this._columns.includes(key));
    return html`
      <div class="table-scroll" role="region" tabindex="0" aria-label=${localize("devices_view_table")}>
        <table>
          <caption class="sr-only">${localize("devices_connected_title")}</caption>
          <thead><tr>${columns.map(([key, label]) => html`
            <th scope="col" aria-sort=${this._sort === key ? (this._descending ? "descending" : "ascending") : "none"}>
              <button @click=${() => this._sortBy(key)}>${localize(label)}${this._sort === key ? (this._descending ? " ↓" : " ↑") : ""}</button>
            </th>
          `)}</tr></thead>
          <tbody>${devices.map(device => html`
            <tr class=${device.state === "home" ? "" : "disconnected"}>
              ${columns.map(([key]) => key === "name"
                ? html`<th scope="row">${this._cellValue(device, key, topo)}</th>`
                : html`<td>${this._cellValue(device, key, topo)}</td>`)}
            </tr>
          `)}</tbody>
        </table>
      </div>
    `;
  }

  render() {
    const all = Object.values(this.hass?.states || {}).filter((s) =>
      String(s?.entity_id || "").startsWith("device_tracker.miwifi_")
    );

    const st = (d) => String(d.state || "").toLowerCase();
    const topo = this._getTopologyInfo();
    const visible = this._visibleDevices(all, topo);
    const disconnected = visible.filter((d) => st(d) !== "home");
    const connected = visible.filter((d) => st(d) === "home");
    const breakdown = this._buildNodeBreakdown(all.filter(d => st(d) === "home"), topo);

    // Agrupar SOLO conectados por tipo de conexión
    const grouped = {};
    for (const device of connected) {
      const key = this._getConnectionKey(device.attributes?.connection);
      if (!grouped[key]) grouped[key] = [];
      grouped[key].push(device);
    }

    const breakdownText = (breakdown.perNode || [])
      .map((n) => `${n.name}: ${n.count}`)
      .join(" | ");

    const totalDevices = all.length;
    const totalConnected = all.filter(d => st(d) === "home").length;

    return html`
      <div class="content">
        <h2>${localize("devices_connected_title")}</h2>

        <div class="counts">
          ${localize("label_devices_total") || localize("devices_total_connected")}: <strong>${totalDevices}</strong>
          &nbsp;|&nbsp; ${localize("devices_connected")}: <strong>${totalConnected}</strong>
          &nbsp;|&nbsp; ${localize("badge_main")}: <strong>${breakdown.mainCount}</strong>
          &nbsp;|&nbsp; ${localize("badge_mesh")}: <strong>${breakdown.meshCount}</strong>
        </div>

        ${breakdownText ? html`<div class="counts-sub">${breakdownText}</div>` : ""}

        ${this._renderToolbar()}
        ${!connected.length && !(this._showOffline && disconnected.length)
          ? html`<p role="status">${localize("devices_no_results")}</p>` : ""}

        ${this._view === "table" ? this._renderTable(this._showOffline ? visible : connected, topo)
          : Object.entries(grouped).map(([key, devs]) =>
          this._renderGroup(key, devs, topo, breakdown)
        )}

        <div class="offline-toggle">
          <button class="miwifi-button" @click=${this._toggleOffline}>
            ${this._showOffline
              ? (localize("toggle_offline_hide") || "Hide offline devices")
              : (localize("toggle_offline_show") || "Show offline devices")}
            ${disconnected.length ? html` <span class="pill">${disconnected.length}</span>` : ""}
          </button>
        </div>

        ${this._view === "cards" && this._showOffline && disconnected.length
          ? html`
              <div class="section-title" style="margin-top: 18px;">
                 ${localize("status_disconnected") || localize("toggle_offline_show") || "Offline devices"}
              </div>
              <div class="device-grid">
                ${disconnected.map((device) => this._renderCard(device, topo, breakdown))}
              </div>
            `
          : ""}
      </div>
    `;
  }

  _toggleOffline() {
    this._showOffline = !this._showOffline;
    this.requestUpdate();
  }

  _normalizeMac(mac) {
    if (!mac) return "";
    return String(mac).trim().toLowerCase();
  }

  _getTopologyInfo() {
    const routersByMac = {};
    let mainMac = "";
    let mainName = "";

    const statesObj = this.hass?.states || {};
    const states = Object.values(statesObj);

    const setName = (macRaw, nameRaw) => {
      const mac = this._normalizeMac(macRaw);
      if (!mac) return;

      const name = (nameRaw || "").toString().trim();
      if (!name) return;

      // Solo sobreescribe si no había nada o si antes solo teníamos el MAC como "nombre"
      const prev = routersByMac[mac];
      if (!prev || prev === mac) {
        routersByMac[mac] = name;
      }
    };

    // 1) Sensores/topología (graph + leafs)
    for (const s of states) {
      const eid = String(s?.entity_id || "");
      if (!eid.startsWith("sensor.miwifi_")) continue;

      const a = s.attributes || {};

      // Buscar graph en múltiples formatos
      let g =
        a.graph ||
        a.topo_graph?.graph ||
        a.topo_graph ||
        a.topology?.graph ||
        a.topology ||
        null;

      if (!g) continue;
      if (g.graph && typeof g.graph === "object") g = g.graph;

      const gMac = g?.mac;
      const gName = (g?.name || g?.locale || g?.model || gMac || "").toString().trim();

      setName(gMac, gName);

      // is_main tolerante a tipos
      const isMain =
        g?.is_main === true ||
        g?.is_main === 1 ||
        g?.is_main === "1" ||
        String(g?.is_main || "").toLowerCase() === "true";

      if (isMain) {
        mainMac = this._normalizeMac(gMac) || mainMac;
        mainName = gName || mainName || "Main";
      }

      const leafs =
        (Array.isArray(g?.leafs) && g.leafs) ||
        (Array.isArray(g?.leaves) && g.leaves) ||
        (Array.isArray(g?.leaf) && g.leaf) ||
        [];

      for (const leaf of leafs) {
        setName(
          leaf?.mac,
          (leaf?.name || leaf?.locale || leaf?.model || leaf?.mac || "").toString().trim()
        );
      }
    }

    // 2) ✅ Extra: mapear nombres desde TODOS los device_tracker del scanner miwifi (incluye routers/nodos)
    for (const s of states) {
      const eid = String(s?.entity_id || "");
      if (!eid.startsWith("device_tracker.")) continue;

      const a = s.attributes || {};

      const isMiWiFi =
        String(a.scanner || "").toLowerCase() === "miwifi" ||
        String(a.device_class || "").toLowerCase().includes("miwifi") ||
        String(a.attribution || "").toLowerCase().includes("miwifi");

      if (!isMiWiFi) continue;

      // Mapear el MAC del propio device_tracker (esto cubre device_tracker.ax9000_salon)
      setName(a.mac || a.mac_address, a.friendly_name || a.name || a.hostname || "");

      // Opcional: si algún tracker trae nombres del "via", también los aprovechamos
      setName(a.connected_via_router_mac, a.connected_via_router_name || "");
      setName(a.router_mac, a.router_name || "");
    }

    return { mainMac, mainName, routersByMac };
  }


  _getViaMac(device) {
    const a = device?.attributes || {};
    return this._normalizeMac(a.connected_via_router_device_mac || a.connected_via_router_mac || a.router_mac || "");
  }

  _getViaEntryId(device) {
    const a = device?.attributes || {};
    return String(a.connected_via_entry_id || a.updater_entry_id || "").trim();
  }

  _buildNodeBreakdown(connectedDevices, topo) {
      const counts = new Map(); // viaMac -> count

      for (const dev of connectedDevices) {
        const viaMac = this._getViaMac(dev) || "unknown";
        counts.set(viaMac, (counts.get(viaMac) || 0) + 1);
      }

      const sorted = Array.from(counts.entries()).sort((a, b) => b[1] - a[1]);

      // MAIN por topo.mainMac (fiable). Si no existe, fallback al más frecuente (si no es unknown)
      const mainMac =
        topo?.mainMac ||
        (sorted[0]?.[0] && sorted[0][0] !== "unknown" ? sorted[0][0] : "");

      let mainCount = 0;
      let meshCount = 0;

      const perNode = sorted.map(([viaMac, count], idx) => {
        const isMain = Boolean(mainMac && viaMac === mainMac);
        if (isMain) mainCount += count;
        else meshCount += count;

        let name = topo?.routersByMac?.[viaMac] || viaMac;
        if (isMain) {
          name = topo?.mainName || topo?.routersByMac?.[viaMac] || "Main";
        } else if (viaMac === "unknown") {
          name = "Unknown";
        } else if (!topo?.routersByMac?.[viaMac]) {
          name = `Mesh ${idx}`;
        }

        return { viaMac, count, name, isMain };
      });

      return { mainMac, mainCount, meshCount, perNode };
    }

  _getConnectionKey(connection) {
    const c = String(connection || "").toLowerCase().trim();

    if (c === "lan") return "lan";
    if (c === "iot" || c.includes("iot")) return "iot";
    if (c === "2.4g" || c === "2.4" || c.includes("2.4")) return "g24";
    if (c === "5g game" || c === "game" || c.includes("game")) return "g5_game";
    if (c === "5g" || c.includes("5g")) return "g5";
    if (c === "guest") return "guest";

    return "unknown";
  }

  _getConnectionTitle(key) {
    const map = {
      lan: localize("section_LAN") || "LAN",
      iot: localize("section_IoT") || "IoT",
      g24: localize("section_2.4G") || "2.4G",
      g5: localize("section_5G") || "5G",
      g5_game: localize("section_5G Game") || "5G Game",
      guest: localize("section_Guest") || "Guest",
      unknown: localize("section_Unknown") || "Unknown",
    };
    return map[key] || key;
  }

  _translateSignalQuality(quality) {
    switch (quality) {
      case "very_strong":
        return localize("signal_quality_very_strong");
      case "strong":
        return localize("signal_quality_strong");
      case "fair":
        return localize("signal_quality_fair");
      case "weak":
        return localize("signal_quality_weak");
      case "very_weak":
        return localize("signal_quality_very_weak");
      case "no_signal":
        return localize("signal_quality_no_signal") || localize("signal_quality_unknown");
      default:
        return localize("signal_quality_unknown");
    }
  }

  _renderGroup(key, devices, topo, breakdown) {
    return html`
      <div class="section-title">${this._getConnectionTitle(key)}</div>
      <div class="device-grid">
        ${devices.map((device) => this._renderCard(device, topo, breakdown))}
      </div>
    `;
  }

  _renderCard(device, topo, breakdown) {
    const isOffline = String(device.state).toLowerCase() !== "home";
    const a = device.attributes || {};

    const viaMac = this._getViaMac(device);
    const mainMac = breakdown?.mainMac || topo?.mainMac || "";

    const isMesh = Boolean(mainMac && viaMac && viaMac !== mainMac);
    const badge = viaMac
      ? (isMesh ? localize("badge_mesh") || "Mesh" : localize("badge_main") || "Principal")
      : "";

    let viaLabel = "";
    if (viaMac) {
      const node = (breakdown?.perNode || []).find((n) => n.viaMac === viaMac);
      const viaName = node?.name || topo?.routersByMac?.[viaMac] || viaMac;

      const viaMeshLabel = localize("connected_via_mesh") || "Connected via (Mesh)";
      const viaMainLabel = localize("connected_via_main") || "Connected via (Main)";

      viaLabel = isMesh ? `${viaMeshLabel}: ${viaName}` : `${viaMainLabel}: ${viaName}`;
    }


    return html`
      <div class="device-card ${isOffline ? "disconnected" : ""}">
        <div class="card-header">
          <div class="device-name" title=${a.friendly_name || device.entity_id}>
            ${a.friendly_name || device.entity_id}
          </div>
          ${badge ? html`<div class="badge ${isMesh ? "mesh" : "main"}">${badge}</div>` : ""}
        </div>

        <div class="device-info">${localize("ip")}: ${a.ip || "-"}</div>
        <div class="device-info">${localize("mac_address")}: ${a.mac || "-"}</div>
        ${viaLabel ? html`<div class="device-info">${viaLabel}</div>` : ""}

        <div class="device-status ${isOffline ? "offline" : ""}">
          ${this._cellValue(device, "state", topo)}
        </div>

        ${String(a.connection || "").toLowerCase() !== "lan"
          ? html`
              <div class="device-info">${localize("signal")}: ${this._cellValue(device, "signal", topo)}</div>
              ${a.wifi_protocol ? html`<div class="device-info">${localize("wifi_protocol")}: ${a.wifi_protocol}</div>` : ""}
              ${a.link_tx_rate != null ? html`<div class="device-info">${localize("link_tx_rate")}: ${a.link_tx_rate} Mbps</div>` : ""}
              ${a.link_rx_rate != null ? html`<div class="device-info">${localize("link_rx_rate")}: ${a.link_rx_rate} Mbps</div>` : ""}
              <div class="device-info">${localize("signal_quality")}: ${this._translateSignalQuality(a.signal_quality)}</div>
            `
          : ""}

        <div class="device-info">↑ ${a.up_speed ?? "0 B/s"}</div>
        <div class="device-info">↓ ${a.down_speed ?? "0 B/s"}</div>
        <div class="device-info">${localize("last_activity")}: ${a.last_activity ?? "-"}</div>

        <div class="device-info">
          ${localize("wan_access")}:
          ${a.internet_blocked
            ? html`<span class="wan-blocked">${localize("wan_blocked")}</span>`
            : html`<span class="wan-allowed">${localize("wan_allowed")}</span>`}
        </div>

        <div class="device-info-wan">
          <span>${localize("wan_unblock_button")}</span>
          <ha-switch
            .checked=${a.internet_blocked}
            ?disabled=${!this.hass?.user?.is_admin || this._wanPending.has(device.entity_id)}
            aria-label=${localize("wan_access")}
            @change=${async (ev) => {
              const control = ev.target;
              await this._toggleWAN(device, control.checked);
              control.checked = Boolean(this.hass?.states?.[device.entity_id]?.attributes?.internet_blocked ?? a.internet_blocked);
            }}
          ></ha-switch>
          <span>${localize("wan_block_button")}</span>
        </div>
      </div>
    `;
  }

  async _toggleWAN(device, checked) {
    if (!this.hass?.user?.is_admin || !device?.entity_id || this._wanPending.has(device.entity_id)) return;
    this._wanPending = new Set([...this._wanPending, device.entity_id]);
    this._wanError = "";
    try {
      if (!device?.entity_id) {
        // eslint-disable-next-line no-console
        console.warn("[MiWiFi] Missing entity_id for device:", device);
        return;
      }

      await this.hass.callService("miwifi", "block_device", {
        entity_id: device.entity_id,
        allow: !checked,
      });
    } catch (err) {
      this._wanError = localize("devices_wan_error");
      // eslint-disable-next-line no-console
      console.error("[MiWiFi] Failed toggling WAN:", err);
    } finally {
      this._wanPending = new Set([...this._wanPending].filter(id => id !== device.entity_id));
      this.requestUpdate();
    }
  }


  static styles = css`
    :host { display: block; min-width: 0; }
    * { box-sizing: border-box; }
    .content { text-align: center; min-width: 0; }
    button, input { font: inherit; }
    button { min-height: 44px; padding: 8px 14px; cursor: pointer; color: inherit; background: rgba(0,0,0,.15); border: 1px solid rgba(255,255,255,.45); border-radius: 8px; }
    button:focus-visible, input:focus-visible, summary:focus-visible, .table-scroll:focus-visible { outline: 3px solid #ffdf70; outline-offset: 3px; }
    button[aria-pressed="true"] { color: #123a62; background: #fff; }
    .toolbar { display: flex; flex-wrap: wrap; justify-content: space-between; align-items: end; gap: 16px; margin: 24px 0 12px; text-align: left; }
    .view-buttons { display: flex; gap: 6px; }
    .search { display: grid; gap: 6px; flex: 1 1 220px; max-width: 420px; }
    .search input { width: 100%; min-width: 0; min-height: 44px; border: 1px solid var(--divider-color, #ccc); border-radius: 8px; padding: 10px; color: var(--primary-text-color, #212121); background: var(--card-background-color, white); }
    .column-picker { text-align: left; border: 1px solid rgba(255,255,255,.4); border-radius: 8px; padding: 10px 14px; }
    .column-picker summary { cursor: pointer; min-height: 28px; }
    .column-options { display: flex; flex-wrap: wrap; gap: 8px 24px; padding-top: 12px; }
    .column-options label { display: flex; align-items: center; gap: 8px; min-height: 44px; }
    .column-options input { width: 20px; height: 20px; }
    .table-hint { text-align: left; font-size: 13px; opacity: .9; }
    .table-scroll { overflow: auto; max-width: 100%; border: 1px solid rgba(255,255,255,.35); border-radius: 10px; margin-top: 14px; }
    table { border-collapse: separate; border-spacing: 0; width: 100%; text-align: left; }
    th, td { padding: 12px; min-width: 120px; max-width: 280px; overflow-wrap: anywhere; border-bottom: 1px solid rgba(255,255,255,.22); }
    thead th { background: #155ba7; white-space: nowrap; }
    thead button { border: 0; background: none; padding: 0; text-align: left; width: 100%; }
    tbody th { font-weight: 600; background: #1b68c5; }
    th:first-child { position: sticky; left: 0; z-index: 1; min-width: 150px; }
    tbody tr:nth-child(even) td { background: rgba(0,0,0,.08); }
    .sr-only { position: absolute; width: 1px; height: 1px; overflow: hidden; clip-path: inset(50%); }
    @media (max-width: 600px) {
      .toolbar { align-items: stretch; gap: 12px; }
      .search { max-width: none; flex-basis: 100%; }
      .view-buttons { display: grid; grid-template-columns: 1fr 1fr; width: 100%; }
      th:first-child { min-width: 125px; max-width: 145px; }
      th, td { padding: 10px; }
      .counts, .counts-sub { white-space: normal !important; overflow-wrap: anywhere; line-height: 1.7; }
      .device-info-wan { flex-wrap: wrap; }
      .device-name { font-size: 19px; }
      .card-header { flex-wrap: wrap; }
      .device-name { white-space: normal; overflow-wrap: anywhere; }
    }

    .device-grid {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(min(100%, 240px), 1fr));
      gap: 18px;
      margin-top: 14px;
    }

    .section-title {
      font-size: 20px;
      font-weight: 700;
      margin: 28px 0 6px;
    }

    .device-card {
      background: rgba(255,255,255,0.08);
      border-radius: 12px;
      padding: 16px 14px;
      box-shadow: 0 6px 16px rgba(0,0,0,0.25);
      border: 1px solid rgba(255,255,255,0.07);
      position: relative;
      overflow: hidden;
    }

    .device-card.disconnected {
      opacity: 0.85;
      filter: grayscale(0.25);
    }

    .card-header {
      display: flex;
      justify-content: center;
      align-items: center;
      gap: 10px;
      margin-bottom: 10px;
      flex-wrap: nowrap;
    }

    /* ✅ una línea */
    .device-name {
      font-size: 22px;
      font-weight: 700;
      line-height: 1.2;
      white-space: nowrap;
      overflow: hidden;
      text-overflow: ellipsis;
      max-width: 100%;
    }

    .badge {
      font-size: 11px;
      font-weight: 800;
      letter-spacing: 0.4px;
      padding: 3px 8px;
      border-radius: 999px;
      border: 1px solid rgba(255,255,255,0.25);
      background: rgba(0,0,0,0.18);
      user-select: none;
      white-space: nowrap;
      flex: 0 0 auto;
    }

    .badge.main { background: rgba(0,0,0,0.18); }
    .badge.mesh { background: rgba(0,0,0,0.18); }

    .device-info {
      overflow-wrap: anywhere;
      font-size: 14px;
      margin-top: 6px;
      line-height: 1.2;
    }

    .device-info-wan {
      margin-top: 12px;
      display: inline-flex;
      justify-content: center;
      align-items: center;
      gap: 10px;
    }

    .device-status.offline { color: #ffb3b3; }

    .counts {
      margin-top: 8px;
      opacity: 0.95;
      font-size: 14px;
      white-space: normal;
      overflow-wrap: anywhere;
    }

    .counts strong { font-weight: 800; }

    .counts-sub {
      margin-top: 4px;
      opacity: 0.9;
      font-size: 13px;
      white-space: normal;
      overflow-wrap: anywhere;
    }

    .offline-toggle { margin-top: 12px; }

    .pill {
      display: inline-block;
      margin-left: 6px;
      padding: 0 8px;
      border-radius: 999px;
      background: rgba(255,255,255,0.14);
      border: 1px solid rgba(255,255,255,0.12);
      font-size: 12px;
      font-weight: 800;
    }

    .wan-allowed { color: lightgreen; }
    .wan-blocked { color: #ff6b6b; }
  `;
}

customElements.define("miwifi-device-cards", MiWiFiDeviceCards);
