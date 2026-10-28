import { LitElement, html } from "../vendor/lit.js?v=3.13.0";
import { localize } from "../translations/localize.js?v=3.13.0";
import { renderToggle } from "../pages/utils.js?v=3.13.0";

const pendingReads = new WeakMap();

class MiWiFiWifiSwitches extends LitElement {
  static properties = { hass: {}, switches: {}, routerMac: {}, routerIp: {}, unified: {}, _unified: {state: true}, _radioIds: {state: true} };
  constructor() { super(); this.switches = []; this._unified = null; this._radioIds = {}; this._attempted = false; }
  createRenderRoot() { return this; }
  updated(changed = new Map()) {
    if ((changed.has("routerMac") || changed.has("routerIp")) && this._attempted) {
      this._unified = null; this._radioIds = {}; this._attempted = false;
    }
    if (!this._attempted && this.hass?.user?.is_admin) { this._attempted = true; this._load(); }
  }
  async _load() {
    if (!this.hass?.user?.is_admin) return;
    const session = this.hass.connection || this.hass;
    let pending;
    try {
      pending = pendingReads.get(session);
      if (!pending) {
        pending = this.hass.callWS({type: "miwifi/router_wifi_state"});
        pendingReads.set(session, pending);
      }
      const result = await pending;
      const normalize = value => String(value || "").toLowerCase().replace(/[:-]/g, "");
      const row = result?.routers?.find(router => this.routerMac
        ? [router.mac, router.graph_mac].some(mac => normalize(mac) === normalize(this.routerMac))
        : !!this.routerIp && router.ip === this.routerIp);
      this._unified = typeof row?.unified === "boolean" ? row.unified : null;
      this._radioIds = row?.switches || {};
    } catch { /* The topology flag remains a fallback; never guess from switch states. */ }
    finally { if (pendingReads.get(session) === pending) pendingReads.delete(session); }
  }
  _isUnified() { return this._unified ?? this.unified === true; }
  _band(sw) {
    const id = sw.entity_id;
    const registered = Object.entries(this._radioIds).find(([, entityId]) => entityId === id);
    if (registered) return registered[0];
    // Entity IDs come from the display name (5g), not the description key (5_0).
    if (/_wifi_5(?:g|_0)_game(?:_\d+)?$/.test(id)) return "game";
    if (/_wifi_5(?:g|_0)(?:_\d+)?$/.test(id)) return "5g";
    if (/_wifi_(?:2g|2_4g?)(?:_\d+)?$/.test(id)) return "2g";
    return null;
  }
  _switches() {
    const ids = Object.values(this._radioIds);
    const switches = [...this.switches];
    for (const id of ids) {
      if (!switches.some(sw => sw.entity_id === id) && this.hass?.states?.[id]) switches.push(this.hass.states[id]);
    }
    return switches.filter(sw => !(this._isUnified() && ["5g", "game"].includes(this._band(sw))));
  }
  render() {
    return html`<div class="section">
      <h3>${localize("settings_wifi_switches")}</h3>
      ${this._isUnified() ? html`<p class="note">${localize("wifi_unified_hint")}</p>` : ""}
      ${this._switches().map(sw => renderToggle(this.hass, sw,
        this._isUnified() && this._band(sw) === "2g" ? localize("wifi_unified_control") : undefined))}
    </div>`;
  }
}
customElements.define("miwifi-wifi-switches", MiWiFiWifiSwitches);
