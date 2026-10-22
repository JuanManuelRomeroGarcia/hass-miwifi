import { LitElement, html, css } from "../vendor/lit.js?v=3.13.0";
import { localize } from "../translations/localize.js?v=3.13.0";

const pendingReads = new WeakMap();

class MiWiFiRouterSpecific extends LitElement {
  static properties = { hass: {}, scope: {}, routerMac: {}, routerIp: {}, _data: { state: true }, _busy: { state: true }, _error: { state: true } };
  constructor() { super(); this.scope = "main"; this.routerMac = ""; this.routerIp = ""; this._data = null; this._busy = false; this._error = false; this._attempted = false; }
  updated() {
    if (!this._attempted && this.hass?.user?.is_admin) { this._attempted = true; this._load(); }
  }
  async _load() {
    if (this._busy || !this.hass?.user?.is_admin) return;
    this._busy = true; this._error = false;
    const session = this.hass.connection || this.hass;
    let pending;
    try {
      pending = pendingReads.get(session);
      if (!pending) {
        pending = this.hass.callWS({ type: "miwifi/router_specific" });
        pendingReads.set(session, pending);
      }
      const data = await pending;
      if (!Array.isArray(data?.routers)) throw new Error();
      this._data = data;
    } catch { this._error = true; this._data = null; }
    finally {
      if (pendingReads.get(session) === pending) pendingReads.delete(session);
      this._busy = false;
    }
  }
  _flag(value) {
    return localize(value === true ? "router_specific_on" : value === false ? "router_specific_off" : "status_unavailable");
  }
  _visibleRouters() {
    const normalize = value => String(value || "").toLowerCase().replace(/[:-]/g, "");
    return (this._data?.routers || []).filter(router => {
      if (this.scope !== "mesh") return router.is_main === true;
      if (router.is_main !== false) return false;
      if (this.routerMac) return [router.mac, router.graph_mac].some(mac => normalize(mac) === normalize(this.routerMac));
      return !!this.routerIp && router.ip === this.routerIp;
    });
  }
  _rows(router) {
    const m = router.metrics || {}, rows = [];
    const add = (key, value) => rows.push({ label: localize(`router_specific_${key}`), value });
    if (Number.isFinite(m.temperature)) add("temperature", `${m.temperature} °C`);
    if (Number.isFinite(m.fan_speed)) add("fan", `${m.fan_speed} RPM`);
    for (const key of ["multiwan", "wps", "nfc"]) if (Object.hasOwn(m, key)) add(key, this._flag(m[key]));
    if (["auto", "wired", "wireless"].includes(m.backhaul)) add("backhaul", localize(`router_specific_${m.backhaul}`));
    for (const [band, value] of Object.entries(m.roaming || {})) {
      if (Number.isFinite(value)) add("roaming", `${band === "2g" ? "2.4 GHz" : band === "5gh" ? "5 GHz Game" : "5 GHz"}: ${value} dBm`);
    }
    for (const port of m.ports || []) add("port", `${port.label || "—"} · ${port.speed || "—"} · ${port.service || "—"}`);
    return rows;
  }
  render() {
    if (!this.hass?.user?.is_admin) return html``;
    const routers = this._visibleRouters();
    if (this._data && !routers.length && this.scope === "mesh") return html``;
    return html`<section class="specific-card">
      ${this.scope === "mesh" ? html`<h3>${localize("router_specific_title")}</h3>` : html`<h2>${localize("router_specific_title")}</h2>`}
      <p>${localize("router_specific_hint")}</p>
      <button ?disabled=${this._busy} @click=${() => this._load()}>${localize(this._busy ? "ui_loading" : "router_specific_refresh")}</button>
      ${this._error ? html`<p role="alert">${localize("router_specific_error")}</p>` : ""}
      ${this._data ? html`<p><time>${new Date(this._data.captured_at).toLocaleString(this.hass.language)}</time></p>
        ${!routers.length ? html`<p>${localize("router_specific_empty")}</p>` : ""}
        <div class="routers">${routers.map(router => html`<article>
          ${this.scope !== "mesh" ? html`<h3>${router.name} · ${router.model === "rc01" ? "BE10000" : "BE7000"}</h3>` : ""}
          ${router.failed?.length ? html`<p role="status">${localize("router_specific_partial")}</p>` : ""}
          ${!this._rows(router).length ? html`<p>${localize("status_unavailable")}</p>` : ""}
          <dl>${this._rows(router).map(row => html`<div><dt>${row.label}</dt><dd>${row.value}</dd></div>`)}</dl>
          ${router.model === "rc01" ? html`<p class="hint">${localize("router_specific_thermal_hint")}</p>` : ""}
        </article>`)}</div>` : ""}
    </section>`;
  }
  static styles = css`
    :host { display: block; color: white; margin: 30px; text-align: left; }
    .specific-card { padding: 20px; border-radius: 12px; background: #1a73e8; box-shadow: 0 4px 8px #0005; }
    h2, h3 { text-align: center; margin-top: 0; }
    :host([embedded]) { margin: 30px; text-align: left; }
    :host([embedded]) .routers { display: block; }
    :host([embedded]) article { padding: 0; background: transparent; }
    * { box-sizing: border-box; } h2, h3 { overflow-wrap: anywhere; }
    p { line-height: 1.5; } button { min-height: 44px; padding: 10px 16px; font: inherit; cursor: pointer; border-radius: 8px; border: 1px solid currentColor; color: inherit; background: transparent; }
    button:disabled { opacity: .6; cursor: default; } button:focus-visible { outline: 3px solid white; outline-offset: 3px; }
    .routers { display: grid; grid-template-columns: repeat(auto-fit, minmax(min(100%, 320px), 1fr)); gap: 16px; }
    article { min-width: 0; padding: 16px; background: #ffffff08; border-radius: 12px; }
    dl { margin: 0; } dl div { display: flex; flex-wrap: wrap; gap: 8px; padding: 10px 0; border-bottom: 1px solid #ffffff40; }
    dt { flex: 1 1 160px; } dd { margin: 0; flex: 1 1 120px; font-weight: 600; overflow-wrap: anywhere; }
    .hint { font-size: .9em; } @media(max-width: 600px) { :host, :host([embedded]) { margin: 20px 0; } .specific-card { padding: 12px; } dl div { display: block; } dd { margin-top: 6px; } }
  `;
}
customElements.define("miwifi-router-specific", MiWiFiRouterSpecific);
