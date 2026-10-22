import { LitElement, html } from "../vendor/lit.js?v=3.13.0";
import { localize } from "../translations/localize.js?v=3.13.0";

class MiWiFiIot extends LitElement {
  static properties = {hass: {}, routerMac: {}, snapshot: {state: true}, form: {state: true}, busy: {state: true}, error: {state: true}, saved: {state: true}, showPasswords: {state: true}};
  constructor() { super(); this.snapshot = null; this.form = null; this.busy = false; this.error = ""; this.saved = false; this.showPasswords = [false, false]; this._attempted = false; }
  createRenderRoot() { return this; }
  updated() { if (!this._attempted && this.hass?.user?.is_admin && this.routerMac) { this._attempted = true; this._load(); } }
  _accept(data) {
    if (!data?.entry_id || !data.revision || !Array.isArray(data.bands) || data.bands.length !== 2) throw Error();
    this.snapshot = data;
    this.form = {enabled: data.enabled, bands: data.bands.map(b => ({ssid: b.ssid, password: typeof b.password === "string" ? b.password : ""}))};
    this.showPasswords = [false, false];
  }
  _error(err) {
    const key = ["unsupported", "stale", "unverified", "invalid"].includes(err?.code) ? err.code : "error";
    this.error = localize(`iot_${key}`);
  }
  async _load() {
    if (this.busy || !this.hass?.user?.is_admin) return;
    this.busy = true; this.error = ""; this.saved = false; this.snapshot = null; this.form = null; this.showPasswords = [false, false];
    try { this._accept(await this.hass.callWS({type: "miwifi/iot_read", router_mac: this.routerMac})); }
    catch (err) { this._error(err); }
    finally { this.busy = false; }
  }
  _edit(index, key, value) {
    this.form = {...this.form, bands: this.form.bands.map((band, i) => i === index ? {...band, [key]: value} : band)};
    this.saved = false;
  }
  _dirty() {
    return !!this.snapshot && (this.form.enabled !== this.snapshot.enabled
      || this.form.bands.some((b, i) => b.ssid !== this.snapshot.bands[i].ssid
        || (b.password !== "" && b.password !== (this.snapshot.bands[i].password || ""))));
  }
  _togglePassword(index) {
    if (!this.hass?.user?.is_admin) return;
    this.showPasswords = this.showPasswords.map((shown, i) => i === index ? !shown : shown);
  }
  async _save() {
    if (this.busy || !this.hass?.user?.is_admin || !this.snapshot?.writable || !this._dirty()) return;
    this.busy = true; this.error = ""; this.saved = false;
    try {
      this._accept(await this.hass.callWS({type: "miwifi/iot_write", entry_id: this.snapshot.entry_id,
        revision: this.snapshot.revision, enabled: this.form.enabled,
        bands: this.form.bands.map((b, i) => ({ssid: b.ssid,
          password: b.password === this.snapshot.bands[i].password ? "" : b.password}))}));
      this.saved = true;
    } catch (err) { this._error(err); this.snapshot = null; this.form = null; this.showPasswords = [false, false]; }
    finally { this.busy = false; }
  }
  render() {
    if (!this.hass?.user?.is_admin) return html``;
    return html`<div class="section">
      <h3>${localize("iot_title")}</h3><p class="note">${localize("iot_hint")}</p>
      ${this.error ? html`<p role="alert">${this.error}</p>` : ""}
      ${this.saved ? html`<p role="status">${localize("iot_saved")}</p>` : ""}
      ${this.snapshot && this.form ? html`
        ${!this.snapshot.writable ? html`<p>${localize("iot_unsupported")}</p>` : ""}
        <div class="switchline"><label>${localize("guest_enable")}</label>
          <ha-switch .checked=${this.form.enabled} ?disabled=${this.busy || !this.snapshot.writable}
            @change=${e => { this.form = {...this.form, enabled: e.target.checked}; this.saved = false; }}></ha-switch></div>
        ${this.form.bands.map((band, index) => html`<div class="wifi-block">
          <h4>${localize(index === 0 ? "wifi_title_24g" : "wifi_title_5g")}</h4>
          <div class="row"><mw-input><label>${localize("guest_ssid")}</label>
            <input type="text" .value=${band.ssid} ?disabled=${this.busy || !this.snapshot.writable} @input=${e => this._edit(index, "ssid", e.target.value)} /></mw-input>
            <mw-input><label>${localize("guest_encryption")}</label><input readonly .value=${this.snapshot.bands[index].encryption} /></mw-input>
            <mw-input><label>${localize("guest_password")} (${localize("guest_password_hint")})</label>
              <div style="display:flex;align-items:center;gap:8px">
                <input .type=${this.showPasswords[index] ? "text" : "password"} autocomplete="new-password" .value=${band.password}
                  style="flex:1;min-width:0" ?disabled=${this.busy || !this.snapshot.writable} @input=${e => this._edit(index, "password", e.target.value)} />
                <button type="button" class="miwifi-button" style="min-width:44px;flex:0 0 auto" ?disabled=${this.busy}
                  aria-label=${localize(this.showPasswords[index] ? "iot_hide_password" : "iot_show_password")}
                  aria-pressed=${this.showPasswords[index]} @click=${() => this._togglePassword(index)}>${this.showPasswords[index] ? "🙈" : "👁"}</button>
              </div></mw-input></div>
        </div>`)}
      ` : ""}
      <div class="right"><button class="miwifi-button" ?disabled=${this.busy} @click=${() => this._load()}>${localize(this.busy ? "ui_loading" : "ui_reload")}</button>
        ${this.snapshot?.writable ? html`<button class="miwifi-button" ?disabled=${this.busy || !this._dirty()} @click=${() => this._save()}>${localize("ui_apply")}</button>` : ""}</div>
    </div>`;
  }
}
customElements.define("miwifi-iot", MiWiFiIot);
