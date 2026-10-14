import { LitElement, html, css } from "../vendor/lit.js?v=3.9.1";
import { localize } from "../translations/localize.js?v=3.9.1";

export class MiWiFiDhcp extends LitElement {
  static properties = {
    hass: {}, routers: { state: true }, entry: { state: true }, snapshot: { state: true },
    busy: { state: true }, error: { state: true }, saved: { state: true },
    form: { state: true }, editing: { state: true }, pending: { state: true },
  };
  static styles = css`
    :host { display: block; max-width: 1000px; margin: 20px auto; padding: 20px; box-sizing: border-box; text-align: left; color: var(--primary-text-color, #212121); background: var(--card-background-color, #fff); border-radius: 12px; }
    h3 { margin: 0 0 12px; } p { line-height: 1.5; }
    label { display: block; margin: 10px 0; }
    input, select { width: 100%; box-sizing: border-box; padding: 10px; margin-top: 6px; font: inherit; color: inherit; background: var(--card-background-color, #fff); border: 1px solid var(--divider-color, #ccc); border-radius: 6px; }
    button { padding: 9px 14px; font: inherit; color: inherit; background: var(--card-background-color, #fff); border: 1px solid var(--divider-color, #ccc); border-radius: 6px; cursor: pointer; }
    button.primary { background: var(--primary-color, #03a9f4); color: var(--text-primary-color, #fff); }
    button:disabled { opacity: .5; cursor: default; }
    .actions { display: flex; flex-wrap: wrap; gap: 8px; align-items: center; }
    .hint { color: var(--secondary-text-color, #555); font-size: .9em; }
    .error { color: var(--error-color, #c00); } .success { color: var(--success-color, #238636); }
    ul { list-style: none; padding: 0; } li { border: 1px solid var(--divider-color, #ddd); border-radius: 8px; padding: 14px; margin: 10px 0; }
    .row { display: flex; align-items: center; justify-content: space-between; flex-wrap: wrap; gap: 12px; }
    .identity { min-width: 0; overflow-wrap: anywhere; } .identity span { display: block; margin-top: 6px; }
    form { border-top: 1px solid var(--divider-color, #ddd); padding-top: 16px; margin-top: 20px; }
    .fields { display: grid; grid-template-columns: repeat(3, minmax(0, 1fr)); gap: 12px; }
    @media (max-width: 600px) { :host { padding: 14px; } .fields { grid-template-columns: 1fr; gap: 0; } }
  `;
  constructor() {
    super();
    this.routers = []; this.entry = ""; this.snapshot = null; this.busy = false;
    this.error = ""; this.saved = false; this.form = { mac: "", ip: "", name: "" };
    this.editing = false; this.pending = null; this._attempted = false; this._epoch = 0;
  }
  updated(changed) {
    if (changed.has("hass") && this.hass?.user?.is_admin && !this._attempted) this._routers();
  }
  _error(error) {
    const key = `dhcp_error_${error?.code || "read_failed"}`;
    const text = localize(key);
    this.error = text === key ? localize("dhcp_error_read_failed") : text;
  }
  async _routers() {
    if (this.busy || !this.hass?.user?.is_admin) return;
    const previous = this.entry;
    this._attempted = true; this.busy = true; this.error = "";
    this.routers = []; this.entry = ""; this.snapshot = null; this.saved = false; this._reset();
    try {
      const result = await this.hass.callWS({ type: "miwifi/dhcp_routers" });
      if (!Array.isArray(result?.routers)) throw new Error();
      this.routers = result.routers;
    } catch (error) { this._error(error); }
    finally { this.busy = false; }
    const entry = this.routers.length === 1 ? this.routers[0].entry_id
      : this.routers.find(row => row.entry_id === previous)?.entry_id;
    if (entry) await this._select(entry);
  }
  _reset() { this.form = { mac: "", ip: "", name: "" }; this.editing = false; this.pending = null; }
  async _select(entry) {
    if (this.busy) return;
    this.entry = entry; this.snapshot = null; this.saved = false; this.error = ""; this._reset();
    if (entry) await this._load();
  }
  _valid(result) {
    return Array.isArray(result?.bindings) && Array.isArray(result.clients) && typeof result.revision === "string" && typeof result.writable === "boolean";
  }
  async _load() {
    if (!this.entry || this.busy || !this.hass?.user?.is_admin) return;
    const epoch = ++this._epoch, entry = this.entry;
    this.busy = true; this.snapshot = null; this.error = ""; this.saved = false; this._reset();
    try {
      const result = await this.hass.callWS({ type: "miwifi/dhcp_read", entry_id: entry });
      if (!this._valid(result)) throw new Error();
      if (epoch === this._epoch && entry === this.entry) this.snapshot = result;
    } catch (error) { if (epoch === this._epoch) this._error(error); }
    finally { if (epoch === this._epoch) this.busy = false; }
  }
  _edit(row) { if (!this.busy && this.snapshot?.writable) { this.form = { ...row }; this.editing = true; this.pending = null; this.saved = false; } }
  _choose(mac) { const row = this.snapshot?.clients.find(item => item.mac === mac); if (row && !this.busy) { this.form = { ...row }; this.editing = false; this.pending = null; } }
  _field(key, value) { this.form = { ...this.form, [key]: value }; }
  async _write(action, row = this.form) {
    if (!this.hass?.user?.is_admin || this.busy || !this.entry || !this.snapshot?.writable) return;
    if (action === "delete" && this.pending?.mac !== row.mac) return;
    const entry = this.entry, epoch = ++this._epoch;
    const payload = { type: "miwifi/dhcp_write", entry_id: entry, revision: this.snapshot.revision, action, mac: row.mac };
    if (action !== "delete") { payload.ip = row.ip; payload.name = row.name; }
    this.busy = true; this.error = ""; this.saved = false;
    try {
      const result = await this.hass.callWS(payload);
      if (!this._valid(result)) throw { code: "unverified" };
      if (epoch === this._epoch && entry === this.entry) { this.snapshot = result; this.saved = true; this._reset(); }
    } catch (error) {
      if (epoch === this._epoch) { this.snapshot = null; this._error(error?.code ? error : { code: "unverified" }); }
    } finally { if (epoch === this._epoch) this.busy = false; }
  }
  render() {
    if (!this.hass?.user?.is_admin) return html`<p>${localize("mac_admin_only")}</p>`;
    const data = this.snapshot, disabled = this.busy || !data?.writable;
    return html`
      <h3>${localize("dhcp_title")}</h3><p>${localize("dhcp_description")}</p>
      ${this.routers.length === 1 ? html`<p><strong>${localize("dhcp_router")}:</strong> ${this.routers[0].name} (${this.routers[0].ip})</p>`
        : this.routers.length > 1 ? html`<label>${localize("dhcp_router")}<select .value=${this.entry} ?disabled=${this.busy} @change=${event => this._select(event.target.value)}>
        <option value="">${localize("dhcp_choose_router")}</option>
        ${this.routers.map(row => html`<option value=${row.entry_id}>${row.name} (${row.ip})</option>`)}
      </select></label>` : ""}
      <div class="actions"><button ?disabled=${this.busy} @click=${() => this._routers()}>${localize("mac_reload")}</button></div>
      ${!this.busy && !this.routers.length ? html`<p>${localize("dhcp_no_routers")}</p>` : ""}
      ${this.busy ? html`<p role="status">${localize("ui_loading")}</p>` : ""}
      ${this.error ? html`<p class="error" role="alert">${this.error}</p>` : ""}
      ${this.saved ? html`<p class="success" role="status">${localize("dhcp_saved")}</p>` : ""}
      ${data ? html`
        <p>${data.model} · ${data.firmware} · ${data.subnet}</p>
        ${!data.enabled ? html`<p class="hint">${localize("dhcp_error_disabled")}</p>` : !data.writable ? html`<p class="hint">${localize("dhcp_error_unsupported")}</p>` : ""}
        ${!data.bindings.length ? html`<p>${localize("dhcp_empty")}</p>` : html`<ul>${data.bindings.map(row => html`
          <li><div class="row"><div class="identity"><strong>${row.name || row.mac}</strong><span>${row.mac} · ${row.ip}</span></div>
            <div class="actions"><button ?disabled=${disabled} @click=${() => this._edit(row)}>${localize("dhcp_edit")}</button>
            <button ?disabled=${disabled} @click=${() => { this.pending = row; }}>${localize("dhcp_delete")}</button></div></div>
            ${this.pending?.mac === row.mac ? html`<p>${localize("dhcp_confirm_delete")} ${row.name || row.mac} (${row.ip})</p>
              <div class="actions"><button ?disabled=${disabled} @click=${() => this._write("delete", row)}>${localize("dhcp_delete")}</button>
              <button ?disabled=${this.busy} @click=${() => { this.pending = null; }}>${localize("dhcp_cancel")}</button></div>` : ""}
          </li>`)}</ul>`}
        <form @submit=${event => { event.preventDefault(); this._write(this.editing ? "edit" : "add"); }}>
          <h3>${localize(this.editing ? "dhcp_edit" : "dhcp_add")}</h3>
          ${!this.editing ? html`<label>${localize("dhcp_client")}<select ?disabled=${disabled} @change=${event => { this._choose(event.target.value); event.target.value = ""; }}>
            <option value="">${localize("dhcp_manual")}</option>
            ${data.clients.filter(row => !data.bindings.some(binding => binding.mac === row.mac)).map(row => html`<option value=${row.mac}>${row.name || row.mac} · ${row.ip}</option>`)}
          </select></label>` : ""}
          <div class="fields">
            <label>MAC<input required .value=${this.form.mac} ?disabled=${disabled || this.editing} @input=${event => this._field("mac", event.target.value)}></label>
            <label>IPv4<input required .value=${this.form.ip} ?disabled=${disabled} @input=${event => this._field("ip", event.target.value)}></label>
            <label>${localize("dhcp_name")}<input .value=${this.form.name} ?disabled=${disabled} @input=${event => this._field("name", event.target.value)}></label>
          </div>
          <p class="hint">${localize("dhcp_hint")}</p>
          <div class="actions"><button type="submit" class="primary" ?disabled=${disabled}>${localize("ui_save")}</button>
          <button type="button" ?disabled=${this.busy} @click=${() => this._reset()}>${localize("dhcp_cancel")}</button></div>
        </form>` : ""}
    `;
  }
}
customElements.define("miwifi-dhcp", MiWiFiDhcp);
