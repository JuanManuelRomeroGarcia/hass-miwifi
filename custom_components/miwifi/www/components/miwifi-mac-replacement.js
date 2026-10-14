import { LitElement, html, css } from "../vendor/lit.js?v=3.10.0";
import { localize } from "../translations/localize.js?v=3.10.0";

export class MiWiFiMacReplacement extends LitElement {
  static properties = {
    hass: {}, rows: { state: true }, names: { state: true }, loading: { state: true },
    saving: { state: true }, dirty: { state: true }, error: { state: true }, saved: { state: true },
  };
  static styles = css`
    :host { display: block; max-width: 760px; margin: 20px auto; padding: 20px; box-sizing: border-box; text-align: left; color: var(--primary-text-color, #212121); background: var(--card-background-color, #fff); border-radius: 12px; }
    h3 { margin: 0 0 12px; }
    .clients { list-style: none; padding: 0; margin: 16px 0; border: 1px solid var(--divider-color, #ddd); border-radius: 8px; overflow: hidden; }
    .row { display: flex; align-items: flex-start; gap: 12px; padding: 12px; }
    .row + .row { border-top: 1px solid var(--divider-color, #ddd); }
    details { flex: 1; min-width: 0; }
    summary { padding: 9px 0; cursor: pointer; overflow-wrap: anywhere; font-weight: 600; }
    .heading, .actions { display: flex; align-items: center; justify-content: space-between; gap: 12px; flex-wrap: wrap; }
    label { display: block; margin: 10px 0 6px; }
    textarea, select { box-sizing: border-box; width: 100%; padding: 10px; font: inherit; color: inherit; background: var(--card-background-color, white); border: 1px solid var(--divider-color, #ccc); border-radius: 6px; }
    textarea { resize: vertical; }
    .actions { justify-content: flex-end; margin-top: 16px; }
    .hint { font-size: .9em; color: var(--secondary-text-color, #555); }
    @media (max-width: 480px) { :host { padding: 14px; } .row { gap: 8px; } button { max-width: 100%; } }
    button { padding: 9px 14px; font: inherit; cursor: pointer; border-radius: 6px; border: 1px solid var(--divider-color, #ccc); background: var(--card-background-color, white); color: inherit; }
    button.primary { background: var(--primary-color, #03a9f4); color: var(--text-primary-color, white); }
    button:disabled { opacity: .5; cursor: default; }
    p { line-height: 1.5; }
    .error { color: var(--error-color, #c00); }
    .success { color: var(--success-color, #238636); }
  `;
  constructor() {
    super();
    this.rows = []; this.names = []; this.loading = false; this.saving = false;
    this.dirty = false; this.error = ""; this.saved = false; this._loaded = false; this._attempted = false;
  }
  updated(changed) {
    if (changed.has("hass") && this.hass?.user?.is_admin && !this._attempted && !this.loading) this._load();
  }
  async _load() {
    this.loading = true; this.error = ""; this._attempted = true;
    try {
      const result = await this.hass.callWS({ type: "miwifi/get_mac_replacement" });
      if (!result?.clients || !Array.isArray(result.available_names)) throw new Error(localize("mac_load_error"));
      this.rows = Object.entries(result.clients).map(([key, names]) => ({ key, text: names.join("\n") }));
      this.names = result.available_names; this.dirty = false; this._loaded = true;
    } catch (error) { this.error = `${localize("mac_load_error")}: ${error.message || error}`; this._loaded = false; }
    finally { this.loading = false; }
  }
  _add(name = "") {
    if (name && this.rows.some(row => row.text.split(/\r?\n/).some(alias => alias.trim().toLocaleLowerCase() === name.trim().toLocaleLowerCase()))) {
      this.error = localize("mac_duplicate_names"); return;
    }
    let index = 1;
    while (this.rows.some(row => row.key === `client_${index}`)) index++;
    this.rows = [...this.rows, { key: `client_${index}`, text: name, expanded: !name }]; this._changed();
  }
  _changed() { this.dirty = true; this.saved = false; this.error = ""; }
  _edit(key, text) { this.rows = this.rows.map(row => row.key === key ? { ...row, text } : row); this._changed(); }
  _remove(key) { this.rows = this.rows.filter(row => row.key !== key); this._changed(); }
  _clients() {
    const clients = {}, used = new Set();
    for (const row of this.rows) {
      const names = row.text.split(/\r?\n/).map(name => name.trim()).filter(Boolean);
      if (!names.length) throw new Error(localize("mac_empty_names"));
      for (const name of names) {
        const normalized = name.toLocaleLowerCase();
        if (used.has(normalized)) throw new Error(localize("mac_duplicate_names"));
        used.add(normalized);
      }
      clients[row.key] = names;
    }
    return clients;
  }
  async _save() {
    if (!this.hass?.user?.is_admin || this.saving || !this._loaded || this.loading) return;
    this.error = ""; this.saved = false;
    let clients;
    try { clients = this._clients(); } catch (error) { this.error = error.message; return; }
    this.saving = true;
    try {
      await this.hass.callService("miwifi", "configure_mac_replacement", { clients });
      this.dirty = false; this.saved = true;
    } catch (error) { this.error = `${localize("ui_error")}: ${error.message || error}`; }
    finally { this.saving = false; }
  }
  render() {
    if (!this.hass?.user?.is_admin) return html`<p>${localize("mac_admin_only")}</p>`;
    return html`
      <h3>${localize("mac_title")}</h3>
      <p>${localize("mac_description")}</p>
      ${this.loading ? html`<p>${localize("ui_loading")}</p>` : ""}
      ${this.error ? html`<p class="error" role="alert">${this.error}</p>` : ""}
      ${this.saved ? html`<p class="success" role="status">${localize("mac_saved")}</p>` : ""}
      ${this._loaded && !this.loading && !this.rows.length ? html`<p>${localize("mac_disabled")}</p>` : ""}
      ${this.rows.length ? html`<ul class="clients">${this.rows.map(row => html`
        <li class="row">
          <details ?open=${!!row.expanded}>
          <summary>${row.text.split("\n")[0] || localize("mac_new_client")}</summary>
          <label>${localize("mac_aliases")}
            <textarea rows="3" .value=${row.text} ?disabled=${this.saving} @input=${event => this._edit(row.key, event.target.value)}></textarea>
          </label>
          </details>
          <button ?disabled=${this.saving} @click=${() => this._remove(row.key)}>${localize("mac_remove")}</button>
        </li>
      `)}</ul>` : ""}
      <label>${localize("mac_choose")}
        <select ?disabled=${this.loading || this.saving || !this._loaded} @change=${event => { if (event.target.value) { this._add(event.target.value); event.target.value = ""; } }}>
          <option value="">${localize("mac_choose_placeholder")}</option>
          ${this.names.filter(name => !this.rows.some(row => row.text.split(/\r?\n/).some(alias => alias.trim().toLocaleLowerCase() === name.toLocaleLowerCase()))).map(name => html`<option value=${name}>${name}</option>`)}
        </select>
      </label>
      <p class="hint">${localize("mac_hint")}</p>
      <div class="actions">
        <button ?disabled=${this.loading || this.saving || !this._loaded} @click=${() => this._add()}>${localize("mac_add_manual")}</button>
        <button ?disabled=${this.loading || this.saving || this.dirty} @click=${() => this._load()}>${localize("mac_reload")}</button>
        <button class="primary" ?disabled=${!this.dirty || this.loading || this.saving || !this._loaded} @click=${() => this._save()}>${this.saving ? localize("mac_saving") : localize("ui_save")}</button>
      </div>
    `;
  }
}
customElements.define("miwifi-mac-replacement", MiWiFiMacReplacement);
