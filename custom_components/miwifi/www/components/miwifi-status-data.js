import { LitElement, html, css } from "../vendor/lit.js?v=3.10.0";
import { localize } from "../translations/localize.js?v=3.10.0";

const PREFERENCE_KEY = "miwifi.status-view.v1";

class MiWiFiStatusData extends LitElement {
  static properties = { sections: {}, _view: { state: true } };

  constructor() {
    super();
    this.sections = [];
    this._view = "cards";
    try {
      if (localStorage.getItem(PREFERENCE_KEY) === "list") this._view = "list";
    } catch { /* Private windows and restricted storage remain usable. */ }
  }

  _setView(view) {
    this._view = view === "list" ? "list" : "cards";
    try { localStorage.setItem(PREFERENCE_KEY, this._view); } catch { /* Optional. */ }
  }

  _value(value) {
    return value == null || ["", "unknown", "unavailable"].includes(String(value))
      || String(value).includes("unavailable")
      ? localize("status_unavailable") : value;
  }

  render() {
    return html`
      <div class="toolbar" role="group" aria-label=${localize("status_view")}>
        <button aria-pressed=${this._view === "cards"} @click=${() => this._setView("cards")}>${localize("devices_view_cards")}</button>
        <button aria-pressed=${this._view === "list"} @click=${() => this._setView("list")}>${localize("status_view_list")}</button>
      </div>
      ${this.sections.map(section => html`
        <section>
          <h2>${section.title}</h2>
          ${section.message ? html`<p class="empty">${section.message}</p>` : ""}
          ${!section.items?.length ? "" : this._view === "list" ? html`
            <table>
              <caption>${section.title}</caption>
              <thead><tr><th scope="col">${localize("status_column_field")}</th><th scope="col">${localize("status_column_value")}</th></tr></thead>
              <tbody>${section.items.map(item => html`
                <tr><th scope="row">${item.label}</th><td>${this._value(item.value)}</td></tr>
              `)}</tbody>
            </table>
          ` : html`
            <div class="grid">${section.items.map(item => html`
              <div class="card"><div class="label">${item.label}</div><div class="value">${this._value(item.value)}</div></div>
            `)}</div>
          `}
        </section>
      `)}
    `;
  }

  static styles = css`
    :host { display: block; min-width: 0; color: white; }
    *, *::before, *::after { box-sizing: border-box; }
    .toolbar { display: flex; justify-content: flex-end; flex-wrap: wrap; gap: 8px; padding: 8px 16px 0; }
    button { min-height: 44px; padding: 8px 16px; border: 1px solid white; border-radius: 8px; background: transparent; color: white; font: inherit; cursor: pointer; }
    button[aria-pressed="true"] { background: white; color: #17457e; font-weight: 600; }
    button:focus-visible { outline: 3px solid white; outline-offset: 3px; }
    h2 { font-size: 20px; text-align: center; margin: 24px 16px 16px; overflow-wrap: anywhere; }
    .grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(min(100%, 170px), 1fr)); gap: 16px; padding: 0 16px 16px; }
    .card { min-width: 0; background: #1a73e8; padding: 16px; border-radius: 12px; text-align: center; box-shadow: 0 4px 8px #0004; }
    .label { font-size: 14px; line-height: 1.5; color: #e3edff; overflow-wrap: anywhere; }
    .value { margin-top: 8px; font-size: clamp(1rem, 2.1vw, 1.375rem); line-height: 1.4; font-weight: 600; overflow-wrap: anywhere; }
    table { width: calc(100% - 32px); margin: 0 16px 16px; table-layout: fixed; border-collapse: collapse; background: var(--card-background-color, white); color: var(--primary-text-color, #162437); }
    caption { position: absolute; width: 1px; height: 1px; overflow: hidden; clip-path: inset(50%); }
    th, td { padding: 12px 16px; text-align: left; vertical-align: top; border-bottom: 1px solid var(--divider-color, #d9e1eb); line-height: 1.5; overflow-wrap: anywhere; }
    th { width: 45%; font-weight: 600; }
    thead { background: var(--secondary-background-color, #edf3fa); }
    .empty { text-align: center; padding: 12px; }
    @media (max-width: 600px) {
      .toolbar { padding: 8px; justify-content: center; }
      .toolbar button { flex: 1; }
      .grid { padding: 0 8px 8px; gap: 12px; grid-template-columns: 1fr; }
      table { width: calc(100% - 16px); margin: 0 8px 8px; font-size: 14px; }
      th, td { padding: 12px 10px; }
    }
  `;
}

customElements.define("miwifi-status-data", MiWiFiStatusData);
