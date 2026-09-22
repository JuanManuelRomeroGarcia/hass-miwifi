import { loadTranslations, localize } from "./translations/localize.js?v=3.7.0";
import { navigate, goBack } from "./router.js?v=3.7.0";
import { logToBackend } from "./pages/utils.js?v=3.7.0";
import { html, css, LitElement } from "./vendor/lit.js?v=3.7.0";
import { until } from "./vendor/lit.js?v=3.7.0";

const MIWIFI_VERSION = "3.7.0";
class MiWiFiPanel extends LitElement {

  static properties = {
    hass: {},
    narrow: {},
    isWide: {},
    _currentPage: { state: true },
    _router: { state: true },
    _pagePromise: { state: true },
    _hasMesh: { state: true },
  };

  constructor() {
    super();
    this._currentPage = "/";
    this._router = null;
    this._pagePromise = null;
    this._lastLoadedPage = null;
    this._translationsLoaded = false;
    this._onApplySettings = () => this._applySettings();
    this._onNavigate = (event) => this._navigate(event.detail.path);
    this._pendingTimeouts = new Set();
  }

  connectedCallback() {
    super.connectedCallback();
    window.addEventListener("miwifi-apply-settings", this._onApplySettings);
    window.addEventListener("miwifi-navigate", this._onNavigate);
    this._startAutoRefresh();
    if (this.hass) {
      if (this._router) this._navigate(this._router.currentPath());
      else this._loadRouter();
    }
  }

  _schedule(callback, delay) {
    if (!this.isConnected) return;
    const timer = setTimeout(() => {
      this._pendingTimeouts.delete(timer);
      if (this.isConnected) callback();
    }, delay);
    this._pendingTimeouts.add(timer);
  }

  updated(changedProperties) {
    if (changedProperties.has("hass") && this.hass) {
      const main = Object.values(this.hass.states).find(
        (s) => s.entity_id.startsWith("sensor.miwifi_topology") &&
              s.attributes?.graph?.is_main === true
      );
      this._hasMesh = Array.isArray(main?.attributes?.graph?.leafs) &&
                      main.attributes.graph.leafs.length > 0;
    }

    if (changedProperties.has("hass") && this.hass && !this._translationsLoaded) {
      this._loadRouter();
    }

    if (changedProperties.has("hass") && this._pagePromise && this._router) {
      this.requestUpdate();
    }
  }

  async _loadRouter() {
    if (!this.isConnected || !this.hass || this._routerLoading) return;
    this._routerLoading = true;
    try {
      await loadTranslations(this.hass);
      const module = await import(`./router.js?v=${MIWIFI_VERSION}`);
      if (!this.isConnected) return;
      this._translationsLoaded = true;
      this._router = module;
      this._navigate(this._router.currentPath());
    } catch (error) {
      console.error("MiWiFi panel initialization failed:", error);
    } finally {
      this._routerLoading = false;
    }
  }

  _navigate(path) {
    if (!this.isConnected || !this._router) return;
    if (path === this._currentPage && this._pagePromise) return;

    this._currentPage = path;
    this._loadPage(path);

    this._router.navigate(path);
  }

  _applySettings() {
    if (!this.isConnected) return;
    const panelActiveEl = this.renderRoot.querySelector("#panel_active");
    const speedUnitEl = this.renderRoot.querySelector("#speed_unit");
    const logLevelEl = this.renderRoot.querySelector("#log_level");

    if (!panelActiveEl || !speedUnitEl || !logLevelEl) {
      this._showToast(localize("error.form_elements_not_found"));
      return;
    }

    const panelActive = panelActiveEl.checked;
    const speedUnit = speedUnitEl.value;
    const logLevel = logLevelEl.value;

    this._showToast(localize("settings.applying"));

    this.hass.callService("miwifi", "apply_config", {
      panel_active: panelActive,
      speed_unit: speedUnit,
      log_level: logLevel,
    }).then(() => {
      this._showToast(localize("settings.success"));
      logToBackend(this.hass, logLevel, "✅ [panel-frontend.js] Settings applied successfully.");
      this._schedule(() => {
        this._loadPage("/settings");
      }, 4000);
    }).catch((err) => {
      console.error("❌ Error applying settings:", err);
      logToBackend(this.hass, "error", `❌ [panel-frontend.js] Failed to apply settings: ${err.message}`);

      this._showToast(localize("settings.error"));
    });
  }

  _showToast(message) {
    this.hass.callService("persistent_notification", "create", {
      message,
      title: "⚙️ MiWiFi",
      notification_id: "miwifi_feedback"
    });
  }

  async _loadPage(path) {
    if (!this.isConnected || !this._router) return;
    const PageComponent = this._router.router[path] || this._router.router["/error"];
    this._pagePromise = PageComponent(this.hass);
    this.requestUpdate();
  }

  renderLoading(message = localize("loading.panel")) {
    return html`
      <div class="loading-container">
        <div class="spinner"></div>
        <div class="loading-text">${message}</div>
      </div>
    `;
  }

  _renderVersionWarning() {
    const expectedVersion = MIWIFI_VERSION;
    const actualVersion = window.miwifiPanelVersion || "";
  
    if (actualVersion && actualVersion !== expectedVersion) {
      return html`
        <ha-alert alert-type="warning" title="⚠️ Panel Version Mismatch">
          A new version of the MiWiFi Panel is available.<br />
          <b>Installed:</b> ${actualVersion} — <b>Expected:</b> ${expectedVersion}<br />
          Please <b>press Ctrl+F5</b> to refresh your browser and load the latest version.
        </ha-alert>
      `;
    }
  
    return html``;
  }

_startAutoRefresh() {
  clearInterval(this._refreshInterval);
  this._refreshInterval = setInterval(() => {
    const root = this.shadowRoot?.querySelector(".content");
    const isEmpty = !root || root.offsetHeight === 0;

    if (!this.hass || !this._router || !this._currentPage) {
      console.warn(localize("log.autorefresh_cancelled"));
      return;
    }

    // 🔌 Si la conexión WebSocket está caída, notificar y recargar
    if (!this.hass.connection?.connected) {
      console.warn(localize("log.websocket_lost"));

      logToBackend(this.hass, "warning", "❌ [panel-frontend.js] WebSocket lost. Triggering forced reload.");

      this.hass.callService("persistent_notification", "create", {
        title: "⚠️ MiWiFi",
        message: localize("notification.connection_lost"),
        notification_id: "miwifi_connection_lost"
      });

      this._schedule(() => {
        window.location.reload();
      }, 1000);

      return;
    }

    if (isEmpty) {
      logToBackend(this.hass, "warning", "⚠️ [panel-frontend.js] Panel content is empty – attempting reload.");
      console.warn(localize("log.panel_frozen"));

      // 🔁 Forzar navegación para recargar correctamente
      const current = this._currentPage;
      this._navigate("/error");
      this._schedule(() => this._navigate(current), 300);
      return;
    } else {
      console.log(localize("log.refreshing_section"));
    }

    this._pagePromise = null;
    this.requestUpdate();

    this._loadPage(this._currentPage).catch((err) => {
      console.error(localize("log.page_reload_error"), err);
      logToBackend(this.hass, "error", `❌ [panel-frontend.js] Error loading page '${this._currentPage}': ${err.message}`);
      this._navigate("/error");
    });
  }, 5 * 60 * 1000); // cada 5 minutos
}




  disconnectedCallback() {
    super.disconnectedCallback();
    clearInterval(this._refreshInterval);
    window.removeEventListener("miwifi-apply-settings", this._onApplySettings);
    window.removeEventListener("miwifi-navigate", this._onNavigate);
    for (const timer of this._pendingTimeouts) clearTimeout(timer);
    this._pendingTimeouts.clear();
    this._pagePromise = null;
  }

  render() {
    if (!this._pagePromise) return this.renderLoading();

    return html`
      <ha-app-layout>
        <ha-top-app-bar slot="header">
          <div class="header-content">
            <ha-menu-button .hass=${this.hass} .narrow=${this.narrow}></ha-menu-button>
            <img src="/miwifi_static/assets/logo.png" class="logo" alt="Logo" />
            <div class="center" main-title>XiaoHack Edition</div>
            <span class="version-badge">v${MIWIFI_VERSION}</span>
          </div>
        </ha-top-app-bar>

        <div slot="content" class="content">
        ${this._renderVersionWarning()}
          <div class="miwifi-button-group">
            <button class="miwifi-button" @click=${() => this._navigate("/status")}>${localize("nav_status")}</button>
            <button class="miwifi-button" @click=${() => this._navigate("/topologia")}>${localize("nav_topology")}</button>
            <button class="miwifi-button" @click=${() => this._navigate("/miwifi-devices")}>${localize("nav_devices")}</button>
            ${this._hasMesh ? html`
              <button class="miwifi-button" @click=${() => this._navigate("/mesh")}>
                ${localize("nav_mesh")}
              </button>
            ` : ""}
            <button class="miwifi-button" @click=${() => this._navigate("/portforwarding")}>${localize("nav_portforwarding")}</button>
            <button class="miwifi-button" @click=${() => this._navigate("/settings")}>${localize("nav_settings")}</button>
          </div>

          ${until(this._pagePromise, this.renderLoading(localize("loading_section")))}

          <div style="text-align: center; margin-top: 40px;">
            <button class="miwifi-button" @click=${() => goBack()}>
              ⬅️ ${localize("button_back") || "Back"}
            </button>
            <button class="miwifi-button" @click=${() => window.scrollTo({ top: 0, behavior: 'smooth' })}>
              ⬆️ ${localize("button_scroll_top")}
            </button>
          </div>
        </div>
      </ha-app-layout>
    `;
  }

  static styles = css`
  :host {
    --miwifi-primary-color: #1a73e8;
    --miwifi-text-color: white;
    --miwifi-border-radius: 12px;
    --miwifi-font-size: 16px;
    --miwifi-padding: 16px;
    display: block;
    background-color: var(--miwifi-primary-color);
    min-height: 100vh;
    overflow-x: hidden;
  }

  .content {
    padding: var(--miwifi-padding);
    animation: fadeIn 0.3s ease-in-out;
    color: var(--miwifi-text-color);
    min-height: calc(100vh - 80px);
    overflow-x: hidden;
    box-sizing: border-box;
  }

  ha-app-layout {
    display: block;
    height: 100%;
    background-color: var(--miwifi-primary-color);
    color: var(--miwifi-text-color);
  }

  .logo {
    height: 36px;
    margin-right: 10px;
  }

  ha-top-app-bar-fixed {
    display: flex;
    align-items: center;
  }
  
  ha-top-app-bar {
    position: sticky;
    top: 0;
    left: 0;
    right: 0;
    width: 100%;
    background-color: var(--miwifi-primary-color);
    box-shadow: 0 2px 5px rgba(0, 0, 0, 0.3);
  }

  .header-content {
    display: flex; 
    align-items: center;
    gap: 10px; 
    padding-left: 16px;
    padding-top: 10px;
  }

  .row{
    display:grid;
    grid-template-columns: repeat(3, minmax(180px, 1fr));
    gap:12px;
  }

  .switchline{ 
    display:flex; 
    align-items:center; 
    gap:10px;
    min-width:0;
  }
 
  .right { 
    display:flex; 
    gap:8px; 
    justify-content:flex-end; 
  }

  .hidden { 
    display:none; 
  }
  
  mw-input{ 
    display:flex; 
    flex-direction:column; 
    gap:6px;
    min-width:0;
  }
       
  mw-input label{ 
    font-size:12px; 
    opacity:.8 
  }
  
  mw-input input, mw-input select{ 
    padding:8px; 
    border:1px solid var(--divider-color); 
    border-radius:8px; 
    color:var(--primary-text-color); 
    width:100%; 
    box-sizing:border-box;
  }

  mw-input > div{ display:flex; align-items:center; gap:8px; }
  mw-input > div > input{ flex:1 1 auto; min-width:0; width:auto; }
  mw-input > div > .miwifi-button{ flex:0 0 auto; }

  mw-input .miwifi-button{
    min-width: auto;
    width: auto;
    padding: 6px 10px;
    border-radius: 12px;
  }

  .wifi-block { 
    border:1px solid var(--divider-color); 
    border-radius:12px; 
    margin-bottom:12px; 
  }
  
  .wifi-block .header{
    padding:10px;
    display:flex;
    align-items:center;
    justify-content:space-between;
    flex-wrap:wrap;
    gap:8px;
  }
  
  .wifi-block .body { 
    border-top:1px solid var(--divider-color); 
    padding:10px; 
  }
  
  .wifi-card { 
    display:grid; 
    grid-template-columns: repeat(2, minmax(140px,1fr)); 
    gap:6px; 
  }
  
  .wifi-title { 
    font-weight:600; 
    margin-bottom:6px; 
    grid-column: 1 / -1; 
  }

  .wifi-row b { 
    opacity:.8; 
    margin-right:6px; 
  }

  .hint { 
    opacity:.7; 
    font-size:12px; 
  }

  .dialog-backdrop{ 
    position:fixed;
    inset:0; 
    background:rgba(0,0,0,.35);
    display:flex; 
    justify-content:center; 
    align-items:center; 
    z-index:1000; 
  }

  .dialog{ 
    background:var(--card-background-color); 
    padding:16px; 
    border-radius:12px; 
    max-width:520px; 
    width:95%; 
  }

  .dump-grid{ 
    display:grid; 
    grid-template-columns: repeat(2, 1fr); 
    gap:10px; 
    margin-top:8px; 
  }

  .dump-check{ 
    display:flex; 
    align-items:center; 
    gap:8px; 
  }

  .note{ 
    font-size:12px; 
    opacity:.7; 
  }

  .select-grid{ 
    display:grid; 
    grid-template-columns: repeat(2, 1fr); 
    gap:12px; 
  }

  .select-block{ 
    display:flex; 
    flex-direction:column; 
    gap:6px; 
  }

  .miwifi-issue { 
    margin-top:12px; 
    border-top:1px dashed var(--divider-color); 
    padding-top:8px; 
    display:flex; 
    justify-content:space-between; 
    align-items:center; 
  }

  .miwifi-issue-link { 
    text-decoration:none; 
    border:1px solid var(--divider-color); 
    border-radius:8px; 
    padding:6px 10px; 
  }

  .miwifi-button-group {
    display: flex;
    flex-wrap: wrap;
    gap: 12px;
    margin-bottom: 20px;
    justify-content: center;
  }

  .miwifi-button {
    background: linear-gradient(135deg, #00c6ff 0%, #0072ff 100%);
    color: white;
    border: none;
    border-radius: 30px;
    padding: 10px 20px;
    font-size: 15px;
    font-weight: 600;
    min-width: 140px;
    text-align: center;
    box-shadow: 0px 2px 5px rgba(0, 0, 0, 0.2);
    cursor: pointer;
    transition: transform 0.2s ease, box-shadow 0.2s ease;
  }

  .miwifi-button:hover {
    transform: translateY(-2px);
    box-shadow: 0px 4px 8px rgba(0, 0, 0, 0.25);
  }

  .miwifi-button:active {
    transform: scale(0.98);
    box-shadow: 0px 2px 4px rgba(0, 0, 0, 0.2);
  }
  
  button.back-button {
    background: #1a73e8;
    color: white;
    padding: 8px 16px;
    border: 1px solid white;
    border-radius: 8px;
    font-size: 14px;
    cursor: pointer;
    margin-top: 30px;
  }

  .loading-container {
    display: flex;
    flex-direction: column;
    align-items: center;
    justify-content: center;
    height: 70vh;
    text-align: center;
    color: white;
  }

  .spinner {
    border: 6px solid rgba(255, 255, 255, 0.2);
    border-top: 6px solid white;
    border-radius: 50%;
    width: 60px;
    height: 60px;
    animation: spin 1s linear infinite;
    margin-bottom: 20px;
  }

  .loading-text {
    font-size: 20px;
    font-weight: bold;
    animation: pulse 1.5s infinite;
  }

  @keyframes spin {
    0% { transform: rotate(0deg); }
    100% { transform: rotate(360deg); }
  }

  @keyframes pulse {
    0% { opacity: 1; }
    50% { opacity: 0.5; }
    100% { opacity: 1; }
  }

  @keyframes fadeIn {
    from { opacity: 0; transform: translateY(-10px); }
    to { opacity: 1; transform: translateY(0); }
  }

  .topo-box {
    width: 270px;
    margin-bottom: 20px;
    display: inline-block;
    text-align: center;
    color: #fff;
  }

  .topo-icon {
    width: 50px;
    height: 50px;
    margin-bottom: 6px;
    border-radius: 8px;
    padding: 5px;
  }

  .topo-icon-lg {
    width: 60px;
    height: 60px;
    margin-bottom: 6px;
    border-radius: 8px;
    padding: 5px;
  }

  .topo-name {
    font-size: 13px;
    font-weight: normal;
    margin-bottom: 2px;
    white-space: nowrap;
    overflow: hidden;
    text-overflow: ellipsis;
  }

  .topo-ip {
    font-size: 12px;
    color: #a9bcd8;
  }

  .line-net {
    display: inline-block;
    width: 4px;
    height: 40px;
    background-color: #0f3;
    margin: 15px 0 5px;
  }

  .line-horizontal {
    height: 4px;
    background-color: #0f3;
    width: 100%;
    max-width: 300px;
    margin-bottom: 20px;
  }

  .branch-container {
    display: flex;
    flex-direction: column;
    align-items: center;
    margin-top: 10px;
  }

  .branch-nodes {
    display: flex;
    justify-content: center;
    flex-wrap: wrap;
    gap: 40px;
  }

  img {
    max-width: 100%;
    height: auto;
    display: block;
  }

  .status-grid {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
    gap: 16px;
    padding: 16px;
  }

  .status-card {
    background: #1a73e8;
    color: white;
    padding: 16px;
    border-radius: 12px;
    text-align: center;
    box-shadow: 0px 4px 8px rgba(0,0,0,0.3);
    animation: fadeIn 0.5s ease;
  }

  .status-value {
    font-size: 22px;
    font-weight: bold;
    margin-bottom: 8px;
  }

  .status-label {
    font-size: 14px;
    color: #d0d0d0;
  }

  .unavailable {
    color: #aaa;
  }

  .section-title {
    font-size: 20px;
    font-weight: bold;
    color:white;
    margin-top: 24px;
    text-align: center;
  }

  .device-grid {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
    gap: 16px;
    padding: 16px;
  }

  .device-card {
    background: #1a73e8;
    color: white;
    padding: 16px;
    border-radius: 12px;
    text-align: center;
    box-shadow: 0px 4px 8px rgba(0,0,0,0.3);
    animation: fadeIn 0.5s ease;
  }
  .device-card.disconnected {
    background-color: rgba(255, 255, 255, 0.1);
    color: #bbb;
    filter: grayscale(100%);
  }

  .device-card.disconnected .device-status {
    color: #ff4d4d;
  }

  .device-card.disconnected .device-info {
    color: #999;
  }
  
  .center {
    text-align: center;
  }

  .device-name {
    font-size: 18px;
    font-weight: bold;
    margin-bottom: 8px;
  }

  .device-info {
    font-size: 14px;
    margin-bottom: 4px;
    color: #d0d0d0;
  }

  .device-status {
    margin-top: 8px;
    font-weight: bold;
  }

  .online {
    color: #00ff00;
  }

  .offline {
    color: #ff4d4d;
  }

  .text-center {
    text-align: center;
  }

  .section {
    background: #1a73e8;
    color: white;
    padding: 16px;
    margin: 30px;
    border-radius: 12px;
    text-align: center;
    box-shadow: 0px 4px 8px rgba(0,0,0,0.3);
    animation: fadeIn 0.5s ease;
  }

  .setting-row {
    display: flex;
    justify-content: space-between;
    align-items: center;
    padding: 8px 0;
    border-bottom: 1px solid #eee;
  }

  .setting-row:last-child {
    border-bottom: none;
  }

  .switch {
    position: relative;
    display: inline-block;
    width: 42px;
    height: 24px;
  }

  .switch input {
    opacity: 0;
    width: 0;
    height: 0;
  }

  .slider {
    position: absolute;
    cursor: pointer;
    top: 0;
    left: 0;
    right: 0;
    bottom: 0;
    background-color: #ccc;
    transition: 0.4s;
    border-radius: 24px;
  }

  .slider:before {
    position: absolute;
    content: "";
    height: 18px;
    width: 18px;
    left: 3px;
    bottom: 3px;
    background-color: white;
    transition: 0.4s;
    border-radius: 50%;
  }

  .switch input:checked + .slider {
    background-color: #03a9f4;
  }

  .switch input:checked + .slider:before {
    transform: translateX(18px);
  }

  .select-grid {
    display: flex;
    flex-wrap: wrap;
    gap: 16px;
  }

  .select-block {
    display: flex;
    flex-direction: column;
    width: 100%;
    max-width: 240px;
  }

  .select-block select {
    padding: 8px;
    border-radius: 8px;
    border: 1px solid #ccc;
    font-size: 14px;
  }

  button.reboot-btn {
    background: #f44336;
    color: white;
    font-weight: bold;
    border: none;
    border-radius: 10px;
    padding: 12px 20px;
    cursor: pointer;
    width: 100%;
    margin-top: 16px;
  }

  button.reboot-btn:hover {
    background: #e53935;
  }

  .panel-header,
  .config-header {
    text-align: center;
    margin-bottom: 28px;
  }

  .config-header img {
    display: inline;
    vertical-align: middle;
    margin-right: 6px;
    filter: drop-shadow(1px 1px 1px rgba(0,0,0,0.3));
  }
  
  .miwifi-dump-modal-backdrop {
    position: fixed;
    top: 0; left: 0; right: 0; bottom: 0;
    background-color: rgba(0,0,0,0.4);
    display: flex;
    justify-content: center;
    align-items: center;
    z-index: 10000;
  }
  .miwifi-dump-modal-window {
    background: #1a73e8;
    color: white;
    padding: 16px;
    border-radius: 12px;
    text-align: center;
    box-shadow: 0px 4px 8px rgba(0,0,0,0.3);
    animation: fadeIn 0.5s ease;
  }

  .version-badge {
    background: #1a73e8;
    color: white;
    font-size: 12px;
    padding: 4px 10px;
    border-radius: 8px;
    display: inline-block;
    margin-left: 8px;
  }

  .miwifi-mesh-group {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(280px, 1fr));
    gap: 40px;
    margin: 20px;
    padding: 0 16px;
  }

  .mesh-card {
    background: #2366d1;
    padding: 16px;
    border-radius: 10px;
    text-align: center;
    box-shadow: 0px 4px 8px rgba(0,0,0,0.3);
    transition: transform 0.3s, box-shadow 0.3s;
    color: white;
    width: auto; 
    max-width: 100%;
  }

  .mesh-card:hover {
    transform: scale(1.01);
    box-shadow: 0px 6px 14px rgba(0,0,0,0.5);
  }

  .mesh-name {
    font-size: 18px;
    font-weight: bold;
    margin-bottom: 8px;
  }

  .mesh-info {
    font-size: 14px;
    color: #d0d0d0;
    margin-bottom: 4px;
  }

  .miwifi-issue-link {
    display: inline-block;
    margin-top: 8px;
    padding: 8px 16px;
    color: white;
    background-color: #1a73e8;
    text-decoration: none;
    border-radius: 8px;
    font-weight: bold;
  }

  .miwifi-issue-link:hover {
    background-color: #155ab6;
  }

  /* ====== Responsivo ====== */

  @media (max-width: 1024px) {
    .row{ grid-template-columns: repeat(2, minmax(160px, 1fr)); }
  }

  @media (max-width: 849px) {
    ha-top-app-bar {
      position: fixed;
      top: 0;
      left: 0;
      right: 0;
      height: 64px;
      width: 100%;
      z-index: 99;
      background-color: var(--miwifi-primary-color);
      box-shadow: 0 2px 5px rgba(0, 0, 0, 0.3);
    }

    .content { padding-top: 82px; }
  }

  @media (max-width: 768px) {
    .miwifi-mesh-group {
      grid-template-columns: 1fr !important;
      padding: 0;
      gap: 16px;
      margin: 0;
    }

    .section { padding: 12px; margin: 20px 0; }

    .select-grid { flex-direction: column; align-items: stretch; }

    .select-block { max-width: 100%; width: 100%; }

    .status-grid, .device-grid { grid-template-columns: 1fr !important; padding: 8px; }
    .status-card, .device-card { width: auto; }

    .miwifi-button-group { gap: 8px; flex-direction: row; }

    .config-header h2 { font-size: 18px; }

    .disabled-message {
      padding: 2rem;
      text-align: center;
      color: red;
      font-size: 1.2rem;
    }

    /* Botones grandes SOLO en zonas de acciones */
    .miwifi-button-group .miwifi-button,
    .right .miwifi-button,
    button.reboot-btn{
      min-width: unset;
      width: 90%;
      padding: 10px;
      font-size: 15px;
    }

    /* Botón del ojo siempre compacto */
    mw-input .miwifi-button{
      width: auto !important;
      min-width: auto !important;
      padding: 6px 10px;
      font-size: 14px;
    }
  }

  @media (max-width: 720px) {
    .row{ grid-template-columns: 1fr; }
    .wifi-card{ grid-template-columns: 1fr; }

    /* Botones grandes SOLO en zonas de acciones */
    .miwifi-button-group .miwifi-button,
    .right .miwifi-button,
    button.reboot-btn{ width:100%; }

    /* Botón del ojo compacto */
    mw-input .miwifi-button{
      width:auto !important;
      min-width:auto !important;
    }

    .wifi-block .header{ gap:6px; }
    mw-input input, mw-input select{ font-size:16px; }
  }
`;
}

if (!customElements.get("miwifi-panel")) {
  customElements.define("miwifi-panel", MiWiFiPanel);
}

