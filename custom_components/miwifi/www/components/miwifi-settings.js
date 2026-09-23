import { getRouterImage } from "../pages/utils.js?v=3.8.1";
import { LitElement, html } from "../vendor/lit.js?v=3.8.1";
import { renderToggle, renderSelects, logToBackend } from "../pages/utils.js?v=3.8.1";
import { localize } from "../translations/localize.js?v=3.8.1";

const MIWIFI_VERSION = "3.8.1";
const REPOSITORY = "JuanManuelRomeroGarcia/hass-miwifi";

export class MiWiFiSettingsPanel extends LitElement {
  static properties = {
    hass: {},
    routerSensor: { state: true },

    showDumpModal: { state: true },
    dumpOptions: { state: true },
    isDumpLoading: { state: true },

    // Guest Wi-Fi
    guestLoading: { state: true },
    guestError: { state: true },
    guestForm: { state: true },   // { enable, ssid, password, encryption, hidden }
    guestOrig: { state: true },   // original values for diff
    guestDirty: { state: true },
    guestApplying: { state: true },
    guestShowPwd: { state: true },

    // Radios (read-only form + working enable switch)
    radios: { state: true },      // { twoG, fiveG, game }
    _wifisLoaded: { state: true },

    // Show/Hide password per radio
    radioShowPwd: { state: true }, // { twoG:false, fiveG:false, game:false }
  };

  constructor() {
    super();
    this.routerSensor = null;

    this.showDumpModal = false;
    this.isDumpLoading = false;
    this.dumpOptions = {
      system: true,
      network: true,
      devices: true,
      nat_rules: true,
      qos: true,
      wifi_config: false,
      hide_sensitive: true,
    };

    this.guestLoading = false;
    this.guestError = null;
    this.guestForm = null;
    this.guestOrig = null;
    this.guestDirty = false;
    this.guestApplying = false;
    this.guestShowPwd = false;

    this.radios = { twoG: null, fiveG: null, game: null };
    this._wifisLoaded = false;

    this.radioShowPwd = { twoG: false, fiveG: false, game: false };
  }

  createRenderRoot() { return this; }

  // ------------------ Wi-Fis (Guest + radios) ------------------
  async _fetchWifis() {
    this.guestLoading = true;
    this.guestError = null;
    this.requestUpdate();

    const isAdmin = !!(this.hass?.user?.is_admin);
    try {
      const res = await this.hass.callWS({
        type: "miwifi/get_wifis",
        hide_sensitive: !isAdmin,
      });
      const w = res?.wifis;
      if (!w) throw new Error("invalid_response");

      const g = w.guest || {};
      const two = w["2g"] || null;
      const five = w["5g"] || null;
      const game = w["game"] || null;

      const hiddenRaw = g.hidden;
      const hidden = hiddenRaw === 1 || hiddenRaw === "1" || hiddenRaw === true;
      const safePwd = isAdmin && typeof g.password === "string" ? g.password : "";

      this.guestOrig = {
        enabled: !!g.enabled,
        ssid: g.ssid || "",
        encryption: g.encryption || "psk2",
        hidden,
        password: safePwd,
      };
      this.guestForm = {
        enable: this.guestOrig.enabled,
        ssid: this.guestOrig.ssid,
        password: this.guestOrig.password,
        encryption: this.guestOrig.encryption,
        hidden: this.guestOrig.hidden,
      };
      this.guestDirty = false;

      this.radios = { twoG: two, fiveG: five, game: game };
      this._wifisLoaded = true;
    } catch (err) {
      try {
        const mainMac = this.routerSensor?.attributes?.graph?.mac?.toLowerCase()?.replace(/:/g, "_") || "";
        const guestSwitch = Object.values(this.hass.states).find(
          (sw) => sw.entity_id === `switch.miwifi_${mainMac}_wifi_guest`
        );
        const fallbackEnabled = guestSwitch ? guestSwitch.state === "on" : false;

        this.guestOrig = { enabled: fallbackEnabled, ssid: "", encryption: "psk2", hidden: false, password: "" };
        this.guestForm = { ...this.guestOrig, enable: fallbackEnabled };
        this.guestDirty = false;

        this.guestError = "Este HA no devuelve respuesta de miwifi/get_wifis. Modo básico.";
      } catch (e2) {
        this.guestError = String(err?.message || err) || "Unknown error";
      }
    } finally {
      this.guestLoading = false;
      this.requestUpdate();
    }
  }

  _guestIsDirty() {
    if (!this.guestForm || !this.guestOrig) return false;
    if (!!this.guestForm.enable !== !!this.guestOrig.enabled) return true;
    if ((this.guestForm.ssid || "") !== (this.guestOrig.ssid || "")) return true;
    if ((this.guestForm.encryption || "psk2") !== (this.guestOrig.encryption || "psk2")) return true;
    if (!!this.guestForm.hidden !== !!this.guestOrig.hidden) return true;

    const isAdmin = !!(this.hass?.user?.is_admin);
    if (isAdmin && (this.guestForm.password || "") !== (this.guestOrig.password || "")) return true;

    return false;
  }

  _onGuestChange(key, val) {
    const f = { ...(this.guestForm || {}) };
    f[key] = val;
    this.guestForm = f;
    this.guestDirty = this._guestIsDirty();
    this.requestUpdate();
  }

  async _applyGuest() {
    if (!this._guestIsDirty()) return;
    this.guestApplying = true;
    this.requestUpdate();

    try {
      const f = this.guestForm;
      const o = this.guestOrig;

      const body = {
        enable: !!f.enable,
        ...(f.ssid !== (o.ssid || "") ? { ssid: f.ssid } : {}),
        ...(f.encryption !== (o.encryption || "psk2") ? { encryption: f.encryption } : {}),
        ...(f.hidden !== !!o.hidden ? { hidden: !!f.hidden } : {}),
      };

      const isAdmin = !!(this.hass?.user?.is_admin);
      if (isAdmin) {
        body.password = f.password || "";
      }

      await this.hass.callService("miwifi", "set_guest_wifi", body);

      this.hass.callService("persistent_notification", "create", {
        title: localize("title") || "MiWiFi",
        message: localize("ui_saved") || "Changes sent.",
        notification_id: "miwifi_guest_saved",
      });

      await this._fetchWifis();
    } catch (e) {
      this.hass.callService("persistent_notification", "create", {
        title: localize("title") || "MiWiFi",
        message: (localize("ui_error") || "Error") + ": " + (e?.message || e),
        notification_id: "miwifi_guest_error",
      });
    } finally {
      this.guestApplying = false;
      this.guestDirty = false;
      this.requestUpdate();
    }
  }

  // ------------------ Dump modal ------------------
  _openDumpModal() {
    this.showDumpModal = true;
    this.requestUpdate();
  }

  _closeDumpModal() {
    this.showDumpModal = false;
    this.requestUpdate();
  }

  _toggleDumpOption(key) {
    this.dumpOptions = { ...this.dumpOptions, [key]: !this.dumpOptions[key] };
    this.requestUpdate();
  }

  _renderDumpModal() {
    if (!this.showDumpModal) return "";
    return html`
      <div class="dialog-backdrop" @click=${(e)=>{ if (e.target.classList.contains("dialog-backdrop")) this._closeDumpModal(); }}>
        <div class="dialog">
          <h3>${localize("dump_title") || "Dump router data"}</h3>
          <p>${localize("dump_description") || "Select what to include:"}</p>

          <div class="dump-grid">
            ${Object.entries(this.dumpOptions).map(([k, v]) => html`
              <label class="dump-check">
                <input type="checkbox" .checked=${!!v} @change=${()=>this._toggleDumpOption(k)} />
                <span>${localize("dump_"+k) || k}</span>
              </label>
            `)}
          </div>

          <div class="right" style="margin-top:12px;">
            <button class="miwifi-button" @click=${()=>this._closeDumpModal()}>${localize("ui_cancel") || "Cancelar"}</button>
            <button class="miwifi-button" @click=${()=>this._sendDump()}>${localize("ui_apply") || "Aplicar"}</button>
          </div>
        </div>
      </div>
    `;
  }

  async _sendDump() {
    try {
      this.isDumpLoading = true;
      const opts = { ...this.dumpOptions };
      await this.hass.callService("miwifi", "dump_router_data", opts);
      await this._downloadExport("dump");
      this.isDumpLoading = false;
      this._closeDumpModal();
    } catch (e) {
      this.isDumpLoading = false;
      this._closeDumpModal();
      this.hass.callService("persistent_notification", "create", {
        title: localize("dump_error_title") || "Dump error",
        message: (localize("ui_error") || "Error") + ": " + (e?.message || e),
        notification_id: "miwifi_dump_err",
      });
    }
  }

  async _downloadExport(kind) {
    const { url } = await this.hass.callWS({ type: "miwifi/get_download_url", kind });
    const { path } = await this.hass.callWS({ type: "auth/sign_path", path: url, expires: 120 });
    window.location.assign(path);
  }

  async _downloadLogs() {
    try {
      await this.hass.callService("miwifi", "download_logs");
      await this._downloadExport("logs");
    } catch (error) {
      console.error("MiWiFi log download failed:", error);
      this.hass.callService("persistent_notification", "create", {
        title: localize("title") || "MiWiFi",
        message: `${localize("ui_error") || "Download error"}: ${error?.message || error}`,
        notification_id: "miwifi_download_error",
      });
    }
  }

  // ------------------ Helpers ------------------
  _getMainRouter() {
    if (!this.hass) return null;
    const main = Object.values(this.hass.states).find(
      (s) => s.entity_id.startsWith("sensor.miwifi_topology") &&
             s.attributes?.graph?.is_main === true
    );
    return main || null;
  }

  _getRouterIcon(model) {
    return "/miwifi_static/assets/icon_panel.png";
  }

  _switchForRadioFromList(key, switches) {
    const byName = (sw) => (sw?.attributes?.friendly_name || sw?.entity_id || "").toLowerCase();
    const findGame = () =>
      switches.find((sw) =>
        sw.entity_id.endsWith("_wifi_5g_game") ||
        (/5g/.test(byName(sw)) && /game/.test(byName(sw)))
      );
    const find5G = () =>
      switches.find((sw) =>
        (sw.entity_id.endsWith("_wifi_5g") && !sw.entity_id.endsWith("_wifi_5g_game")) ||
        (/5g/.test(byName(sw)) && !/game/.test(byName(sw)))
      );
    const find24G = () =>
      switches.find((sw) =>
        sw.entity_id.endsWith("_wifi_2g") ||
        sw.entity_id.endsWith("_wifi_2_4g") ||
        (/2\.?4|2g/.test(byName(sw)) && !/guest/.test(byName(sw)) && !/5g/.test(byName(sw)))
      );

    if (key === "game") return findGame() || null;
    if (key === "fiveG") return find5G() || null;
    return find24G() || null; // twoG
  }

  _getSelectEntity(selects, suffixes, fuzzy = []) {
    try {

      const exact = selects.find(e => suffixes.some(suf => e.entity_id.endsWith(suf)));
      if (exact) return exact.entity_id;

    
      const norm = (s) => (s || "").toLowerCase();
      for (const e of selects) {
        const name = norm(e.attributes?.friendly_name);
        if (!name) continue;
        for (const tokens of fuzzy) {
          if (tokens.every(t => name.includes(norm(t)))) {
            return e.entity_id;
          }
        }
      }
    } catch {/* ignore */}
    return null;
  }

  
  _findSelectEntityId(suffixes) {
    try {
      const mac = this.routerSensor?.attributes?.graph?.mac || "";
      const macKey = mac.toLowerCase().replace(/:/g, "_");
      if (!macKey) return null;
      const prefix = `select.miwifi_${macKey}`;
      const all = Object.values(this.hass.states).filter((e) => e.entity_id.startsWith(prefix));
      const found = all.find((e) => suffixes.some((suf) => e.entity_id.endsWith(suf)));
      return found ? found.entity_id : null;
    } catch {
      return null;
    }
  }

  _selectOption(entity_id, option) {
    if (!entity_id) return;
    this.hass.callService("select", "select_option", { entity_id, option }).catch(console.error);
  }

  _renderReadonlyWifiForm(w, key, selects) {
    if (!w) {
      return html`<div class="wifi-row"><i>${localize("ui_loading") || "Loading…"}</i></div>`;
    }
    const hidden = String(w.hidden) === "1" || w.hidden === true;
    const showPwd = !!this.radioShowPwd[key];
    const hasPwd = typeof w.password === "string" && w.password.length > 0;

    // CHANNEL
    const channelEntity = key === "twoG"
      ? this._getSelectEntity(
          selects,
          ["_wifi_2_4g_channel","_wifi_2g_channel"],
          [["2.4","channel"],["2g","channel"]]
        )
      : key === "fiveG"
        ? this._getSelectEntity(
            selects,
            ["_wifi_5g_channel"],
            [["5g","channel"]]
          )
        : this._getSelectEntity(
            selects,
            ["_wifi_5g_game_channel"],
            [["5g","game","channel"]]
          );

    // POWER / SIGNAL STRENGTH
    const powerEntity = key === "twoG"
      ? this._getSelectEntity(
          selects,
          [
            "_wifi_2_4g_signal_strength",
            "_wifi_2g_signal_strength",
            "_wifi_2_4g_power",
            "_wifi_2g_power",
            "_wifi_2_4g_txpower",
            "_wifi_2g_txpower",
            "_wifi_2_4g_tx_power",
            "_wifi_2g_tx_power",
          ],
          [
            ["2.4","signal"],["2g","signal"],
            ["2.4","power"], ["2g","power"],
            ["2.4","tx"],    ["2g","tx"],
          ]
        )
      : key === "fiveG"
        ? this._getSelectEntity(
            selects,
            ["_wifi_5g_signal_strength","_wifi_5g_power","_wifi_5g_txpower","_wifi_5g_tx_power"],
            [["5g","signal"],["5g","power"],["5g","tx"]]
          )
        : this._getSelectEntity(
            selects,
            ["_wifi_5g_game_signal_strength","_wifi_5g_game_power","_wifi_5g_game_txpower","_wifi_5g_game_tx_power"],
            [["5g","game","signal"],["5g","game","power"],["5g","game","tx"]]
          );

    const chState = channelEntity ? this.hass.states[channelEntity] : null;
    const pwState = powerEntity ? this.hass.states[powerEntity] : null;
    const chVal = chState?.state || "";
    const chOpts = chState?.attributes?.options || [];
    const pwVal = pwState?.state || "";
    const pwOpts = pwState?.attributes?.options || [];

    const onChan = (e) => this._selectOption(channelEntity, e.target.value);
    const onPow  = (e) => this._selectOption(powerEntity, e.target.value);

    return html`
      <div class="row">
        <mw-input>
          <label>${localize("wifi_encryption") || "Encryption"}</label>
          <input type="text" .value=${w.encryption || "-"} readonly />
        </mw-input>

        <mw-input>
          <label>${localize("wifi_ssid") || "SSID"}</label>
          <input type="text" .value=${w.ssid || "-"} readonly />
        </mw-input>

        <mw-input>
          <label>${localize("wifi_channel") || "Channel"}</label>
          ${channelEntity ? html`
            <select @change=${onChan}>
              ${chOpts.map((o) => html`<option value=${o} ?selected=${o===chVal}>${o}</option>`)}
            </select>
          ` : html`<input type="text" .value=${w.channel ?? "-"} readonly />`}
        </mw-input>

        <mw-input>
          <label>${localize("wifi_signal_strength") || "Signal strength"}</label>
          ${powerEntity ? html`
            <select @change=${onPow}>
              ${pwOpts.map((o) => html`<option value=${o} ?selected=${o===pwVal}>${o}</option>`)}
            </select>
          ` : html`<input type="text" .value=${w.txpower ?? "-"} readonly />`}
        </mw-input>

        <div class="switchline">
          <label>${localize("wifi_hidden") || "Hidden"}</label>
          <ha-switch .checked=${hidden} disabled></ha-switch>
        </div>

        <mw-input style="grid-column: 1 / -1;">
          <label>${localize("wifi_password") || "Password"}</label>
          <div style="display:flex; gap:8px; align-items:center;">
            <input
              .type=${showPwd ? "text" : "password"}
              .value=${hasPwd ? w.password : ""}
              readonly
              style="flex:1;"
            />
            <button class="miwifi-button" @click=${()=>{
              this.radioShowPwd = { ...this.radioShowPwd, [key]: !showPwd };
              this.requestUpdate();
            }}>
              ${showPwd ? "🙈" : "👁"}
            </button>
          </div>
          ${!hasPwd ? html`<div class="hint">${localize("ui_no_data") || "No data / hidden by permissions."}</div>` : ""}
        </mw-input>
      </div>
    `;
  }

  _renderRadioBlock(key, swEntity, w, selects) {
    const cfg = {
      twoG:  { title: localize("wifi_title_24g") || "2.4G Wi-Fi" },
      fiveG: { title: localize("wifi_title_5g")  || "5G Wi-Fi" },
      game:  { title: localize("wifi_title_game")|| "5G Gaming" },
    }[key];

    const checked = swEntity ? swEntity.state === "on" : !!w?.enabled;

    const handleToggle = (e) => {
      if (!swEntity) return;
      const entity_id = swEntity.entity_id;
      if (e.target.checked) {
        this.hass.callService("switch", "turn_on", { entity_id }).catch(console.error);
      } else {
        this.hass.callService("switch", "turn_off", { entity_id }).catch(console.error);
      }
    };

    return html`
      <div class="wifi-block">
        <div class="header" style="display:flex; align-items:center; justify-content:space-between;">
          <div class="wifi-title">${cfg.title}</div>
          <div class="switchline" title="${swEntity ? "" : (localize("ui_unavailable") || "Entity not found")}">
            <label>${localize("wifi_enable") || "Enable"}</label>
            <ha-switch
              .checked=${checked}
              ?disabled=${!swEntity}
              @change=${handleToggle}
            ></ha-switch>
          </div>
        </div>
        <div class="body">
          ${this._renderReadonlyWifiForm(w, key, selects)}
        </div>
      </div>
    `;
  }

  // ------------------ Render ------------------
  render() {
    if (!this.routerSensor) {
      return html`
        <div class="content" style="text-align:center; margin-top:20px;">
          <p style="font-size: 16px;">❗ ${localize("topology_main_not_found")}</p>
          <p>${localize("nav_topology")}.</p>
        </div>
      `;
    }

    const version = MIWIFI_VERSION;
    const mainGraph = this.routerSensor.attributes.graph;
    const routerIcon = getRouterImage(mainGraph.hardware);

    const mac = (mainGraph?.mac || "").toLowerCase().replace(/:/g, "_");
    const config = this.hass?.states?.["sensor.miwifi_config"]?.attributes || {};

    const switches = Object.values(this.hass.states).filter((e) =>
      e.entity_id.startsWith("switch.miwifi_" + mac)
    );
    const selects = Object.values(this.hass.states).filter((e) =>
      e.entity_id.startsWith("select.miwifi_" + mac)
    );

    const led = this.hass.states[`light.miwifi_${mac}_led`];
    const reboot = this.hass.states[`button.miwifi_${mac}_reboot`];

    const handleReboot = (ev) => {
      const root = ev?.currentTarget?.getRootNode?.() || document;
      const selectedLog = root.querySelector("#log_level")?.value || (config.log_level || "info");

      this.hass.callService("button", "press", { entity_id: reboot.entity_id }).catch((err) =>
        console.error("callService error:", err)
      );
      logToBackend(this.hass, selectedLog, `🔄 [settings.js] Reboot requested for router: ${mainGraph.name} (${mainGraph.mac})`);
      this.hass.callService("persistent_notification", "create", {
        title: localize("settings_restart_router"),
        message: localize("settings_restart_router_done"),
        notification_id: "miwifi_reboot_done",
      }).catch((err) => console.error("callService error:", err));
    };

    const clearMain = () => {
      if (confirm(localize("settings_confirm_clear_main"))) {
        this.hass.callService("miwifi", "select_main_router", { mac: "" })
          .then(() => location.reload())
          .catch(console.error);
      }
    };

    const handleDumpService = () => {
      const selected = Object.entries(this.dumpOptions).filter(([k, v]) => v && k !== "hide_sensitive");
      if (selected.length === 0) {
        alert(localize("dump_select_one") || "Select at least one section to include.");
        return;
      }
      this._openDumpModal();
    };

    const currentPanel = config.panel_active ?? true;
    const currentUnit = config.speed_unit || "Mbps";
    const currentLog = config.log_level || "info";

    const guestSwitch = switches.find((sw) => sw.entity_id.endsWith("_wifi_guest"));
    const guestEnabled = guestSwitch ? guestSwitch.state === "on" : this.guestForm?.enable;

    const sw24 = this._switchForRadioFromList("twoG", switches);
    const sw5  = this._switchForRadioFromList("fiveG", switches);
    const swG  = this._switchForRadioFromList("game", switches);

    if (!this._wifisLoaded && !this.guestLoading) {
      this._fetchWifis();
    }

    return html`
      <div class="content">
        <div class="config-header">
          <img src="/miwifi_static/assets/logo.png" class="logo" alt="Logo" />
          <div main-title>XiaoHack Edition</div>
          <div><span class="version-badge">v${version}</span></div>
          <h2>${localize("settings_router_config")}</h2>
          <div class="topo-box">
            <img src="${routerIcon}" class="topo-icon-lg" />
            <div class="topo-name">${mainGraph.name} (${localize("gateway")})</div>
            <div class="topo-ip">${mainGraph.ip}</div>
            ${!mainGraph.is_main_auto ? html`
              <button class="reboot-btn" style="margin-top:8px" @click=${clearMain}>
                🔄 ${localize("settings_clear_main_router")}
              </button>
            ` : ""}
          </div>
        </div>

        <div class="section">
          <h3>${localize("settings_wifi_config") || "Configuración Wi-Fi"}</h3>
          ${this._renderRadioBlock("twoG", sw24, this.radios.twoG, selects)}
          ${this._renderRadioBlock("fiveG", sw5, this.radios.fiveG, selects)}
          ${(swG || this.radios.game) ? this._renderRadioBlock("game", swG, this.radios.game, selects) : ""}
        </div>

        <div class="section">
          <h3>${localize("settings_guest_config_title") || "Configuración Wi-Fi de invitados"}</h3>

          ${guestSwitch ? "" : html`
            <div class="note">
              ${localize("settings_guest_switch_missing") || "Guest switch entity not found. You can still edit via form below."}
            </div>
          `}

          ${this.guestLoading ? html`<div>${localize("ui_loading") || "Loading…"} </div>` : ""}
          ${this.guestError ? html`<div style="color:var(--error-color)">${localize("ui_error") || "Error"}: ${this.guestError}</div>` : ""}

          ${this.guestForm ? html`
            <div class="switchline" style="margin-bottom:12px;">
              <label>${localize("guest_enable") || "Activar"}</label>
              <ha-switch .checked=${guestEnabled}
                @change=${(e)=>{ 
                  const on = e.target.checked; 
                  if (guestSwitch) {
                    this.hass.callService("switch", on ? "turn_on" : "turn_off", { entity_id: guestSwitch.entity_id });
                  }
                  this._onGuestChange("enable", on);
                }}></ha-switch>
            </div>

            ${guestEnabled ? html`
              <div class="row">
                <mw-input>
                  <label>${localize("guest_encryption") || "Cifrado"}</label>
                  <select @change=${(e)=>this._onGuestChange("encryption", e.target.value)}>
                    <option value="psk2" ?selected=${this.guestForm.encryption==="psk2"}>psk2 (WPA2-PSK)</option>
                    <option value="none" ?selected=${this.guestForm.encryption==="none"}>none (open)</option>
                  </select>
                </mw-input>

                <mw-input>
                  <label>${localize("guest_ssid") || "SSID"}</label>
                  <input type="text" .value=${this.guestForm.ssid}
                    @input=${(e)=>this._onGuestChange("ssid", e.target.value)} />
                </mw-input>

                <mw-input>
                  <label>
                    ${localize("guest_password") } 
                    <span class="hint">(${localize("guest_password_hint")})</span>
                  </label>
                  <input
                    .type=${this.guestShowPwd ? "text" : "password"}
                    .value=${this.guestForm.password}
                    @input=${(e)=>this._onGuestChange("password", e.target.value)} />
                  <button class="miwifi-button" style="margin-top:6px"
                    @click=${()=>{ this.guestShowPwd = !this.guestShowPwd; this.requestUpdate(); }}>
                    ${this.guestShowPwd ? "🙈 Ocultar" : "👁 Mostrar"}
                  </button>
                </mw-input>

                <div class="switchline">
                  <label>${localize("guest_hidden") || "Ocultar SSID"}</label>
                  <ha-switch .checked=${!!this.guestForm.hidden}
                    @change=${(e)=>this._onGuestChange("hidden", e.target.checked)}></ha-switch>
                </div>
              </div>
            ` : ""}

            <div class="right" style="margin-top:8px;">
              <button class="miwifi-button" @click=${()=>this._fetchWifis()}>
                ${localize("ui_reload") || "Recargar"}
              </button>
              <button class="miwifi-button ${this.guestDirty && !this.guestApplying ? "" : "hidden"}"
                      @click=${()=>this._applyGuest()}>
                ${localize("ui_apply") || "Aplicar cambios"}
              </button>
            </div>
          ` : ""}
        </div>

        <div class="section">
          <h3>${localize("settings_extra")}</h3>
          ${led ? html`<div>${localize("label_led")} ${renderToggle(this.hass, led)}</div>` : ""}
          ${reboot ? html`<button class="reboot-btn" @click=${handleReboot}>${localize("settings_restart_router")}</button>` : ""}
          <button class="reboot-btn" @click=${() => this._downloadLogs()}>
            📥 ${localize("settings_download_logs")}
          </button>
          <button class="reboot-btn" @click=${() => {
            if (confirm(localize("settings_confirm_clear_logs"))) {
              this.hass.callService("miwifi", "clear_logs")
                .then(() => {
                  this.hass.callService("persistent_notification", "create", {
                    title: localize("settings_clear_logs_done_title"),
                    message: localize("settings_clear_logs_done_msg"),
                    notification_id: "miwifi_clear_logs_done",
                  });
                });
            }
          }}>
            🧹 ${localize("settings_clear_logs")}
          </button>

          <button class="reboot-btn" @click=${handleDumpService}>
            🧰 ${localize("dump_button") || "Dump router data"}
          </button>
          ${this._renderDumpModal()}
        </div>

        <div class="section">
          <h3>${localize("settings_integration_options")}</h3>

          <div class="config-grid">
            <div>
              <b>${localize("setting_panel_active")}</b><br/>
              <span class="note">${localize("setting_panel_active_hint")}</span>
            </div>
            <div class="switchline">
              <label class="switch">
                <input type="checkbox" id="panel_active" .checked=${currentPanel} />
                <span class="slider"></span>
              </label>
            </div>

            <div class="select-block">
              <label>${localize("setting_speed_unit")}</label>
              <select id="speed_unit">
                ${["Mbps", "B/s"].map(unit => html`
                  <option value="${unit}" ?selected=${unit === currentUnit}>${unit}</option>
                `)}
              </select>
            </div>

            <div class="select-block">
              <label>${localize("setting_log_level")}</label>
              <select id="log_level">
                ${["debug", "info", "warning"].map(level => html`
                  <option value="${level}" ?selected=${level === currentLog}>${level}</option>
                `)}
              </select>
            </div>
          </div>

          <div class="right" style="margin-top:12px;">
            <button class="miwifi-button" @click=${(ev) => {
              const confirmMsg = localize("settings_confirm_restart") 
                || "Are you sure you want to apply the changes? This will temporarily restart the MiWiFi integration.";
              if (!confirm(confirmMsg)) return;

              const root = ev?.currentTarget?.getRootNode?.() || document;
              const selectedLog = root.querySelector("#log_level")?.value || "info";

              const event = new CustomEvent("miwifi-apply-settings", { bubbles: true, composed: true });
              window.dispatchEvent(event);

              logToBackend(this.hass, selectedLog, "⚙️ [settings.js] User clicked 'Apply changes' in panel.");
            }}>
              ${localize("ui_save")}
            </button>
          </div>
        </div>

        <div class="section">
          <h2>${localize("settings_integration_title")}</h2>
          <div>
            <b>${localize("settings_issue_title") || "¿Tienes sugerencias?"}</b><br/>
            <span class="note">${localize("settings_issue_desc") || "Cuéntanos qué mejorar o corregir."}</span>
          </div>
          <div style="margin-top: 16px;">
            <a
              class="miwifi-issue-link"
              href="https://github.com/${REPOSITORY}/issues/new?title=[MiWiFi%20Panel%20Feedback]"
              target="_blank"
              rel="noopener"
            >
              💬 ${localize("settings_feedback_button")}
            </a>
          </div>
        </div>
      </div>
    `;
  }
}

customElements.define("miwifi-settings", MiWiFiSettingsPanel);
