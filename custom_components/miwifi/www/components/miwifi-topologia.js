import { getRouterImage } from "../pages/utils.js?v=3.8.1";
import { LitElement, html, css } from "../vendor/lit.js?v=3.8.1";
import { localize } from "../translations/localize.js?v=3.8.1";
import { navigate } from "../router.js?v=3.8.1";

const REPOSITORY = "JuanManuelRomeroGarcia/hass-miwifi";

export class MiwifiTopologia extends LitElement {
  static properties = {
    data: { type: Object },
    devices: { type: Array },
    nodes: { type: Array },
    hass: { type: Object },
  };

  _cleanIp(ip) {
    return (ip ?? "").toString().trim().replace(/\s+/g, "");
  }

  _normalizeMac(mac) {
    if (!mac) return "";
    return String(mac).trim().toLowerCase();
  }

  _normalizeMacForEntity(mac) {
    const m = this._normalizeMac(mac);
    return m ? m.replace(/:/g, "_") : "";
  }

  _getSensorState(entityId) {
    return this.hass?.states?.[entityId]?.state ?? "unavailable";
  }

  _safeNum(v) {
    const n = Number(v);
    return Number.isFinite(n) ? n : 0;
  }

  _getDevicesCountForRouterMac(macNorm) {
    if (!macNorm) return 0;
    const eid = `sensor.miwifi_${macNorm}_devices`;
    return this._safeNum(this._getSensorState(eid));
  }

  /**
   * Construye:
   * - mainMacNorm (del topology MAIN)
   * - mainGraph
   * - meshByIp: ip -> { macNorm, graph }
   */
  _getTopologyMaps() {
    const states = Object.values(this.hass?.states || {});
    const topoSensors = states.filter((s) =>
      String(s?.entity_id || "").startsWith("sensor.miwifi_topology")
    );

    let mainGraph = null;

    // 1) mainGraph
    for (const s of topoSensors) {
      const g = s?.attributes?.graph;
      if (g?.is_main === true) {
        mainGraph = g;
        break;
      }
    }

    // 2) mesh map by IP (topology sensors que NO son main)
    const meshByIp = new Map();

    for (const s of topoSensors) {
      const g = s?.attributes?.graph;
      if (!g) continue;
      if (g.is_main === true) continue;

      const ip = this._cleanIp(g.ip);
      const macNorm = this._normalizeMacForEntity(g.mac);

      // clave principal: IP (que sí la tenemos en leafs)
      if (ip && !meshByIp.has(ip)) {
        meshByIp.set(ip, { macNorm, graph: g });
      }
    }

    const mainMacNorm = this._normalizeMacForEntity(mainGraph?.mac);
    return { mainGraph, mainMacNorm, meshByIp };
  }

  render() {
    if (!this.data) {
      return html`<div class="message">❗ ${localize("topology_main_not_found")}</div>`;
    }

    const routerIcon = getRouterImage(this.data.hardware);

    const internetIcon = `/miwifi_static/assets/icon_internet.png`;

    const { mainMacNorm, meshByIp } = this._getTopologyMaps();

    // ✅ MAIN badge = sensor.miwifi_<mainMac>_devices
    const mainCount = this._getDevicesCountForRouterMac(mainMacNorm);

    return html`
      <h2>${localize("topology_router_network")}</h2>
      <div class="tree">
        <ul>
          <li>
            <div class="topo-box">
              <img src="${internetIcon}" class="topo-icon" />
              <div class="topo-name">${localize("network")}</div>
            </div>

            <div class="line-pulse-vertical"></div>

            <ul>
              <li>
                <div class="topo-box" style="cursor: pointer;" @click=${() => navigate("/settings")}>
                  <div class="topo-icon-container">
                    <img src="${routerIcon}" class="topo-icon-lg" />
                    <div class="device-count-badge">${mainCount}</div>
                  </div>
                  <div class="topo-name">${this.data.name} ${localize("gateway")}</div>
                  <div class="topo-ip">${this._cleanIp(this.data.ip)}</div>
                </div>

                <div class="line-pulse-vertical"></div>

                ${this.data.leafs?.length
                  ? html`<ul>
                      ${this.data.leafs.map((child) => this._renderLeaf(child, meshByIp))}
                    </ul>`
                  : ""}
              </li>
            </ul>
          </li>
        </ul>
      </div>
    `;
  }

  _renderLeaf(node, meshByIp) {
    const icon = getRouterImage(node.hardware);

    const nodeIp = this._cleanIp(node.ip);

    // ✅ Leaf badge = buscar su topology (no-main) por IP -> sacar macNorm -> sensor.miwifi_<mac>_devices
    const meshInfo = nodeIp ? meshByIp.get(nodeIp) : null;
    const leafCount = meshInfo?.macNorm ? this._getDevicesCountForRouterMac(meshInfo.macNorm) : 0;

    return html`
      <li>
        <div class="topo-box" style="cursor: pointer;" @click=${() => navigate("/mesh")}>
          <div class="topo-icon-container">
            <img src="${icon}" class="topo-icon" />
            <div class="device-count-badge">${leafCount}</div>
          </div>
          <div class="topo-name">${node.name}</div>
          <div class="topo-ip">${nodeIp}</div>
        </div>
      </li>
    `;
  }

  static styles = css`
    :host {
      display: block;
      padding: 2rem;
      color: white;
      background-color: #1a73e8;
      font-family: 'Segoe UI', sans-serif;
      text-align: center;
    }
    h2 {
      margin-bottom: 2rem;
    }
    .topo-box {
      display: inline-block;
      margin: 1rem;
      text-align: center;
      transition: transform 0.3s ease;
    }
    .topo-box:hover {
      transform: scale(1.05);
    }
    .topo-icon {
      width: 50px;
      height: 50px;
    }
    .topo-icon-lg {
      width: 90px;
      height: 90px;
    }
    .topo-name {
      font-weight: bold;
      margin-top: 0.5rem;
    }
    .topo-ip {
      font-size: 0.9rem;
      color: #e0e0e0;
      white-space: nowrap;
    }
    .message {
      color: #eee;
      font-size: 1.2rem;
    }
    .tree, .tree ul {
      padding-top: 20px;
      position: relative;
    }
    .tree ul {
      display: flex;
      justify-content: center;
      padding-left: 0;
      flex-wrap: wrap;
    }
    .tree li {
      list-style-type: none;
      text-align: center;
      position: relative;
      padding: 15px 0px 0 0px;
    }
    .tree li::before,
    .tree li::after {
      content: '';
      position: absolute;
      top: 0;
      width: 50%;
      height: 20px;
      border-top: 2px solid #0f3;
    }
    .tree li::before {
      left: 0;
      border-right: 2px solid #0f3;
    }
    .tree li::after {
      right: 0;
      border-left: 2px solid #0f3;
    }
    .tree li:only-child::before,
    .tree li:only-child::after {
      display: none;
    }
    .tree li:only-child {
      padding-top: 0;
    }
    .tree li:first-child::before,
    .tree li:last-child::after {
      border: 0 none;
    }
    .tree li:last-child::before {
      border-right: 2px solid #0f3;
      border-radius: 0 5px 0 0;
    }
    .tree li:first-child::after {
      border-left: 2px solid #0f3;
      border-radius: 5px 0 0 0;
    }
    .line-pulse-vertical {
      width: 2px;
      height: 20px;
      background-color: #0f3;
      margin: 0 auto;
      animation: pulse 2s infinite;
    }
    .topo-icon-container {
      position: relative;
      display: inline-block;
    }
    .device-count-badge {
      position: absolute;
      top: -6px;
      right: -6px;
      background: red;
      color: white;
      font-size: 12px;
      font-weight: bold;
      border-radius: 50%;
      padding: 4px 7px;
      box-shadow: 0 0 4px rgba(0,0,0,0.3);
      min-width: 24px;
      text-align: center;
    }
    @keyframes pulse {
      0%, 100% { background-color: #0f3; }
      50% { background-color: #0b0; }
    }
    @media (max-width: 600px) {
      .tree ul {
        flex-wrap: nowrap;
        overflow-x: auto;
        padding-left: 0;
        margin: 0;
        gap: 0;
      }
      .topo-box {
        margin: 0.5rem;
        transform: scale(0.85);
      }
    }
  `;
}

customElements.define("miwifi-topologia", MiwifiTopologia);
