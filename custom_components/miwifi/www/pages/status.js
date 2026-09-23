import { html } from "../vendor/lit.js?v=3.8.1";
import { getMainRouterMac, formatSignal, logToBackend } from "./utils.js?v=3.8.1";
import { localize } from "../translations/localize.js?v=3.8.1";
import { showDialog } from "../dialogs.js?v=3.8.1";

async function findMainTopoSensor(hass, retries = 6, delay = 500) {
  if (!hass || !hass.states) return null;

  for (let i = 0; i < retries; i++) {
    const sensor = Object.values(hass.states).find(
      (s) =>
        s.entity_id?.startsWith("sensor.miwifi_topology") &&
        s.attributes?.graph?.is_main === true
    );
    if (sensor) return sensor;
    await new Promise((res) => setTimeout(res, delay));
  }
  return null;
}

function normalizeMacForEntity(mac) {
  if (!mac) return "";
  const m = mac.toString().trim().toLowerCase();
  return m.includes(":") ? m.replace(/:/g, "_") : m;
}

function safeNum(v) {
  const n = Number(v);
  return Number.isFinite(n) ? n : 0;
}

const SENSOR_SUFFIXES = {
  temperature: "temperature",
  memory_usage: "memory_usage",
  memory_total: "memory_total",
  uptime: "uptime",
  vpn_uptime: "vpn_uptime",
  wan_download: "wan_download_speed",
  wan_upload: "wan_upload_speed",
  wan_ip: "wan_ip_address",
  wan_type: "wan_type",
  mode: "mode",
  devices: "devices",
  devices_lan: "devices_lan",
  devices_2g: "devices_2_4g",
  devices_5g: "devices_5g",
  devices_guest: "devices_guest",
  devices_5g_game: "devices_5g_game",
  devices_iot: "devices_iot",
};

export function showRouterSelectionDialog(hass) {
  if (!hass || !hass.states) return;

  const candidates = Object.values(hass.states).filter(
    (s) => s.entity_id?.startsWith("sensor.miwifi_topology") && s.attributes?.graph?.mac
  );

  if (!candidates.length) {
    logToBackend(hass, "warning", "❌ No router candidates found for manual selection.");
    return;
  }

  const options = candidates.map((s) => {
    const mac = s.attributes.graph.mac;
    const name = s.attributes.graph.name || mac;
    return { name, mac };
  });

  showDialog(hass, {
    title: localize("select_main_router"),
    options,
    onSelect: async (mac) => {
      await hass.callService("miwifi", "select_main_router", { mac });
      location.reload();
    },
  });
}

export async function renderStatus(hass) {
  // Guard: HA aún no listo
  if (!hass || !hass.states) {
    return html`
      <div style="text-align:center; padding:24px; color:white">
        ${localize("loading") || "Cargando sección..."}
      </div>
    `;
  }

  const topoSensor = await findMainTopoSensor(hass);
  if (!topoSensor) {
    logToBackend(hass, "warning", "❌ No main router MAC found – fallback not resolved (status.js)");
    return html`
      <div style="text-align:center; padding:24px; color:white">
        ❌ ${localize("topology_main_not_found")}<br />
        <button
          class="miwifi-button"
          style="margin-top:16px"
          @click=${() => showRouterSelectionDialog(hass)}
        >
          ${localize("select_main_router")}
        </button>
      </div>
    `;
  }

  const graph = topoSensor?.attributes?.graph ?? {};
  const macFromUtils = getMainRouterMac?.(hass);
  const macFromTopo = normalizeMacForEntity(graph.mac);
  const mac = macFromUtils || macFromTopo;

  if (graph?.mac) {
    logToBackend(hass, "debug", `✅ Main router detected: ${graph.name} (${graph.mac})`);
  }

  const getSensorValueForMac = (macNorm, suffix) => {
    const sensorId = `sensor.miwifi_${macNorm}_${suffix}`;
    return hass.states[sensorId]?.state ?? "unavailable";
  };

  const getSelectValue = (suffix) => {
    const entityId = `select.miwifi_${mac}_${suffix}`;
    return hass.states[entityId]?.state ?? "unavailable";
  };

  const systemItems = [
    { label: localize("label_model"), value: graph.hardware || "unknown" },
    { label: localize("label_name"), value: graph.name || "unknown" },
    { label: localize("label_local_ip"), value: graph.ip || "unknown" },
    { label: localize("label_memory_usage"), value: getSensorValueForMac(mac, SENSOR_SUFFIXES.memory_usage) + "%" },
    { label: localize("label_memory_total"), value: getSensorValueForMac(mac, SENSOR_SUFFIXES.memory_total) + " MB" },
    { label: localize("label_uptime"), value: getSensorValueForMac(mac, SENSOR_SUFFIXES.uptime) },
    { label: localize("label_vpn_uptime"), value: getSensorValueForMac(mac, SENSOR_SUFFIXES.vpn_uptime) },
    { label: localize("label_net_mode"), value: getSensorValueForMac(mac, SENSOR_SUFFIXES.mode) },
  ];

  const internetItems = [
    { label: localize("label_wan_ip"), value: getSensorValueForMac(mac, SENSOR_SUFFIXES.wan_ip) },
    { label: localize("label_wan_type"), value: getSensorValueForMac(mac, SENSOR_SUFFIXES.wan_type) },
    { label: localize("label_wan_download"), value: getSensorValueForMac(mac, SENSOR_SUFFIXES.wan_download) },
    { label: localize("label_wan_upload"), value: getSensorValueForMac(mac, SENSOR_SUFFIXES.wan_upload) },
    { label: localize("label_signal_2g"), value: formatSignal(getSelectValue("wifi_2_4g_signal_strength")) },
    { label: localize("label_signal_5g"), value: formatSignal(getSelectValue("wifi_5g_signal_strength")) },
    { label: localize("label_signal_5g_game"), value: formatSignal(getSelectValue("wifi_5g_game_signal_strength")) },
  ];

  const renderSection = (title, items) => html`
    <div class="section-title">${title}</div>
    <div class="status-grid">
      ${items.map((item) => {
        const isUnavailable = String(item.value).includes("unavailable");
        const value = isUnavailable ? localize("status_unavailable") : item.value;
        return html`
          <div class="status-card">
            <div class="status-label">${item.label}</div>
            <div class="status-value ${isUnavailable ? "unavailable" : ""}">
              ${value}
            </div>
          </div>
        `;
      })}
    </div>
  `;

  // ─────────────────────────────────────────────────────────────
  // DEVICES: main + mesh nodes (por sensores del router, no device_tracker)
  // ─────────────────────────────────────────────────────────────
  const cleanIp = (ip) => (ip || "").toString().trim();
  const cleanName = (g) => ((g?.name || g?.locale || "") + "").trim().toLowerCase();

  const allTopoSensors = Object.values(hass.states).filter(
    (s) => s.entity_id?.startsWith("sensor.miwifi_topology") && s.attributes?.graph?.mac
  );

  // ✅ Deduplicación por IP (y fallback por nombre si no hay IP)
  const seen = new Set();
  const meshNodes = [];

  for (const s of allTopoSensors) {
    const g = s.attributes?.graph;
    if (!g || !g.mac) continue;
    if (g.is_main === true) continue;

    const ip = cleanIp(g.ip);
    const nk = cleanName(g);

    const key = ip ? `ip:${ip}` : (nk ? `name:${nk}` : `mac:${normalizeMacForEntity(g.mac)}`);
    if (seen.has(key)) continue;
    seen.add(key);

    meshNodes.push({
      ...g,
      _ip: ip,
      _macNorm: normalizeMacForEntity(g.mac), // solo para leer sensores
    });
  }

  const readDeviceCounts = (macNorm) => {
    const total = getSensorValueForMac(macNorm, SENSOR_SUFFIXES.devices);
    const lan = getSensorValueForMac(macNorm, SENSOR_SUFFIXES.devices_lan);
    const g24 = getSensorValueForMac(macNorm, SENSOR_SUFFIXES.devices_2g);
    const g5 = getSensorValueForMac(macNorm, SENSOR_SUFFIXES.devices_5g);
    const guest = getSensorValueForMac(macNorm, SENSOR_SUFFIXES.devices_guest);
    const gaming = getSensorValueForMac(macNorm, SENSOR_SUFFIXES.devices_5g_game);
    const iot = getSensorValueForMac(macNorm, SENSOR_SUFFIXES.devices_iot);

    return {
      total,
      lan,
      g24,
      g5,
      guest,
      gaming,
      iot,
    };
  };

  const renderDevicesCards = (counts) => {
    const items = [
      { label: localize("label_devices_total") || "Dispositivos totales", value: counts.total },
      { label: localize("label_devices_lan") || "Dispositivos LAN", value: counts.lan },
      { label: localize("label_devices_2g") || "Dispositivos 2.4G", value: counts.g24 },
      { label: localize("label_devices_5g") || "Dispositivos 5G", value: counts.g5 },
      { label: localize("label_devices_5g_game") || "Dispositivos gaming", value: counts.gaming },
      { label: localize("label_devices_iot") || "Dispositivos IoT", value: counts.iot },
      { label: localize("label_devices_guest") || "Dispositivos invitados", value: counts.guest },
    ];

    return html`
      <div class="status-grid">
        ${items.map((item) => {
          const isUnavailable = String(item.value).includes("unavailable");
          const value = isUnavailable ? localize("status_unavailable") : item.value;
          return html`
            <div class="status-card">
              <div class="status-label">${item.label}</div>
              <div class="status-value ${isUnavailable ? "unavailable" : ""}">
                ${value}
              </div>
            </div>
          `;
        })}
      </div>
    `;
  };

  const mainCounts = readDeviceCounts(mac);

  // Para “Mesh total” usamos suma numérica SOLO si los valores son numéricos.
  const meshTotals = meshNodes.reduce(
    (acc, n) => {
      const nMac = n._macNorm;
      const counts = readDeviceCounts(nMac);

      acc.total += safeNum(counts.total);
      acc.lan += safeNum(counts.lan);
      acc.g24 += safeNum(counts.g24);
      acc.g5 += safeNum(counts.g5);
      acc.guest += safeNum(counts.guest);
      acc.gaming += safeNum(counts.gaming);
      acc.iot += safeNum(counts.iot);
      return acc;
    },
    { total: 0, lan: 0, g24: 0, g5: 0, guest: 0, gaming: 0, iot: 0 }
  );


  const renderDevicesSection = () => html`
    <div class="section-title"> ${localize("section_devices")}</div>

    ${renderDevicesCards(mainCounts)}

    <div style="margin-top:22px;">
      <div class="section-title" style="font-size:1.1rem;">
        🧩 ${localize("section_mesh_devices") || "Dispositivos en Mesh"}
        ${meshNodes.length ? html`<span style="opacity:.9;"> (${meshNodes.length})</span>` : html``}
      </div>

      ${meshNodes.length
        ? html`

            ${meshNodes.map((n) => {
              const nMac = n._macNorm;
              const title = `🧩 ${n.name || n.locale || n.mac}`;
              const c = readDeviceCounts(nMac);

              return html`
                <div style="margin-top:18px;">
                  <div class="section-title" style="font-size:1.05rem;">${title}</div>
                  ${renderDevicesCards(c)}
                </div>
              `;
            })}
          `
        : html`
            <div style="text-align:center; padding:12px; color:white; opacity:.9;">
              ${localize("mesh_no_nodes") || "No se detectaron nodos Mesh integrados."}
            </div>
          `}
    </div>
  `;

  return html`
    ${renderSection(localize("section_system"), systemItems)}
    ${renderSection(localize("section_internet"), internetItems)}
    ${renderDevicesSection()}
  `;
}
