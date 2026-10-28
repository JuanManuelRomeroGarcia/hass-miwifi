import "../components/miwifi-status-data.js?v=3.13.3";
import { html } from "../vendor/lit.js?v=3.13.3";
import { getMainRouterMac, formatSignal, logToBackend } from "./utils.js?v=3.13.3";
import { localize } from "../translations/localize.js?v=3.13.3";
import { showDialog } from "../dialogs.js?v=3.13.3";

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

  // Separate WAN2 status from the existing WAN traffic sensors: configured
  // bandwidth/weights are not measured transfer rates.
  const wan2 = hass.states[`sensor.miwifi_${mac}_wan2_ip_address`];
  if (wan2?.attributes?.enabled === true) {
    const available = wan2.state !== "unavailable";
    const unknown = localize("status_unavailable");
    const state = (value) => available && typeof value === "boolean"
      ? localize(value ? "status_connected" : "status_disconnected") : unknown;
    internetItems.splice(4, 0,
      { label: localize("label_wan2_ip"), value: available && wan2.state !== "unknown" ? wan2.state : unknown },
      { label: localize("label_wan2_type"), value: available ? (wan2.attributes.type || unknown) : unknown },
      { label: localize("label_wan2_link"), value: state(wan2.attributes.link) },
      { label: localize("label_wan2_state"), value: state(wan2.attributes.connected) },
    );
  }

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

  const countItems = counts => [
    { label: localize("label_devices_total"), value: counts.total },
    { label: localize("label_devices_lan"), value: counts.lan },
    { label: localize("label_devices_2g"), value: counts.g24 },
    { label: localize("label_devices_5g"), value: counts.g5 },
    { label: localize("label_devices_5g_game"), value: counts.gaming },
    { label: localize("label_devices_iot"), value: counts.iot },
    { label: localize("label_devices_guest"), value: counts.guest },
  ];
  const sections = [
    { title: localize("section_system"), items: systemItems },
    { title: localize("section_internet"), items: internetItems },
    { title: localize("section_devices"), items: countItems(readDeviceCounts(mac)) },
    { title: localize("section_mesh_devices"), items: [], message: meshNodes.length ? "" : localize("mesh_no_nodes") },
    ...meshNodes.map(node => ({
      title: `🧩 ${node.name || node.locale || node.mac}`,
      items: countItems(readDeviceCounts(node._macNorm)),
    })),
  ];
  return html`<miwifi-status-data .sections=${sections}></miwifi-status-data>`;
}