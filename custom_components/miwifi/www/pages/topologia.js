import { html } from "../vendor/lit.js?v=3.7.0";
import "../components/miwifi-topologia.js?v=3.7.0";
import { logToBackend } from "./utils.js?v=3.7.0";

function cleanStr(v) {
  return (v ?? "").toString().trim();
}

function cleanIp(v) {
  return cleanStr(v).replace(/\s+/g, "");
}

function cleanName(g) {
  return cleanStr(g?.name || g?.locale || "").toLowerCase();
}

function wrapGraph(graph, entityId = "") {
  // Mantiene compatibilidad: el componente puede esperar "sensor-like"
  return { entity_id: entityId, attributes: { graph } };
}

async function findMainGraph(hass, retries = 6, delay = 400) {
  if (!hass || !hass.states) return null;

  for (let i = 0; i < retries; i++) {
    const sensor = Object.values(hass.states).find(
      (s) =>
        s?.entity_id?.startsWith("sensor.miwifi_topology") &&
        s.attributes?.graph?.is_main === true
    );
    if (sensor?.attributes?.graph) return sensor.attributes.graph;
    await new Promise((res) => setTimeout(res, delay));
  }
  return null;
}

function fallbackMainGraph(hass) {
  const topoSensors = Object.values(hass.states || {}).filter(
    (s) => s?.entity_id?.startsWith("sensor.miwifi_topology") && s.attributes?.graph
  );

  if (!topoSensors.length) return null;

  // 1) Preferimos el que sea "router principal" típico: mode == 0
  const mode0 = topoSensors.find((s) => Number(s.attributes.graph?.mode) === 0);
  if (mode0?.attributes?.graph) return mode0.attributes.graph;

  // 2) Si alguno trae leafs, suele ser el principal (mesh master)
  const withLeafs = topoSensors.find((s) => Array.isArray(s.attributes.graph?.leafs) && s.attributes.graph.leafs.length);
  if (withLeafs?.attributes?.graph) return withLeafs.attributes.graph;

  // 3) Último recurso: el primero que haya
  return topoSensors[0].attributes.graph;
}

function buildMeshNodes(hass, mainGraph) {
  const nodes = [];
  const seen = new Set();

  const mainIp = cleanIp(mainGraph?.ip);
  const mainName = cleanName(mainGraph);

  // A) Primero: los leafs del mainGraph (esto es lo “oficial” del mesh)
  const leafs = Array.isArray(mainGraph?.leafs) ? mainGraph.leafs : [];
  for (const leaf of leafs) {
    const ip = cleanIp(leaf?.ip);
    const nk = cleanName(leaf);
    const key = ip ? `ip:${ip}` : nk ? `name:${nk}` : `leaf:${Math.random()}`;

    if (seen.has(key)) continue;
    seen.add(key);

    nodes.push(wrapGraph({ ...leaf, ip }, "leaf"));
  }

  // B) Luego: cualquier sensor topology adicional (por si hay nodos extra o leafs incompletos)
  const topoSensors = Object.values(hass.states || {}).filter(
    (s) => s?.entity_id?.startsWith("sensor.miwifi_topology") && s.attributes?.graph
  );

  for (const s of topoSensors) {
    const g = s.attributes.graph;
    if (!g) continue;

    const ip = cleanIp(g.ip);
    const nk = cleanName(g);

    // Excluir el main (por IP o por nombre, evitando duplicados raros)
    if (mainIp && ip && ip === mainIp) continue;
    if (mainName && nk && nk === mainName) continue;
    if (g.is_main === true) continue;

    const key = ip ? `ip:${ip}` : nk ? `name:${nk}` : `eid:${s.entity_id}`;
    if (seen.has(key)) continue;
    seen.add(key);

    nodes.push(wrapGraph({ ...g, ip }, s.entity_id));
  }

  return nodes;
}

export async function renderTopologia(hass) {
  if (!hass || !hass.states) {
    return html`<div style="text-align:center; padding:24px; color:white">Cargando sección...</div>`;
  }

  let mainGraph = await findMainGraph(hass);

  if (!mainGraph) {
    mainGraph = fallbackMainGraph(hass);
    if (mainGraph) {
      logToBackend(
        hass,
        "debug",
        `⚠️ [topologia.js] Fallback main router selected: ${mainGraph.name || mainGraph.locale || "unknown"} (${mainGraph.ip || "no-ip"})`
      );
    }
  }

  if (mainGraph) {
    logToBackend(hass, "debug", `✅ [topologia.js] Main router detected: ${mainGraph.name} (${mainGraph.mac})`);
  } else {
    logToBackend(hass, "warning", "❌ [topologia.js] No router found with is_main or fallback logic.");
  }

  const connectedDevices = Object.values(hass.states).filter(
    (e) => e?.entity_id?.startsWith("device_tracker.miwifi_") && e.state === "home"
  );

  const meshNodes = mainGraph ? buildMeshNodes(hass, mainGraph) : [];

  return html`
    <miwifi-topologia
      .data=${mainGraph}
      .devices=${connectedDevices}
      .nodes=${meshNodes}
      .hass=${hass}
    ></miwifi-topologia>
  `;
}
