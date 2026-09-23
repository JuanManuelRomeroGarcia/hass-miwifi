import { getRouterImage } from "./utils.js?v=3.8.1";
import { html } from "../vendor/lit.js?v=3.8.1";
import { renderToggle, renderSelects } from "./utils.js?v=3.8.1";
import { localize } from "../translations/localize.js?v=3.8.1";
import { logToBackend } from "./utils.js?v=3.8.1";

const REPOSITORY = "JuanManuelRomeroGarcia/hass-miwifi";

// New feature: retry to find the main router
async function findMainGraph(hass, retries = 3, delay = 500) {
  for (let i = 0; i < retries; i++) {
    const sensor = Object.values(hass.states).find(
      (s) =>
        s.entity_id.startsWith("sensor.miwifi_topology") &&
        s.attributes?.graph?.is_main === true
    );
    if (sensor?.attributes?.graph) return sensor.attributes.graph;
    await new Promise((res) => setTimeout(res, delay));
  }
  return null;
}

export async function renderMesh(hass) {
  let mainGraph = await findMainGraph(hass);

  // Fallback si no hay mainGraph
  if (!mainGraph) {
    const sensorIds = Object.keys(hass.states).filter((id) =>
      id.startsWith("sensor.miwifi_topology")
    );

    for (const id of sensorIds) {
      const sensor = hass.states[id];
      const graph = sensor?.attributes?.graph;

      if (graph?.show === 1 && graph?.assoc === 1) {
        mainGraph = graph;
        logToBackend(
          hass,
          "debug",
          `🧠 [mesh.js] Fallback router by show+assoc: ${graph.name} (${graph.mac})`
        );
        break;
      }

      if (graph?.mode === 0) {
        mainGraph = graph;
        logToBackend(
          hass,
          "debug",
          `⚠️ [mesh.js] Fallback router by mode=0 only: ${graph.name || id}`
        );
        break;
      }
    }
  }

  if (mainGraph) {
    logToBackend(
      hass,
      "debug",
      `✅ [mesh.js] Main router detected: ${mainGraph.name} (${mainGraph.mac})`
    );
  } else {
    logToBackend(hass, "warning", "❌ [mesh.js] No router found with is_main or fallback logic.");
    return html`
      <div class="content text-center" style="color: #ccc;">
        ❗ ${localize("topology_main_not_found")}
      </div>
    `;
  }

  function handleMeshReboot(hass, name, mac, entity_id) {
    hass
      .callService("button", "press", { entity_id })
      .catch((err) => console.error("callService error:", err));

    logToBackend(
      hass,
      "info",
      `🔄 [mesh.js] Reboot requested for mesh node: ${name} (${mac})`
    );

    hass
      .callService("persistent_notification", "create", {
        title: localize("settings_restart_router"),
        message: localize("settings_restart_mesh_done").replace("{name}", name),
        notification_id: `miwifi_reboot_${mac.replace(/:/g, "_").toLowerCase()}`,
      })
      .catch((err) => console.error("callService error:", err));
  }

  // sensores de nodos mesh (mode=3)
  const meshSensors = Object.values(hass.states).filter(
    (s) =>
      s.entity_id.startsWith("sensor.miwifi_topology") &&
      s.attributes?.graph?.mode === 3
  );

  const leafs = Array.isArray(mainGraph.leafs) ? mainGraph.leafs : [];

  return html`
    <div class="content">
      <div class="miwifi-mesh-group">
        ${leafs.map((leaf) => {
          try {
            const sensor = meshSensors.find((s) => s.attributes?.graph?.ip === leaf.ip);

            const mac = (sensor?.attributes?.graph?.mac || leaf.mac || "")
              .toLowerCase()
              .replace(/:/g, "_");

            const icon = getRouterImage(leaf.hardware);

            const switches = mac
              ? Object.values(hass.states).filter((e) =>
                  e.entity_id.startsWith("switch.miwifi_" + mac)
                )
              : [];

            const selects = mac
              ? Object.values(hass.states).filter((e) =>
                  e.entity_id.startsWith("select.miwifi_" + mac)
                )
              : [];

            const led = mac ? hass.states[`light.miwifi_${mac}_led`] : null;
            const reboot = mac ? hass.states[`button.miwifi_${mac}_reboot`] : null;

            return html`
              <div class="mesh-card">
                <img src="${icon}" class="topo-icon" alt="Nodo Mesh" />
                <div class="mesh-name">${leaf.name}</div>
                <div class="mesh-info">
                  ${localize("ip")}: ${leaf.ip}<br />
                  ${localize("modelo")}: ${leaf.hardware}<br />
                  ${localize("estado")}: ${localize("🟢 status_connected")}
                </div>

                ${mac
                  ? html`
                      <div class="section">
                        <h3>${localize("settings_wifi_switches")}</h3>
                        ${switches.map((sw) => renderToggle(hass, sw))}
                      </div>

                      <div class="section">
                        <h3>${localize("settings_channels")}</h3>
                        ${renderSelects(hass, selects)}
                      </div>

                      <div class="section">
                        <h3>${localize("settings_extra")}</h3>
                        ${led
                          ? html`<div>${localize("label_led")} ${renderToggle(hass, led)}</div>`
                          : ""}
                        ${reboot
                          ? html`
                              <button
                                class="reboot-btn"
                                @click=${() =>
                                  handleMeshReboot(hass, leaf.name, leaf.mac, reboot.entity_id)}
                              >
                                ${localize("mesh_node_restart")}
                              </button>
                            `
                          : ""}
                      </div>
                    `
                  : html`
                      <div class="section">
                        ${localize("mesh_node_not_found")}
                      </div>
                    `}
              </div>
            `;
          } catch (err) {
            logToBackend(
              hass,
              "error",
              `❌ [mesh.js] Error rendering mesh node '${leaf.name}': ${err.message}`
            );
            return html`
              <div class="mesh-card">
                <div class="mesh-name">${leaf.name}</div>
                <div class="mesh-info" style="color: red;">
                  ❗ Error loading node data: ${err.message}
                </div>
              </div>
            `;
          }
        })}
      </div>
    </div>
  `;
}
