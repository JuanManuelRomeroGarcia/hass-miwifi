import { localize } from "./translations/localize.js?v=3.7.0";
import { logToBackend } from "./pages/utils.js?v=3.7.0";

/**
 * Get current main router MAC from sensor
 */
function getCurrentMainMac() {
  const hass = document.querySelector("home-assistant")?.hass;
  const sensors = Object.values(hass?.states || {}).filter(
    (s) =>
      s.entity_id.startsWith("sensor.miwifi_topology") &&
      s.attributes?.graph?.is_main === true
  );
  return sensors.length ? sensors[0].attributes.graph.mac : null;
}

/**
 * Show selection dialog for choosing the main router
 */
export async function showDialog(hass, { title, options, onSelect }) {
  const content = document.createElement("div");
  content.style.padding = "16px";

  if (!options?.length) {
    await logToBackend(hass, "warning", "❌ No router candidates found for manual selection (dialogs.js)");
    return;
  }

  const currentMain = getCurrentMainMac();

  options.forEach((opt) => {
    const isSelected = currentMain === opt.mac;
    const btn = document.createElement("button");
      btn.className = "miwifi-button";
      btn.style.display = "block";
      btn.style.width = "100%";
      btn.style.margin = "8px 0";

      btn.textContent = isSelected
        ? `✅ ${opt.name} (${localize("button_selected")})`
        : opt.name;

    btn.addEventListener("click", async () => {
      const isDeselect = isSelected;
      const selectedMac = isDeselect ? "" : opt.mac;

      try {
        await hass.callService("miwifi", "select_main_router", { mac: selectedMac });


        const lvl = hass?.states?.["sensor.miwifi_config"]?.attributes?.log_level || "info";
        await hass.callService("miwifi", "log_panel", {
          level: lvl,
          message: `🖱️ User selected router: ${selectedMac || "none (cleared)"}`,
        });
        await logToBackend(hass, lvl, `🖱️ Manual router ${selectedMac || "cleared"} selected from UI (dialogs.js)`);

      } catch (err) {
        console.error("🛑 Error calling the select_main_router service:", err);
        await logToBackend(hass, "error", `❌ Failed to call select_main_router: ${err}`);
      }

      dialog.close();
      location.reload();
    });

    content.appendChild(btn);
  });

  const dialog = document.createElement("ha-dialog");
  dialog.heading = title;
  dialog.appendChild(content);
  document.body.appendChild(dialog);

  await customElements.whenDefined("ha-dialog");
  await new Promise((r) => setTimeout(r, 50));

  if (typeof dialog.showModal === "function") {
    dialog.showModal();
  } else {
    dialog.setAttribute("open", "");
  }
}
