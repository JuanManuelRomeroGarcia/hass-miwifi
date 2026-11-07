import { html } from "../vendor/lit.js?v=__MIWIFI_VERSION__";
import "../components/miwifi-device-cards.js?v=__MIWIFI_VERSION__";
import { logToBackend } from "./utils.js?v=__MIWIFI_VERSION__";


export function renderDevicesCards(hass) {
  const devices = Object.values(hass.states).filter((state) =>
    state.entity_id.startsWith("device_tracker.miwifi_")
  );

  if (devices.length === 0) {
    logToBackend(hass, "warning", "❗ [miwifi-devices.js] No connected MiWiFi devices found.");
  } else {
    logToBackend(hass, "debug", `📶 [miwifi-devices.js] Rendering ${devices.length} connected device(s).`);
  }

  return html`
    <miwifi-device-cards .hass=${hass} .devices=${devices}></miwifi-device-cards>
  `;
}
