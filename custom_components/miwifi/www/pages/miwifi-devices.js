import { html } from "../vendor/lit.js?v=3.8.1";
import "../components/miwifi-device-cards.js?v=3.8.1";
import { logToBackend } from "./utils.js?v=3.8.1";


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
