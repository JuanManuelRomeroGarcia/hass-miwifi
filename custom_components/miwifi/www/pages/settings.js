import { html } from "../vendor/lit.js?v=3.7.0";
import "../components/miwifi-settings.js?v=3.7.0";
import { logToBackend } from "./utils.js?v=3.7.0";

async function findMainRouter(hass, retries = 3, delay = 500) {
  for (let i = 0; i < retries; i++) {
    const sensor = Object.values(hass.states).find((s) => {
      const g = s.attributes?.graph;
      return g?.is_main === true;
    });
    if (sensor) return sensor;
    await new Promise((res) => setTimeout(res, delay));
  }
  return null;
}

export async function renderSettings(hass) {
  const mainRouter = await findMainRouter(hass);

  if (!mainRouter) {
    logToBackend(hass, "warning", "❌ [settings.js] No router found with is_main or fallback logic.");
  }

  return html`
    <miwifi-settings
      .hass=${hass}
      .routerSensor=${mainRouter}
    ></miwifi-settings>
  `;
}
