import { html } from "../vendor/lit.js?v=3.8.1";
import { localize } from "../translations/localize.js?v=3.8.1";

export function renderToggle(hass, entity) {
  return html`
    <div class="setting-row">
      <span>${entity.attributes.friendly_name}</span>
      <label class="switch">
        <input type="checkbox"
          .checked=${entity.state === "on"}
          @change=${(e) =>
            hass.callService(entity.entity_id.split(".")[0],
              e.target.checked ? "turn_on" : "turn_off",
              { entity_id: entity.entity_id })} />
        <span class="slider"></span>
      </label>
    </div>
  `;
}

export function renderSelects(hass, selects) {
  const unique = {};
  selects.forEach(s => {
    if (!unique[s.attributes.friendly_name]) {
      unique[s.attributes.friendly_name] = s;
    }
  });

  return html`
    <div class="select-grid">
      ${Object.values(unique).map(entity => html`
        <div class="select-block">
          <label>${entity.attributes.friendly_name}</label>
          <select
            .value=${entity.state}
            @change=${(e) =>
              hass.callService("select", "select_option", {
                entity_id: entity.entity_id,
                option: e.target.value,
              })}
          >
            ${entity.attributes.options.map(opt => html`
              <option value="${opt}" ?selected=${opt === entity.state}>${opt}</option>`)}
          </select>
        </div>
      `)}
    </div>
  `;
}

export function getMainRouterMac(hass) {
  const mainGraph = Object.values(hass.states)
    .find((s) =>
      s.entity_id.startsWith("sensor.miwifi_topology") &&
      s.attributes?.graph?.is_main === true
    )?.attributes?.graph;

  return mainGraph?.mac?.toLowerCase()?.replaceAll(":", "_") ?? null;
}

export function formatSignal(value) {
  const map = {
    max: "100%",
    mid: "50%",
    min: "25%",
    unavailable: "N/D",
  };
  return map[value?.toLowerCase()] ?? value + "%";
}

export function logToBackend(hass, level, message) {
  if (!hass || !hass.callService) {
    console.warn("⚠️ [logToBackend] Home Assistant instance not ready.");
    return;
  }

  hass.callService("miwifi", "log_panel", {
    level,
    message,
  }).catch((err) => {
    console.warn("🛑 [logToBackend] Error sending log to backend:", err);
  });
}

const ROUTER_IMAGES = {
  "cb0401": "CB0401.png",
  "cb0401v2": "CB0401V2.png",
  "cr6606": "CR6606.png",
  "cr8808": "CR8808.png",
  "cr8809": "CR8809.png",
  "cr8816": "CR8816.png",
  "d01": "D01.png",
  "r1350": "R1350.png",
  "r1c": "R1C.png",
  "r1cl": "R1CL.png",
  "r1cm": "R1CM.png",
  "r1d": "R1D.png",
  "r2100": "R2100.png",
  "r2350": "R2350.png",
  "r2d": "R2D.png",
  "r3": "R3.png",
  "r3600": "R3600.png",
  "r3a": "R3A.png",
  "r3d": "R3D.png",
  "r3g": "R3G.png",
  "r3l": "R3L.png",
  "r3p": "R3P.png",
  "r4": "R4.png",
  "r4a": "R4A.png",
  "r4ac": "R4AC.png",
  "r4acv2": "R4ACv2.png",
  "r4av2": "R4AV2.png",
  "r4c": "R4C.png",
  "r4cm": "R4CM.png",
  "ra50": "RA50.png",
  "ra67": "RA67.png",
  "ra69": "RA69.png",
  "ra70": "RA70.png",
  "ra71": "RA71.png",
  "ra72": "RA72.png",
  "ra74": "RA74.png",
  "ra80": "RA80.png",
  "ra80v2": "RA80V2.png",
  "ra81": "RA81.png",
  "ra82": "RA82.png",
  "rb01": "RB01.png",
  "rb02": "RB02.png",
  "rb03": "RB03.png",
  "rb04": "RB04.png",
  "rb06": "RB06.png",
  "rb08": "RB08.png",
  "rc01": "RC01.png",
  "rc02": "RC02.png",
  "rc06": "RC06.png",
  "rd03": "RD03.png",
  "rd03v2": "RD03V2.png",
  "rd04": "RD04.png",
  "rd04v2": "RD04v2.png",
  "rd05": "RD05.png",
  "rd08": "RD08.png",
  "rd12": "RD12.png",
  "rd13": "RD13.png",
  "rd15": "RD15.png",
  "rd16": "RD16.png",
  "rd18": "RD18.png",
  "rd23": "RD23.png",
  "rd28": "RD28.png",
  "rm1800": "RM1800.png",
  "rm2100": "RM2100.png",
  "rn01": "RN01.png",
  "rn02": "RN02.png",
  "rn04": "RN04.png",
  "rn06": "RN06.png",
  "rn07": "RN07.png",
  "rn09": "RN09.png",
  "rp04": "RP04.png",
  "table": "table.png"
};

export function getRouterImage(hardware) {
  const filename = ROUTER_IMAGES[String(hardware || "").trim().toLowerCase()];
  return filename ? `/miwifi_static/images/${filename}` : "/miwifi_static/assets/icon_panel.png";
}
