// Render the real status page against synthetic HA states, including WAN2 down.
import assert from "node:assert/strict";
import fs from "node:fs";
import vm from "node:vm";

const source = fs.readFileSync(new URL("../custom_components/miwifi/www/pages/status.js", import.meta.url), "utf8")
  .replace(/^import .*;\r?\n/gm, "").replaceAll("export ", "");
const mac = "02_00_00_00_00_01";
const flatten = item => item?.strings
  ? item.strings.join("") + item.values.map(flatten).join("")
  : Array.isArray(item) ? item.map(flatten).join("")
  : item?.items ? flatten(item.title) + flatten(item.items)
  : item?.label ? flatten(item.label) + flatten(item.value)
  : typeof item === "string" ? item : "";

for (const language of ["en", "es", "de", "fr", "pt-BR", "ru", "tr", "zh-Hans"]) {
  const translations = JSON.parse(fs.readFileSync(new URL(`../custom_components/miwifi/www/translations/${language}.json`, import.meta.url)));
  const context = vm.createContext({
    html: (strings, ...values) => ({strings, values}),
    getMainRouterMac: () => mac, formatSignal: value => value,
    logToBackend() {}, localize: key => translations[key] ?? key,
  });
  vm.runInContext(source + "\nglobalThis.render = renderStatus;", context);
  const hass = {states: {
    "sensor.miwifi_topology": {entity_id: "sensor.miwifi_topology", attributes: {
      graph: {is_main: true, mac: "02:00:00:00:00:01", name: "Synthetic router"},
    }},
    [`sensor.miwifi_${mac}_wan_ip_address`]: {state: "192.0.2.10"},
  }};
  assert.ok(!flatten(await context.render(hass)).includes(translations.label_wan2_ip));
  const wan2 = hass.states[`sensor.miwifi_${mac}_wan2_ip_address`] = {
    state: "192.0.2.20", attributes: {enabled: true, type: "dhcp", link: true, connected: true},
  };
  let text = flatten(await context.render(hass));
  for (const key of ["label_wan2_ip", "label_wan2_type", "label_wan2_link", "label_wan2_state"]) {
    assert.ok(translations[key], `${language}: ${key}`);
    assert.ok(text.includes(translations[key]));
    assert.ok(!text.includes(key));
  }
  assert.ok(text.includes("192.0.2.10") && text.includes("192.0.2.20"));
  wan2.state = "unknown"; // A confirmed disconnected port has no address.
  wan2.attributes.link = wan2.attributes.connected = false;
  text = flatten(await context.render(hass));
  assert.ok(text.includes(translations.status_disconnected));
  wan2.state = "unavailable"; // A request failure is not a confirmed disconnection.
  text = flatten(await context.render(hass));
  assert.ok(!text.includes(translations.status_disconnected));
  wan2.attributes.enabled = false;
  assert.ok(!flatten(await context.render(hass)).includes(translations.label_wan2_ip));
}
console.log("WAN status UI: enabled, disabled, disconnected and unavailable pass in 8 languages.");
