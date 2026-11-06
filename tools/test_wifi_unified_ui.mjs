import assert from "node:assert/strict";
import fs from "node:fs";
import vm from "node:vm";
const flatten = value => value?.strings ? value.strings.map((text, i) => text + flatten(value.values[i])).join("")
  : Array.isArray(value) ? value.map(flatten).join("") : typeof value === "string" ? value : "";
const context = vm.createContext({html: (strings, ...values) => ({strings, values}),
  LitElement: class {requestUpdate() {}}, customElements: {define() {}}, localize: key => key, console});
const read = path => fs.readFileSync(path, "utf8").replace(/^import .*;\r?\n/gm, "").replace(/^export /gm, "");
vm.runInContext(read("custom_components/miwifi/www/pages/utils.js"), context);
vm.runInContext(read("custom_components/miwifi/www/components/miwifi-settings.js") + "\nglobalThis.Settings = MiWiFiSettingsPanel;", context);
const settings = new context.Settings();
settings.hass = {states: {}};
settings.routerSensor = {attributes: {wifi_unified: true}};
const primary = {entity_id: "switch.miwifi_test_wifi_2_4", state: "on"};
const radio = {enabled: true, ssid: "Same network", channel: 36};
assert.ok(flatten(settings._renderRadioBlock("twoG", primary, radio, [])).includes("wifi_unified_control"));
for (const band of ["fiveG", "game"]) {
  const block = flatten(settings._renderRadioBlock(band, null, radio, []));
  assert.ok(!block.split('class="body"')[0].includes("<ha-switch"));
  assert.ok(block.includes('class="body"')); // Physical radio details remain visible.
}
settings.routerSensor.attributes.wifi_unified = false;
assert.ok(flatten(settings._renderRadioBlock("fiveG", primary, radio, [])).split('class="body"')[0].includes("<ha-switch"));
settings.hass = {user: {is_admin: true}, states: {}, callWS: async () => ({unified: true, wifis: {"2g": radio, "5g": radio}})};
await settings._fetchWifis();
assert.equal(settings.wifiUnified, true);
assert.ok(!flatten(settings._renderRadioBlock("fiveG", primary, radio, [])).split('class="body"')[0].includes("<ha-switch"));

// Node-specific unified status: one node must not inherit another node's setting.
const toggles = [];
context.renderToggle = (_hass, entity, label) => { toggles.push({id: entity.entity_id, label}); return ""; };
context.renderSelects = () => ""; context.logToBackend = () => {};
vm.runInContext("{\n" + read("custom_components/miwifi/www/pages/mesh.js") + "\nglobalThis.mesh = renderMesh;\n}", context);
const leaves = [2, 3].map(i => ({mac: `02:00:00:00:00:0${i}`, ip: `192.0.2.${i}`, name: `Node ${i}`, hardware: "rc06"}));
const states = {"sensor.miwifi_topology_main": {entity_id: "sensor.miwifi_topology_main", attributes: {graph: {is_main: true, leafs: leaves}}}};
for (const [index, leaf] of leaves.entries()) {
  states[`sensor.miwifi_topology_${index}`] = {entity_id: `sensor.miwifi_topology_${index}`, attributes: {wifi_unified: index === 0, graph: {...leaf, mode: 3}}};
  for (const band of ["2_4", "5_0", "5_0_game"]) {
    const id = `switch.miwifi_${leaf.mac.replaceAll(":", "_")}_wifi_${band}`;
    states[id] = {entity_id: id, state: "on", attributes: {friendly_name: band}};
  }
}
const markup = flatten(await context.mesh({states}));
assert.equal((markup.match(/<miwifi-wifi-switches/g) || []).length, 2);
vm.runInContext(read("custom_components/miwifi/www/components/miwifi-wifi-switches.js") + "\nglobalThis.Switches = MiWiFiWifiSwitches;", context);
const controls = new context.Switches();
controls.routerMac = leaves[0].mac;
controls.switches = Object.values(states).filter(s => s.entity_id.startsWith("switch.miwifi_02_00_00_00_00_02_"));
// The topology attribute may be absent: read the flag directly from the updater's cached data.
controls.hass = {user: {is_admin: true}, callWS: async () => ({routers: leaves.map((leaf, i) => ({...leaf, unified: i === 0}))})};
await controls._load();
assert.ok(flatten(controls.render()).includes("wifi_unified_hint"));
assert.equal(toggles.filter(row => row.id.includes("00_02_")).length, 1);
controls.routerMac = leaves[1].mac;
controls.switches = Object.values(states).filter(s => s.entity_id.startsWith("switch.miwifi_02_00_00_00_00_03_"));
await controls._load();
assert.ok(!flatten(controls.render()).includes("wifi_unified_hint"));
assert.equal(toggles.filter(row => row.id.includes("00_03_")).length, 3);
assert.equal(toggles.find(row => row.id.includes("00_02_")).label, "wifi_unified_control");
// Real HA entity IDs are slugified display names, unlike the old synthetic keys.
controls._unified = true;
controls.switches = ["2_4g", "5g", "5g_game"].map(band => ({entity_id: `switch.miwifi_node_wifi_${band}`, state: "on"}));
assert.equal(controls._switches().length, 1);
assert.equal(controls._band(controls._switches()[0]), "2g");
controls.switches = ["2g", "5g_2", "5g_game_2"].map(band => ({entity_id: `switch.miwifi_node_wifi_${band}`, state: "on"}));
assert.equal(controls._switches().length, 1);
// Registry mapping also handles arbitrary entity renames.
controls._radioIds = {"2g": "switch.house_wifi", "5g": "switch.radio_b", game: "switch.radio_c"};
controls.switches = [];
controls.hass.states = Object.fromEntries(Object.values(controls._radioIds).map(id => [id, {entity_id: id, state: "on"}]));
assert.equal(controls._switches().length, 1);
assert.equal(controls._switches()[0].entity_id, "switch.house_wifi");
for (const lang of ["en", "es", "de", "fr", "pt-BR", "ru", "tr", "zh-Hans"]) {
  const t = JSON.parse(fs.readFileSync(`custom_components/miwifi/www/translations/${lang}.json`, "utf8"));
  assert.ok(t.wifi_unified_hint && t.wifi_unified_control);
}
console.log("PASS: per-node unification, shared switch, physical radio details and eight languages.");
