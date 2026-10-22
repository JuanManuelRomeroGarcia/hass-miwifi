import assert from "node:assert/strict";
import fs from "node:fs";
import vm from "node:vm";
const source = fs.readFileSync("custom_components/miwifi/www/components/miwifi-router-specific.js", "utf8").replace(/^import .*;\r?\n/gm, "");
const context = vm.createContext({ LitElement: class {}, html: (strings, ...values) => ({strings, values}), css: () => "", localize: key => key, customElements: {define() {}}, Date });
vm.runInContext(source + "\nglobalThis.Panel = MiWiFiRouterSpecific;", context);
const panel = new context.Panel();
let calls = 0, finish;
panel.hass = {user: {is_admin: false}};
await panel._load();
assert.equal(panel._data, null);
panel.hass = {user: {is_admin: true}, callWS: message => {
  assert.equal(message.type, "miwifi/router_specific"); calls++;
  return new Promise(resolve => { finish = resolve; });
}};
const first = panel._load();
const secondPanel = new context.Panel();
secondPanel.hass = panel.hass;
const sharedRead = secondPanel._load();
await panel._load();
assert.equal(calls, 1);
finish({routers: []}); await first;
await sharedRead;
panel._data = {routers: [
  {model: "rc01", is_main: true, mac: "02:00:00:00:00:01", ip: "192.0.2.1"},
  {model: "rc06", is_main: false, mac: "02:00:00:00:00:02", ip: "192.0.2.2"},
  {model: "rc06", is_main: false, mac: "02:00:00:00:00:03", ip: "192.0.2.3"},
]};
assert.deepEqual(Array.from(panel._visibleRouters(), r => r.ip), ["192.0.2.1"]);
panel.scope = "mesh"; panel.routerMac = "02-00-00-00-00-03";
assert.deepEqual(Array.from(panel._visibleRouters(), r => r.ip), ["192.0.2.3"]);
panel.routerIp = "192.0.2.2"; // A mismatching MAC must not fall back to another node's IP.
panel.routerMac = "02:00:00:00:00:99";
assert.equal(panel._visibleRouters().length, 0);
panel.routerMac = "";
assert.deepEqual(Array.from(panel._visibleRouters(), r => r.ip), ["192.0.2.2"]);
const rows = panel._rows({metrics: {temperature: 75, fan_speed: 0, multiwan: false, wps: false, nfc: true, backhaul: "wired", roaming: {"2g": -65}, ports: [{label: "1", speed: "2.5G", service: "LAN"}]}});
assert.ok(rows.some(row => row.value === "0 RPM"));
assert.ok(rows.some(row => row.label === "router_specific_multiwan" && row.value === "router_specific_off"));
assert.ok(!panel._rows({metrics: {}}).some(row => row.label === "router_specific_temperature"));
panel.hass.callWS = async () => { throw Error("private details"); };
await panel._load();
assert.equal(panel._error, true);
assert.equal(panel._data, null);
assert.equal(panel._busy, false);
for (const lang of ["en", "es", "de", "fr", "pt-BR", "ru", "tr", "zh-Hans"]) {
  const t = JSON.parse(fs.readFileSync(`custom_components/miwifi/www/translations/${lang}.json`, "utf8"));
  const keys = [...source.matchAll(/localize\("(router_specific_\w+)"\)/g)].map(m => m[1]);
  for (const key of [...keys, ...["temperature", "fan", "multiwan", "backhaul", "roaming", "port", "wps", "nfc", "auto", "wired", "wireless", "on", "off"].map(k => `router_specific_${k}`)]) assert.ok(t[key], `${lang}: ${key}`);
}
// Render the actual Mesh page: the block belongs inside supported node cards.
const meshSource = fs.readFileSync("custom_components/miwifi/www/pages/mesh.js", "utf8")
  .replace(/^import .*;\r?\n/gm, "").replace(/^export /gm, "");
const meshContext = vm.createContext({
  html: (strings, ...values) => ({strings, values}), localize: key => key,
  getRouterImage: () => "router.png", renderToggle: () => "", renderSelects: () => "", logToBackend() {},
});
vm.runInContext(meshSource + "\nglobalThis.renderMeshPage = renderMesh;", meshContext);
const leaves = ["rc06", "rc01", "rd08"].map((hardware, i) => ({
  hardware, ip: `192.0.2.${i + 2}`, name: `Node ${i}`, mac: `02:00:00:00:00:0${i + 2}`,
}));
const meshPage = await meshContext.renderMeshPage({states: {
  "sensor.miwifi_topology_main": {entity_id: "sensor.miwifi_topology_main", attributes: {graph: {is_main: true, leafs: leaves}}},
}});
const flatten = item => item?.strings ? item.strings.map((text, i) => text + flatten(item.values[i])).join("")
  : Array.isArray(item) ? item.map(flatten).join("") : typeof item === "string" ? item : "";
const markup = flatten(meshPage);
assert.equal((markup.match(/<miwifi-router-specific embedded/g) || []).length, 2);
assert.ok(markup.includes('.scope=mesh'));
assert.ok(markup.includes('.routerMac=02:00:00:00:00:02'));
console.log("PASS: per-node identity, main/mesh separation, shared reads, admin gate, zero/false, errors and eight languages.");
