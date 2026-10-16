// Actual component behavior, with browser/HA I/O replaced by small doubles.
import assert from "node:assert/strict";
import fs from "node:fs";
import vm from "node:vm";

const path = "custom_components/miwifi/www/components/miwifi-device-cards.js";
const source = fs.readFileSync(path, "utf8").replace(/^import .*;\r?\n/gm, "");
const saved = new Map();
const context = vm.createContext({
  LitElement: class { requestUpdate() {} }, html: (strings, ...values) => ({ strings, values }), css: () => "",
  localize: key => key, customElements: { define() {} }, Intl,
  localStorage: { getItem: key => saved.get(key) ?? null, setItem: (key, value) => saved.set(key, value) },
  console: { warn() {}, error() {} },
});
vm.runInContext(source + "\nglobalThis.Panel = MiWiFiDeviceCards;", context);
const panel = new context.Panel();
panel.hass = { language: "en", user: { is_admin: true } };
const topo = { routersByMac: {} };
const device = (name, ip, signal, state = "home") => ({
  entity_id: `device_tracker.miwifi_${ip.split('.').at(-1)}`, state,
  attributes: { friendly_name: name, ip, mac: "02:00:00:00:00:01", signal, connection: "5G", connected_via_router_name: "Living room" },
});
const devices = [device("Client 10", "192.0.2.10", 10), device("Client 2", "192.0.2.2", 90), device("Offline", "192.0.2.3", null, "unavailable")];
assert.deepEqual(Array.from(panel._visibleDevices(devices, topo), d => d.attributes.friendly_name), ["Client 2", "Client 10", "Offline"]);
panel._sortBy("ip");
assert.deepEqual(Array.from(panel._visibleDevices(devices, topo), d => d.attributes.ip), ["192.0.2.2", "192.0.2.3", "192.0.2.10"]);
panel._sortBy("ip");
assert.equal(panel._visibleDevices(devices, topo)[0].attributes.ip, "192.0.2.10");
devices[0].attributes.up_speed = "900 KB/s";
devices[1].attributes.up_speed = "1 MB/s";
panel._sortBy("up");
assert.equal(panel._visibleDevices(devices.slice(0, 2), topo)[0], devices[0]);
panel._search = "LIVING";
assert.equal(panel._visibleDevices(devices, topo).length, 3);
panel._search = "not present";
assert.equal(panel._visibleDevices(devices, topo).length, 0);
panel._setView("table"); panel._setColumn("mac", true); panel._setColumn("ip", false);
panel._setColumn("name", false);
assert.ok(panel._columns.includes("name"));
const restored = new context.Panel();
assert.equal(restored._view, "table");
assert.ok(restored._columns.includes("mac"));
assert.ok(!restored._columns.includes("ip"));
assert.equal(restored._search, ""); // Names, addresses and search text are never persisted.
assert.ok(![...saved.values()].some(value => value.includes("Living") || value.includes("192.0.2")));
assert.equal(panel._cellValue(devices[2], "state", topo), "status_unavailable");
devices[0].attributes.connected_via_router_device_mac = "02:00:00:00:00:AA";
devices[0].attributes.router_mac = "02:00:00:00:00:BB";
assert.equal(panel._getViaMac(devices[0]), "02:00:00:00:00:aa");
saved.set("miwifi.device-view.v1", "not json");
assert.equal(new context.Panel()._view, "cards");
context.localStorage.getItem = () => { throw Error("blocked"); };
context.localStorage.setItem = () => { throw Error("blocked"); };
const blocked = new context.Panel(); blocked._setView("table");
assert.equal(blocked._view, "table");
let calls = 0, release;
panel.hass.callService = () => { calls++; return new Promise(resolve => { release = resolve; }); };
const pending = panel._toggleWAN(devices[0], true);
await panel._toggleWAN(devices[0], true);
assert.equal(calls, 1);
release(); await pending;
panel.hass.user.is_admin = false;
await panel._toggleWAN(devices[0], true);
assert.equal(calls, 1);
panel.hass.user.is_admin = true;
panel.hass.callService = async () => { throw Error("private backend detail"); };
await panel._toggleWAN(devices[0], true);
assert.equal(panel._wanError, "devices_wan_error");
assert.equal(panel._wanPending.size, 0);
const keys = [...source.matchAll(/localize\("(devices_[a-z_]+)"\)/g)].map(match => match[1]);
for (const language of ["en", "es", "de", "fr", "pt-BR", "ru", "tr", "zh-Hans"]) {
  const translations = JSON.parse(fs.readFileSync(`custom_components/miwifi/www/translations/${language}.json`, "utf8"));
  for (const key of [...keys, "devices_column_node", "devices_column_connection", "devices_column_upload", "devices_column_download"]) assert.ok(translations[key], `${language}: ${key}`);
}
console.log("PASS: numeric name/IP sorting, search, columns, preference restore, blocked storage, unavailable state, admin-only WAN writes, duplicate-write guard, failure feedback and eight languages.");
