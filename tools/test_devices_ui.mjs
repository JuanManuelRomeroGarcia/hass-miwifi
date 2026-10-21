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
const enriched = device("Metrics", "192.0.2.50", -43);
enriched.attributes.signal_unit = "dBm";
enriched.attributes.link_tx_rate = 2401;
enriched.attributes.link_rx_rate = 0;
enriched.attributes.wifi_protocol = "Wi-Fi 6(802.11ax)";
assert.equal(panel._cellValue(enriched, "signal", topo), "-43 dBm");
assert.equal(panel._cellValue(enriched, "link_tx_rate", topo), "2401 Mbps");
assert.equal(panel._cellValue(enriched, "link_rx_rate", topo), "0 Mbps");
assert.equal(panel._cellValue(enriched, "wifi_protocol", topo), "Wi-Fi 6(802.11ax)");
enriched.attributes.connection = "Lan";
for (const key of ["signal", "wifi_protocol", "link_tx_rate", "link_rx_rate"]) assert.equal(panel._cellValue(enriched, key, topo), "—");
const cardOutput = JSON.stringify(panel._renderCard(enriched, topo, {}));
for (const value of ["signal_quality", "wifi_protocol", "link_tx_rate", "link_rx_rate", "2401 Mbps"]) assert.ok(!cardOutput.includes(value));
enriched.attributes.connection = "5G";
enriched.attributes.signal = "";
enriched.attributes.link_tx_rate = null;
assert.equal(panel._cellValue(enriched, "signal", topo), "—");
assert.equal(panel._cellValue(enriched, "link_tx_rate", topo), "—");
for (const language of ["en", "es", "de", "fr", "pt-BR", "ru", "tr", "zh-Hans"]) {
  const t = JSON.parse(fs.readFileSync(`custom_components/miwifi/www/translations/${language}.json`, "utf8"));
  for (const key of ["wifi_protocol", "link_tx_rate", "link_rx_rate"]) assert.ok(t[key]);
}
const ws = [];
panel.hass.callWS = async message => {
  ws.push(message);
  return message.type === "config/entity_registry/get"
    ? { device_id: "device-1", original_name: "02:00:00:00:00:01" }
    : { entity_entry: { original_name: "02:00:00:00:00:01" } };
};
const named = device("02:00:00:00:00:01", "192.0.2.60", 50);
panel._renaming = named.entity_id;
await panel._rename(named, "  Kitchen TV ");
assert.deepEqual(ws.map(message => message.type),
  ["config/entity_registry/get", "config/entity_registry/update", "config/device_registry/update"]);
assert.equal(ws[1].name, "Kitchen TV");
assert.equal(ws[2].device_id, "device-1");
assert.equal(ws[2].name_by_user, "Kitchen TV");
assert.equal(panel._cellValue(named, "name", topo), "Kitchen TV"); // Shown before HA pushes the new state.
assert.equal(panel._renaming, null);
named.attributes.friendly_name = "Renamed elsewhere";
assert.equal(panel._cellValue(named, "name", topo), "Renamed elsewhere"); // Newer HA state wins.
ws.length = 0;
panel._renaming = named.entity_id;
await panel._rename(named, "   ");
assert.equal(ws[1].name, null);
assert.equal(ws[2].name_by_user, null);
assert.equal(panel._cellValue(named, "name", topo), "02:00:00:00:00:01"); // Empty restores the original.
ws.length = 0;
await panel._rename(named, "Not editing");
panel.hass.user.is_admin = false;
panel._renaming = named.entity_id;
await panel._rename(named, "Not an admin");
assert.equal(ws.length, 0);
panel.hass.user.is_admin = true;
let releaseRename;
panel.hass.callWS = message => { ws.push(message); return new Promise(resolve => { releaseRename = resolve; }); };
const renaming = panel._rename(named, "Once");
await panel._rename(named, "Twice");
assert.equal(ws.length, 1);
releaseRename({}); // Registry entry without a device: only the entity update follows.
await new Promise(resolve => setTimeout(resolve));
releaseRename({}); await renaming;
assert.equal(ws.length, 2);
panel.hass.callWS = async () => { throw Error("private backend detail"); };
panel._renaming = named.entity_id;
await panel._rename(named, "Fails");
assert.equal(panel._renameError, "devices_rename_error");
assert.equal(panel._renamePending.size, 0);
assert.equal(panel._renaming, null);
console.log("PASS: numeric name/IP sorting, search, columns, preference restore, blocked storage, unavailable state, admin-only WAN writes, duplicate-write guard, failure feedback, admin-only registry renames and eight languages.");
