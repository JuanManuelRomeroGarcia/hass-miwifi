import assert from "node:assert/strict";
import fs from "node:fs";
import vm from "node:vm";
const source = fs.readFileSync("custom_components/miwifi/www/components/miwifi-iot.js", "utf8").replace(/^import .*;\r?\n/gm, "");
const context = vm.createContext({LitElement: class {}, html: (strings, ...values) => ({strings, values}),
  localize: key => key, customElements: {define() {}}});
vm.runInContext(source + "\nglobalThis.Panel = MiWiFiIot;", context);
const panel = new context.Panel();
const snapshot = {entry_id: "main", revision: "before", enabled: true, writable: true,
  bands: [{ssid: "IoT 2G", encryption: "psk2", has_password: true, password: "current-key-2g"}, {ssid: "IoT 5G", encryption: "psk2", has_password: true, password: "current-key-5g"}]};
let calls = [];
panel.routerMac = "02:00:00:00:00:01";
panel.hass = {user: {is_admin: false}, callWS: async message => { calls.push(message); return snapshot; }};
await panel._load(); assert.equal(calls.length, 0);
panel.hass.user.is_admin = true;
await panel._load();
assert.equal(calls[0].type, "miwifi/iot_read");
assert.equal(panel.form.bands[0].password, "current-key-2g");
assert.equal(panel.showPasswords[0], false);
panel._togglePassword(0);
assert.equal(panel.showPasswords[0], true);
assert.equal(panel.showPasswords[1], false);
panel._togglePassword(0);
assert.equal(panel._dirty(), false);
panel._edit(0, "password", "");
assert.equal(panel._dirty(), false); // Empty keeps the current key.
panel._edit(0, "password", "changed-key-2g");
assert.equal(panel._dirty(), true);
panel._edit(0, "password", "current-key-2g");
assert.equal(panel._dirty(), false);
panel._edit(0, "ssid", "New IoT");
assert.equal(panel._dirty(), true);
let finish;
panel.hass.callWS = message => { calls.push(message); return new Promise(resolve => { finish = resolve; }); };
const saving = panel._save();
await panel._save();
assert.equal(calls.length, 2);
assert.equal(calls[1].type, "miwifi/iot_write");
assert.equal(calls[1].bands[0].password, "");
finish({...snapshot, revision: "after", bands: [{...snapshot.bands[0], ssid: "New IoT"}, snapshot.bands[1]]});
await saving;
assert.equal(panel.saved, true);
assert.equal(panel.showPasswords[0], false);
assert.equal(panel._dirty(), false);
panel._edit(1, "ssid", "Another name");
panel.hass.callWS = async () => { throw {code: "unverified"}; };
await panel._save();
assert.equal(panel.error, "iot_unverified");
assert.equal(panel.snapshot, null);
assert.equal(panel.busy, false);
for (const lang of ["en", "es", "de", "fr", "pt-BR", "ru", "tr", "zh-Hans"]) {
  const t = JSON.parse(fs.readFileSync(`custom_components/miwifi/www/translations/${lang}.json`, "utf8"));
  for (const key of ["title", "hint", "error", "saved", "unsupported", "stale", "unverified", "invalid", "show_password", "hide_password"]) assert.ok(t[`iot_${key}`]);
}
console.log("PASS: IoT admin access, read/edit/save, password preservation, duplicate writes, failure feedback and eight languages.");
