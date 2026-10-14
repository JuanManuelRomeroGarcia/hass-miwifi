// Exercise the real component's state transitions without a live router.
import assert from "node:assert/strict";
import fs from "node:fs";
import vm from "node:vm";

const file = new URL("../custom_components/miwifi/www/components/miwifi-dhcp.js", import.meta.url);
const source = fs.readFileSync(file, "utf8").replace(/^import .*;\r?\n/gm, "").replace("export class", "class");
const context = vm.createContext({
  LitElement: class {}, html: (strings, ...values) => ({ strings, values }), css: () => "",
  localize: key => `translated:${key}`, customElements: { define() {} },
});
vm.runInContext(source + "\nglobalThis.Panel = MiWiFiDhcp;", context);
const calls = [], panel = new context.Panel();
const row = { mac: "02:00:00:00:00:51", ip: "192.0.2.51", name: "Watch" };
const snapshot = { bindings: [row], clients: [row], revision: "first", writable: true, enabled: true };
let result = snapshot;
panel.hass = { user: { is_admin: true }, callWS: async payload => { calls.push(payload); return result; } };
result = { routers: [{ entry_id: "main", name: "Main", ip: "192.0.2.1" }] };
await panel._routers();
assert.equal(panel.entry, ""); // Selecting the actual router is explicit.
result = snapshot;
await panel._select("main");
assert.equal(calls.at(-1).entry_id, "main");
panel._edit(row);
panel._field("ip", "192.0.2.53");
assert.equal(panel.editing, true);
result = { ...snapshot, revision: "second" };
await panel._write("edit");
assert.equal(calls.at(-1).action, "edit");
assert.equal(calls.at(-1).revision, "first");
assert.equal(calls.at(-1).ip, "192.0.2.53");
assert.equal(panel.snapshot.revision, "second");
assert.equal(panel.saved, true);
const count = calls.length;
await panel._write("delete", row);
assert.equal(calls.length, count); // A deletion must be explicitly confirmed.
panel.pending = row;
await panel._write("delete", row);
assert.equal(calls.at(-1).action, "delete");
assert.equal(calls.at(-1).name, undefined);
panel.hass.callWS = async payload => { calls.push(payload); throw { code: "unverified", message: "private router text" }; };
await panel._write("add", row);
assert.equal(panel.snapshot, null);
assert.equal(panel.error, "translated:dhcp_error_unverified");
const failedCount = calls.length;
await panel._write("add", row);
assert.equal(calls.length, failedCount); // No blind resubmit after a write error.
panel.hass.callWS = async payload => { calls.push(payload); return snapshot; };
await panel._load();
assert.equal(panel.snapshot, snapshot);
panel.snapshot = { ...snapshot, writable: false };
await panel._write("add", row);
assert.equal(calls.at(-1).type, "miwifi/dhcp_read");
panel.snapshot = snapshot;
panel.hass.user.is_admin = false;
const viewerCount = calls.length;
await panel._write("add", row);
await panel._load();
assert.equal(calls.length, viewerCount);
// Late responses must not populate another router's view.
panel.hass.user.is_admin = true;
let finish;
panel.hass.callWS = () => new Promise(resolve => { finish = resolve; });
const pendingRead = panel._load();
panel.entry = "other";
finish(snapshot);
await pendingRead;
assert.equal(panel.snapshot, null);
console.log("PASS: explicit router, edit, confirmed delete, verified result, failed-write refresh, read-only/admin controls and late-response isolation.");
