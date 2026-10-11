// Exercise settings behavior without a live Home Assistant or browser session.
import assert from "node:assert/strict";
import fs from "node:fs";
import vm from "node:vm";

// Missing locale keys exposed implementation labels instead of UI text in HA.
const translations = new URL("../custom_components/miwifi/www/translations/", import.meta.url);
const english = JSON.parse(fs.readFileSync(new URL("en.json", translations), "utf8"));
for (const language of ["en", "es", "de", "fr", "pt-BR", "ru", "tr", "zh-Hans"]) {
  const dictionary = JSON.parse(fs.readFileSync(new URL(`${language}.json`, translations), "utf8"));
  for (const key of Object.keys(english)) {
    assert.equal(typeof dictionary[key], "string", `${language}: missing ${key}`);
    assert.ok(dictionary[key].trim(), `${language}: empty ${key}`);
  }
}

const file = new URL("../custom_components/miwifi/www/components/miwifi-mac-replacement.js", import.meta.url);
const source = fs.readFileSync(file, "utf8").replace(/^import .*;\r?\n/gm, "").replace("export class", "class");
const context = vm.createContext({
  LitElement: class {}, html: (strings, ...values) => ({ strings, values }), css: () => "",
  localize: key => key, customElements: { define() {} },
});
vm.runInContext(source + "\nglobalThis.Panel = MiWiFiMacReplacement;", context);
const panel = new context.Panel();
const calls = [];
panel.hass = { user: { is_admin: true },
  callWS: async () => ({ clients: { watch: ["SM-L315F", "Reloj JuanMa"], phone: ["Redmi"] }, available_names: ["Redmi", "Laptop"] }),
  callService: async (...args) => { calls.push(JSON.parse(JSON.stringify(args))); },
};
await panel._load();
assert.equal(panel.rows.length, 2);
panel._add("Laptop");
await panel._save();
assert.deepEqual(calls[0], ["miwifi", "configure_mac_replacement", { clients: {
  watch: ["SM-L315F", "Reloj JuanMa"], phone: ["Redmi"], client_1: ["Laptop"],
} }]);
panel._remove("phone");
await panel._save();
assert.equal(calls[1][2].clients.phone, undefined);
assert.deepEqual(calls[1][2].clients.watch, ["SM-L315F", "Reloj JuanMa"]);
panel._add("sm-l315f");
assert.equal(panel.rows.length, 2);
assert.equal(panel.error, "mac_duplicate_names");
panel._add("Other");
panel._edit("client_2", "sm-l315f");
await panel._save();
assert.equal(panel.error, "mac_duplicate_names");
assert.equal(calls.length, 2);
panel._remove("client_2");
panel._add();
assert.equal(panel.rows[2].expanded, true);
panel._edit("client_2", "Manual device");
assert.equal(panel.rows[2].expanded, true);
panel._remove("client_2");
panel._edit("watch", "");
await panel._save();
assert.equal(panel.error, "mac_empty_names");
assert.equal(calls.length, 2);
const failed = new context.Panel();
failed.hass = { ...panel.hass, callWS: async () => { throw new Error("offline"); } };
await failed._load();
failed._add("New");
await failed._save();
assert.equal(failed._loaded, false);
assert.equal(calls.length, 2);
const viewer = new context.Panel();
viewer.hass = { ...panel.hass, user: { is_admin: false } };
await viewer._save();
assert.equal(calls.length, 2);
console.log("PASS: eight-language coverage, load existing rules, preserve aliases and other clients, remove one rule, reject invalid aliases, block saving after a load failure and restrict writes to administrators.");
