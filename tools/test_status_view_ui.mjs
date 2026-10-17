// Actual component behavior with browser storage replaced by a small double.
import assert from "node:assert/strict";
import fs from "node:fs";
import vm from "node:vm";

const source = fs.readFileSync(new URL("../custom_components/miwifi/www/components/miwifi-status-data.js", import.meta.url), "utf8")
  .replace(/^import .*;\r?\n/gm, "");
const flatten = value => value?.strings ? value.strings.join("") + value.values.map(flatten).join("")
  : Array.isArray(value) ? value.map(flatten).join("")
  : ["string", "number"].includes(typeof value) ? String(value) : "";
const saved = new Map();
for (const language of ["en", "es", "de", "fr", "pt-BR", "ru", "tr", "zh-Hans"]) {
  const translations = JSON.parse(fs.readFileSync(new URL(`../custom_components/miwifi/www/translations/${language}.json`, import.meta.url)));
  saved.clear();
  const context = vm.createContext({
    LitElement: class {}, html: (strings, ...values) => ({strings, values}), css: () => "",
    localize: key => { assert.ok(translations[key], `${language}: missing ${key}`); return translations[key]; },
    customElements: {define() {}}, localStorage: {
      getItem: key => saved.get(key), setItem: (key, value) => saved.set(key, value),
    },
  });
  vm.runInContext(source + "\nglobalThis.Panel = MiWiFiStatusData;", context);
  const panel = new context.Panel();
  panel.sections = [{title: "Synthetic WAN", items: [
    {label: "WAN1 IP", value: "192.0.2.10"}, {label: "WAN2 IP", value: "203.0.113.254"},
    {label: "Count", value: 0}, {label: "Missing", value: null},
  ]}];
  const cardText = flatten(panel.render());
  assert.ok(!cardText.includes("<table>"));
  assert.ok(cardText.includes('class="card"'));
  panel._setView("list");
  const listText = flatten(panel.render());
  assert.ok(listText.includes("<table>") && listText.includes('scope="row"'));
  assert.ok(!listText.includes('class="card"'));
  for (const value of ["192.0.2.10", "203.0.113.254", translations.status_unavailable, "Count", "0"]) {
    assert.ok(cardText.includes(value) && listText.includes(value));
  }
  assert.equal(new context.Panel()._view, "list");
  assert.equal(saved.size, 1);
  assert.equal([...saved.values()][0], "list"); // Never persist addresses/readings.
  panel.sections = [{title: "Synthetic WAN", items: [{label: "WAN2 IP", value: "203.0.113.253"}]}];
  assert.ok(flatten(panel.render()).includes("203.0.113.253"));
  assert.ok(!flatten(panel.render()).includes("203.0.113.254"));
  panel._setView("invalid");
  assert.equal(new context.Panel()._view, "cards");
  context.localStorage.getItem = context.localStorage.setItem = () => { throw new Error("blocked"); };
  const privatePanel = new context.Panel();
  privatePanel._setView("list");
  assert.equal(privatePanel._view, "list");
}
console.log("Status cards/list: equal data, updates, zero/missing values, restricted storage and 8 languages pass.");
