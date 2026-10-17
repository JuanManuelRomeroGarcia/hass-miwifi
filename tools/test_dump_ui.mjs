// Real settings component: opt-in capture, admin guard and no duplicate exports.
import assert from "node:assert/strict";
import fs from "node:fs";
import vm from "node:vm";

const source = fs.readFileSync(new URL("../custom_components/miwifi/www/components/miwifi-settings.js", import.meta.url), "utf8")
  .replace(/^import .*;\r?\n/gm, "").replace("export class", "class");
const flatten = value => value?.strings ? value.strings.join("") + value.values.map(flatten).join("")
  : Array.isArray(value) ? value.map(flatten).join("") : typeof value === "string" ? value : "";

for (const language of ["en", "es", "de", "fr", "pt-BR", "ru", "tr", "zh-Hans"]) {
  const translations = JSON.parse(fs.readFileSync(new URL(`../custom_components/miwifi/www/translations/${language}.json`, import.meta.url)));
  const downloads = [], calls = [], ws = [];
  const context = vm.createContext({
    LitElement: class { requestUpdate() {} }, html: (strings, ...values) => ({strings, values}),
    localize: key => { assert.ok(translations[key], `${language}: ${key}`); return translations[key]; },
    customElements: {define() {}}, window: {location: {assign: path => downloads.push(path)}},
  });
  vm.runInContext(source + "\nglobalThis.Panel = MiWiFiSettingsPanel;", context);
  const panel = new context.Panel();
  let finish;
  panel.hass = {user: {is_admin: true}, callService: async (domain, service, data) => {
    calls.push({domain, service, data});
    if (service === "dump_router_data") await new Promise(resolve => {finish = resolve;});
  }, callWS: async payload => {ws.push(payload); return payload.type === "miwifi/get_download_url"
    ? {url: "/api/miwifi/exports/dump_test.zip"} : {path: "/api/miwifi/exports/dump_test.zip?signed=example"};}};
  assert.equal(panel.dumpOptions.api_diagnostics, false);
  panel._openDumpModal();
  panel._toggleDumpOption("api_diagnostics");
  assert.ok(flatten(panel._renderDumpModal()).includes(translations.dump_api_diagnostics_hint));
  const pending = panel._sendDump();
  assert.equal(panel.isDumpLoading, true);
  assert.equal(calls[0].data.api_diagnostics, true);
  assert.equal(calls[0].data.hide_sensitive, true);
  await panel._sendDump();
  assert.equal(calls.length, 1);
  panel._closeDumpModal();
  assert.equal(panel.showDumpModal, true);
  finish();
  await pending;
  assert.equal(panel.showDumpModal, false);
  assert.equal(panel.isDumpLoading, false);
  assert.equal(downloads.length, 1);
  assert.deepEqual(ws.map(call => call.type), ["miwifi/get_download_url", "auth/sign_path"]);
  panel.hass.user.is_admin = false;
  panel._openDumpModal();
  await panel._sendDump();
  assert.equal(calls.length, 1);
  assert.equal(panel.showDumpModal, false);
  panel.hass.user.is_admin = true;
  for (const key of Object.keys(panel.dumpOptions)) panel.dumpOptions[key] = key === "hide_sensitive";
  await panel._sendDump();
  assert.equal(calls.at(-1).service, "create");
  assert.equal(downloads.length, 1);
  panel.dumpOptions.api_diagnostics = true;
  panel.hass.callService = async (domain, service) => {if (service === "dump_router_data") throw new Error("capture failed");};
  await panel._sendDump();
  assert.equal(panel.isDumpLoading, false);
  assert.equal(downloads.length, 1); // Never download an old export after failure.
}
console.log("Dump UI: opt-in, permissions, duplicate guard, private download, failures and 8 languages pass.");
