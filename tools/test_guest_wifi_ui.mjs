// Exercise the real guest form with synthetic WebSocket replies and writes.
import assert from "node:assert/strict";
import fs from "node:fs";
import vm from "node:vm";

const source = fs.readFileSync(new URL("../custom_components/miwifi/www/components/miwifi-settings.js", import.meta.url), "utf8")
  .replace(/^import .*;\r?\n/gm, "").replace("export class", "class");
const context = vm.createContext({
  LitElement: class { requestUpdate() {} },
  html: (strings, ...values) => ({strings, values}),
  localize: key => key, getRouterImage: () => "", customElements: {define() {}},
});
vm.runInContext(source + "\nglobalThis.Panel = MiWiFiSettingsPanel;", context);

function guestToggle(value) {
  if (Array.isArray(value)) return value.map(guestToggle).find(Boolean);
  if (!value?.strings) return undefined;
  const index = value.strings.findIndex(text => text.includes("<ha-switch .checked="));
  if (index !== -1) {
    const change = value.strings.findIndex((text, i) => i > index && text.includes("@change="));
    return {checked: value.values[index], change: value.values[change]};
  }
  return value.values.map(guestToggle).find(Boolean);
}

function disabledBindings(value) {
  if (Array.isArray(value)) return value.flatMap(disabledBindings);
  if (!value?.strings) return [];
  return [...value.strings.flatMap((text, i) => text.includes("?disabled=") ? [value.values[i]] : []),
    ...value.values.flatMap(disabledBindings)];
}

function setup(guest, switchState) {
  const panel = new context.Panel();
  const calls = [];
  const entity_id = "switch.miwifi_02_00_00_00_00_01_wifi_guest";
  panel.routerSensor = {attributes: {graph: {mac: "02:00:00:00:00:01", hardware: "RC06"}}};
  panel._renderRadioBlock = () => "";
  panel.hass = {
    user: {is_admin: true},
    states: switchState ? {[entity_id]: {entity_id, state: switchState}} : {},
    callWS: async payload => {
      assert.equal(payload.type, "miwifi/get_wifis");
      return {wifis: {guest: {...guest}}};
    },
    callService: async (domain, service, data) => {
      calls.push({domain, service, data});
      if (service === "set_guest_wifi") guest.status = data.enable ? "1" : "0";
    },
  };
  return {panel, calls};
}

// A router without a guest interface must still load its normal radios.
{
  const {panel} = setup({});
  panel.hass.callWS = async () => ({wifis: {guest: null, "2g": {ssid: "Radio"}}});
  assert.equal(await panel._fetchWifis(), true);
  assert.equal(panel.radios.twoG.ssid, "Radio");
  assert.equal(panel.guestForm, null);
  assert.equal(panel.guestError, null);
}

// External entity transitions update a clean form but not an in-progress edit.
{
  const {panel} = setup({enabled: "1", status: "0"}, "off");
  await panel._fetchWifis();
  assert.equal(guestToggle(panel.render()).checked, false);
  const entity = Object.values(panel.hass.states)[0];
  entity.state = "on";
  assert.equal(guestToggle(panel.render()).checked, true);
  guestToggle(panel.render()).change({target: {checked: false}});
  entity.state = "off";
  assert.equal(guestToggle(panel.render()).checked, false);
  assert.equal(panel.guestDirty, true);
}

const cases = [
  [{enabled: "1", status: "0"}, false], // RC06: configured, operationally off.
  ...["1", 1, true, "true", "on", "yes"].map(status => [{enabled: "0", status}, true]),
  ...["0", 0, false, "false", "off", "", "unknown"].map(status => [{enabled: "1", status}, false]),
  ...["1", 1, true].map(enabled => [{enabled}, true]),
  ...["0", 0, false].map(enabled => [{enabled}, false]),
  [{enabled: "1", status: null}, true],
  [{}, false],
];
for (const [guest, expected] of cases) {
  for (const switchState of [undefined, expected ? "off" : "on"]) {
    const {panel} = setup(guest, switchState);
    await panel._fetchWifis();
    const label = JSON.stringify(guest);
    assert.equal(panel.guestError, null, label);
    assert.equal(panel.guestOrig.enabled, expected, label);
    assert.equal(panel.guestForm.enable, expected, label);
    assert.equal(guestToggle(panel.render()).checked, expected, label);
    assert.equal(panel._guestIsDirty(), false, label);
  }
}

// Apply is the only writer, even when the HA switch entity exists and is stale.
for (const switchState of [undefined, "off"]) {
  const {panel, calls} = setup({enabled: "1", status: "0", ssid: "Synthetic guest", password: "Existing-secret"}, switchState);
  await panel._fetchWifis();
  for (const enable of [true, false]) {
    guestToggle(panel.render()).change({target: {checked: enable}});
    assert.equal(calls.filter(call => call.domain === "switch").length, 0);
    assert.equal(guestToggle(panel.render()).checked, enable);
    assert.equal(panel.guestDirty, true);
    await panel._applyGuest();
    const write = calls.filter(call => call.service === "set_guest_wifi").at(-1);
    assert.equal(write.domain, "miwifi");
    assert.equal(write.data.enable, enable);
    assert.deepEqual(Object.keys(write.data), ["enable"]);
    assert.equal(panel.guestOrig.enabled, enable);
    assert.equal(guestToggle(panel.render()).checked, enable);
    assert.equal(panel.guestDirty, false);
  }
  const writes = calls.filter(call => call.service === "set_guest_wifi").length;
  await panel._applyGuest();
  assert.equal(calls.filter(call => call.service === "set_guest_wifi").length, writes);
}
// A successful service call alone must not override the router's readback.
{
  const {panel} = setup({enabled: "1", status: "0"}, "on");
  await panel._fetchWifis();
  panel.hass.callService = async () => {};
  guestToggle(panel.render()).change({target: {checked: true}});
  await panel._applyGuest();
  assert.equal(guestToggle(panel.render()).checked, true); // Unconfirmed draft remains editable.
  assert.equal(panel.guestOrig.enabled, false);
  assert.equal(panel.guestDirty, true);
}

// Failures keep edits and never emit a saved notification.
for (const failure of ["service", "read", "mismatch", "missing", "partial", "invalid-status"]) {
  const {panel, calls} = setup({enabled: "1", status: "0", password: "Existing-secret"}, "off");
  await panel._fetchWifis();
  panel._onGuestChange("enable", true);
  panel._onGuestChange("ssid", "Requested guest");
  panel.hass.callService = async (domain, service, data) => {
    calls.push({domain, service, data});
    if (service === "set_guest_wifi" && failure === "service") throw new Error("write failed");
  };
  panel.hass.callWS = async () => {
    if (failure === "read") throw new Error("read failed");
    if (failure === "missing") return {wifis: {}};
    return {wifis: {guest: {status: failure === "invalid-status" ? "unknown" : failure === "mismatch" ? "0" : "1"}}};
  };
  await panel._applyGuest();
  assert.equal(panel.guestForm.enable, true, failure);
  assert.equal(panel.guestForm.ssid, "Requested guest", failure);
  assert.equal(panel.guestForm.password, "Existing-secret", failure);
  assert.equal(panel.guestDirty, true, failure);
  assert.ok(panel.guestError, failure);
  assert.equal(calls.some(call => call.data?.notification_id === "miwifi_guest_saved"), false, failure);
}

// A save and its confirmation read form a single guarded operation.
{
  const {panel} = setup({status: "0", password: "Existing-secret"}, "off");
  await panel._fetchWifis();
  panel._onGuestChange("enable", true);
  let finishWrite, finishRead, readStarted, writes = 0, reads = 0;
  const reading = new Promise(resolve => {readStarted = resolve;});
  panel.hass.callService = async (_domain, service) => {
    if (service === "set_guest_wifi") { writes++; await new Promise(resolve => {finishWrite = resolve;}); }
  };
  panel.hass.callWS = async () => {
    reads++;
    return await new Promise(resolve => {finishRead = resolve; readStarted();});
  };
  const pending = panel._applyGuest();
  assert.ok(disabledBindings(panel.render()).length >= 8);
  assert.ok(disabledBindings(panel.render()).every(Boolean));
  await panel._applyGuest();
  await panel._fetchWifis();
  panel._onGuestChange("enable", false);
  assert.equal(panel.guestForm.enable, true);
  assert.equal(writes, 1);
  assert.equal(reads, 0);
  finishWrite();
  await reading;
  assert.equal(reads, 1);
  assert.ok(disabledBindings(panel.render()).every(Boolean));
  await panel._applyGuest();
  panel._onGuestChange("ssid", "Must not be accepted");
  finishRead({wifis: {guest: {status: "1", password: "Existing-secret"}}});
  await pending;
  assert.equal(panel.guestForm.ssid, "");
  assert.equal(panel.guestDirty, false);
}

// Clearing the password input means keep it; it is never sent as an empty secret.
{
  const {panel, calls} = setup({status: "0", password: "Existing-secret"});
  await panel._fetchWifis();
  panel._onGuestChange("password", "");
  assert.equal(panel.guestDirty, false);
  panel._onGuestChange("enable", true);
  await panel._applyGuest();
  assert.deepEqual(Object.keys(calls.find(call => call.service === "set_guest_wifi").data), ["enable"]);
}

// Only explicitly edited configuration fields accompany the enable flag.
for (const [field, value] of [["ssid", "New guest"], ["encryption", "none"], ["hidden", true], ["password", "New-secret"]]) {
  const guest = {status: "1", ssid: "Old guest", encryption: "psk2", hidden: false, password: "Existing-secret"};
  const {panel, calls} = setup(guest);
  await panel._fetchWifis();
  panel._onGuestChange(field, value);
  panel.hass.callService = async (domain, service, data) => {
    calls.push({domain, service, data});
    if (service === "set_guest_wifi") Object.assign(guest, data);
  };
  await panel._applyGuest();
  const body = calls.find(call => call.service === "set_guest_wifi").data;
  assert.deepEqual(Object.keys(body).sort(), ["enable", field].sort());
  assert.equal(panel.guestDirty, false, field);
  assert.equal(panel.guestError, null, field);
}
// Missing fields and unknown hidden flags cannot confirm a requested value.
for (const [field, before, after, reply] of [
  ["hidden", true, false, {}],
  ["hidden", true, false, {hidden: "unknown"}],
  ["encryption", "none", "psk2", {}],
  ["ssid", "Old guest", "", {}],
]) {
  const {panel, calls} = setup({status: "1", [field]: before});
  await panel._fetchWifis();
  panel._onGuestChange(field, after);
  panel.hass.callWS = async () => ({wifis: {guest: {status: "1", ...reply}}});
  await panel._applyGuest();
  assert.equal(panel.guestDirty, true, field);
  assert.equal(panel.guestForm[field], after, field);
  assert.ok(panel.guestError, field);
  assert.equal(calls.some(call => call.data?.notification_id === "miwifi_guest_saved"), false);
}
for (const language of ["en", "es", "de", "fr", "pt-BR", "ru", "tr", "zh-Hans"]) {
  const translations = JSON.parse(fs.readFileSync(new URL(`../custom_components/miwifi/www/translations/${language}.json`, import.meta.url)));
  assert.ok(translations.guest_save_unconfirmed, language);
}
console.log(`Guest Wi-Fi: ${cases.length} state cases, single writes, selective payloads, errors, readback and concurrency pass.`);
