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
  if (index !== -1) return {checked: value.values[index], change: value.values[index + 1]};
  return value.values.map(guestToggle).find(Boolean);
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

// Both write paths retain the draft even while the HA switch still says off.
for (const switchState of [undefined, "off"]) {
  const {panel, calls} = setup({enabled: "1", status: "0", ssid: "Synthetic guest"}, switchState);
  await panel._fetchWifis();
  for (const enable of [true, false]) {
    guestToggle(panel.render()).change({target: {checked: enable}});
    assert.equal(guestToggle(panel.render()).checked, enable);
    assert.equal(panel.guestDirty, true);
    await panel._applyGuest();
    const write = calls.filter(call => call.service === "set_guest_wifi").at(-1);
    assert.equal(write.domain, "miwifi");
    assert.equal(write.data.enable, enable);
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
  assert.equal(guestToggle(panel.render()).checked, false);
  assert.equal(panel.guestDirty, false);
}
console.log(`Guest Wi-Fi: ${cases.length} state cases and enable/disable/save/readback with and without a switch pass.`);
