// Run the real preview launcher: hostile query/DOM values cannot select a URL.
import assert from "node:assert/strict";
import fs from "node:fs";
import vm from "node:vm";

const html = fs.readFileSync(new URL("./panel-preview.html", import.meta.url), "utf8");
const source = html.match(/<script type="module">([\s\S]*?)<\/script>/)[1];
const choices = {
  "#width": ["320", "390", "768", "1280"],
  "#language": ["es", "en", "de", "fr", "pt-BR", "ru", "tr", "zh-Hans"],
  "#page": ["status", "miwifi-devices", "topologia", "mesh", "portforwarding", "dhcp", "settings", "error"],
};
for (const search of ["?page=status&width=320", "?page=javascript:alert(1)&width=bad"]) {
  let update;
  const controls = Object.fromEntries(Object.entries(choices).map(([key, options]) => [key, {
    selectedIndex: 0, checked: false,
    set value(value) { this.selectedIndex = options.indexOf(String(value)); },
    get value() { return options[this.selectedIndex] ?? ""; },
    addEventListener(_name, callback) { update = callback; },
  }]));
  controls["#theme"] = {checked: false, addEventListener() {}};
  controls["#viewer"] = {checked: false, addEventListener() {}};
  const frame = {style: {}, src: ""};
  const document = {body: {}, querySelector: key => key === "iframe" ? frame : controls[key],
    querySelectorAll: () => Object.values(controls)};
  await vm.runInNewContext(`(async () => {${source}})()`, {document, location: {search}, URLSearchParams});
  let url = new URL(frame.src, "http://localhost");
  assert.equal(url.origin, "http://localhost");
  assert.equal(url.pathname, "/");
  assert.equal(url.searchParams.get("page"), "status");
  assert.ok(["320px", "390px"].includes(frame.style.width));
  controls["#page"].value = "dhcp";
  controls["#language"].value = "fr";
  controls["#viewer"].checked = true;
  update();
  url = new URL(frame.src, "http://localhost");
  assert.equal(url.searchParams.get("page"), "dhcp");
  assert.equal(url.searchParams.get("lang"), "fr");
  assert.equal(url.searchParams.get("viewer"), "true");
  controls["#page"].value = '\"><script>alert(1)</script>';
  controls["#language"].value = "en&frame=0&outside=1";
  update();
  url = new URL(frame.src, "http://localhost");
  assert.equal(url.searchParams.get("page"), "status");
  assert.equal(url.searchParams.get("lang"), "es");
  assert.equal(url.searchParams.get("frame"), "1");
  assert.equal(url.searchParams.has("outside"), false);
}
console.log("Panel preview: predefined routes/languages, encoded parameters and invalid selections pass.");
