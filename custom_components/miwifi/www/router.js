import { logToBackend } from "./pages/utils.js?v=3.8.1";

const MIWIFI_VERSION = "3.8.1";

async function loadPage(module) {
  return (await import(`./pages/${module}.js?v=${MIWIFI_VERSION}`));
}

export const router = {
  "/status": (hass) => loadPage("status").then((mod) => mod.renderStatus(hass)),
  "/topologia": (hass) => loadPage("topologia").then((mod) => mod.renderTopologia(hass)),
  "/miwifi-devices": (hass) => loadPage("miwifi-devices").then((mod) => mod.renderDevicesCards(hass)),
  "/mesh": (hass) => loadPage("mesh").then((mod) => mod.renderMesh(hass)),
  "/settings": (hass) => loadPage("settings").then((mod) => mod.renderSettings(hass)),
  "/error": (hass) => loadPage("error").then((mod) => mod.renderError(hass)),
  "/portforwarding": (hass) => loadPage("portforwarding").then((mod) => mod.renderPortForwarding(hass)),

};

let _currentPath = "/status";
const _history = ["/status"];

export function navigate(path, hass) {
  if (_currentPath !== path) {
    _history.push(path);
  }
  _currentPath = path;
  window.dispatchEvent(new CustomEvent("miwifi-navigate", { detail: { path, hass } }));
  if (hass) {
    logToBackend(hass, "debug", `➡️ [router.js] Navigated to: ${path}`);
  }
}

export function goBack(hass) {
  if (_history.length <= 1) {
    logToBackend(hass, "warning", "🔙 [router.js] goBack() called with no internal history. Using browser back.");
    window.history.back();
  } else {
    _history.pop();
    const previous = _history.pop() || "/status";
    navigate(previous, hass);
    logToBackend(hass, "debug", `🔙 [router.js] Going back to previous route: ${previous}`);
  }
}

export function currentPath() {
  return _currentPath;
}