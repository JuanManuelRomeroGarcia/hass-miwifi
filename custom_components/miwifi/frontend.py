"""Serve the MiWiFi frontend shipped with the integration."""

import asyncio
import json
import os
from pathlib import Path

from homeassistant.components.frontend import DATA_PANELS, async_remove_panel
from homeassistant.components.http import StaticPathConfig
from homeassistant.components.panel_custom import async_register_panel as register_custom_panel
from homeassistant.core import HomeAssistant

from .const import MAIN_ROUTER_STORE_FILE
from .logger import _LOGGER

PANEL_PATH = Path(__file__).parent / "www"
PANEL_URL = "/miwifi_static"
_LOCK = "miwifi_panel_lock"
_STATIC = "miwifi_panel_static_registered"


def _read_json_file(path) -> dict:
    with open(path, encoding="utf-8") as file:
        return json.load(file)


def _write_json_file(path: str, data: dict) -> None:
    with open(path, "w", encoding="utf-8") as file:
        json.dump(data, file)


async def read_local_version(hass: HomeAssistant) -> str:
    """Read the bundled version, never a downloaded or stored version."""
    if "miwifi_cached_panel_version" not in hass.data:
        data = await hass.async_add_executor_job(_read_json_file, PANEL_PATH / "version.json")
        hass.data["miwifi_cached_panel_version"] = data["version"]
    return hass.data["miwifi_cached_panel_version"]


async def async_register_panel(hass: HomeAssistant, version: str) -> None:
    """Register static resources once, including concurrent router setup."""
    async with hass.data.setdefault(_LOCK, asyncio.Lock()):
        if not hass.data.get(_STATIC):
            await hass.http.async_register_static_paths([
                StaticPathConfig(PANEL_URL, str(PANEL_PATH), False)
            ])
            hass.data[_STATIC] = True

        expected_url = f"{PANEL_URL}/panel-frontend.js?v={version}"
        panel = hass.data.get(DATA_PANELS, {}).get("miwifi")
        if panel is not None:
            if (panel.config or {}).get("_panel_custom", {}).get("module_url") == expected_url:
                return
            async_remove_panel(hass, "miwifi")

        await register_custom_panel(
            hass,
            frontend_url_path="miwifi",
            webcomponent_name="miwifi-panel",
            sidebar_title="MiWiFi",
            sidebar_icon="mdi:router-network",
            module_url=expected_url,
            embed_iframe=False,
            trust_external=False,
            require_admin=True,
        )


async def async_remove_miwifi_panel(hass: HomeAssistant) -> None:
    """Remove the sidebar panel; retain static registration for reloads."""
    async with hass.data.setdefault(_LOCK, asyncio.Lock()):
        if "miwifi" in hass.data.get(DATA_PANELS, {}):
            async_remove_panel(hass, "miwifi")


# ------- Persistence for Main Router Manual -------

async def async_save_manual_main_mac(hass: HomeAssistant, mac: str):
    """Save manually selected MAC to a JSON file."""
    path = hass.config.path(MAIN_ROUTER_STORE_FILE)
    try:
        os.makedirs(os.path.dirname(path), exist_ok=True)
        await hass.async_add_executor_job(_write_json_file, path, {"manual_main_mac": mac})
        await hass.async_add_executor_job(_LOGGER.info, "[MiWiFi] ✅ MAC Manual saved correctly in %s", path)
        
        from .updater import async_get_integrations
        integrations = async_get_integrations(hass)
        for integ in integrations.values():
            try:
                await integ["updater"].coordinator.async_request_refresh()
            except Exception:
                pass

    except Exception as e:
        await hass.async_add_executor_job(_LOGGER.error, "[MiWiFi] ❌ Error saving file from manual MAC: %s", e)


async def async_load_manual_main_mac(hass: HomeAssistant) -> str | None:
    """Load manually selected MAC from file."""
    path = hass.config.path(MAIN_ROUTER_STORE_FILE)
    if not os.path.exists(path):
        await hass.async_add_executor_job(_LOGGER.debug, "[MiWiFi] No manual MAC file found at %s", path)
        return None
    try:
        data = await hass.async_add_executor_job(_read_json_file, path)
        if isinstance(data, dict):
            mac = data.get("manual_main_mac")
            await hass.async_add_executor_job(_LOGGER.debug, "[MiWiFi] ✅ MAC loaded from file: %s", mac)
            return mac
        else:
            await hass.async_add_executor_job(_LOGGER.warning, "[MiWiFi] ❌ Unexpected format in file: %s (expected: dict, received: %s)", path, type(data).__name__)
            return None
    except Exception as e:
        await hass.async_add_executor_job(_LOGGER.error, "[MiWiFi] ❌ Error reading manual MAC: %s", e)
        return None


async def async_clear_manual_main_mac(hass: HomeAssistant):
    """Remove stored MAC file."""
    path = hass.config.path(MAIN_ROUTER_STORE_FILE)
    try:
        if os.path.exists(path):
            await hass.async_add_executor_job(os.remove, path)
            await hass.async_add_executor_job(_LOGGER.info, "[MiWiFi] 🗑️Manual MAC file deleted: %s", path)
    except Exception as e:
        await hass.async_add_executor_job(_LOGGER.error, "[MiWiFi] ❌ Error deleting file from MAC manually: %s", e)

