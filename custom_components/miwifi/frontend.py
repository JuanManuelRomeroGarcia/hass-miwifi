"""Handle MiWiFi Frontend panel."""

import os
import json
import aiohttp

from homeassistant.core import HomeAssistant
from homeassistant.components.frontend import async_register_built_in_panel, async_remove_panel
from homeassistant.components.frontend import DATA_PANELS, Panel
from homeassistant.helpers.event import async_track_time_interval

from .const import (
    PANEL_REPO_VERSION_URL,
    PANEL_REPO_FILES_URL,
    PANEL_REPO_BASE_URL,
    PANEL_LOCAL_PATH,
    PANEL_STORAGE_FILE,
    DEFAULT_PANEL_VERSION,
    MAIN_ROUTER_STORE_FILE,
    PANEL_MONITOR_INTERVAL,
)
from .logger import _LOGGER


DEFAULT_PANEL_VERSION = "1.2.3" # Minimum version required v 1.2.3


async def async_download_panel_if_needed(hass: HomeAssistant) -> str:
    """Check and download panel if needed. Return the version."""
    if hass.data.get("_miwifi_panel_updating"):
        return await read_local_version(hass)

    hass.data["_miwifi_panel_updating"] = True
    async with aiohttp.ClientSession() as session:
        try:
            remote_version = await read_remote_version(session)
            local_version = await read_local_version(hass)

            if remote_version != local_version:
                _LOGGER.info(f"[MiWiFi] New panel version detected: {remote_version}, updating files...")
                await download_panel_files(hass, session, remote_version)
                await save_local_version(hass, remote_version)
            else:
                _LOGGER.info(f"[MiWiFi] Version {remote_version} detected, checking files...")
                await download_panel_files(hass, session, remote_version)

            return remote_version
        except Exception as e:
            _LOGGER.error(f"[MiWiFi] Error checking/downloading frontend panel: {e}")
            return "0.0"
        finally:
            hass.data["_miwifi_panel_updating"] = False


async def read_remote_version(session: aiohttp.ClientSession) -> str:
    async with session.get(PANEL_REPO_VERSION_URL) as resp:
        resp.raise_for_status()
        text = await resp.text()
        data = json.loads(text)
        return data.get("version", "0.0")


async def read_remote_files(session: aiohttp.ClientSession) -> list:
    async with session.get(PANEL_REPO_FILES_URL) as resp:
        resp.raise_for_status()
        text = await resp.text()
        data = json.loads(text)
        return data.get("files", [])


def _read_json_file(path: str) -> dict:
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def _write_json_file(path: str, data: dict) -> None:
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f)


def _read_binary_file(path: str) -> bytes:
    with open(path, "rb") as f:
        return f.read()


def _write_binary_file(path: str, content: bytes) -> None:
    with open(path, "wb") as f:
        f.write(content)


async def save_local_version(hass: HomeAssistant, version: str) -> None:
    path = hass.config.path(PANEL_STORAGE_FILE)
    os.makedirs(os.path.dirname(path), exist_ok=True)
    await hass.async_add_executor_job(_write_json_file, path, {"version": version})


async def read_local_version(hass: HomeAssistant) -> str:
    path = hass.config.path(PANEL_STORAGE_FILE)
    if not os.path.exists(path):
        _LOGGER.info(f"[MiWiFi] First installation detected, downloading frontend panel version {DEFAULT_PANEL_VERSION}")
        os.makedirs(os.path.dirname(path), exist_ok=True)

        async with aiohttp.ClientSession() as session:
            try:
                await download_panel_files(hass, session, DEFAULT_PANEL_VERSION)
                await hass.async_add_executor_job(_write_json_file, path, {"version": DEFAULT_PANEL_VERSION})
            except Exception as e:
                _LOGGER.error(f"[MiWiFi] Error downloading panel on first installation: {e}")
                return "0.0"

        return DEFAULT_PANEL_VERSION

    data = await hass.async_add_executor_job(_read_json_file, path)
    return data.get("version", DEFAULT_PANEL_VERSION)


async def download_panel_files(hass: HomeAssistant, session: aiohttp.ClientSession, remote_version: str) -> None:
    try:
        files = await read_remote_files(session)
    except Exception as e:
        _LOGGER.error(f"[MiWiFi] Error reading files.json: {e}")
        return

    for file in files:
        remote_url = f"{PANEL_REPO_BASE_URL}{file}"
        local_path = hass.config.path(PANEL_LOCAL_PATH, file)

        os.makedirs(os.path.dirname(local_path), exist_ok=True)

        async with session.get(remote_url) as resp:
            if resp.status != 200:
                _LOGGER.warning(f"[MiWiFi] Could not download {file} (status {resp.status})")
                continue

            remote_content = await resp.read()

            if file.endswith(".js"):
                content = remote_content.decode("utf-8").replace("__MIWIFI_VERSION__", remote_version)
                remote_content = content.encode("utf-8")

            if os.path.exists(local_path):
                existing_content = await hass.async_add_executor_job(_read_binary_file, local_path)
                if remote_content == existing_content:
                    continue

            await hass.async_add_executor_job(_write_binary_file, local_path, remote_content)
            _LOGGER.debug(f"[MiWiFi] File updated: {file}")


async def async_register_panel(hass: HomeAssistant, version: str) -> None:
    """Register the MiWiFi panel in Home Assistant, only once if needed."""
    panel_data = hass.data.get(DATA_PANELS, {}).get("miwifi")
    if isinstance(panel_data, Panel):
        config = getattr(panel_data, "config", {})
        current_url = config.get("_panel_custom", {}).get("module_url", "")
        expected_url = f"/local/miwifi/panel-frontend.js?v={version}"

        if current_url == expected_url:
            _LOGGER.debug("[MiWiFi] The panel is already registered with the current version.")
            return

    if panel_data is not None:
        try:
            await async_remove_panel(hass, "miwifi")
            _LOGGER.debug("[MiWiFi] Panel 'miwifi' deleted before registering a new one.")
        except Exception as e:
            _LOGGER.debug(f"[MiWiFi] Could not delete panel: {e}")
    else:
        _LOGGER.debug("[MiWiFi] The 'miwifi' panel was not registered, deletion skipped.")

    async_register_built_in_panel(
        hass,
        component_name="custom",
        sidebar_title="MiWiFi",
        sidebar_icon="mdi:router-network",
        frontend_url_path="miwifi",
        config={
            "_panel_custom": {
                "name": "miwifi-panel",
                "module_url": f"/local/miwifi/panel-frontend.js?v={version}",
                "embed_iframe": False,
                "trust_external_script": False,
            }
        },
        require_admin=True,
    )
    _LOGGER.info(f"[MiWiFi] Panel successfully registered with version: {version}")


async def async_remove_miwifi_panel(hass: HomeAssistant) -> None:
    """Remove the MiWiFi panel if it exists."""
    panels = hass.data.get(DATA_PANELS)

    if not panels or "miwifi" not in panels:
        _LOGGER.debug("[MiWiFi] Panel 'miwifi' not registered — skipping removal.")
        return

    try:
        await async_remove_panel(hass, "miwifi")
        _LOGGER.info("[MiWiFi] Panel successfully removed.")
    except Exception as e:
        _LOGGER.debug(f"[MiWiFi] Error deleting panel: {e}")
        

async def async_start_panel_monitor(hass):
    """Start periodic panel version monitoring."""

    async def _check_panel_version(now):
        try:
            local = await read_local_version(hass)
            async with aiohttp.ClientSession() as session:
                remote = await read_remote_version(session)
            if local != remote:
                _LOGGER.warning(f"[MiWiFi] New panel version available: {remote} (local: {local})")
            else:
                _LOGGER.debug(f"[MiWiFi] Panel up-to-date: {local}")
        except Exception as e:
            _LOGGER.warning(f"[MiWiFi] Panel monitor error: {e}")

    # Register periodic execution outside the try block
    async_track_time_interval(hass, _check_panel_version, PANEL_MONITOR_INTERVAL)


# ------- Persistence for Main Router Manual -------

async def async_save_manual_main_mac(hass: HomeAssistant, mac: str):
    """Save manually selected MAC to a JSON file."""
    path = hass.config.path(MAIN_ROUTER_STORE_FILE)
    try:
        os.makedirs(os.path.dirname(path), exist_ok=True)
        await hass.async_add_executor_job(_write_json_file, path, {"manual_main_mac": mac})
        _LOGGER.info("[MiWiFi] ✅ MAC Manual saved correctly in %s", path)
    except Exception as e:
        _LOGGER.error("[MiWiFi] ❌ Error saving file from manual MAC: %s", e)


async def async_load_manual_main_mac(hass: HomeAssistant) -> str | None:
    """Load manually selected MAC from file."""
    path = hass.config.path(MAIN_ROUTER_STORE_FILE)
    if not os.path.exists(path):
        _LOGGER.debug("[MiWiFi] No manual MAC file found at %s", path)
        return None
    try:
        data = await hass.async_add_executor_job(_read_json_file, path)
        if isinstance(data, dict):
            mac = data.get("manual_main_mac")
            _LOGGER.debug("[MiWiFi] ✅ MAC loaded from file: %s", mac)
            return mac
        else:
            _LOGGER.warning("[MiWiFi] ❌ Unexpected format in file: %s (expected: dict, received: %s)", path, type(data).__name__)
            return None
    except Exception as e:
        _LOGGER.error("[MiWiFi] ❌ Error reading manual MAC: %s", e)
        return None


async def async_clear_manual_main_mac(hass: HomeAssistant):
    """Remove stored MAC file."""
    path = hass.config.path(MAIN_ROUTER_STORE_FILE)
    try:
        if os.path.exists(path):
            await hass.async_add_executor_job(os.remove, path)
            _LOGGER.info("[MiWiFi] 🗑️Manual MAC file deleted: %s", path)
    except Exception as e:
        _LOGGER.error("[MiWiFi] ❌ Error deleting file from MAC manually: %s", e)


