"""Self check."""

from __future__ import annotations

import urllib.parse
from typing import Final

from .logger import _LOGGER
from .const import DOMAIN, NAME
from .exceptions import LuciError
from .luci import LuciClient

import homeassistant.components.persistent_notification as pn
from homeassistant.core import HomeAssistant
from homeassistant.loader import async_get_integration

SELF_CHECK_METHODS: Final = (
    ("xqsystem/login", "🟢"),
    ("xqsystem/init_info", "🟢"),
    ("misystem/status", "status"),
    ("xqnetwork/mode", "mode"),
    ("xqnetwork/get_netmode", "netmode"),
    ("xqsystem/vpn_status", "vpn_status"),
    ("misystem/topo_graph", "topo_graph"),
    ("xqsystem/check_rom_update", "rom_update"),
    ("xqnetwork/wan_info", "wan_info"),
    ("misystem/led", "led"),
    ("xqnetwork/wifi_detail_all", "wifi_detail_all"),
    ("xqnetwork/wifi_diag_detail_all", "wifi_diag_detail_all"),
    ("xqnetwork/avaliable_channels", "avaliable_channels"),
    ("xqnetwork/wifi_connect_devices", "wifi_connect_devices"),
    ("misystem/devicelist", "device_list"),
    ("xqnetwork/wifiap_signal", "wifi_ap_signal"),
    ("misystem/newstatus", "new_status"),
    ("xqsystem/reboot", "⚪"),
    ("xqsystem/upgrade_rom", "⚪"),
    ("xqsystem/flash_permission", "⚪"),
    ("xqnetwork/set_wifi", "⚪"),
    ("xqnetwork/set_wifi_without_restart", "⚪"),
)


from .frontend import read_local_version

async def async_self_check(hass: HomeAssistant, client: LuciClient, model: str) -> None:
    """Perform a self check against known router API methods."""

    results: dict[str, str] = {}

    for path, status in SELF_CHECK_METHODS:
        if status in {"🟢", "🔴", "⚪"}:
            results[path] = status
            continue

        try:
            method = getattr(client, status, None)
            if callable(method):
                await method()
                results[path] = "🟢"
            else:
                results[path] = "❓"
        except LuciError as e:
            _LOGGER.warning("❌ Self check failed for %s: %s", path, e)
            results[path] = "🔴"

    # Get versions safely
    integration = await async_get_integration(hass, DOMAIN)
    ha_version = getattr(hass.config, "version", "unknown")
    try:
        panel_version = await read_local_version(hass)
    except Exception as e:
        _LOGGER.warning("[MiWiFi] Could not read panel version: %s", e)
        panel_version = "unknown"

    # Format message
    title = f"Router not supported.\n\nModel: {model}"
    checklist = "\n".join(f" * {method}: {icon}" for method, icon in results.items())

    versions = (
        f"\n\nVersions:\n"
        f" * MiWiFi Integration: {integration.version}\n"
        f" * Frontend Panel: {panel_version}\n"
        f" * Home Assistant: {ha_version}"
    )

    message = f"{title}\n\nCheck list:\n{checklist}{versions}\n\n"

    # GitHub issue link
    issue_url = (
        f"{integration.issue_tracker}/new?title="
        + urllib.parse.quote_plus(f"Add support for {model}")
        + "&body="
        + urllib.parse.quote_plus(message)
    )

    message += f'<a href="{issue_url}" target="_blank">Create an issue with this data</a>'

    pn.async_create(hass, message, NAME)
