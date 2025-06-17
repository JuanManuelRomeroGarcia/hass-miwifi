from __future__ import annotations

import math
import time
from datetime import datetime
from typing import Any

from homeassistant import config_entries
from homeassistant.core import HomeAssistant
from homeassistant.helpers.json import JSONEncoder
from homeassistant.helpers.storage import Store
from homeassistant.loader import async_get_integration
from homeassistant.util import slugify
from httpx import codes

from .const import (
    DEFAULT_TIMEOUT,
    DOMAIN,
    MANUFACTURERS,
    STORAGE_VERSION,
    GLOBAL_LOG_STORE,
    CONF_LOG_LEVEL,
    DEFAULT_LOG_LEVEL,
    GLOBAL_PANEL_STORE,
    DEFAULT_ENABLE_PANEL,
)
from .updater import LuciUpdater


# ────────────────────────────────────────────────────────────────────────────────
# CONFIGURATION HELPER
# ────────────────────────────────────────────────────────────────────────────────

def get_config_value(
    config_entry: config_entries.ConfigEntry | None, param: str, default=None
) -> Any:
    """Get current value for configuration parameter."""
    return (
        config_entry.options.get(param, config_entry.data.get(param, default))
        if config_entry is not None
        else default
    )


async def async_verify_access(
    hass: HomeAssistant,
    ip: str,
    password: str,
    encryption: str,
    timeout: int = DEFAULT_TIMEOUT,
) -> codes:
    """Verify IP and password against the router."""
    updater = LuciUpdater(
        hass=hass,
        ip=ip,
        password=password,
        encryption=encryption,
        timeout=timeout,
        is_only_login=True,
    )
    await updater.async_request_refresh()
    await updater.async_stop()
    return updater.code


async def async_user_documentation_url(hass: HomeAssistant) -> str:
    """Return documentation URL for the integration."""
    integration = await async_get_integration(hass, DOMAIN)
    return f"{integration.documentation}"


async def async_get_version(hass: HomeAssistant) -> str:
    """Return current integration version."""
    integration = await async_get_integration(hass, DOMAIN)
    return f"{integration.version}"


def generate_entity_id(entity_id_format: str, mac: str, name: str | None = None) -> str:
    """Generate a slugified entity ID based on MAC and optional name."""
    _name: str = f"_{name}" if name is not None else ""
    return entity_id_format.format(slugify(f"miwifi_{mac}{_name}".lower()))


def get_store(hass: HomeAssistant, ip: str) -> Store:
    """Create a Store object for a given IP address."""
    return Store(hass, STORAGE_VERSION, f"{DOMAIN}/{ip}.json", encoder=JSONEncoder)


def parse_last_activity(last_activity: str) -> int:
    """Convert last activity datetime string to timestamp."""
    return int(
        time.mktime(datetime.strptime(last_activity, "%Y-%m-%dT%H:%M:%S").timetuple())
    )


def pretty_size(speed: float) -> str:
    """Convert speed in bytes/s to human-readable form."""
    if speed == 0.0:
        return "0 B/s"
    _unit = ("B/s", "KB/s", "MB/s", "GB/s")
    _i = int(math.floor(math.log(speed, 1024)))
    _p = math.pow(1024, _i)
    return f"{round(speed / _p, 2)} {_unit[_i]}"


def detect_manufacturer(mac: str) -> str | None:
    """Get manufacturer based on MAC address prefix."""
    identifier: str = mac.replace(":", "").upper()[:6]
    return MANUFACTURERS[identifier] if identifier in MANUFACTURERS else None


# ────────────────────────────────────────────────────────────────────────────────
# GLOBAL CONFIGURATION STATE (CACHED)
# ────────────────────────────────────────────────────────────────────────────────

_global_log_level_cache: str | None = None
_global_panel_state_cache: bool | None = None


async def get_global_log_level(hass: HomeAssistant) -> str:
    """Get global log level from Store."""
    global _global_log_level_cache
    if _global_log_level_cache is not None:
        return _global_log_level_cache

    store = Store(hass, 1, GLOBAL_LOG_STORE)
    data = await store.async_load()
    if not data:
        await store.async_save({CONF_LOG_LEVEL: DEFAULT_LOG_LEVEL})
        _global_log_level_cache = DEFAULT_LOG_LEVEL
        return DEFAULT_LOG_LEVEL

    _global_log_level_cache = data.get(CONF_LOG_LEVEL, DEFAULT_LOG_LEVEL)
    return _global_log_level_cache


async def set_global_log_level(hass: HomeAssistant, level: str) -> None:
    """Set global log level into Store."""
    global _global_log_level_cache
    _global_log_level_cache = level
    store = Store(hass, 1, GLOBAL_LOG_STORE)
    await store.async_save({CONF_LOG_LEVEL: level})


async def get_global_panel_state(hass: HomeAssistant) -> bool:
    """Get the global panel enable state."""
    global _global_panel_state_cache
    if _global_panel_state_cache is not None:
        return _global_panel_state_cache

    store = Store(hass, 1, GLOBAL_PANEL_STORE)
    data = await store.async_load()
    if not data:
        await store.async_save({"enabled": DEFAULT_ENABLE_PANEL})
        _global_panel_state_cache = DEFAULT_ENABLE_PANEL
        return DEFAULT_ENABLE_PANEL

    _global_panel_state_cache = data.get("enabled", DEFAULT_ENABLE_PANEL)
    return _global_panel_state_cache


async def set_global_panel_state(hass: HomeAssistant, enabled: bool) -> None:
    """Set the global panel enable state."""
    global _global_panel_state_cache
    _global_panel_state_cache = enabled
    store = Store(hass, 1, GLOBAL_PANEL_STORE)
    await store.async_save({"enabled": enabled})

def map_signal_quality(signal: int) -> str:
    """Map numeric signal (0-100) to quality."""
    
    if signal >= 70:
        return "very_strong"
    elif signal >= 50:
        return "strong"
    elif signal >= 30:
        return "fair"
    elif signal >= 10:
        return "weak"
    else:
        return "no_signal"
