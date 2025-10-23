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
from httpx import codes, HTTPError, ConnectError, TimeoutException

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
    STORE_AUTO_PURGE,
    DEFAULT_AUTO_PURGE_AT,
    DEFAULT_AUTO_PURGE_EVERY_DAYS,
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
    protocol: str = None,
) -> tuple[codes, str]:
    """Verify IP and password against the router and return code + reason."""
    from .logger import _LOGGER  # Asegura que _LOGGER esté disponible aquí

    # Import DEFAULT_PROTOCOL here to avoid circular import
    from .const import DEFAULT_PROTOCOL
    
    updater = LuciUpdater(
        hass=hass,
        ip=ip,
        password=password,
        encryption=encryption,
        timeout=timeout,
        protocol=protocol or DEFAULT_PROTOCOL,
        is_only_login=True,
    )

    try:
        await updater.async_request_refresh()
        await updater.async_stop()
        await hass.async_add_executor_job(_LOGGER.debug, "[MiWiFi] Login OK - código %s", updater.code)
        return updater.code, ""
    
    except (ConnectError, TimeoutException) as e:
        await hass.async_add_executor_job(_LOGGER.error, "[MiWiFi] Error de conexión o timeout con %s: %s", ip, str(e))
        return codes.REQUEST_TIMEOUT, str(e)

    except HTTPError as e:
        await hass.async_add_executor_job(_LOGGER.error, "[MiWiFi] Error HTTP con %s: %s", ip, str(e))
        return codes.SERVICE_UNAVAILABLE, str(e)

    except Exception as e:
        await hass.async_add_executor_job(_LOGGER.exception, "[MiWiFi] Error inesperado durante el login con %s", ip)
        return codes.INTERNAL_SERVER_ERROR, str(e)



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
    
def _auto_purge_store(hass: HomeAssistant) -> Store:
    return Store(hass, STORAGE_VERSION, f"{DOMAIN}/{STORE_AUTO_PURGE}")

def _normalize_time_str(v: str | None) -> str:
    "Returns normalized time 'HH:MM' (accepts 'HH:MM' or 'HH:MM:SS')."
    if not v:
        return DEFAULT_AUTO_PURGE_AT
    parts = str(v).split(":")
    try:
        hh = int(parts[0])
        mm = int(parts[1]) if len(parts) > 1 else 0
    except Exception:
        return DEFAULT_AUTO_PURGE_AT
    return f"{hh:02d}:{mm:02d}"

async def get_global_auto_purge(hass: HomeAssistant) -> dict:
    "Reads the global config; if any keys are missing, adds them and persists."
    data = await _auto_purge_store(hass).async_load() or {}
    changed = False
    if "every_days" not in data:
        data["every_days"] = DEFAULT_AUTO_PURGE_EVERY_DAYS
        changed = True
    if "at" not in data:
        data["at"] = DEFAULT_AUTO_PURGE_AT
        changed = True

    norm_at = _normalize_time_str(data.get("at"))
    if norm_at != data.get("at"):
        data["at"] = norm_at
        changed = True
    if changed:
        await _auto_purge_store(hass).async_save(data)
    return data

async def set_global_auto_purge(
    hass: HomeAssistant,
    *, every_days: int | None = None,
    at: str | None = None
) -> dict:
    "Updates and persists the global autopurge configuration."
    data = await get_global_auto_purge(hass)
    if every_days is not None:
        data["every_days"] = int(every_days)
    if at is not None:
        data["at"] = _normalize_time_str(at)
    await _auto_purge_store(hass).async_save(data)
    return data
