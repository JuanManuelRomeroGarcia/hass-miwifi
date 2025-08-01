"""Initialize the MiWiFi integration."""

from __future__ import annotations

import asyncio
import logging
import traceback

from homeassistant.config_entries import ConfigEntry
from homeassistant.components import websocket_api
from homeassistant.const import (
    CONF_IP_ADDRESS,
    CONF_PASSWORD,
    CONF_SCAN_INTERVAL,
    CONF_TIMEOUT,
    EVENT_HOMEASSISTANT_STOP,
)
from homeassistant.core import CALLBACK_TYPE, Event, HomeAssistant, ServiceCall
from homeassistant.exceptions import PlatformNotReady

from .const import (
    CONF_ACTIVITY_DAYS,
    CONF_ENCRYPTION_ALGORITHM,
    CONF_IS_FORCE_LOAD,
    CONF_ENABLE_PANEL,
    CONF_WAN_SPEED_UNIT,
    CONF_LOG_LEVEL,
    DEFAULT_ACTIVITY_DAYS,
    DEFAULT_ENABLE_PANEL,
    DEFAULT_SCAN_INTERVAL,
    DEFAULT_SLEEP,
    DEFAULT_TIMEOUT,
    DOMAIN,
    OPTION_IS_FROM_FLOW,
    PLATFORMS,
    UPDATE_LISTENER,
    UPDATER,
)
from .logger import _LOGGER
from . import ws_api
from .discovery import async_start_discovery
from .enum import EncryptionAlgorithm
from .helper import (
    get_config_value,
    get_store,
    get_global_log_level,
    set_global_log_level,
    get_global_panel_state,
    set_global_panel_state,
)
from .services import SERVICES
from .updater import LuciUpdater
from .frontend import (
    async_download_panel_if_needed,
    async_register_panel,
    async_remove_miwifi_panel,
    read_local_version,
    async_start_panel_monitor
)


async def async_setup(hass: HomeAssistant, config: dict) -> bool:
    """Initialize domain level services."""
    
    from .logger import async_init_log_handlers
    await async_init_log_handlers(hass) 

    async def handle_apply_config(service_call: ServiceCall) -> None:
        data = service_call.data
        log_level = data.get("log_level")
        speed_unit = data.get("speed_unit")
        panel_active = data.get("panel_active")

        
        if log_level:
            await set_global_log_level(hass, log_level)
        if panel_active is not None:
            await set_global_panel_state(hass, panel_active)

        
        for entry in hass.config_entries.async_entries(DOMAIN):
            new_options = {**entry.options}
            if log_level:
                new_options[CONF_LOG_LEVEL] = log_level
            if speed_unit:
                new_options[CONF_WAN_SPEED_UNIT] = speed_unit
            if panel_active is not None:
                new_options[CONF_ENABLE_PANEL] = panel_active
            hass.config_entries.async_update_entry(entry, options=new_options)


        await asyncio.gather(*[
            hass.config_entries.async_reload(entry.entry_id)
            for entry in hass.config_entries.async_entries(DOMAIN)
        ])

    if not hass.services.has_service(DOMAIN, "apply_config"):
        hass.services.async_register(DOMAIN, "apply_config", handle_apply_config)
        
    # 📡 Websocket command for downloading logs
    websocket_api.async_register_command(hass, ws_api.handle_get_download_url)

    return True


async def async_setup_entry(hass: HomeAssistant, entry: ConfigEntry) -> bool:
    async_start_discovery(hass)

    # Config level log
    log_level = await get_global_log_level(hass)
    _LOGGER.setLevel(getattr(logging, log_level.upper(), logging.WARNING))

    # Config panel Frontend
    try:
        panel_enabled = await get_global_panel_state(hass)
        if panel_enabled:
            local_version = await read_local_version(hass)
            await async_register_panel(hass, local_version)

            await async_start_panel_monitor(hass)

        else:
            await async_remove_miwifi_panel(hass)
    except Exception as e:
        await hass.async_add_executor_job(_LOGGER.warning, f"[MiWiFi] Error managing the panel: {e}")


    is_new = get_config_value(entry, OPTION_IS_FROM_FLOW, False)
    if is_new:
        hass.config_entries.async_update_entry(entry, data=entry.data, options={})

    _ip = get_config_value(entry, CONF_IP_ADDRESS)

    _updater = LuciUpdater(
        hass,
        _ip,
        get_config_value(entry, CONF_PASSWORD),
        get_config_value(entry, CONF_ENCRYPTION_ALGORITHM, EncryptionAlgorithm.SHA1),
        get_config_value(entry, CONF_SCAN_INTERVAL, DEFAULT_SCAN_INTERVAL),
        get_config_value(entry, CONF_TIMEOUT, DEFAULT_TIMEOUT),
        get_config_value(entry, CONF_IS_FORCE_LOAD, False),
        get_config_value(entry, CONF_ACTIVITY_DAYS, DEFAULT_ACTIVITY_DAYS),
        get_store(hass, _ip),
        entry_id=entry.entry_id,
    )

    hass.data.setdefault(DOMAIN, {})
    hass.data[DOMAIN][entry.entry_id] = {
        CONF_IP_ADDRESS: _ip,
        UPDATER: _updater,
    }
    hass.data[DOMAIN][entry.entry_id][UPDATE_LISTENER] = entry.add_update_listener(
        async_update_options
    )

    await _updater.async_config_entry_first_refresh()
    if not _updater.last_update_success:
        if _updater.last_exception is not None:
            raise PlatformNotReady from _updater.last_exception
        raise PlatformNotReady

    if not is_new:
        await asyncio.sleep(DEFAULT_SLEEP)

    await hass.config_entries.async_forward_entry_setups(entry, PLATFORMS)

    async def async_stop(event: Event) -> None:
        await _updater.async_stop()

    hass.bus.async_listen_once(EVENT_HOMEASSISTANT_STOP, async_stop)

    for service_name, service in SERVICES:
        if not hass.services.has_service(DOMAIN, service_name):
            hass.services.async_register(
                DOMAIN, service_name, service(hass).async_call_service, service.schema
            )

    return True


async def async_update_options(hass: HomeAssistant, entry: ConfigEntry) -> None:
    if entry.entry_id not in hass.data.get(DOMAIN, {}):
        return

    try:
        panel_enabled = await get_global_panel_state(hass)
        if panel_enabled:
            local_version = await read_local_version(hass)
            await async_register_panel(hass, local_version)

            await async_start_panel_monitor(hass)

        else:
            await async_remove_miwifi_panel(hass)
    except Exception as e:
         await hass.async_add_executor_job(_LOGGER.warning, f"[MiWiFi] Error managing the panel: {e}")

    await asyncio.gather(*[
        hass.config_entries.async_reload(e.entry_id)
        for e in hass.config_entries.async_entries(DOMAIN)
    ])


async def async_unload_entry(hass: HomeAssistant, entry: ConfigEntry) -> bool:
    if is_unload := await hass.config_entries.async_unload_platforms(entry, PLATFORMS):
        _updater = hass.data[DOMAIN][entry.entry_id][UPDATER]
        await _updater.async_stop()
        _update_listener: CALLBACK_TYPE = hass.data[DOMAIN][entry.entry_id][UPDATE_LISTENER]
        _update_listener()
        hass.data[DOMAIN].pop(entry.entry_id)
    return is_unload


async def async_remove_entry(hass: HomeAssistant, entry: ConfigEntry) -> None:
    _updater = hass.data[DOMAIN][entry.entry_id][UPDATER]
    await _updater.async_stop(clean_store=True)