from __future__ import annotations
import contextlib
import homeassistant.helpers.config_validation as cv
import voluptuous as vol
from homeassistant import config_entries
from homeassistant.components import dhcp, ssdp
from homeassistant.const import (
    CONF_IP_ADDRESS,
    CONF_PASSWORD,
    CONF_SCAN_INTERVAL,
    CONF_TIMEOUT,
)
from homeassistant.core import callback
from homeassistant.data_entry_flow import FlowResult
from httpx import codes

try:
    from .logger import _LOGGER
except Exception:
    import logging
    _LOGGER = logging.getLogger(__name__)

from .const import (
    CONF_ACTIVITY_DAYS,
    CONF_ENCRYPTION_ALGORITHM,
    CONF_IS_FORCE_LOAD,
    CONF_IS_TRACK_DEVICES,
    CONF_PROTOCOL,
    CONF_STAY_ONLINE,
    DEFAULT_ACTIVITY_DAYS,
    DEFAULT_PROTOCOL,
    DEFAULT_SCAN_INTERVAL,
    DEFAULT_STAY_ONLINE,
    DEFAULT_TIMEOUT,
    DOMAIN,
    OPTION_IS_FROM_FLOW,
    CONF_WAN_SPEED_UNIT,
    DEFAULT_WAN_SPEED_UNIT,
    WAN_SPEED_UNIT_OPTIONS,
    CONF_LOG_LEVEL,
    LOG_LEVEL_OPTIONS,
    CONF_ENABLE_PANEL,
    CONF_AUTO_PURGE_EVERY_DAYS, 
    DEFAULT_AUTO_PURGE_EVERY_DAYS,
    CONF_AUTO_PURGE_AT, 
    DEFAULT_AUTO_PURGE_AT,
    PROTOCOL_OPTIONS,
    CONF_ENABLE_DEVICE_SENSORS,
    DEFAULT_ENABLE_DEVICE_SENSORS,
    CONF_ENABLE_PORT_PROBE,
    DEFAULT_ENABLE_PORT_PROBE,


)
from .discovery import async_start_discovery
from .enum import EncryptionAlgorithm
from .helper import (
    async_user_documentation_url,
    async_verify_access,
    get_config_value,
    get_global_log_level,
    set_global_log_level,
    get_global_panel_state,
    set_global_panel_state,
    get_global_auto_purge,
    set_global_auto_purge
)

from .updater import LuciUpdater, async_get_updater


class MiWifiConfigFlow(config_entries.ConfigFlow, domain=DOMAIN):
    _discovered_device: dict | None = None

    @staticmethod
    @callback
    def async_get_options_flow(config_entry: config_entries.ConfigEntry) -> MiWifiOptionsFlow:
        return MiWifiOptionsFlow(config_entry)

    async def async_step_ssdp(self, discovery_info: ssdp.SsdpServiceInfo) -> FlowResult:
        return await self._async_discovery_handoff()

    async def async_step_dhcp(self, discovery_info: dhcp.DhcpServiceInfo) -> FlowResult:
        return await self._async_discovery_handoff()

    async def _async_discovery_handoff(self) -> FlowResult:
        async_start_discovery(self.hass)
        return self.async_abort(reason="discovery_started")

    async def async_step_integration_discovery(self, discovery_info: dict) -> FlowResult:
        await self.async_set_unique_id(discovery_info[CONF_IP_ADDRESS])
        self._abort_if_unique_id_configured()
        self._discovered_device = discovery_info
        return await self.async_step_discovery_confirm()

    async def async_step_user(self, user_input=None, errors=None) -> FlowResult:
        errors = errors or {}
        return await self._show_form(user_input, errors, step_id="discovery_confirm")

    async def async_step_discovery_confirm(self, user_input=None) -> FlowResult:
        errors = {}
        if user_input is not None:
            if self._discovered_device is None:
                await self.async_set_unique_id(user_input[CONF_IP_ADDRESS])
                self._abort_if_unique_id_configured()

            code, reason = await async_verify_access(
                self.hass,
                user_input[CONF_IP_ADDRESS],
                user_input[CONF_PASSWORD],
                user_input[CONF_ENCRYPTION_ALGORITHM],
                user_input[CONF_TIMEOUT],
                user_input.get(CONF_PROTOCOL, DEFAULT_PROTOCOL),
            )

            if codes.is_success(code):
                return self.async_create_entry(
                    title=user_input[CONF_IP_ADDRESS],
                    data=user_input,
                    options={OPTION_IS_FROM_FLOW: True},
                )

            await self.hass.async_add_executor_job(_LOGGER.error, "[MiWiFi] Access to router %s failed with code %s and reason: %s",
                user_input[CONF_IP_ADDRESS], code, reason or "No details")

            errors["base"] = {
                codes.CONFLICT: "router.not.supported",
                codes.FORBIDDEN: "password.not_matched",
            }.get(code)

            if errors["base"] is None:
                final_reason = reason or "Unknown"
                await self.hass.async_add_executor_job(_LOGGER.error, "[MiWiFi] Router access failed (%s): %s", user_input[CONF_IP_ADDRESS], final_reason)
                errors["base"] = f"router.error_with_reason::{final_reason}"

        return await self._show_form(user_input, errors, step_id="discovery_confirm")

    async def _show_form(self, user_input, errors, step_id: str) -> FlowResult:
        defaults = self._discovered_device or {}
        ip = defaults.get(CONF_IP_ADDRESS, "")
        model = defaults.get("model", "MiWiFi")

        panel_state = await get_global_panel_state(self.hass)
        log_level = await get_global_log_level(self.hass)

        schema_dict = {
            vol.Required(CONF_IP_ADDRESS, default=ip): str,
            vol.Required(CONF_PASSWORD): str,
            vol.Required(CONF_ENCRYPTION_ALGORITHM, default=EncryptionAlgorithm.SHA1): vol.In([
                EncryptionAlgorithm.SHA1, EncryptionAlgorithm.SHA256
            ]),
            vol.Required(CONF_PROTOCOL, default=DEFAULT_PROTOCOL): vol.In(PROTOCOL_OPTIONS),
            vol.Required(CONF_IS_TRACK_DEVICES, default=True): cv.boolean,
            vol.Required(CONF_STAY_ONLINE, default=DEFAULT_STAY_ONLINE): cv.positive_int,
            vol.Required(CONF_SCAN_INTERVAL, default=DEFAULT_SCAN_INTERVAL): vol.All(vol.Coerce(int), vol.Range(min=10)),
            vol.Required(CONF_TIMEOUT, default=DEFAULT_TIMEOUT): vol.All(vol.Coerce(int), vol.Range(min=10)),
            vol.Optional(CONF_ENABLE_DEVICE_SENSORS, default=DEFAULT_ENABLE_DEVICE_SENSORS): cv.boolean,
            
        }

        if step_id == "discovery_confirm":
            schema_dict[vol.Optional(CONF_ENABLE_PANEL, default=panel_state)] = cv.boolean
            schema_dict[vol.Optional(CONF_WAN_SPEED_UNIT, default=DEFAULT_WAN_SPEED_UNIT)] = vol.In(WAN_SPEED_UNIT_OPTIONS)
            schema_dict[vol.Optional(CONF_LOG_LEVEL, default=log_level)] = vol.In(LOG_LEVEL_OPTIONS)
            schema_dict[vol.Optional(CONF_ENABLE_PORT_PROBE, default=DEFAULT_ENABLE_PORT_PROBE)] = cv.boolean

        schema = vol.Schema(schema_dict)

        description_placeholders = None
        if step_id == "discovery_confirm":
            description_placeholders = {
                "name": f"{model} ({ip})",
                "ip_address": ip,
                "local_user_documentation_url": await async_user_documentation_url(self.hass),
            }

        if "base" in errors and "::" in errors["base"]:
            error_key, reason = errors["base"].split("::", 1)
            errors["base"] = error_key
            description_placeholders = description_placeholders or {}
            description_placeholders["reason"] = reason
            await self.hass.async_add_executor_job(_LOGGER.error, "[MiWiFi] Final Reason Placeholder: %s", description_placeholders.get("reason"))
        
        elif errors.get("base") == "router.error_with_reason":
            description_placeholders = description_placeholders or {}
            description_placeholders.setdefault("reason", "Unknown error")
            await self.hass.async_add_executor_job(_LOGGER.warning, "[MiWiFi] Default reason added for error_with_reason")

            
        if "base" in errors:
            await self.hass.async_add_executor_job(_LOGGER.error, "[MiWiFi] Base error received: %s", errors["base"])
            if "::" in errors["base"]:
                await self.hass.async_add_executor_job(_LOGGER.error, "[MiWiFi] Separating key and error reason: %s", errors["base"])


        return self.async_show_form(
            step_id=step_id,
            data_schema=schema,
            errors=errors,
            description_placeholders=description_placeholders,
        )



class MiWifiOptionsFlow(config_entries.OptionsFlow):
    def __init__(self, config_entry: config_entries.ConfigEntry) -> None:
        self._config_entry = config_entry

    async def async_step_init(self, user_input: dict | None = None) -> FlowResult:
        errors: dict[str, str] = {}

        if user_input is not None:
            if CONF_LOG_LEVEL in user_input:
                await set_global_log_level(self.hass, user_input[CONF_LOG_LEVEL])

            if CONF_ENABLE_PANEL in user_input:
                await set_global_panel_state(self.hass, user_input[CONF_ENABLE_PANEL])

            code, reason = await async_verify_access(
                self.hass,
                user_input[CONF_IP_ADDRESS],
                user_input[CONF_PASSWORD],
                user_input[CONF_ENCRYPTION_ALGORITHM],
                user_input[CONF_TIMEOUT],
                user_input.get(CONF_PROTOCOL, DEFAULT_PROTOCOL),
            )

            if codes.is_success(code):
                at_val = user_input.get(CONF_AUTO_PURGE_AT)
                if isinstance(at_val, str) and len(at_val) == 8:
                    at_val = at_val[:5]  # HH:MM:SS -> HH:MM

                await set_global_auto_purge(
                    self.hass,
                    every_days=user_input.get(CONF_AUTO_PURGE_EVERY_DAYS),
                    at=at_val,
                )

                for e in self.hass.config_entries.async_entries(DOMAIN):
                    new_opts = dict(e.options)
                    if CONF_AUTO_PURGE_EVERY_DAYS in user_input:
                        new_opts[CONF_AUTO_PURGE_EVERY_DAYS] = int(user_input[CONF_AUTO_PURGE_EVERY_DAYS])
                    if CONF_AUTO_PURGE_AT in user_input and at_val:
                        new_opts[CONF_AUTO_PURGE_AT] = at_val
                    self.hass.config_entries.async_update_entry(e, options=new_opts)

                await self.async_update_unique_id(user_input[CONF_IP_ADDRESS])
                return self.async_create_entry(title=user_input[CONF_IP_ADDRESS], data=user_input)

            await self.hass.async_add_executor_job(
                _LOGGER.warning,
                "[MiWiFi] Re-auth failed for %s with code %s and reason: %s",
                user_input[CONF_IP_ADDRESS],
                code,
                reason or "No details"
            )

            errors["base"] = {
                codes.CONFLICT: "router.not.supported",
                codes.FORBIDDEN: "password.not_matched",
            }.get(code)

            if errors["base"] is None:
                self._last_reason = reason or "Unknown"
                await self.hass.async_add_executor_job(
                    _LOGGER.warning,
                    "[MiWiFi] Router re-auth failed (%s): %s",
                    user_input[CONF_IP_ADDRESS],
                    self._last_reason
                )
                errors["base"] = "router.error_with_reason"

        return self.async_show_form(
            step_id="init",
            data_schema=await self._get_options_schema(),
            errors=errors
        )

    async def async_update_unique_id(self, unique_id: str) -> None:
        if self._config_entry.unique_id == unique_id:
            return

        for flow in self.hass.config_entries.flow.async_progress(True):
            if flow["flow_id"] != self.flow_id and flow["context"].get("unique_id") == unique_id:
                self.hass.config_entries.flow.async_abort(flow["flow_id"])

        self.hass.config_entries.async_update_entry(self._config_entry, unique_id=unique_id)

    async def _get_options_schema(self) -> vol.Schema:
        """Generate the schema for the options form."""
        try:
            panel_state = await get_global_panel_state(self.hass)
            log_level = await get_global_log_level(self.hass)
            global_cfg = await get_global_auto_purge(self.hass)
            ap_every = int(global_cfg.get("every_days", DEFAULT_AUTO_PURGE_EVERY_DAYS))
            ap_at = str(global_cfg.get("at", DEFAULT_AUTO_PURGE_AT))

            schema: dict = {
                vol.Required(CONF_IP_ADDRESS, default=get_config_value(self._config_entry, CONF_IP_ADDRESS, "")): str,
                vol.Required(CONF_PASSWORD, default=get_config_value(self._config_entry, CONF_PASSWORD, "")): str,
                vol.Required(CONF_ENCRYPTION_ALGORITHM, default=get_config_value(
                    self._config_entry, CONF_ENCRYPTION_ALGORITHM, EncryptionAlgorithm.SHA1
                )): vol.In([EncryptionAlgorithm.SHA1, EncryptionAlgorithm.SHA256]),
                vol.Required(CONF_PROTOCOL, default=get_config_value(
                    self._config_entry, CONF_PROTOCOL, DEFAULT_PROTOCOL
                )): vol.In(PROTOCOL_OPTIONS),
                vol.Optional(CONF_ENABLE_PANEL, default=panel_state): cv.boolean,
                vol.Required(CONF_IS_TRACK_DEVICES, default=get_config_value(self._config_entry, CONF_IS_TRACK_DEVICES, True)): cv.boolean,
                vol.Required(CONF_STAY_ONLINE, default=get_config_value(self._config_entry, CONF_STAY_ONLINE, DEFAULT_STAY_ONLINE)): cv.positive_int,
                vol.Required(CONF_SCAN_INTERVAL, default=get_config_value(self._config_entry, CONF_SCAN_INTERVAL, DEFAULT_SCAN_INTERVAL)): vol.All(vol.Coerce(int), vol.Range(min=10)),
                vol.Optional(CONF_ACTIVITY_DAYS, default=get_config_value(self._config_entry, CONF_ACTIVITY_DAYS, DEFAULT_ACTIVITY_DAYS)): cv.positive_int,
                vol.Optional(CONF_TIMEOUT, default=get_config_value(self._config_entry, CONF_TIMEOUT, DEFAULT_TIMEOUT)): vol.All(vol.Coerce(int), vol.Range(min=10)),
                vol.Optional(CONF_WAN_SPEED_UNIT, default=get_config_value(self._config_entry, CONF_WAN_SPEED_UNIT, DEFAULT_WAN_SPEED_UNIT)): vol.In(WAN_SPEED_UNIT_OPTIONS),
                vol.Optional(CONF_AUTO_PURGE_EVERY_DAYS, default=ap_every): vol.All(vol.Coerce(int), vol.Range(min=1, max=3650)),
                vol.Optional(CONF_AUTO_PURGE_AT, default=ap_at): str,
                vol.Optional(CONF_ENABLE_DEVICE_SENSORS,default=get_config_value(self._config_entry,CONF_ENABLE_DEVICE_SENSORS,DEFAULT_ENABLE_DEVICE_SENSORS,),): cv.boolean,
                vol.Optional(CONF_ENABLE_PORT_PROBE, default=get_config_value(self._config_entry, CONF_ENABLE_PORT_PROBE, DEFAULT_ENABLE_PORT_PROBE)): cv.boolean,
            }

            with contextlib.suppress(ValueError):
                updater: LuciUpdater = async_get_updater(self.hass, self._config_entry.entry_id)
                if not updater.is_repeater:
                    schema[vol.Optional(CONF_LOG_LEVEL, default=log_level)] = vol.In(LOG_LEVEL_OPTIONS)
                    return vol.Schema(schema)

            schema |= {
                vol.Optional(CONF_IS_FORCE_LOAD, default=get_config_value(self._config_entry, CONF_IS_FORCE_LOAD, False)): cv.boolean,
                vol.Optional(CONF_LOG_LEVEL, default=log_level): vol.In(LOG_LEVEL_OPTIONS),
            }

            return vol.Schema(schema)
        except Exception as e:
            await self.hass.async_add_executor_job(_LOGGER.exception, "[MiWiFi] Error generating the options form: %s", e)
            raise
