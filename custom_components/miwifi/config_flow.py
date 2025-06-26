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

from .const import (
    CONF_ACTIVITY_DAYS,
    CONF_ENCRYPTION_ALGORITHM,
    CONF_IS_FORCE_LOAD,
    CONF_IS_TRACK_DEVICES,
    CONF_STAY_ONLINE,
    DEFAULT_ACTIVITY_DAYS,
    DEFAULT_SCAN_INTERVAL,
    DEFAULT_STAY_ONLINE,
    DEFAULT_TIMEOUT,
    DOMAIN,
    OPTION_IS_FROM_FLOW,
    CONF_WAN_SPEED_UNIT,
    DEFAULT_WAN_SPEED_UNIT,
    WAN_SPEED_UNIT_OPTIONS,
    CONF_LOG_LEVEL,
    DEFAULT_LOG_LEVEL,
    LOG_LEVEL_OPTIONS,
    CONF_ENABLE_PANEL,
    DEFAULT_ENABLE_PANEL,
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
)

from .logger import _LOGGER 
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

            code: codes = await async_verify_access(
                self.hass,
                user_input[CONF_IP_ADDRESS],
                user_input[CONF_PASSWORD],
                user_input[CONF_ENCRYPTION_ALGORITHM],
                user_input[CONF_TIMEOUT],
            )

            if codes.is_success(code):
                return self.async_create_entry(
                    title=user_input[CONF_IP_ADDRESS],
                    data=user_input,
                    options={OPTION_IS_FROM_FLOW: True},
                )

            errors["base"] = {
                codes.CONFLICT: "router.not.supported",
                codes.FORBIDDEN: "password.not_matched",
            }.get(code, "ip_address.not_matched")

        return await self._show_form(user_input, errors, step_id="discovery_confirm")

    async def _show_form(self, user_input, errors, step_id: str) -> FlowResult:
        defaults = self._discovered_device or {}
        ip = defaults.get(CONF_IP_ADDRESS, "")

        schema = vol.Schema({
            vol.Required(CONF_IP_ADDRESS, default=ip): str,
            vol.Required(CONF_PASSWORD): str,
            vol.Required(CONF_ENCRYPTION_ALGORITHM, default=EncryptionAlgorithm.SHA1): vol.In([
                EncryptionAlgorithm.SHA1, EncryptionAlgorithm.SHA256
            ]),
            vol.Required(CONF_IS_TRACK_DEVICES, default=True): cv.boolean,
            vol.Required(CONF_STAY_ONLINE, default=DEFAULT_STAY_ONLINE): cv.positive_int,
            vol.Required(CONF_SCAN_INTERVAL, default=DEFAULT_SCAN_INTERVAL): vol.All(vol.Coerce(int), vol.Range(min=10)),
            vol.Required(CONF_TIMEOUT, default=DEFAULT_TIMEOUT): vol.All(vol.Coerce(int), vol.Range(min=10)),
        })

        description_placeholders = None
        if step_id == "discovery_confirm":
            description_placeholders = {
                "name": ip,
                "ip_address": ip,
                "local_user_documentation_url": await async_user_documentation_url(self.hass),
            }

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
            # Solo guardamos valores globales
            if CONF_LOG_LEVEL in user_input:
                await set_global_log_level(self.hass, user_input[CONF_LOG_LEVEL])

            if CONF_ENABLE_PANEL in user_input:
                await set_global_panel_state(self.hass, user_input[CONF_ENABLE_PANEL])

            code: codes = await async_verify_access(
                self.hass,
                user_input[CONF_IP_ADDRESS],
                user_input[CONF_PASSWORD],
                user_input[CONF_ENCRYPTION_ALGORITHM],
                user_input[CONF_TIMEOUT],
            )

            if codes.is_success(code):
                await self.async_update_unique_id(user_input[CONF_IP_ADDRESS])
                return self.async_create_entry(title=user_input[CONF_IP_ADDRESS], data=user_input)

            errors["base"] = {
                codes.CONFLICT: "router.not.supported",
                codes.FORBIDDEN: "password.not_matched",
            }.get(code, "ip_address.not_matched")

        return self.async_show_form(step_id="init", data_schema=await self._get_options_schema(), errors=errors)

    async def async_update_unique_id(self, unique_id: str) -> None:
        if self._config_entry.unique_id == unique_id:
            return

        for flow in self.hass.config_entries.flow.async_progress(True):
            if flow["flow_id"] != self.flow_id and flow["context"].get("unique_id") == unique_id:
                self.hass.config_entries.flow.async_abort(flow["flow_id"])

        self.hass.config_entries.async_update_entry(self._config_entry, unique_id=unique_id)

    async def _get_options_schema(self) -> vol.Schema:
            try:

                panel_state = await get_global_panel_state(self.hass)
                log_level = await get_global_log_level(self.hass)

                schema: dict = {
                    vol.Required(CONF_IP_ADDRESS, default=get_config_value(self._config_entry, CONF_IP_ADDRESS, "")): str,
                    vol.Required(CONF_PASSWORD, default=get_config_value(self._config_entry, CONF_PASSWORD, "")): str,
                    vol.Required(CONF_ENCRYPTION_ALGORITHM, default=get_config_value(
                        self._config_entry, CONF_ENCRYPTION_ALGORITHM, EncryptionAlgorithm.SHA1
                    )): vol.In([EncryptionAlgorithm.SHA1, EncryptionAlgorithm.SHA256]),
                    vol.Optional(CONF_ENABLE_PANEL, default=panel_state): cv.boolean,
                    vol.Required(CONF_IS_TRACK_DEVICES, default=get_config_value(self._config_entry, CONF_IS_TRACK_DEVICES, True)): cv.boolean,
                    vol.Required(CONF_STAY_ONLINE, default=get_config_value(self._config_entry, CONF_STAY_ONLINE, DEFAULT_STAY_ONLINE)): cv.positive_int,
                    vol.Required(CONF_SCAN_INTERVAL, default=get_config_value(self._config_entry, CONF_SCAN_INTERVAL, DEFAULT_SCAN_INTERVAL)): vol.All(vol.Coerce(int), vol.Range(min=10)),
                    vol.Optional(CONF_ACTIVITY_DAYS, default=get_config_value(self._config_entry, CONF_ACTIVITY_DAYS, DEFAULT_ACTIVITY_DAYS)): cv.positive_int,
                    vol.Optional(CONF_TIMEOUT, default=get_config_value(self._config_entry, CONF_TIMEOUT, DEFAULT_TIMEOUT)): vol.All(vol.Coerce(int), vol.Range(min=10)),
                    vol.Optional(CONF_WAN_SPEED_UNIT, default=get_config_value(self._config_entry, CONF_WAN_SPEED_UNIT, DEFAULT_WAN_SPEED_UNIT)): vol.In(WAN_SPEED_UNIT_OPTIONS),
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
                _LOGGER.exception("[MiWiFi] Error generating the options form: %s", e)
                raise   
