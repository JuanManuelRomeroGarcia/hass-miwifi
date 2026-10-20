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
    CONF_IS_AP_MODE,
    CONF_IS_FORCE_LOAD,
    CONF_IS_TRACK_DEVICES,
    CONF_PROTOCOL,
    CONF_STAY_ONLINE,
    DEFAULT_ACTIVITY_DAYS,
    DEFAULT_IS_AP_MODE,
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
    CONF_DEVICE_SENSORS_GLOBAL,
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
    set_global_auto_purge,
    get_mesh_device_sensors_enabled,
    get_mesh_device_sensors_save,
)

from .updater import LuciUpdater, async_get_updater


def _minimum_presence_seconds(values: dict) -> int:
    """Budget one polling interval and one request timeout, not a full cycle."""
    return int(values.get(CONF_SCAN_INTERVAL, DEFAULT_SCAN_INTERVAL)) + int(
        values.get(CONF_TIMEOUT, DEFAULT_TIMEOUT)
    )


def _invalid_presence_timing(values: dict) -> bool:
    return bool(values.get(CONF_IS_TRACK_DEVICES, True)) and int(
        values.get(CONF_STAY_ONLINE, DEFAULT_STAY_ONLINE)
    ) < _minimum_presence_seconds(values)


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
            if _invalid_presence_timing(user_input):
                return await self._show_form(
                    user_input, {CONF_STAY_ONLINE: "presence_too_short"},
                    step_id="discovery_confirm",
                )
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
        }

        # Until the global options step is saved, every entry still votes for
        # the mesh-wide client sensors. After that the saved value decides and
        # this field would change nothing.
        if not get_mesh_device_sensors_save(self.hass):
            schema_dict[vol.Optional(CONF_ENABLE_DEVICE_SENSORS, default=DEFAULT_ENABLE_DEVICE_SENSORS)] = cv.boolean

        if step_id == "discovery_confirm":
            schema_dict[vol.Optional(CONF_ENABLE_PANEL, default=panel_state)] = cv.boolean
            schema_dict[vol.Optional(CONF_WAN_SPEED_UNIT, default=DEFAULT_WAN_SPEED_UNIT)] = vol.In(WAN_SPEED_UNIT_OPTIONS)
            schema_dict[vol.Optional(CONF_LOG_LEVEL, default=log_level)] = vol.In(LOG_LEVEL_OPTIONS)
            schema_dict[vol.Optional(CONF_ENABLE_PORT_PROBE, default=DEFAULT_ENABLE_PORT_PROBE)] = cv.boolean

        schema = self.add_suggested_values_to_schema(vol.Schema(schema_dict), user_input)

        description_placeholders = {
            "minimum_stay_online": str(_minimum_presence_seconds(user_input or {})),
        }
        if step_id == "discovery_confirm":
            description_placeholders |= {
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
        menu_options = ["device_settings"]
        if self._shows_global_settings():
            menu_options.insert(0, "global_settings")

        return self.async_show_menu(step_id="init", menu_options=menu_options)

    def _shows_global_settings(self) -> bool:
        """Return whether this entry offers the mesh-wide settings.

        They belong to the entry whose topology identifies the main node. When
        no loaded entry is identified as the main (a topology that has not
        loaded yet, a mesh whose main is not added to Home Assistant), every
        entry offers them, so they always stay reachable.
        """
        mains = set()
        for entry in self.hass.config_entries.async_entries(DOMAIN):
            try:
                updater: LuciUpdater = async_get_updater(self.hass, entry.entry_id)
            except ValueError:
                continue
            if self._is_main_router(updater):
                mains.add(entry.entry_id)

        return not mains or self._config_entry.entry_id in mains

    @staticmethod
    def _is_main_router(updater: LuciUpdater) -> bool:
        """Return whether the updater's topology identifies the mesh main node."""
        data = updater.data or {}
        topology = data.get("topo_graph") if isinstance(data, dict) else None
        graph = topology.get("graph") if isinstance(topology, dict) else None
        return isinstance(graph, dict) and bool(graph.get("is_main", False))

    async def async_step_global_settings(
        self, user_input: dict | None = None
    ) -> FlowResult:
        if user_input is not None:
            if CONF_LOG_LEVEL in user_input:
                await set_global_log_level(self.hass, user_input[CONF_LOG_LEVEL])

            if CONF_ENABLE_PANEL in user_input:
                await set_global_panel_state(self.hass, user_input[CONF_ENABLE_PANEL])

            await set_global_auto_purge(
                self.hass,
                every_days=user_input.get(CONF_AUTO_PURGE_EVERY_DAYS),
                at=user_input.get(CONF_AUTO_PURGE_AT),
            )

            # The log level and the purge schedule are read from their global
            # stores only, so they are not copied into the entry. The entry
            # keeps what is read from it: the panel state its config sensor
            # shows, and the client-sensor setting with a save counter, so the
            # latest save wins on whichever entry it was made. The counter also
            # changes the options on every save, so the update listener still
            # runs: it applies the panel and reloads this entry, or every entry
            # when the client-sensor value changed.
            options = dict(self._config_entry.options)
            if CONF_ENABLE_PANEL in user_input:
                options[CONF_ENABLE_PANEL] = user_input[CONF_ENABLE_PANEL]
            options[CONF_ENABLE_DEVICE_SENSORS] = user_input.get(
                CONF_ENABLE_DEVICE_SENSORS,
                get_mesh_device_sensors_enabled(self.hass),
            )
            options[CONF_DEVICE_SENSORS_GLOBAL] = (
                get_mesh_device_sensors_save(self.hass) + 1
            )
            return self.async_create_entry(title="", data=options)

        panel_state = await get_global_panel_state(self.hass)
        log_level = await get_global_log_level(self.hass)
        global_cfg = await get_global_auto_purge(self.hass)
        schema = vol.Schema(
            {
                vol.Optional(CONF_ENABLE_PANEL, default=panel_state): cv.boolean,
                vol.Optional(CONF_LOG_LEVEL, default=log_level): vol.In(
                    LOG_LEVEL_OPTIONS
                ),
                vol.Optional(
                    CONF_AUTO_PURGE_EVERY_DAYS,
                    default=int(
                        global_cfg.get(
                            "every_days", DEFAULT_AUTO_PURGE_EVERY_DAYS
                        )
                    ),
                ): vol.All(vol.Coerce(int), vol.Range(min=0, max=3650)),
                vol.Optional(
                    CONF_AUTO_PURGE_AT,
                    default=str(global_cfg.get("at", DEFAULT_AUTO_PURGE_AT)),
                ): str,
                vol.Optional(
                    CONF_ENABLE_DEVICE_SENSORS,
                    default=get_mesh_device_sensors_enabled(self.hass),
                ): cv.boolean,
            }
        )
        return self.async_show_form(
            step_id="global_settings",
            data_schema=schema,
        )

    async def async_step_device_settings(
        self, user_input: dict | None = None
    ) -> FlowResult:
        errors: dict[str, str] = {}

        if user_input is not None and _invalid_presence_timing(user_input):
            return self.async_show_form(
                step_id="device_settings",
                data_schema=self.add_suggested_values_to_schema(
                    await self._get_device_options_schema(), user_input
                ),
                errors={CONF_STAY_ONLINE: "presence_too_short"},
                description_placeholders={
                    "minimum_stay_online": str(_minimum_presence_seconds(user_input)),
                },
            )

        if user_input is not None:
            code, reason = await async_verify_access(
                self.hass,
                user_input[CONF_IP_ADDRESS],
                user_input[CONF_PASSWORD],
                user_input[CONF_ENCRYPTION_ALGORITHM],
                user_input[CONF_TIMEOUT],
                user_input.get(CONF_PROTOCOL, DEFAULT_PROTOCOL),
            )

            if codes.is_success(code):
                await self.async_update_unique_id(user_input[CONF_IP_ADDRESS])
                # Only the fields of this form change. The other stored values
                # stay: the mesh-wide ones this step does not show, and a
                # per-node value the form may hide for a moment, such as
                # force-load while the node's mode is not known yet.
                options = {**self._config_entry.options, **user_input}
                return self.async_create_entry(
                    title=user_input[CONF_IP_ADDRESS],
                    data=options,
                )

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
            step_id="device_settings",
            data_schema=self.add_suggested_values_to_schema(
                await self._get_device_options_schema(), user_input
            ),
            errors=errors,
            description_placeholders={
                "minimum_stay_online": str(_minimum_presence_seconds(user_input or {
                    CONF_SCAN_INTERVAL: get_config_value(self._config_entry, CONF_SCAN_INTERVAL, DEFAULT_SCAN_INTERVAL),
                    CONF_TIMEOUT: get_config_value(self._config_entry, CONF_TIMEOUT, DEFAULT_TIMEOUT),
                })),
            },
        )

    async def async_update_unique_id(self, unique_id: str) -> None:
        if self._config_entry.unique_id == unique_id:
            return

        for flow in self.hass.config_entries.flow.async_progress(True):
            if flow["flow_id"] != self.flow_id and flow["context"].get("unique_id") == unique_id:
                self.hass.config_entries.flow.async_abort(flow["flow_id"])

        self.hass.config_entries.async_update_entry(self._config_entry, unique_id=unique_id)

    async def _get_device_options_schema(self) -> vol.Schema:
        """Generate the schema for per-device options."""
        try:
            schema: dict = {
                vol.Required(CONF_IP_ADDRESS, default=get_config_value(self._config_entry, CONF_IP_ADDRESS, "")): str,
                vol.Required(CONF_PASSWORD, default=get_config_value(self._config_entry, CONF_PASSWORD, "")): str,
                vol.Required(CONF_ENCRYPTION_ALGORITHM, default=get_config_value(
                    self._config_entry, CONF_ENCRYPTION_ALGORITHM, EncryptionAlgorithm.SHA1
                )): vol.In([EncryptionAlgorithm.SHA1, EncryptionAlgorithm.SHA256]),
                vol.Required(CONF_PROTOCOL, default=get_config_value(
                    self._config_entry, CONF_PROTOCOL, DEFAULT_PROTOCOL
                )): vol.In(PROTOCOL_OPTIONS),
                vol.Required(CONF_IS_TRACK_DEVICES, default=get_config_value(self._config_entry, CONF_IS_TRACK_DEVICES, True)): cv.boolean,
                vol.Required(CONF_STAY_ONLINE, default=get_config_value(self._config_entry, CONF_STAY_ONLINE, DEFAULT_STAY_ONLINE)): cv.positive_int,
                vol.Required(CONF_SCAN_INTERVAL, default=get_config_value(self._config_entry, CONF_SCAN_INTERVAL, DEFAULT_SCAN_INTERVAL)): vol.All(vol.Coerce(int), vol.Range(min=10)),
                vol.Optional(CONF_ACTIVITY_DAYS, default=get_config_value(self._config_entry, CONF_ACTIVITY_DAYS, DEFAULT_ACTIVITY_DAYS)): cv.positive_int,
                vol.Optional(CONF_TIMEOUT, default=get_config_value(self._config_entry, CONF_TIMEOUT, DEFAULT_TIMEOUT)): vol.All(vol.Coerce(int), vol.Range(min=10)),
                vol.Optional(CONF_WAN_SPEED_UNIT, default=get_config_value(self._config_entry, CONF_WAN_SPEED_UNIT, DEFAULT_WAN_SPEED_UNIT)): vol.In(WAN_SPEED_UNIT_OPTIONS),
                vol.Optional(CONF_ENABLE_PORT_PROBE, default=get_config_value(self._config_entry, CONF_ENABLE_PORT_PROBE, DEFAULT_ENABLE_PORT_PROBE)): cv.boolean,
                # Offered for every node: a leaf behind a foreign gateway often
                # fails to report its own mode, so it never looks like a repeater.
                vol.Optional(CONF_IS_AP_MODE, default=get_config_value(self._config_entry, CONF_IS_AP_MODE, DEFAULT_IS_AP_MODE)): cv.boolean,
            }

            # Force-load is offered on repeaters, and wherever it is on: a node
            # can read as a non-repeater for a while (before its topology
            # arrives, or when the mode probe fails), and an option in effect
            # must stay visible so that it can be turned off.
            is_force_load = get_config_value(self._config_entry, CONF_IS_FORCE_LOAD, False)
            with contextlib.suppress(ValueError):
                updater: LuciUpdater = async_get_updater(self.hass, self._config_entry.entry_id)
                if not updater.is_repeater and not is_force_load:
                    return vol.Schema(schema)

            schema |= {
                vol.Optional(CONF_IS_FORCE_LOAD, default=is_force_load): cv.boolean,
            }

            return vol.Schema(schema)
        except Exception as e:
            await self.hass.async_add_executor_job(_LOGGER.exception, "[MiWiFi] Error generating the options form: %s", e)
            raise
