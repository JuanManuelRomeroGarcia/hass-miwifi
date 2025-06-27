"""Services."""

from __future__ import annotations

import hashlib
from .logger import _LOGGER
from typing import Final

import homeassistant.components.persistent_notification as pn
import voluptuous as vol
from homeassistant.const import CONF_DEVICE_ID, CONF_IP_ADDRESS, CONF_TYPE
from homeassistant.core import HomeAssistant, ServiceCall
from homeassistant.helpers import entity_registry as er
from homeassistant.helpers import device_registry as dr


from .const import (
    ATTR_DEVICE_HW_VERSION,
    ATTR_DEVICE_MAC_ADDRESS,
    CONF_BODY,
    CONF_REQUEST,
    CONF_RESPONSE,
    CONF_URI,
    EVENT_LUCI,
    EVENT_TYPE_RESPONSE,
    NAME,
    SERVICE_CALC_PASSWD,
    SERVICE_REQUEST,
    UPDATER,
)
from .exceptions import LuciError
from .updater import LuciUpdater, async_get_updater, async_update_panel_entity
from .frontend import async_save_manual_main_mac, async_clear_manual_main_mac


class MiWifiServiceCall:
    """Parent class for all MiWifi service calls."""

    schema = vol.Schema({
        vol.Required(CONF_DEVICE_ID): vol.All(
            vol.Coerce(list),
            vol.Length(min=1, max=1, msg="The service only supports one device per call."),
        )
    })

    def __init__(self, hass: HomeAssistant) -> None:
        self.hass = hass

    def get_updater(self, service: ServiceCall) -> LuciUpdater:
        device_id: str = service.data[CONF_DEVICE_ID][0]
        device: dr.DeviceEntry | None = dr.async_get(self.hass).async_get(device_id)
        if device is None:
            raise vol.Invalid(f"Device {device_id} not found.")

        for connection_type, identifier in device.connections:
            if connection_type == CONF_IP_ADDRESS and len(identifier) > 0:
                return async_get_updater(self.hass, identifier)

        raise vol.Invalid(
            f"Device {device_id} does not support the called service. Choose a router with MiWifi support."
        )

    async def async_call_service(self, service: ServiceCall) -> None:
        raise NotImplementedError


class MiWifiCalcPasswdServiceCall(MiWifiServiceCall):
    """Calculate passwd."""

    salt_old: str = "A2E371B0-B34B-48A5-8C40-A7133F3B5D88"
    salt_new: str = "6d2df50a-250f-4a30-a5e6-d44fb0960aa0"

    async def async_call_service(self, service: ServiceCall) -> None:
        updater: LuciUpdater = self.get_updater(service)
        if hw_version := updater.data.get(ATTR_DEVICE_HW_VERSION):
            _salt: str = hw_version + (self.salt_new if "/" in hw_version else self.salt_old)
            return pn.async_create(self.hass, f"Your passwd: {hashlib.md5(_salt.encode()).hexdigest()[:8]}", NAME)

        raise vol.Invalid(f"Integration with ip address: {updater.ip} does not support this service.")


class MiWifiRequestServiceCall(MiWifiServiceCall):
    """Send request."""

    schema = MiWifiServiceCall.schema.extend({
        vol.Required(CONF_URI): str,
        vol.Optional(CONF_BODY): dict
    })

    async def async_call_service(self, service: ServiceCall) -> None:
        updater: LuciUpdater = self.get_updater(service)
        device_identifier: str = updater.data.get(ATTR_DEVICE_MAC_ADDRESS, updater.ip)

        _data: dict = dict(service.data)
        try:
            response: dict = await updater.luci.get(
                uri := _data.get(CONF_URI), body := _data.get(CONF_BODY, {})  # type: ignore
            )
        except LuciError:
            return

        device: dr.DeviceEntry | None = dr.async_get(self.hass).async_get_device(set(), {(dr.CONNECTION_NETWORK_MAC, device_identifier)})
        if device is not None:
            self.hass.bus.async_fire(EVENT_LUCI, {
                CONF_DEVICE_ID: device.id,
                CONF_TYPE: EVENT_TYPE_RESPONSE,
                CONF_URI: uri,
                CONF_REQUEST: body,
                CONF_RESPONSE: response,
            })


class MiWifiGetTopologyGraphServiceCall(MiWifiServiceCall):
    """Get Topology Graph."""

    async def async_call_service(self, service: ServiceCall) -> None:
        updater: LuciUpdater = self.get_updater(service)
        await updater._async_prepare_topo()

        if updater.data.get("topo_graph"):
            _LOGGER.info("[MiWiFi] Topology graph retrieved successfully.")
        else:
            _LOGGER.warning("[MiWiFi] Topology graph could not be retrieved or is empty.")


class MiWifiLogPanelServiceCall:
    """Log messages sent from the frontend panel."""

    schema = vol.Schema({
        vol.Required("level"): vol.In(["debug", "info", "warning", "error"]),
        vol.Required("message"): str,
    })

    def __init__(self, hass: HomeAssistant) -> None:
        self.hass = hass

    async def async_call_service(self, service: ServiceCall) -> None:
        level = service.data.get("level", "info")
        message = service.data.get("message", "")

        if level == "debug":
            _LOGGER.debug("[PanelJS] %s", message)
        elif level == "warning":
            _LOGGER.warning("[PanelJS] %s", message)
        elif level == "error":
            _LOGGER.error("[PanelJS] %s", message)
        else:
            _LOGGER.info("[PanelJS] %s", message)


from .updater import async_get_integrations

class MiWifiSelectMainNodeServiceCall(MiWifiServiceCall):
    """Allow setting a router manually as main."""

    schema = vol.Schema({vol.Required("mac"): str})

    def __init__(self, hass: HomeAssistant) -> None:
        self.hass = hass

    async def async_call_service(self, service: ServiceCall) -> None:
        selected_mac = service.data["mac"]
        _LOGGER.info("[MiWiFi] 📥 Service 'select_main_router' invoked with MAC: %s", selected_mac)

        integrations = async_get_integrations(self.hass)
        routers = [entry[UPDATER] for entry in integrations.values()]

        if selected_mac:
            await async_save_manual_main_mac(self.hass, selected_mac)
            _LOGGER.info("[MiWiFi] ✅ Manual MAC saved successfully: %s", selected_mac)
        else:
            await async_clear_manual_main_mac(self.hass)
            _LOGGER.info("[MiWiFi] 🧹 Cleared manual selection of main router.")

        for router in routers:
            await router._async_prepare_topo()
            await async_update_panel_entity(self.hass, router)


class MiWifiBlockDeviceServiceCall:
    """Block or unblock WAN access for a device automatically."""

    schema = vol.Schema({
        vol.Required(CONF_DEVICE_ID): str,
        vol.Required("allow"): bool,
    })

    def __init__(self, hass: HomeAssistant) -> None:
        self.hass = hass

    async def async_call_service(self, service: ServiceCall) -> None:
        device_id: str = service.data[CONF_DEVICE_ID]

        entity_registry = er.async_get(self.hass)
        entities = [e for e in entity_registry.entities.values() if e.device_id == device_id and e.platform == "miwifi" and e.domain == "device_tracker"]

        if not entities:
            raise vol.Invalid("No MiWiFi device_tracker entity found for selected device.")

        entity_entry = entities[0]
        state = self.hass.states.get(entity_entry.entity_id)
        if state is None:
            raise vol.Invalid("Cannot get state of entity.")

        mac_address = state.attributes.get("mac")
        if not mac_address:
            raise vol.Invalid("MAC not found in entity attributes.")

        _LOGGER.debug(f"[MiWiFi] Target MAC: {mac_address}")

        integrations = async_get_integrations(self.hass)
        main_updater = None

        for integration in integrations.values():
            updater = integration[UPDATER]
            topo_graph = (updater.data or {}).get("topo_graph", {}).get("graph", {})
            if topo_graph.get("is_main", False):
                main_updater = updater
                break

        if main_updater is None:
            raise vol.Invalid("Main router not found (is_main).")

        if not (getattr(main_updater, "capabilities", {}) or {}).get("mac_filter", False):
            raise vol.Invalid("This router does not support MAC Filter API.")

        allow = service.data["allow"]

        try:
            await main_updater.luci.login()
            await main_updater.luci.set_mac_filter(mac_address, not allow)
            await main_updater._async_prepare_devices(main_updater.data)

            _LOGGER.info(f"[MiWiFi] MAC Filter applied: mac={mac_address}, WAN={'Blocked' if allow else 'Allowed'}")
        except LuciError as e:
            if "Connection error" in str(e):
                _LOGGER.info("[MiWiFi] Connection dropped after applying MAC filter (likely successfully applied): %s", e)

            else:
                _LOGGER.error("[MiWiFi] Error applying MAC filter: %s", e)
                raise vol.Invalid(f"Failed to apply mac filter: {e}")
        finally:
            device_registry = dr.async_get(self.hass)
            device_entry = device_registry.async_get(device_id)
            friendly_name = device_entry.name_by_user or device_entry.name or mac_address

            pn.async_create(
                self.hass,
                f"El dispositivo {friendly_name} ha sido {'BLOQUEADO' if allow else 'DESBLOQUEADO'} automáticamente.",
                NAME,
            )




SERVICES: Final = (
    (SERVICE_CALC_PASSWD, MiWifiCalcPasswdServiceCall),
    (SERVICE_REQUEST, MiWifiRequestServiceCall),
    ("get_topology_graph", MiWifiGetTopologyGraphServiceCall),
    ("log_panel", MiWifiLogPanelServiceCall),
    ("select_main_router", MiWifiSelectMainNodeServiceCall),
    ("block_device", MiWifiBlockDeviceServiceCall),
)
