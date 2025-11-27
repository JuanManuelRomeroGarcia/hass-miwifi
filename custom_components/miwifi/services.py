"""Services."""

from __future__ import annotations

import datetime
import time
import hashlib
import json
import os
import re
import zipfile
from .logger import _LOGGER, async_recreate_log_handlers
from typing import Final
from .sensor import MiWifiNATRulesSensor 
from .notifier import MiWiFiNotifier
from .helper import parse_last_activity


import homeassistant.components.persistent_notification as pn
import voluptuous as vol
from homeassistant.const import CONF_DEVICE_ID, CONF_IP_ADDRESS, CONF_TYPE
from homeassistant.core import HomeAssistant, ServiceCall
from homeassistant.helpers import entity_registry as er
from homeassistant.helpers import device_registry as dr
from homeassistant.helpers import config_validation as cv
from homeassistant.helpers.network import get_url
from homeassistant.helpers.selector import selector
from homeassistant.helpers.dispatcher import async_dispatcher_send


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
    ATTR_TRACKER_LAST_ACTIVITY,
    ATTR_TRACKER_MAC,
    ATTR_TRACKER_ENTRY_ID,
    SIGNAL_PURGE_DEVICE,
    DOMAIN
)
from .exceptions import LuciError
from .updater import LuciUpdater, async_get_updater, async_update_panel_entity, async_get_integrations
from .frontend import async_save_manual_main_mac, async_clear_manual_main_mac
from .unsupported import safe_call_with_support


class _I18nMixin:
    async def _t(self, key: str, default: str = "", **fmt) -> str:
    
        notifier = MiWiFiNotifier(self.hass)
        tr = await notifier.get_translations() or {}
        msg = ((tr.get("errors") or {}).get(key)) or default
        try:
            return msg.format(**fmt)
        except Exception:
            return msg


class MiWifiServiceCall:
    """Parent class for all MiWifi service calls."""

    schema = vol.Schema({
        vol.Required(CONF_DEVICE_ID): vol.All(
            cv.ensure_list,
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
    
class MiWifiMainOrDeviceServiceCall(MiWifiServiceCall):
    """Permite omitir device_id; si falta, usa el router principal (is_main)."""

    schema = vol.Schema({
        vol.Optional(CONF_DEVICE_ID, description="service_fields.common.device_id"):
            vol.All(cv.ensure_list, vol.Length(min=1, max=1)),
    })

    def get_updater(self, service: ServiceCall) -> LuciUpdater:
        device_data = service.data.get(CONF_DEVICE_ID)
        if device_data:
            device_id = device_data[0]
            device = dr.async_get(self.hass).async_get(device_id)
            if device is None:
                raise vol.Invalid(f"Device {device_id} not found.")
            for connection_type, identifier in device.connections:
                if connection_type == CONF_IP_ADDRESS and identifier:
                    return async_get_updater(self.hass, identifier)
            raise vol.Invalid("Selected device is not a MiWiFi router.")

        integrations = async_get_integrations(self.hass)  # ip -> {UPDATER: LuciUpdater, ...}
        candidates = [data[UPDATER] for data in integrations.values()]
        for upd in candidates:
            topo = (upd.data or {}).get("topo_graph", {}).get("graph", {})
            if topo.get("is_main"):
                return upd

        if len(candidates) == 1:
            return candidates[0]

        raise vol.Invalid("No se encontró router principal (is_main) y hay varias integraciones MiWiFi.")



class MiWifiCalcPasswdServiceCall(MiWifiServiceCall):
    """Calculate passwd."""

    salt_old: str = "A2E371B0-B34B-48A5-8C40-A7133F3B5D88"
    salt_new: str = "6d2df50a-250f-4a30-a5e6-d44fb0960aa0"

    async def async_call_service(self, service: ServiceCall) -> None:
        updater: LuciUpdater = self.get_updater(service)

        if hw_version := updater.data.get(ATTR_DEVICE_HW_VERSION):
            _salt: str = hw_version + (self.salt_new if "/" in hw_version else self.salt_old)
            passwd = hashlib.md5(_salt.encode()).hexdigest()[:8]

            notifier = MiWiFiNotifier(self.hass)
            translations = await notifier.get_translations()
            message_template = translations.get("notifications", {}).get(
                "calc_passwd_message", "🔐 Your password is: <b>{passwd}</b>"
            )
            message = message_template.replace("{passwd}", passwd)

            await notifier.notify(
                message=message,
                title=NAME,
                notification_id="miwifi_calc_passwd"
            )
            return

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
            await self.hass.async_add_executor_job(_LOGGER.info, "[MiWiFi] Topology graph retrieved successfully.")
        else:
            await self.hass.async_add_executor_job(_LOGGER.warning, "[MiWiFi] Topology graph could not be retrieved or is empty.")


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
            await self.hass.async_add_executor_job(_LOGGER.debug, "[PanelJS] %s", message)
        elif level == "warning":
            await self.hass.async_add_executor_job(_LOGGER.warning, "[PanelJS] %s", message)
        elif level == "error":
            await self.hass.async_add_executor_job(_LOGGER.error, "[PanelJS] %s", message)
        else:
            await self.hass.async_add_executor_job(_LOGGER.info, "[PanelJS] %s", message)


class MiWifiSelectMainNodeServiceCall(MiWifiServiceCall):
    """Allow setting a router manually as main."""

    schema = vol.Schema({vol.Required("mac"): str})

    def __init__(self, hass: HomeAssistant) -> None:
        self.hass = hass

    async def async_call_service(self, service: ServiceCall) -> None:
        selected_mac = service.data["mac"]
        await self.hass.async_add_executor_job(_LOGGER.info, "[MiWiFi] 📥 Service 'select_main_router' invoked with MAC: %s", selected_mac)

        integrations = async_get_integrations(self.hass)
        routers = [entry[UPDATER] for entry in integrations.values()]

        if selected_mac:
            await async_save_manual_main_mac(self.hass, selected_mac)
            await self.hass.async_add_executor_job(_LOGGER.info, "[MiWiFi] ✅ Manual MAC saved successfully: %s", selected_mac)
        else:
            await async_clear_manual_main_mac(self.hass)
            await self.hass.async_add_executor_job(_LOGGER.info, "[MiWiFi] 🧹 Cleared manual selection of main router.")

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
        entities = [e for e in entity_registry.entities.values()
                    if e.device_id == device_id and e.platform == "miwifi" and e.domain == "device_tracker"]

        if not entities:
            raise vol.Invalid("No MiWiFi device_tracker entity found for selected device.")

        entity_entry = entities[0]
        state = self.hass.states.get(entity_entry.entity_id)
        if state is None:
            raise vol.Invalid("Cannot get state of entity.")

        mac_address = state.attributes.get("mac")
        if not mac_address:
            raise vol.Invalid("MAC not found in entity attributes.")

        await self.hass.async_add_executor_job(_LOGGER.debug, f"[MiWiFi] Target MAC: {mac_address}")

        integrations = async_get_integrations(self.hass)
        main_updater = next(
            (i[UPDATER] for i in integrations.values()
             if (i[UPDATER].data or {}).get("topo_graph", {}).get("graph", {}).get("is_main", False)),
            None
        )

        if not main_updater:
            raise vol.Invalid("Main router not found (is_main).")

        if not (getattr(main_updater, "capabilities", {}) or {}).get("mac_filter", False):
            raise vol.Invalid("This router does not support MAC Filter API.")

        allow = service.data["allow"]

        try:
            await main_updater.luci.login()
            await main_updater.luci.set_mac_filter(mac_address, not allow)
            await main_updater._async_prepare_devices(main_updater.data)

            await self.hass.async_add_executor_job(_LOGGER.info, f"[MiWiFi] MAC Filter applied: mac={mac_address}, WAN={'Blocked' if allow else 'Allowed'}")
        except LuciError as e:
            if "Connection error" in str(e):
                await self.hass.async_add_executor_job(_LOGGER.info, "[MiWiFi] Connection dropped after applying MAC filter (likely successfully applied): %s", e)
            else:
                await self.hass.async_add_executor_job(_LOGGER.error, "[MiWiFi] Error applying MAC filter: %s", e)
                raise vol.Invalid(f"Failed to apply mac filter: {e}")

        # Notificación final
        device_registry = dr.async_get(self.hass)
        device_entry = device_registry.async_get(device_id)
        friendly_name = device_entry.name_by_user or device_entry.name or mac_address

        notifier = MiWiFiNotifier(self.hass)
        translations = await notifier.get_translations()

        notify = translations.get("notifications", {})
        title = translations.get("title", "MiWiFi")

        message_template = notify.get(
            "device_blocked_message",
            "Device {name} has been automatically {status}."
        )

        status = notify.get(
            "status_blocked" if allow else "status_unblocked",
            "BLOCKED" if allow else "UNBLOCKED"
        )

        message = message_template.replace("{name}", friendly_name).replace("{status}", status)

        await notifier.notify(
            message,
            title=title,
            notification_id=f"miwifi_block_{mac_address.replace(':', '_')}",
        )

class MiWifiListPortsServiceCall:
    """List NAT port forwarding rules automatically from the main router."""

    schema = vol.Schema({
        vol.Required("ftype"): vol.In([1, 2])
    })

    def __init__(self, hass: HomeAssistant) -> None:
        self.hass = hass

    async def async_call_service(self, service: ServiceCall) -> None:
        ftype = service.data["ftype"]
        integrations = async_get_integrations(self.hass)

        main_updater = None
        for integration in integrations.values():
            updater = integration[UPDATER]
            topo_graph = (updater.data or {}).get("topo_graph", {}).get("graph", {})
            if topo_graph.get("is_main", False):
                main_updater = updater
                break

        if main_updater is None:
            raise vol.Invalid("No main router detected (is_main).")

        await main_updater.luci.login()
        await self.hass.async_add_executor_job(_LOGGER.info, "[MiWiFi] 📡 Main router detected (IP: %s). Requesting NAT rules (ftype=%s)", main_updater.ip, ftype)

        try:
            data = await main_updater.luci.portforward(ftype)
            await self.hass.async_add_executor_job(_LOGGER.info, "[MiWiFi] 🔁 NAT rules fetched (ftype=%s): %s", ftype, data)
            return data
        except LuciError as e:
            await self.hass.async_add_executor_job(_LOGGER.error, "[MiWiFi] ❌ Error fetching NAT rules: %s", e)
            raise vol.Invalid(f"Error communicating with the main router: {e}")


class MiWifiAddPortServiceCall:
    """Add a single port forwarding rule (ftype=1)."""

    schema = vol.Schema({
        vol.Required("ip"): str,             
        vol.Required("name"): str,           
        vol.Required("proto"): vol.In([1, 2, 3]),  
        vol.Required("sport"): int,          
        vol.Required("dport"): int,          
    })

    def __init__(self, hass: HomeAssistant) -> None:
        self.hass = hass

    async def async_call_service(self, service: ServiceCall) -> None:
        ip = service.data["ip"]
        name = service.data["name"]
        proto = service.data["proto"]
        sport = service.data["sport"]
        dport = service.data["dport"]

        integrations = async_get_integrations(self.hass)
        main_updater = None

        for integration in integrations.values():
            updater = integration[UPDATER]
            topo_graph = (updater.data or {}).get("topo_graph", {}).get("graph", {})
            if topo_graph.get("is_main", False):
                main_updater = updater
                break

        if main_updater is None:
            raise vol.Invalid("No main router detected (is_main).")

        await self.hass.async_add_executor_job(_LOGGER.info, "[MiWiFi] ➕ Adding NAT rule ftype=1: %s:%s → %s:%s (%s)", sport, name, ip, dport, proto)

        try:
            await main_updater.luci.login()
            response = await main_updater.luci.add_redirect(name, proto, sport, ip, dport)
            await self.hass.async_add_executor_job(_LOGGER.info, "[MiWiFi] ✅ Rule successfully added: %s", response)

            await main_updater.luci.redirect_apply()
            await self.hass.async_add_executor_job(_LOGGER.info, "[MiWiFi] 🔄 NAT changes applied after adding rule.")
        except LuciError as e:
            await self.hass.async_add_executor_job(_LOGGER.error, "[MiWiFi] ❌ Error adding NAT rule: %s", e)
            raise vol.Invalid(f"Failed to add rule: {e}")


class MiWifiAddRangePortServiceCall:
    """Add a port range forwarding rule (ftype=2)."""

    schema = vol.Schema({
        vol.Required("ip"): str,
        vol.Required("name"): str,
        vol.Required("proto"): vol.In([1, 2, 3]),
        vol.Required("fport"): int,
        vol.Required("tport"): int,
    })

    def __init__(self, hass: HomeAssistant) -> None:
        self.hass = hass

    async def async_call_service(self, service: ServiceCall) -> None:
        ip = service.data["ip"]
        name = service.data["name"]
        proto = service.data["proto"]
        fport = service.data["fport"]
        tport = service.data["tport"]

        integrations = async_get_integrations(self.hass)
        main_updater = None

        for integration in integrations.values():
            updater = integration[UPDATER]
            topo_graph = (updater.data or {}).get("topo_graph", {}).get("graph", {})
            if topo_graph.get("is_main", False):
                main_updater = updater
                break

        if main_updater is None:
            raise vol.Invalid("No main router detected (is_main).")

        await self.hass.async_add_executor_job(_LOGGER.info, "[MiWiFi] ➕ Adding NAT rule ftype=2: %s:%s-%s (%s)", name, fport, tport, proto)

        try:
            await main_updater.luci.login()
            response = await main_updater.luci.add_range_redirect(name, proto, fport, tport, ip)
            await self.hass.async_add_executor_job(_LOGGER.info, "[MiWiFi] ✅ Range rule successfully added: %s", response)

            await main_updater.luci.redirect_apply()
            await self.hass.async_add_executor_job(_LOGGER.info, "[MiWiFi] 🔄 NAT changes applied after adding range rule.")
        except LuciError as e:
            await self.hass.async_add_executor_job(_LOGGER.error, "[MiWiFi] ❌ Error adding NAT range rule: %s", e)
            raise vol.Invalid(f"Failed to add range rule: {e}")


class MiWifiDeletePortServiceCall:
    """Delete a port forwarding rule (ftype=1 or 2)."""

    schema = vol.Schema({
        vol.Required("proto"): vol.In([1, 2, 3]),
        vol.Required("port"): int,
    })

    def __init__(self, hass: HomeAssistant) -> None:
        self.hass = hass

    async def async_call_service(self, service: ServiceCall) -> None:
        proto = service.data["proto"]
        port = service.data["port"]

        integrations = async_get_integrations(self.hass)
        main_updater = None

        for integration in integrations.values():
            updater = integration[UPDATER]
            topo_graph = (updater.data or {}).get("topo_graph", {}).get("graph", {})
            if topo_graph.get("is_main", False):
                main_updater = updater
                break

        if main_updater is None:
            raise vol.Invalid("No main router detected (is_main).")

        await self.hass.async_add_executor_job(_LOGGER.info, "[MiWiFi] 🗑️ Deleting NAT rule: proto=%s, port=%s", proto, port)

        try:
            await main_updater._async_prepare_topo()
            await main_updater.luci.login()

            response = await main_updater.luci.delete_redirect(port, proto)
            await self.hass.async_add_executor_job(_LOGGER.info, "[MiWiFi] ✅ Rule successfully deleted: %s", response)

            await main_updater.luci.redirect_apply()
            await self.hass.async_add_executor_job(_LOGGER.info, "[MiWiFi] 🔄 NAT changes applied after rule deletion.")

        except LuciError as e:
            await self.hass.async_add_executor_job(_LOGGER.error, "[MiWiFi] ❌ Error deleting NAT rule: %s", e)
            raise vol.Invalid(f"Failed to delete rule: {e}")


class MiWifiRefreshNATRulesServiceCall:
    """Force refresh of NAT rules."""
    
    schema = vol.Schema({})

    def __init__(self, hass: HomeAssistant) -> None:
        self.hass = hass

    async def async_call_service(self, service: ServiceCall) -> None:
        integrations = async_get_integrations(self.hass)
        main_updater = None

        for integration in integrations.values():
            updater = integration[UPDATER]
            topo_graph = (updater.data or {}).get("topo_graph", {}).get("graph", {})
            if topo_graph.get("is_main", False):
                main_updater = updater
                break

        if main_updater is None:
            raise vol.Invalid("No main router detected (is_main).")

        await self.hass.async_add_executor_job(_LOGGER.info, "[MiWiFi] 🔄 Forcing NAT rules refresh...")

        await main_updater._async_prepare_topo()
        await main_updater.update()
        main_updater.async_set_updated_data(main_updater.data)

        for entity_id in self.hass.states.async_entity_ids("sensor"):
            entity = self.hass.data["entity_components"]["sensor"].get_entity(entity_id)
            if isinstance(entity, MiWifiNATRulesSensor) and getattr(entity, "_updater", None) == main_updater:
                await self.hass.async_add_executor_job(_LOGGER.debug, "[MiWiFi] 🔁 Forcing update of NAT sensor: %s", entity_id)
                entity.async_update_from_updater()

        await self.hass.async_add_executor_job(_LOGGER.info, "[MiWiFi] ✅ NAT rules successfully refreshed.")
        

class MiWifiClearLogsService:
    """Service to clear and recreate all MiWiFi log files."""

    schema = vol.Schema({}) 

    def __init__(self, hass: HomeAssistant) -> None:
        self.hass = hass

    async def async_call_service(self, service: ServiceCall) -> None:
        await async_recreate_log_handlers(self.hass)
        
from functools import partial

class MiWifiDownloadLogsService:
    """Service to zip logs and make them downloadable from the frontend or services."""

    schema = vol.Schema({})

    def __init__(self, hass):
        self.hass = hass

    async def async_call_service(self, service: ServiceCall) -> None:
        log_dir = os.path.join(self.hass.config.config_dir, "miwifi", "logs")
        www_export_dir = os.path.join(self.hass.config.config_dir, "www", "miwifi", "exports")

        await self.hass.async_add_executor_job(partial(os.makedirs, www_export_dir, exist_ok=True))

        max_zip_files = 1

        def _list_existing_logs():
            return sorted(
                (f for f in os.listdir(www_export_dir) if f.startswith("logs_") and f.endswith(".zip")),
                key=lambda x: os.path.getmtime(os.path.join(www_export_dir, x)),
                reverse=True
            )
        existing_zips = await self.hass.async_add_executor_job(_list_existing_logs)


        def _remove_old():
            for old_zip in existing_zips[max_zip_files:]:
                try:
                    os.remove(os.path.join(www_export_dir, old_zip))
                    _LOGGER.debug("Removed old log archive: %s", old_zip)
                except Exception as e:
                    _LOGGER.warning("Failed to remove old log archive %s: %s", old_zip, e)

        await self.hass.async_add_executor_job(_remove_old)

        now = datetime.datetime.now().strftime("%Y%m%d-%H%M%S")
        filename = f"logs_{now}.zip"
        zip_path = os.path.join(www_export_dir, filename)

        def _zip_logs():
            with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED) as zipf:
                for file in os.listdir(log_dir):
                    if file.startswith("miwifi_") and (file.endswith(".log") or ".log." in file):
                        abs_path = os.path.join(log_dir, file)
                        zipf.write(abs_path, arcname=file)

        await self.hass.async_add_executor_job(_zip_logs)

        url = f"/local/miwifi/exports/{filename}"
        await self.hass.async_add_executor_job(_LOGGER.info, "📦 MiWiFi logs zipped and available at: %s", url)

        self.hass.data.setdefault(DOMAIN, {})
        self.hass.data[DOMAIN]["last_log_zip_url"] = url

        notifier = MiWiFiNotifier(self.hass)
        translations = await notifier.get_translations()
        title = translations.get("title", "MiWiFi")
        message_template = translations.get("notifications", {}).get(
            "download_ready",
            "📦 Logs listos: <a href='{url}' target='_blank'>Descargar</a>"
        )
        message = message_template.replace("{url}", url)
        await notifier.notify(message, title=title, notification_id="miwifi_download_logs")
        
class MiWifiAddUnsupportedService:
    """Service to add unsupported features to unsupported_user.py."""

    schema = vol.Schema({
        vol.Required("feature"): str,
        vol.Required("model"): str,
    })

    def __init__(self, hass: HomeAssistant) -> None:
        self.hass = hass
        self.user_file = os.path.join(os.path.dirname(__file__), "unsupported_user.py")

    async def async_call_service(self, service: ServiceCall) -> None:
        feature = service.data.get("feature")
        model_name = service.data.get("model")

        if not feature or not model_name:
            await self.hass.async_add_executor_job(
                _LOGGER.warning,
                "[MiWiFi] Missing feature or model in add_unsupported service call."
            )
            return

        from .enum import Model
        try:
            model_enum = Model[model_name.upper()]
        except KeyError:
            await self.hass.async_add_executor_job(
                _LOGGER.warning,
                "[MiWiFi] Invalid model name: %s",
                model_name
            )
            return

        user_data = {}
        if os.path.exists(self.user_file):
            try:
                import importlib.util
                spec = importlib.util.spec_from_file_location("custom_components.miwifi.unsupported_user", self.user_file)
                user_module = importlib.util.module_from_spec(spec)
                spec.loader.exec_module(user_module)
                user_data = getattr(user_module, "UNSUPPORTED", {})
                if not isinstance(user_data, dict):
                    user_data = {}
            except Exception as e:
                await self.hass.async_add_executor_job(
                    _LOGGER.warning,
                    "[MiWiFi] Could not read unsupported_user.py: %s",
                    e
                )
                user_data = {}

        from .unsupported import UNSUPPORTED as BASE_UNSUPPORTED

        already_exists = (
            (feature in user_data and model_enum in user_data[feature]) or
            (feature in BASE_UNSUPPORTED and model_enum in BASE_UNSUPPORTED[feature])
        )


        from .notifier import MiWiFiNotifier
        notifier = MiWiFiNotifier(self.hass)
        translations = await notifier.get_translations()
        title = translations.get("title", "MiWiFi")

        if not already_exists:
            if feature not in user_data:
                user_data[feature] = []
            user_data[feature].append(model_enum)

            new_content = "from .enum import Model\n\nUNSUPPORTED = {\n"
            for k, v in user_data.items():
                models = ", ".join(f"Model.{m.name}" for m in v)
                new_content += f'    "{k}": [{models}],\n'
            new_content += "}\n"

            def _write_file():
                with open(self.user_file, "w", encoding="utf-8") as f:
                    f.write(new_content)

            try:
                await self.hass.async_add_executor_job(_write_file)
                await self.hass.async_add_executor_job(
                    _LOGGER.debug,
                    "[MiWiFi] Added %s to feature '%s' in unsupported_user.py",
                    model_enum.name, feature
                )

                message_template = translations.get("notifications", {}).get(
                    "add_unsupported",
                    "➕ Added {model} to feature {feature} in unsupported_user.py"
                )
            except Exception as e:
                await self.hass.async_add_executor_job(
                    _LOGGER.warning,
                    "[MiWiFi] Failed to write unsupported_user.py: %s",
                    e
                )
                return
        else:
            await self.hass.async_add_executor_job(
                _LOGGER.debug,
                "[MiWiFi] Model %s already exists in feature '%s' of unsupported_user.py",
                model_enum.name, feature
            )
            message_template = translations.get("notifications", {}).get(
                "already_in_unsupported",
                "⚠️ {model} is already in feature {feature} of unsupported_user.py"
            )

        # Preparar mensaje y notificar
        message = message_template.replace("{model}", model_enum.name).replace("{feature}", feature)
        await notifier.notify(
            message,
            title=title,
            notification_id="miwifi_add_unsupported"
        )

class MiWifiDumpRouterDataService:
    """Dump router data into a JSON file with selectable blocks."""

    schema = vol.Schema({
        vol.Optional("system", default=True, description="service_fields.dump_router_data.system"): selector({"boolean": {}}),
        vol.Optional("network", default=True, description="service_fields.dump_router_data.network"): selector({"boolean": {}}),
        vol.Optional("devices", default=True, description="service_fields.dump_router_data.devices"): selector({"boolean": {}}),
        vol.Optional("nat_rules", default=True, description="service_fields.dump_router_data.nat_rules"): selector({"boolean": {}}),
        vol.Optional("qos", default=True, description="service_fields.dump_router_data.qos"): selector({"boolean": {}}),
        vol.Optional("wifi_config", default=False, description="service_fields.dump_router_data.wifi_config"): selector({"boolean": {}}),
        vol.Optional("hide_sensitive", default=True, description="service_fields.dump_router_data.hide_sensitive"): selector({"boolean": {}}),
    })

    def __init__(self, hass: HomeAssistant) -> None:
        self.hass = hass

    def _mask_sensitive(self, data: dict) -> dict:
        """Hide MAC addresses and passwords."""
        import re
        data_str = json.dumps(data)
        data_str = re.sub(r"([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}", "XX:XX:XX:XX:XX:XX", data_str)
        data_str = re.sub(r'("([^"]*(pass|pwd)[^"]*)"\s*:\s*)"[^"]*"', r'\1"***"', data_str)
        return json.loads(data_str)

    async def async_call_service(self, service: ServiceCall) -> None:
        opts = service.data
        from .updater import async_get_integrations
        integrations = async_get_integrations(self.hass)
        main_updater = None

        for integration in integrations.values():
            updater = integration[UPDATER]
            topo_graph = (updater.data or {}).get("topo_graph", {}).get("graph", {})
            if topo_graph.get("is_main", False):
                main_updater = updater
                break

        if main_updater is None:
            raise vol.Invalid("No main router detected (is_main).")

        luci = main_updater.luci
        model = main_updater.data.get("model", "unknown")

        notifier = MiWiFiNotifier(self.hass)
        translations = await notifier.get_translations()
        title = translations.get("title", "MiWiFi")

        try:
            await luci.login()
            dump_data = {
                "timestamp": datetime.datetime.now().isoformat(),
                "router_ip": main_updater.ip
            }

            if opts.get("system"):
                dump_data["system"] = {
                    "status": await safe_call_with_support(self.hass, luci, "status", luci.status(), model),
                    "new_status": await safe_call_with_support(self.hass, luci, "new_status", luci.new_status(), model),
                    "init_info": await safe_call_with_support(self.hass, luci, "init_info", luci.init_info(), model),
                    "rom_update": await safe_call_with_support(self.hass, luci, "rom_update", luci.rom_update(), model),
                    "flash_permission": await safe_call_with_support(self.hass, luci, "flash_permission", luci.flash_permission(), model),
                    "vpn_status": await safe_call_with_support(self.hass, luci, "vpn_status", luci.vpn_status(), model),
                }
            if opts.get("network"):
                dump_data["network"] = {
                    "wan": await safe_call_with_support(self.hass, luci, "wan_info", luci.wan_info(), model),
                    "mode": await safe_call_with_support(self.hass, luci, "mode", luci.mode(), model),
                    "topology": await safe_call_with_support(self.hass, luci, "topo_graph", luci.topo_graph(), model),
                    "wifi": {
                        "signal": await safe_call_with_support(self.hass, luci, "wifi_ap_signal", luci.wifi_ap_signal(), model),
                        "details": await safe_call_with_support(self.hass, luci, "wifi_detail_all", luci.wifi_detail_all(), model),
                        "diagnostics": await safe_call_with_support(self.hass, luci, "wifi_diag_detail_all", luci.wifi_diag_detail_all(), model),
                    }
                }
            if opts.get("devices"):
                dump_data["devices"] = {
                    "connected": await safe_call_with_support(self.hass, luci, "device_list", luci.device_list(), model),
                    "wifi_clients": await safe_call_with_support(self.hass, luci, "wifi_connect_devices", luci.wifi_connect_devices(), model),
                    "macfilter": await safe_call_with_support(self.hass, luci, "mac_filter_info", luci.macfilter_info(), model),
                }
            if opts.get("nat_rules"):
                dump_data["nat_rules"] = {
                    "single": await safe_call_with_support(self.hass, luci, "portforward", luci.portforward(ftype=1), model),
                    "ranges": await safe_call_with_support(self.hass, luci, "portforward", luci.portforward(ftype=2), model),
                }
            if opts.get("qos"):
                dump_data["qos"] = await safe_call_with_support(self.hass, luci, "qos_info", luci.qos_info(), model)
            if opts.get("wifi_config"):
                dump_data["wifi_config"] = {
                    "wifi": await safe_call_with_support(self.hass, luci, "wifi_config", luci.set_wifi({}), model),
                    "guest_wifi": await safe_call_with_support(self.hass, luci, "wifi_config", luci.set_guest_wifi({}), model),
                }

            if opts.get("hide_sensitive", True):
                dump_data = self._mask_sensitive(dump_data)
                
            
            errors = []
            def _find_errors(prefix, data):
                if isinstance(data, dict) and "error" in data:
                    errors.append(prefix)
                elif isinstance(data, dict):
                    for k, v in data.items():
                        _find_errors(f"{prefix}.{k}", v)

            for key, value in dump_data.items():
                _find_errors(key, value)

            dump_data["status"] = "partial" if errors else "ok"
            dump_data["errors"] = errors

            export_dir = os.path.join(self.hass.config.path(), "www", "miwifi", "exports")
            await self.hass.async_add_executor_job(partial(os.makedirs, export_dir, exist_ok=True))

            def _clean_old_dumps():
                dumps = sorted(
                    (f for f in os.listdir(export_dir) if f.startswith("dump_") and f.endswith(".zip")),
                    key=lambda x: os.path.getmtime(os.path.join(export_dir, x)),
                    reverse=True
                )
                max_files = 1
                for old in dumps[max_files:]:
                    try:
                        os.remove(os.path.join(export_dir, old))
                        json_name = old.replace(".zip", ".json")
                        json_path = os.path.join(export_dir, json_name)
                        if os.path.exists(json_path):
                            os.remove(json_path)
                        _LOGGER.debug("Removed old dump archive and JSON: %s", old)
                    except Exception as e:
                        _LOGGER.warning("Failed to remove old dump archive %s: %s", old, e)
            await self.hass.async_add_executor_job(_clean_old_dumps)

            timestamp = datetime.datetime.now().strftime('%Y-%m-%d_%H-%M-%S')
            json_filename = f"dump_{timestamp}.json"
            zip_filename = f"dump_{timestamp}.zip"
            json_path = os.path.join(export_dir, json_filename)
            zip_path = os.path.join(export_dir, zip_filename)

            def _write_and_zip():
                with open(json_path, "w", encoding="utf-8") as f:
                    json.dump(dump_data, f, indent=4, ensure_ascii=False, sort_keys=False)
                with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED) as zipf:
                    zipf.write(json_path, arcname=json_filename)
            await self.hass.async_add_executor_job(_write_and_zip)

            url = f"/local/miwifi/exports/{zip_filename}"
            await self.hass.async_add_executor_job(_LOGGER.info, "[MiWiFi] Dump created in: %s", zip_path)

            message_template = translations.get("notifications", {}).get(
                "dump_ready",
                "📄 Dump generated: <a href='{url}' target='_blank'>Download</a>"
            )
            message = message_template.replace("{url}", url)
            await notifier.notify(message, title=title, notification_id="miwifi_dump_router_data")

        except Exception as e:
            await self.hass.async_add_executor_job(_LOGGER.error, "[MiWiFi] Error creating Dump: %s", e)
            await notifier.notify(
                translations.get("notifications", {}).get("dump_error", "❌ Error generating dump"),
                title=title,
                notification_id="miwifi_dump_router_data"
            )
            raise vol.Invalid(f"Failed to create router dump: {e}")
        
class MiWifiTestGuestWifiServiceCall(MiWifiMainOrDeviceServiceCall):
    """Shows the status of the guest Wi-Fi (does not change anything)."""

    schema = vol.Schema({
        vol.Optional(CONF_DEVICE_ID, description="service_fields.common.device_id"):
            vol.All(cv.ensure_list, vol.Length(min=1, max=1)),
    })

    async def async_call_service(self, service: ServiceCall) -> None:
        updater = self.get_updater(service)
        luci = updater.luci
        await self.hass.async_add_executor_job(_LOGGER.debug, "[MiWiFi] test_guest_wifi: starting (ip=%s)", updater.ip)

        await updater.async_request_refresh()

        try:
            diag = await luci.wifi_diag_detail_all()
            await self.hass.async_add_executor_job(_LOGGER.debug, "[MiWiFi] test_guest_wifi: got diagnostics")
        except LuciError:
            diag = await luci.wifi_detail_all()
            await self.hass.async_add_executor_job(_LOGGER.debug, "[MiWiFi] test_guest_wifi: fallback to wifi_detail_all")

        guest = {"enabled": False, "ssid": None, "encryption": None, "ifname": None}
        cfg_enabled = False
        ifname = None

        for it in (diag or {}).get("info", []) or []:
            if str(it.get("iftype")) == "3" or it.get("ifname") in ("wl14", "wl33"):
                raw_enabled = it.get("enabled")
                cfg_enabled = (str(raw_enabled).strip().lower() in ("1", "true", "on", "yes")) if raw_enabled is not None else False
                guest["ssid"] = it.get("ssid") or guest["ssid"]
                guest["encryption"] = it.get("encryption") or guest["encryption"]
                ifname = it.get("ifname") or ifname
                break

        ap_active = False
        try:
            details = await luci.wifi_detail_all()
            for d in (details or {}).get("info", []) or []:
                if (ifname and d.get("ifname") == ifname) or d.get("ifname") in ("wl14", "wl33"):
                    ifname = d.get("ifname") or ifname
                    ap_active = str(d.get("status", "0")).strip().lower() in ("1", "true", "on", "yes")
                    guest["ssid"] = guest["ssid"] or d.get("ssid")
                    guest["encryption"] = guest["encryption"] or d.get("encryption")
                    break
        except LuciError:
            await self.hass.async_add_executor_job(_LOGGER.debug, "[MiWiFi] test_guest_wifi: wifi_detail_all failed")

        guest["ifname"] = ifname
        guest["enabled"] = bool(cfg_enabled and ap_active)

        notifier = MiWiFiNotifier(self.hass)
        translations = await notifier.get_translations()
        title = translations.get("title", "MiWiFi")
        notify = translations.get("notifications", {})
        state_on = notify.get("status_on", "ON")
        state_off = notify.get("status_off", "OFF")

        msg_tpl = notify.get(
            "guest_status_message",
            "Guest Wi-Fi: {state}\nSSID: {ssid}\nEncryption: {encryption}\nInterface: {ifname}\nSource: {source}"
        )
        msg = (
            msg_tpl
            .replace("{state}", state_on if guest["enabled"] else state_off)
            .replace("{ssid}", guest["ssid"] or "-")
            .replace("{encryption}", guest["encryption"] or "-")
            .replace("{ifname}", guest["ifname"] or "-")
            .replace("{source}", "wifi_diagnostics")
        )

        await self.hass.async_add_executor_job(
            _LOGGER.debug,
            "[MiWiFi] test_guest_wifi: result enabled=%s ssid=%s ifname=%s",
            guest["enabled"], guest["ssid"], guest["ifname"]
        )

        await notifier.notify(message=msg, title=title, notification_id="miwifi_test_guest_wifi")


class MiWifiSetGuestWifiServiceCall(_I18nMixin, MiWifiMainOrDeviceServiceCall):
    """Activa/desactiva y/o renombra la Wi-Fi Guest. 'enable' fija el estado explícitamente."""

    schema = vol.Schema({
        vol.Optional(CONF_DEVICE_ID, description="service_fields.common.device_id"):
            vol.All(cv.ensure_list, vol.Length(min=1, max=1)),
        vol.Required("enable", description="service_fields.set_guest_wifi.enable"):
            selector({"boolean": {}}),
        vol.Optional("ssid", description="service_fields.set_guest_wifi.ssid"): str,
        vol.Optional("password", description="service_fields.set_guest_wifi.password"): str,
        vol.Optional("encryption", description="service_fields.set_guest_wifi.encryption"):
            vol.In(["psk2", "none"]),
        vol.Optional("hidden", description="service_fields.set_guest_wifi.hidden"):
            vol.In([0, 1]),
    })

    async def async_call_service(self, service: ServiceCall) -> None:
        updater = self.get_updater(service)
        luci = updater.luci

        new_enabled = bool(service.data["enable"])
        req_ssid = service.data.get("ssid")
        req_password = service.data.get("password")
        want_encryption = service.data.get("encryption")
        hidden = service.data.get("hidden")

        await self.hass.async_add_executor_job(
            _LOGGER.info,
            "[MiWiFi] set_guest_wifi: request enable=%s ssid=%s enc=%s hidden=%s (ip=%s)",
            new_enabled, req_ssid, want_encryption, hidden, updater.ip
        )
        if req_password:
            await self.hass.async_add_executor_job(
                _LOGGER.info, "[MiWiFi] set_guest_wifi: password_len=%s", len(req_password)
            )

        
        cur_ssid = None
        cur_encryption = None
        wifi_index = 3
        ifname = None
        try:
            diag = await luci.wifi_diag_detail_all()
        except LuciError:
            diag = await luci.wifi_detail_all()

        for it in (diag or {}).get("info", []) or []:
            if str(it.get("iftype")) == "3" or it.get("ifname") in ("wl14", "wl33"):
                cur_ssid = it.get("ssid")
                cur_encryption = it.get("encryption") or it.get("enctype")
                dev = it.get("device") or ""
                m = re.search(r"wifi(\d+)\.network", dev)
                if m:
                    wifi_index = int(m.group(1))
                ifname = it.get("ifname")
                break

        await self.hass.async_add_executor_job(
            _LOGGER.info,
            "[MiWiFi] set_guest_wifi: resolved wifiIndex=%s ifname=%s cur_ssid=%s cur_enc=%s",
            wifi_index, ifname, cur_ssid, cur_encryption
        )

        
        effective_encryption = want_encryption if want_encryption is not None else cur_encryption

        payload: dict = {
            "wifiIndex": wifi_index,
           
            "on": 1 if new_enabled else 0,
            "enable": 1 if new_enabled else 0,
            "enabled": 1 if new_enabled else 0,
        }

       
        if req_ssid is not None:
            payload["ssid"] = req_ssid

        if ifname:
            payload["ifname"] = ifname  

        if effective_encryption:
            payload["encryption"] = effective_encryption
            payload["enctype"] = effective_encryption

        if hidden is not None:
            payload["hidden"] = hidden

        if req_password is not None and (effective_encryption or "psk2") != "none":
            if not (8 <= len(req_password) <= 63):
                msg = await self._t(
                    "password_length_error", "La contraseña debe tener entre 8 y 63 caracteres."
                )
                raise vol.Invalid(msg)

            payload["pwd"] = req_password        
            payload["password"] = req_password  
           
            payload.setdefault("passwd", req_password)

    
        if payload.get("encryption") == "none":
            payload.pop("password", None)
            payload.pop("pwd", None)
            payload.pop("passwd", None)


        def _mask(v): 
            return f"<len:{len(v)}>" if isinstance(v, str) else v
        safe_payload = {
            k: (_mask(v) if k.lower() in ("password", "pwd", "passwd") else v)
            for k, v in payload.items()
        }
        await self.hass.async_add_executor_job(_LOGGER.info, "[MiWiFi] set_guest_wifi: payload=%s", safe_payload)


        await luci.login()
        resp = await luci.set_guest_wifi(payload)
        await self.hass.async_add_executor_job(_LOGGER.info, "[MiWiFi] set_guest_wifi: response=%s", resp)
        code = (resp or {}).get("code")

        if code not in (0, "0", None):
            await self.hass.async_add_executor_job(
                _LOGGER.info, "[MiWiFi] set_guest_wifi: first call failed (code=%s), trying set_wifi", code
            )
            resp2 = await luci.set_wifi(payload)
            await self.hass.async_add_executor_job(_LOGGER.info, "[MiWiFi] set_guest_wifi: set_wifi response=%s", resp2)
            code2 = (resp2 or {}).get("code")
            if code2 not in (0, "0", None):
                msg = await self._t("router_error", "El router devolvió un error.")
                await self.hass.async_add_executor_job(_LOGGER.info, "[MiWiFi] set_guest_wifi: both calls failed")
                raise vol.Invalid(msg)

        
        await updater.async_request_refresh()
        await self.hass.async_add_executor_job(_LOGGER.info, "[MiWiFi] set_guest_wifi: applied successfully")

 
        notifier = MiWiFiNotifier(self.hass)
        translations = await notifier.get_translations()
        title = translations.get("title", "MiWiFi")
        notify = translations.get("notifications", {})
        state_on = notify.get("status_on", "ON")
        state_off = notify.get("status_off", "OFF")

        msg_tpl = notify.get(
            "guest_updated",
            "Guest Wi-Fi: {state}<br>SSID: {ssid}<br>Encryption: {encryption}"
        )
        msg = (
            msg_tpl
            .replace("{state}", state_on if new_enabled else state_off)
            .replace("{ssid}", payload.get("ssid", "(no change)"))
            .replace("{encryption}", payload.get("encryption", effective_encryption) or "(no change)")
        )
        await notifier.notify(msg, title=title, notification_id="miwifi_set_guest_wifi")


class MiWifiGetWifisServiceCall(MiWifiMainOrDeviceServiceCall):
    "Reads current Wi-Fi configuration and returns it in response_data (guest/2g/5g/game)."

    schema = vol.Schema({
        vol.Optional(CONF_DEVICE_ID, description="service_fields.common.device_id"):
            vol.All(cv.ensure_list, vol.Length(min=1, max=1)),
        vol.Optional("hide_sensitive", description="service_fields.get_wifis.hide_sensitive", default=True):
            selector({"boolean": {}})
    })

    async def async_call_service(self, service: ServiceCall) -> dict:
        updater = self.get_updater(service)
        luci = updater.luci
        hide_sensitive: bool = bool(service.data.get("hide_sensitive", True))

        await self.hass.async_add_executor_job(
            _LOGGER.debug, "[MiWiFi] get_wifis: starting (ip=%s, hide_sensitive=%s)", updater.ip, hide_sensitive
        )

        await updater.async_request_refresh()

        try:
            diag = await luci.wifi_diag_detail_all()
        except LuciError:
            diag = {}
        details = await luci.wifi_detail_all()

        d_info = (details or {}).get("info", []) or []
        g_info = (diag or {}).get("info", []) or []
       
        all_info = list(g_info) + [it for it in d_info if it not in g_info]

        def _norm_bool(v):
            return str(v).strip().lower() in ("1", "true", "on", "yes")

        def _chan(it):
            ci = it.get("channelInfo") or {}
            ch = ci.get("channel")
           
            return it.get("channel", ch)

        def _band_str(it):
            s = (it.get("band") or it.get("radio") or "").lower()
            return s

        def _is_24g(it):
            ch = _chan(it)
            if isinstance(ch, int) and ch <= 14:
                return True
            b = _band_str(it)
            return "2.4" in b or "2g" in b or "2ghz" in b or str(it.get("iftype")) == "1"

        def _is_5g(it):
            ch = _chan(it)
            if isinstance(ch, int) and ch > 14:
                return True
            b = _band_str(it)
            if "5g" in b or "5ghz" in b:
                return True
            return str(it.get("iftype")) == "2"

        def _is_game_5g(it):
            
            if (it.get("ifname") or "").lower() == "wl2":
                return True
            ssid = (it.get("ssid") or "").lower()
           
            return "game" in ssid or "gaming" in ssid

        def _find_guest():
            
            for it in all_info:
                if str(it.get("iftype")) == "3":
                    return it
                if (it.get("ifname") or "").lower() in ("wl14", "wl33"):
                    return it
            return None

        def _find_2g():
            for it in all_info:
                if _is_24g(it) and not _is_game_5g(it):
                    return it
            return None

        def _find_game():
            for it in all_info:
                if _is_5g(it) and _is_game_5g(it):
                    return it
            return None

        def _find_5g():
            
            for it in all_info:
                if _is_5g(it) and not _is_game_5g(it):
                    return it
            return None

        def _wifi_index_from_device(dev: str | None) -> int | None:
            if not dev or not isinstance(dev, str):
                return None
            m = re.search(r"wifi(\d+)\.network", dev)
            return int(m.group(1)) if m else None

        def _pack(it: dict | None) -> dict | None:
            if not it:
                return None
            pwd = it.get("password")
            return {
                "wifiIndex": _wifi_index_from_device(it.get("device")),
                "ifname": it.get("ifname"),
                "enabled": _norm_bool(it.get("enabled", it.get("status", 0))),
                "ssid": it.get("ssid"),
                "encryption": it.get("encryption") or it.get("enctype"),
                "hidden": it.get("hidden"),
                "channel": _chan(it),
                "bandwidth": (it.get("channelInfo") or {}).get("bandwidth"),
                "txpwr": it.get("txpwr"),
                "password": (None if hide_sensitive else pwd) if pwd is not None else None,
            }

        data = {
            "guest": _pack(_find_guest()),
            "2g": _pack(_find_2g()),
            "5g": _pack(_find_5g()),
            "game": _pack(_find_game()),
        }

        def _scrub(d):
            if not d:
                return d
            c = dict(d)
            if "password" in c and c["password"] is not None:
                c["password"] = "<hidden>"
            return c

        safe_data = {k: _scrub(v) for k, v in data.items()}
        await self.hass.async_add_executor_job(_LOGGER.debug, "[MiWiFi] get_wifis: result=%s", safe_data)

        return {"wifis": data}


class MiWifiSetWifisServiceCall(_I18nMixin, MiWifiMainOrDeviceServiceCall):
    """Set 2.4G / 5G / 5G-Game without forcing state; only apply the fields you fill in."""
    schema = vol.Schema({
        vol.Optional(CONF_DEVICE_ID, description="service_fields.common.device_id"):
            vol.All(cv.ensure_list, vol.Length(min=1, max=1)),
        vol.Optional("wifi2g", description="service_fields.set_wifis.wifi2g"): selector({"object": {}}),
        vol.Optional("wifi5g", description="service_fields.set_wifis.wifi5g"): selector({"object": {}}),
        vol.Optional("wifi5g_game", description="service_fields.set_wifis.wifi5g_game"): selector({"object": {}}),
    })

    async def async_call_service(self, service: ServiceCall) -> None:
        updater = self.get_updater(service)
        luci = updater.luci

        blocks = {k: v for k, v in {
            "wifi2g": service.data.get("wifi2g"),
            "wifi5g": service.data.get("wifi5g"),
            "wifi5g_game": service.data.get("wifi5g_game"),
        }.items() if isinstance(v, dict) and v}

        if not blocks:
            msg = await self._t("no_blocks", "No Wi-Fi block provided (wifi2g/wifi5g/wifi5g_game).")
            raise vol.Invalid(msg)
        
        await self.hass.async_add_executor_job(_LOGGER.info, "[MiWiFi] set_wifis: blocks=%s (ip=%s)", list(blocks.keys()), updater.ip)

        details = await luci.wifi_detail_all()
        info = (details or {}).get("info", []) or []

        def pick(role: str):
            if role == "wifi2g":
                for it in info:
                    ch = it.get("channelInfo", {}).get("channel")
                    if str(it.get("iftype")) == "1" or (isinstance(ch, int) and ch <= 14):
                        return it
            elif role in ("wifi5g", "wifi5g_game"):
                for it in info:
                    if str(it.get("iftype")) == "2":
                        if role == "wifi5g_game" and it.get("ifname") == "wl2":
                            return it
                        if role == "wifi5g" and it.get("ifname") != "wl2":
                            return it
            return None

        allowed = {"ssid", "password", "encryption", "hidden"}

        await luci.login()
        applied = []
        for role, data in blocks.items():
            cur = pick(role)
            if not cur:
                await self.hass.async_add_executor_job(_LOGGER.warning, "[MiWiFi] set_wifis: could not resolve role=%s", role)
                continue
            dev = cur.get("device", "")
            m = re.search(r"wifi(\d+)\.network", dev)
            wifi_index = int(m.group(1)) if m else None
            if wifi_index is None:
                await self.hass.async_add_executor_job(_LOGGER.warning, "[MiWiFi] set_wifis: no wifiIndex for role=%s", role)
                continue

            payload = {"wifiIndex": wifi_index}
            for k in allowed:
                if k in data:
                    payload[k] = data[k]

            if payload.get("encryption") == "none":
                payload.pop("password", None)

            if "password" in payload and payload.get("password") is not None:
                if payload.get("encryption", "psk2") == "psk2":
                    if not (8 <= len(payload["password"]) <= 63):
                        msg = await self._t(
                            "password_length_role",
                            "[{role}] Password must be 8–63 characters.",
                            role=role
                        )
                        raise vol.Invalid(msg)


            safe_payload = {k: (v if k != "password" else f"<len:{len(v)}>")
                            for k, v in payload.items()}
            await self.hass.async_add_executor_job(_LOGGER.debug, "[MiWiFi] set_wifis: role=%s payload=%s", role, safe_payload)

            resp = await luci.set_wifi(payload)
            if (resp or {}).get("code") not in (0, "0", None):
                msg = await self._t(
                    "apply_role_error",
                    "Error applying changes to {role}.",
                    role=role
                )
                await self.hass.async_add_executor_job(_LOGGER.error, "[MiWiFi] set_wifis: %s -> %s", msg, resp)
                raise vol.Invalid(msg)

            applied.append(role)

        await updater.async_request_refresh()
        await self.hass.async_add_executor_job(_LOGGER.info, "[MiWiFi] set_wifis: applied=%s", applied)

        notifier = MiWiFiNotifier(self.hass)
        translations = await notifier.get_translations()
        title = translations.get("title", "MiWiFi")
        notify = translations.get("notifications", {})
        msg_tpl = notify.get("wifis_updated", "Wi-Fi updated: {bands}")
        msg = msg_tpl.replace("{bands}", ", ".join(applied) if applied else "-")
        await notifier.notify(msg, title=title, notification_id="miwifi_set_wifis")

class MiWifiPurgeInactiveDevicesServiceCall:
    """Purge device_trackers and orphaned devices due to inactivity."""

    schema = vol.Schema({
        vol.Optional("days", description="service_fields.purge_inactive.days", default=30):
            vol.All(vol.Coerce(int), vol.Range(min=1, max=3650)),
        vol.Optional("only_randomized", description="service_fields.purge_inactive.only_randomized", default=True):
            cv.boolean,
        vol.Optional("include_orphans", description="service_fields.purge_inactive.include_orphans", default=True):
            cv.boolean,
        vol.Optional("include_orphans_without_age", description="service_fields.purge_inactive.include_orphans_without_age", default=True):
            cv.boolean,
        vol.Optional("verbose", description="service_fields.common.verbose", default=True):
            cv.boolean,
        vol.Optional("apply", description="service_fields.purge_inactive.apply", default=False):
            cv.boolean,
    })

    def __init__(self, hass):
        self.hass = hass

    @staticmethod
    def _is_randomized_mac(mac: str | None) -> bool:
        if not mac or ":" not in mac:
            return False
        try:
            first = int(mac.split(":")[0], 16)
            return bool(first & 0x02)
        except Exception:
            return False

    @staticmethod
    def _norm_mac(mac: str | None) -> str | None:
        if not mac or mac in ("-", ""):
            return None
        m = re.sub(r"[^0-9a-fA-F]", "", mac)
        if len(m) != 12:
            return None
        return ":".join(m[i:i + 2] for i in range(0, 12, 2)).upper()

    @staticmethod
    def _mac_from_unique_id(uq: str | None) -> str | None:
        """Intenta extraer una MAC de unique_id, soportando sufijos tipo '_2'."""
        if not uq:
            return None

        parts = uq.split("-")
        if len(parts) < 3:
            return None

        last = parts[-1]

  
        if "_" in last:
            last = last.split("_", 1)[0]

        mac = MiWifiPurgeInactiveDevicesServiceCall._norm_mac(last)
        if mac:
            return mac

        m = re.search(r"([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})", uq)
        if m:
            return MiWifiPurgeInactiveDevicesServiceCall._norm_mac(m.group(0))

        return None

    async def async_call_service(self, service: ServiceCall):
        days: int = int(service.data.get("days", 30))
        only_rand: bool = bool(service.data.get("only_randomized", True))
        include_orphans: bool = bool(service.data.get("include_orphans", True))
        include_orphans_wo_age: bool = bool(service.data.get("include_orphans_without_age", True))
        verbose: bool = bool(service.data.get("verbose", True))
        apply_changes: bool = bool(service.data.get("apply", False))

        now_ts = int(time.time())
        cutoff = now_ts - days * 86400

        ent_reg = er.async_get(self.hass)
        dev_reg = dr.async_get(self.hass)
        integrations = async_get_integrations(self.hass)
        updaters = [data.get(UPDATER) for data in integrations.values() if data.get(UPDATER)]
        all_entry_ids = list({
            data.get(ATTR_TRACKER_ENTRY_ID)
            for data in integrations.values()
            if data.get(ATTR_TRACKER_ENTRY_ID)
        })

        def _last_ts_from_updaters(mac: str | None) -> int | None:
            if not mac:
                return None
            for upd in updaters:
                dev = getattr(upd, "devices", {}).get(mac)
                if dev and isinstance(dev.get(ATTR_TRACKER_LAST_ACTIVITY), str):
                    try:
                        return parse_last_activity(dev[ATTR_TRACKER_LAST_ACTIVITY])
                    except Exception:
                        continue
            return None

        entity_targets: list[tuple[str, str | None, str | None, float | None, str | None]] = []

        for entry in list(ent_reg.entities.values()):
            if entry.platform != DOMAIN or entry.domain != "device_tracker":
                continue

            st = self.hass.states.get(entry.entity_id)
            attrs = dict(st.attributes) if st else {}
            mac = self._norm_mac(attrs.get(ATTR_TRACKER_MAC) if st else None)
            if not mac:
                mac = self._mac_from_unique_id(entry.unique_id)

            is_rand = self._is_randomized_mac(mac) if mac else False
            if only_rand and not (is_rand or (mac is None and include_orphans_wo_age)):
                continue

            ts: int | None = None
            last = attrs.get(ATTR_TRACKER_LAST_ACTIVITY) if st else None
            if isinstance(last, str):
                try:
                    ts = parse_last_activity(last)
                except Exception:
                    ts = None
            if ts is None:
                ts = _last_ts_from_updaters(mac)

            if ts is None:
                if not include_orphans_wo_age:
                    continue
                days_ago: float | None = None
            else:
                if ts > cutoff:
                    continue
                days_ago = round((now_ts - ts) / 86400, 2)

            entity_targets.append(
                (entry.entity_id, entry.device_id, mac, days_ago, entry.config_entry_id)
            )

 
        orphan_targets: list[tuple[str, str | None, float | None]] = []
        if include_orphans:
            for device in list(dev_reg.devices.values()):
                if not any(dom == DOMAIN for (dom, _id) in device.identifiers):
                    continue

                ents = er.async_entries_for_device(ent_reg, device.id, include_disabled_entities=True)
                if ents:
                
                    continue

                mac: str | None = None
                for dom, ident in device.identifiers:
                    if dom == DOMAIN and isinstance(ident, str) and ":" in ident:
                        mac = self._mac_from_unique_id(ident)
                        break

                is_rand = self._is_randomized_mac(mac) if mac else False
                if only_rand and not (is_rand or (mac is None and include_orphans_wo_age)):
                    continue

                ts = _last_ts_from_updaters(mac)
                if ts is None and not include_orphans_wo_age:
                    continue
                if ts is not None and ts > cutoff:
                    continue

                days_ago = None if ts is None else round((now_ts - ts) / 86400, 2)
                orphan_targets.append((device.id, mac, days_ago))

        entities_removed: list[str] = []
        devices_removed: list[str] = []

        if apply_changes:
      
            macs_to_purge = [mac for *_skip, mac, _days, _entry in entity_targets if mac]
            for mac in macs_to_purge:
                for entry_id in all_entry_ids:
                    async_dispatcher_send(self.hass, SIGNAL_PURGE_DEVICE, entry_id, mac)


            for entity_id, _dev_id, _mac, _days_ago, _entry_id in entity_targets:
                if ent_reg.async_get(entity_id):
                    ent_reg.async_remove(entity_id)
                if not ent_reg.async_get(entity_id):
                    entities_removed.append(entity_id)


            touched_devices = set(
                [d for _, d, *_ in entity_targets if d]
            ) | set(
                [d for d, *_ in orphan_targets]
            )

            for dev_id in list(touched_devices):
                if not dev_id:
                    continue

                if er.async_entries_for_device(ent_reg, dev_id, include_disabled_entities=True):
                    continue
                dev = dev_reg.async_get(dev_id)
                if not dev:
                    continue
   
                if not any(dom == DOMAIN for (dom, _id) in dev.identifiers):
                    continue

                if len(dev.config_entries) > 1:
                    continue
                dev_reg.async_remove_device(dev_id)
                devices_removed.append(dev_id)


        notifier = MiWiFiNotifier(self.hass)
        tr = await notifier.get_translations() or {}
        title = tr.get("title", "MiWiFi")
        t_notify = tr.get("notifications", {})
        tpl_key = "purge_done" if apply_changes else "purge_dry_run"
        default_tpl = (
            "Removed {entities} entities and {devices} devices (> {days} days; randomized={only_randomized})."
            if apply_changes else
            "Dry-run: would remove {entities} entities and {devices} devices (> {days} days; randomized={only_randomized})."
        )

        entities_count = len(entities_removed) if apply_changes else len(entity_targets)
        devices_count = len(devices_removed) if apply_changes else len({d for d, *_ in orphan_targets})

        msg = (t_notify.get(tpl_key, default_tpl)
               .replace("{entities}", str(entities_count))
               .replace("{devices}", str(devices_count))
               .replace("{days}", str(days))
               .replace("{only_randomized}", "true" if only_rand else "false"))
        await notifier.notify(msg, title=title, notification_id="miwifi_purge_inactive")

        if verbose:
            preview_lines: list[str] = []
            if not apply_changes:
                for ent_id, dev_id, mac, days_ago, _eid in entity_targets[:50]:
                    age = "?" if days_ago is None else f"{days_ago}d"
                    reason = "entity_without_age" if days_ago is None else "inactive"
                    preview_lines.append(
                        f"Entity: {ent_id} | dev={dev_id} | mac={mac} | {age} | {reason}"
                    )
                for dev_id, mac, days_ago in orphan_targets[:50]:
                    age = "unknown" if days_ago is None else f"{days_ago}d"
                    preview_lines.append(
                        f"Device: {dev_id} | mac={mac} | {age} | orphan_device"
                    )
                if preview_lines:
                    await notifier.notify(
                        "\n".join(preview_lines),
                        title=f"{title} — Purge preview",
                    )

        return {
            "applied": apply_changes,
            "entities": entities_count,
        }

        
SERVICES: Final = (
    (SERVICE_CALC_PASSWD, MiWifiCalcPasswdServiceCall),
    (SERVICE_REQUEST, MiWifiRequestServiceCall),
    ("get_topology_graph", MiWifiGetTopologyGraphServiceCall),
    ("log_panel", MiWifiLogPanelServiceCall),
    ("select_main_router", MiWifiSelectMainNodeServiceCall),
    ("block_device", MiWifiBlockDeviceServiceCall),
    ("list_ports", MiWifiListPortsServiceCall),
    ("add_port", MiWifiAddPortServiceCall),
    ("add_range_port", MiWifiAddRangePortServiceCall),
    ("delete_port", MiWifiDeletePortServiceCall),
    ("refresh_nat_rules", MiWifiRefreshNATRulesServiceCall),
    ("clear_logs", MiWifiClearLogsService),
    ("purge_inactive_devices", MiWifiPurgeInactiveDevicesServiceCall),
    ("download_logs", MiWifiDownloadLogsService),
    ("add_unsupported", MiWifiAddUnsupportedService),
    ("dump_router_data", MiWifiDumpRouterDataService),
    ("get_wifis", MiWifiGetWifisServiceCall),   
    ("test_guest_wifi", MiWifiTestGuestWifiServiceCall),
    ("set_guest_wifi", MiWifiSetGuestWifiServiceCall),
    #("set_wifis", MiWifiSetWifisServiceCall),
)
