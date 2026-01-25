"""Sensor component."""

from __future__ import annotations

import asyncio
from datetime import datetime
from enum import Enum
from typing import Any, Final
from dataclasses import replace

from homeassistant.components.sensor import (
    ENTITY_ID_FORMAT,
    SensorDeviceClass,
    SensorEntity,
    SensorEntityDescription,
    SensorStateClass,
)
from homeassistant.config_entries import ConfigEntry
from homeassistant.const import (
    PERCENTAGE,
    UnitOfInformation,
    UnitOfTemperature,
    UnitOfDataRate,
)
from homeassistant.core import HomeAssistant, callback
from homeassistant.helpers import device_registry as dr, entity_registry as er
from homeassistant.helpers.dispatcher import async_dispatcher_connect
from homeassistant.helpers.entity import DeviceInfo
from homeassistant.helpers.entity_platform import (
    AddEntitiesCallback,
    EntityPlatform,
    async_get_current_platform,
)
from homeassistant.helpers.entity import EntityCategory
from homeassistant.helpers.update_coordinator import CoordinatorEntity
from homeassistant.util import dt as dt_util

from .const import (
    ATTR_SENSOR_AP_SIGNAL,
    ATTR_SENSOR_AP_SIGNAL_NAME,
    ATTR_SENSOR_DEVICES,
    ATTR_SENSOR_DEVICES_2_4,
    ATTR_SENSOR_DEVICES_2_4_NAME,
    ATTR_SENSOR_DEVICES_5_0,
    ATTR_SENSOR_DEVICES_5_0_GAME,
    ATTR_SENSOR_DEVICES_5_0_GAME_NAME,
    ATTR_SENSOR_DEVICES_5_0_NAME,
    ATTR_SENSOR_DEVICES_GUEST,
    ATTR_SENSOR_DEVICES_GUEST_NAME,
    ATTR_SENSOR_DEVICES_LAN,
    ATTR_SENSOR_DEVICES_LAN_NAME,
    ATTR_SENSOR_DEVICES_NAME,
    ATTR_SENSOR_MEMORY_TOTAL,
    ATTR_SENSOR_MEMORY_TOTAL_NAME,
    ATTR_SENSOR_MEMORY_USAGE,
    ATTR_SENSOR_MEMORY_USAGE_NAME,
    ATTR_SENSOR_MODE,
    ATTR_SENSOR_MODE_NAME,
    ATTR_SENSOR_TEMPERATURE,
    ATTR_SENSOR_TEMPERATURE_NAME,
    ATTR_SENSOR_UPTIME,
    ATTR_SENSOR_UPTIME_NAME,
    ATTR_SENSOR_VPN_UPTIME,
    ATTR_SENSOR_VPN_UPTIME_NAME,
    ATTR_SENSOR_WAN_DOWNLOAD_SPEED,
    ATTR_SENSOR_WAN_DOWNLOAD_SPEED_NAME,
    ATTR_SENSOR_WAN_UPLOAD_SPEED,
    ATTR_SENSOR_WAN_UPLOAD_SPEED_NAME,
    ATTR_SENSOR_WAN_IP,
    ATTR_SENSOR_WAN_IP_NAME,
    ATTR_SENSOR_WAN_TYPE,
    ATTR_SENSOR_WAN_TYPE_NAME,
    # Device tracker attrs (per-device sensors)
    CONF_ENABLE_DEVICE_SENSORS,
    DEFAULT_ENABLE_DEVICE_SENSORS,
    ATTR_TRACKER_CONNECTION,
    ATTR_TRACKER_DOWN_SPEED,
    ATTR_TRACKER_FIRST_SEEN,
    ATTR_TRACKER_INTERNET_BLOCKED,
    ATTR_TRACKER_IP,
    ATTR_TRACKER_LAST_ACTIVITY,
    ATTR_TRACKER_MAC,
    ATTR_TRACKER_NAME,
    ATTR_TRACKER_ONLINE,
    ATTR_TRACKER_OPTIONAL_MAC,
    ATTR_TRACKER_SIGNAL,
    ATTR_TRACKER_TOTAL_USAGE,
    ATTR_TRACKER_UP_SPEED,
    SIGNAL_NEW_DEVICE,
    SIGNAL_PURGE_DEVICE,
    ATTR_STATE,
    CONF_WAN_SPEED_UNIT,
    DEFAULT_WAN_SPEED_UNIT,
    DOMAIN,
    UPDATER,
    ATTR_TRACKER_ROUTER_MAC_ADDRESS,
    ATTR_TRACKER_UPDATER_ENTRY_ID,
)
from .entity import MiWifiEntity
from .enum import Connection, DeviceClass
from .helper import detect_manufacturer, map_signal_quality
from .logger import _LOGGER
from .updater import LuciUpdater, async_get_updater

PARALLEL_UPDATES = 0

DISABLE_ZERO: Final = (
    ATTR_SENSOR_TEMPERATURE,
    ATTR_SENSOR_AP_SIGNAL,
)

ONLY_WAN: Final = (
    ATTR_SENSOR_WAN_DOWNLOAD_SPEED,
    ATTR_SENSOR_WAN_UPLOAD_SPEED,
)

PCS: Final = "pcs"

MIWIFI_SENSORS: tuple[SensorEntityDescription, ...] = (
    SensorEntityDescription(
        key=ATTR_SENSOR_UPTIME,
        name=ATTR_SENSOR_UPTIME_NAME,
        icon="mdi:timer-sand",
        entity_category=EntityCategory.DIAGNOSTIC,
        entity_registry_enabled_default=True,
    ),
    SensorEntityDescription(
        key=ATTR_SENSOR_VPN_UPTIME,
        name=ATTR_SENSOR_VPN_UPTIME_NAME,
        icon="mdi:timer-sand",
        entity_category=EntityCategory.DIAGNOSTIC,
        entity_registry_enabled_default=True,
    ),
    SensorEntityDescription(
        key=ATTR_SENSOR_MEMORY_USAGE,
        name=ATTR_SENSOR_MEMORY_USAGE_NAME,
        icon="mdi:memory",
        native_unit_of_measurement=PERCENTAGE,
        state_class=SensorStateClass.MEASUREMENT,
        entity_category=EntityCategory.DIAGNOSTIC,
        entity_registry_enabled_default=True,
    ),
    SensorEntityDescription(
        key=ATTR_SENSOR_MEMORY_TOTAL,
        name=ATTR_SENSOR_MEMORY_TOTAL_NAME,
        icon="mdi:memory",
        native_unit_of_measurement=UnitOfInformation.MEGABYTES,
        state_class=SensorStateClass.TOTAL,
        entity_category=EntityCategory.DIAGNOSTIC,
        entity_registry_enabled_default=True,
    ),
    SensorEntityDescription(
        key=ATTR_SENSOR_TEMPERATURE,
        name=ATTR_SENSOR_TEMPERATURE_NAME,
        icon="mdi:temperature-celsius",
        native_unit_of_measurement=UnitOfTemperature.CELSIUS,
        device_class=SensorDeviceClass.TEMPERATURE,
        state_class=SensorStateClass.MEASUREMENT,
        entity_category=EntityCategory.DIAGNOSTIC,
        entity_registry_enabled_default=True,
    ),
    SensorEntityDescription(
        key=ATTR_SENSOR_MODE,
        name=ATTR_SENSOR_MODE_NAME,
        icon="mdi:transit-connection-variant",
        device_class=DeviceClass.MODE,
        entity_category=EntityCategory.DIAGNOSTIC,
        entity_registry_enabled_default=True,
    ),
    SensorEntityDescription(
        key=ATTR_SENSOR_AP_SIGNAL,
        name=ATTR_SENSOR_AP_SIGNAL_NAME,
        icon="mdi:wifi-arrow-left-right",
        state_class=SensorStateClass.MEASUREMENT,
        entity_category=EntityCategory.DIAGNOSTIC,
        entity_registry_enabled_default=True,
    ),
    SensorEntityDescription(
        key=ATTR_SENSOR_WAN_DOWNLOAD_SPEED,
        name=ATTR_SENSOR_WAN_DOWNLOAD_SPEED_NAME,
        icon="mdi:speedometer",
        device_class=SensorDeviceClass.DATA_RATE,
        state_class=SensorStateClass.MEASUREMENT,
        entity_category=EntityCategory.DIAGNOSTIC,
        entity_registry_enabled_default=True,
    ),
    SensorEntityDescription(
        key=ATTR_SENSOR_WAN_UPLOAD_SPEED,
        name=ATTR_SENSOR_WAN_UPLOAD_SPEED_NAME,
        icon="mdi:speedometer",
        device_class=SensorDeviceClass.DATA_RATE,
        state_class=SensorStateClass.MEASUREMENT,
        entity_category=EntityCategory.DIAGNOSTIC,
        entity_registry_enabled_default=True,
    ),
    SensorEntityDescription(
        key=ATTR_SENSOR_DEVICES,
        name=ATTR_SENSOR_DEVICES_NAME,
        icon="mdi:counter",
        native_unit_of_measurement=PCS,
        state_class=SensorStateClass.MEASUREMENT,
        entity_registry_enabled_default=True,
    ),
    SensorEntityDescription(
        key=ATTR_SENSOR_DEVICES_LAN,
        name=ATTR_SENSOR_DEVICES_LAN_NAME,
        icon="mdi:counter",
        native_unit_of_measurement=PCS,
        state_class=SensorStateClass.MEASUREMENT,
        entity_registry_enabled_default=True,
    ),
    SensorEntityDescription(
        key=ATTR_SENSOR_DEVICES_2_4,
        name=ATTR_SENSOR_DEVICES_2_4_NAME,
        icon="mdi:counter",
        native_unit_of_measurement=PCS,
        state_class=SensorStateClass.MEASUREMENT,
        entity_registry_enabled_default=True,
    ),
    SensorEntityDescription(
        key=ATTR_SENSOR_DEVICES_5_0,
        name=ATTR_SENSOR_DEVICES_5_0_NAME,
        icon="mdi:counter",
        native_unit_of_measurement=PCS,
        state_class=SensorStateClass.MEASUREMENT,
        entity_registry_enabled_default=True,
    ),
    SensorEntityDescription(
        key=ATTR_SENSOR_DEVICES_GUEST,
        name=ATTR_SENSOR_DEVICES_GUEST_NAME,
        icon="mdi:counter",
        native_unit_of_measurement=PCS,
        state_class=SensorStateClass.MEASUREMENT,
        entity_registry_enabled_default=True,
    ),
    SensorEntityDescription(
        key=ATTR_SENSOR_DEVICES_5_0_GAME,
        name=ATTR_SENSOR_DEVICES_5_0_GAME_NAME,
        icon="mdi:counter",
        native_unit_of_measurement=PCS,
        state_class=SensorStateClass.MEASUREMENT,
        entity_registry_enabled_default=True,
    ),
    SensorEntityDescription(
        key=ATTR_SENSOR_WAN_IP,
        name=ATTR_SENSOR_WAN_IP_NAME,
        icon="mdi:ip",
        entity_category=EntityCategory.DIAGNOSTIC,
        entity_registry_enabled_default=True,
    ),
    SensorEntityDescription(
        key=ATTR_SENSOR_WAN_TYPE,
        name=ATTR_SENSOR_WAN_TYPE_NAME,
        icon="mdi:lan",
        entity_category=EntityCategory.DIAGNOSTIC,
        entity_registry_enabled_default=True,
    ),
)

# ────────────────────────────────────────────────────────────────────────────────
# Per-device sensors (mirrors device_tracker attributes)
# ────────────────────────────────────────────────────────────────────────────────

KEY_SIGNAL_QUALITY: Final = "signal_quality"

MIWIFI_DEVICE_SENSORS: tuple[SensorEntityDescription, ...] = (
    SensorEntityDescription(
        key=ATTR_TRACKER_IP,
        name="IP",
        icon="mdi:ip-network",
        entity_category=EntityCategory.DIAGNOSTIC,
        entity_registry_enabled_default=True,
    ),
    SensorEntityDescription(
        key=ATTR_TRACKER_CONNECTION,
        name="Connection",
        icon="mdi:lan-connect",
        entity_category=EntityCategory.DIAGNOSTIC,
        entity_registry_enabled_default=True,
    ),
    SensorEntityDescription(
        key=ATTR_TRACKER_ONLINE,
        name="Online",
        icon="mdi:timer-outline",
        entity_category=EntityCategory.DIAGNOSTIC,
        entity_registry_enabled_default=True,
    ),
    SensorEntityDescription(
        key=ATTR_TRACKER_DOWN_SPEED,
        name="Down speed",
        icon="mdi:download-network",
        device_class=SensorDeviceClass.DATA_RATE,
        native_unit_of_measurement=UnitOfDataRate.BYTES_PER_SECOND,
        state_class=SensorStateClass.MEASUREMENT,
        entity_category=EntityCategory.DIAGNOSTIC,
        entity_registry_enabled_default=True,
    ),
    SensorEntityDescription(
        key=ATTR_TRACKER_UP_SPEED,
        name="Up speed",
        icon="mdi:upload-network",
        device_class=SensorDeviceClass.DATA_RATE,
        native_unit_of_measurement=UnitOfDataRate.BYTES_PER_SECOND,
        state_class=SensorStateClass.MEASUREMENT,
        entity_category=EntityCategory.DIAGNOSTIC,
        entity_registry_enabled_default=True,
    ),
    SensorEntityDescription(
        key=ATTR_TRACKER_TOTAL_USAGE,
        name="Total usage",
        icon="mdi:counter",
        device_class=SensorDeviceClass.DATA_SIZE,
        native_unit_of_measurement=UnitOfInformation.BYTES,
        state_class=SensorStateClass.TOTAL_INCREASING,
        entity_category=EntityCategory.DIAGNOSTIC,
        entity_registry_enabled_default=False,
    ),
    SensorEntityDescription(
        key=ATTR_TRACKER_SIGNAL,
        name="Signal",
        icon="mdi:wifi",
        device_class=SensorDeviceClass.SIGNAL_STRENGTH,
        native_unit_of_measurement="dBm",
        state_class=SensorStateClass.MEASUREMENT,
        entity_category=EntityCategory.DIAGNOSTIC,
        entity_registry_enabled_default=False,
    ),
    SensorEntityDescription(
        key=KEY_SIGNAL_QUALITY,
        name="Signal quality",
        icon="mdi:wifi-strength-outline",
        entity_category=EntityCategory.DIAGNOSTIC,
        entity_registry_enabled_default=False,
    ),
    SensorEntityDescription(
        key=ATTR_TRACKER_LAST_ACTIVITY,
        name="Last activity",
        icon="mdi:clock-outline",
        device_class=SensorDeviceClass.TIMESTAMP,
        entity_category=EntityCategory.DIAGNOSTIC,
        entity_registry_enabled_default=False,
    ),
    SensorEntityDescription(
        key=ATTR_TRACKER_FIRST_SEEN,
        name="First seen",
        icon="mdi:clock-start",
        device_class=SensorDeviceClass.TIMESTAMP,
        entity_category=EntityCategory.DIAGNOSTIC,
        entity_registry_enabled_default=False,
    ),
    SensorEntityDescription(
        key=ATTR_TRACKER_INTERNET_BLOCKED,
        name="Internet blocked",
        icon="mdi:shield-off-outline",
        entity_category=EntityCategory.DIAGNOSTIC,
        entity_registry_enabled_default=True,
    ),
)

def _device_base_unique_id(mac: str) -> str:
    """Base unique id for a client device, independent of the router/entry."""
    mac_lc = (mac or "").strip().lower()
    return f"{DOMAIN}-dev-{mac_lc}"


class MiWifiSensor(MiWifiEntity, SensorEntity):
    """MiWiFi sensor entity."""

    def __init__(
        self,
        unique_id: str,
        description: SensorEntityDescription,
        updater: LuciUpdater,
    ) -> None:
        super().__init__(unique_id, description, updater, ENTITY_ID_FORMAT)
        self._attr_native_value = self._compute_value()
        self._attr_native_unit_of_measurement = self._compute_unit()

    def _handle_coordinator_update(self) -> None:
        """Update state from coordinator."""
        is_available: bool = self._updater.data.get(ATTR_STATE, False)

        new_value = self._compute_value()
        new_unit = self._compute_unit()

        if (
            self._attr_native_value == new_value
            and self._attr_native_unit_of_measurement == new_unit
            and self._attr_available == is_available  # type: ignore
        ):
            return

        self._attr_available = is_available
        self._attr_native_value = new_value
        self._attr_native_unit_of_measurement = new_unit
        self.async_write_ha_state()

    def _compute_value(self):
        """Compute sensor value with conversion if needed."""
        value = self._updater.data.get(self.entity_description.key)

        if self.entity_description.key in (
            ATTR_SENSOR_WAN_DOWNLOAD_SPEED,
            ATTR_SENSOR_WAN_UPLOAD_SPEED,
        ):
            unit = (
                self._updater.config_entry.options.get(
                    CONF_WAN_SPEED_UNIT, DEFAULT_WAN_SPEED_UNIT
                )
                if self._updater.config_entry
                else DEFAULT_WAN_SPEED_UNIT
            )

            # Source value is expected to be Bytes/second (B/s)
            if isinstance(value, (int, float)):
                if unit == "Mbps":
                    # Convert B/s -> Mb/s (decimal megabits)
                    return round((value * 8) / 1_000_000, 2)
                return round(float(value), 2)

            return None

        if isinstance(value, Enum):
            return value.phrase

        return value

    def _compute_unit(self):
        """Determine unit based on user setting."""
        if self.entity_description.key in (
            ATTR_SENSOR_WAN_DOWNLOAD_SPEED,
            ATTR_SENSOR_WAN_UPLOAD_SPEED,
        ):
            unit = (
                self._updater.config_entry.options.get(
                    CONF_WAN_SPEED_UNIT, DEFAULT_WAN_SPEED_UNIT
                )
                if self._updater.config_entry
                else DEFAULT_WAN_SPEED_UNIT
            )
            return (
                UnitOfDataRate.MEGABITS_PER_SECOND
                if unit == "Mbps"
                else UnitOfDataRate.BYTES_PER_SECOND
            )

        return self.entity_description.native_unit_of_measurement


class MiWifiTopologyGraphSensor(SensorEntity):
    """Sensor to represent the network topology graph."""

    def __init__(self, updater: LuciUpdater) -> None:
        self._attr_unique_id = f"{updater.entry_id}_topology_graph"
        self._attr_name = "MiWiFi Topology"
        self._updater = updater
        self._attr_icon = "mdi:network"
        self._attr_should_poll = False

    @property
    def native_value(self) -> str:
        """Return the state of the topology sensor."""
        return "ok" if self._updater.data.get("topo_graph") else "unavailable"

    @property
    def extra_state_attributes(self) -> dict:
        """Return the topology graph as attributes."""
        return self._updater.data.get("topo_graph", {})

    async def async_update(self) -> None:
        """No polling, data is pushed from coordinator."""
        return


class MiWifiDeviceAttributeSensor(CoordinatorEntity, SensorEntity):
    """Per-device sensor backed by LuciUpdater.devices."""

    _attr_should_poll = False
    _attr_has_entity_name = True

    def __init__(
        self,
        updater: LuciUpdater,
        device: dict[str, Any],
        description: SensorEntityDescription,
    ) -> None:
        super().__init__(updater)
        self._updater = updater
        self.entity_description = description

        # IMPORTANT: keep entity disabled by default (as per description)
        self._attr_entity_registry_enabled_default = bool(
            getattr(description, "entity_registry_enabled_default", True)
        )

        self._mac = str(device.get(ATTR_TRACKER_MAC, "")).upper()

        base_unique = _device_base_unique_id(self._mac)
        self._attr_unique_id = f"{base_unique}-{description.key}"

        # Stable entity_id
        mac_norm = self._mac.lower().replace(":", "_")
        key_norm = str(description.key).lower().replace(" ", "_").replace(".", "_")
        self.entity_id = f"sensor.miwifi_{mac_norm}_{key_norm}"

        # Link to the SAME HA device as device_tracker (identifier = MAC)
        mac_lc = self._mac.lower()

        optional_mac = device.get(ATTR_TRACKER_OPTIONAL_MAC)
        conns = {(dr.CONNECTION_NETWORK_MAC, mac_lc)}
        if optional_mac:
            conns.add((dr.CONNECTION_NETWORK_MAC, str(optional_mac).strip().lower()))

        self._attr_device_info = DeviceInfo(
            connections=conns,
            identifiers={(DOMAIN, mac_lc)},
            name=device.get(ATTR_TRACKER_NAME) or self._mac,
            manufacturer=detect_manufacturer(self._mac),
        )


    def _handle_coordinator_update(self) -> None:
        self.async_write_ha_state()

    @property
    def native_value(self) -> Any:
        cache = (self.hass.data.get(DOMAIN) or {}).get("devices_cache") or {}
        dev = cache.get(self._mac) or (self._updater.devices or {}).get(self._mac, {}) or {}
        key = str(self.entity_description.key)

        conn = dev.get(ATTR_TRACKER_CONNECTION)
        if isinstance(conn, Connection):
            conn_phrase = conn.phrase
        else:
            conn_phrase = conn

        if key == ATTR_TRACKER_CONNECTION:
            return conn_phrase

        if key == KEY_SIGNAL_QUALITY:
            sig = dev.get(ATTR_TRACKER_SIGNAL, None)
            if conn == Connection.LAN:
                sig = None
            try:
                sig_int = int(sig) if sig not in ("", None) else None
            except (TypeError, ValueError):
                sig_int = None
            return map_signal_quality(sig_int) if sig_int is not None else "no_signal"

        if key == ATTR_TRACKER_SIGNAL:
            if conn == Connection.LAN:
                return None
            sig = dev.get(ATTR_TRACKER_SIGNAL, None)
            try:
                return int(sig) if sig not in ("", None) else None
            except (TypeError, ValueError):
                return None

        if key in (ATTR_TRACKER_LAST_ACTIVITY, ATTR_TRACKER_FIRST_SEEN):
            value = dev.get(key)
            if isinstance(value, str) and value:
                dt = dt_util.parse_datetime(value)
                return dt_util.as_local(dt) if dt else None
            return None

        return dev.get(key)
    
    @property
    def extra_state_attributes(self) -> dict[str, Any]:
        """Expose mesh routing info so the panel can show 'connected via'."""
        cache = (self.hass.data.get(DOMAIN) or {}).get("devices_cache") or {}
        dev = cache.get(self._mac) or (self._updater.devices or {}).get(self._mac) or {}

        conn = dev.get(ATTR_TRACKER_CONNECTION)
        conn_text = conn.phrase if isinstance(conn, Connection) else conn

        via_mac = dev.get(ATTR_TRACKER_ROUTER_MAC_ADDRESS)
        via_entry = dev.get(ATTR_TRACKER_UPDATER_ENTRY_ID)

        return {
            # Keep same attribute names as device_tracker
            ATTR_TRACKER_ROUTER_MAC_ADDRESS: via_mac,
            ATTR_TRACKER_UPDATER_ENTRY_ID: via_entry,

            # Optional duplicates (your custom keys) for backwards compatibility
            "connected_via_router_mac": via_mac,
            "connected_via_entry_id": via_entry,

            "connection": conn_text,
        }



def _build_device_sensors(
    updater: LuciUpdater, device: dict[str, Any]
) -> list[SensorEntity]:
    """Build per-device sensors for a client.

    Notes:
    - MIWIFI_DEVICE_SENSORS already define entity_registry_enabled_default=False,
      so they will be created but disabled by default (as desired).
    """
    mac = str(device.get(ATTR_TRACKER_MAC, "")).strip()
    if not mac:
        return []

    return [
        MiWifiDeviceAttributeSensor(updater, device, desc)
        for desc in MIWIFI_DEVICE_SENSORS
    ]



async def async_setup_entry(
    hass: HomeAssistant,
    config_entry: ConfigEntry,
    async_add_entities: AddEntitiesCallback,
) -> None:
    """Set up MiWiFi sensors without blocking startup."""

    updater: LuciUpdater = async_get_updater(hass, config_entry.entry_id)

    def _device_sensors_enabled() -> bool:
        # OPTIONS override DATA. If not present in options (common on first install),
        # fallback to config_entry.data.
        if CONF_ENABLE_DEVICE_SENSORS in (config_entry.options or {}):
            return bool(config_entry.options.get(CONF_ENABLE_DEVICE_SENSORS, DEFAULT_ENABLE_DEVICE_SENSORS))
        return bool((config_entry.data or {}).get(CONF_ENABLE_DEVICE_SENSORS, DEFAULT_ENABLE_DEVICE_SENSORS))

    def _is_main_router() -> bool:
        return bool(
            (updater.data or {}).get("topo_graph", {}).get("graph", {}).get("is_main", False)
        )

    # Migration / cleanup:
    # - Remove legacy per-device sensor unique_ids tied to entry_id (mesh duplicates).
    # - If per-device sensors are disabled, also remove the new scheme.
    registry = er.async_get(hass)
    device_sensors_enabled = _device_sensors_enabled()

    for ent in list(registry.entities.values()):
        if ent.domain != "sensor" or ent.platform != DOMAIN:
            continue

        uid = ent.unique_id or ""

        # Legacy scheme(s) tied to config entry id (avoid mesh duplicates)
        if uid.startswith(f"{DOMAIN}-{config_entry.entry_id}-"):
            registry.async_remove(ent.entity_id)
            continue

        # New scheme: "miwifi-dev-<MAC>-<key>"
        if not device_sensors_enabled and uid.startswith(f"{DOMAIN}-dev-"):
            registry.async_remove(ent.entity_id)

    @callback
    def _handle_new_device(new_device: dict) -> None:
        # Evaluate dynamically: topology may arrive AFTER startup
        if not (_is_main_router() and _device_sensors_enabled()):
            return

        mac = str(new_device.get(ATTR_TRACKER_MAC, "")).strip()
        if not mac:
            return

        # On restart entities may exist in registry but must be instantiated again.
        to_add: list[SensorEntity] = _build_device_sensors(updater, new_device)
        if to_add:
            async_add_entities(to_add)

    @callback
    def _handle_purge(entry_id: str, mac: str) -> None:
        # Only the main router manages client sensors
        if not _is_main_router():
            return

        mac_u = (mac or "").upper()
        if not mac_u:
            return

        reg = er.async_get(hass)
        base_unique = _device_base_unique_id(mac_u)

        for desc in MIWIFI_DEVICE_SENSORS:
            uid = f"{base_unique}-{desc.key}"
            ent_id = reg.async_get_entity_id("sensor", DOMAIN, uid)
            if ent_id:
                reg.async_remove(ent_id)

    # Connect signals
    config_entry.async_on_unload(
        async_dispatcher_connect(hass, SIGNAL_NEW_DEVICE, _handle_new_device)
    )
    config_entry.async_on_unload(
        async_dispatcher_connect(hass, SIGNAL_PURGE_DEVICE, _handle_purge)
    )

    # Defer initial entity creation to avoid blocking startup.
    hass.async_create_task(
        _async_add_all_sensors_later(hass, config_entry, async_add_entities)
    )

class MiWifiNATRulesSensor(CoordinatorEntity, SensorEntity):
    """Sensor to represent the NAT rules of the main router."""

    def __init__(self, updater: LuciUpdater) -> None:
        super().__init__(updater)
        self._updater = updater
        self._attr_unique_id = f"{updater.entry_id}_nat_rules"
        self._attr_name = "MiWiFi NAT Rules"
        self._attr_icon = "mdi:router-network"
        self._attr_should_poll = False
        self._attr_entity_category = EntityCategory.DIAGNOSTIC
        self._attr_state_class = SensorStateClass.MEASUREMENT

    async def async_update_from_updater(self):
        """Compatibility shim for services expecting this method."""
        await self.async_request_refresh()

    @property
    def native_value(self) -> int:
        """Return the total number of NAT rules."""
        rules_data = self._updater.data.get("nat_rules", {})
        total = 0

        for key in ("ftype_1", "ftype_2"):
            rules = rules_data.get(key, [])
            if isinstance(rules, list):
                total += len(rules)
            else:
                _LOGGER.warning(
                    "[MiWiFi] NAT Sensor: Expected a list on '%s', but received: %s",
                    key,
                    type(rules),
                )
        return total

    @property
    def extra_state_attributes(self) -> dict:
        """Return details about NAT rules."""
        nat_data = self._updater.data.get("nat_rules", {})
        return {
            "source": self._updater.ip,
            "ftype_1": nat_data.get("ftype_1", []),
            "ftype_2": nat_data.get("ftype_2", []),
            "total": sum(len(r) for r in nat_data.values() if isinstance(r, list)),
        }


class MiWifiConfigSensor(CoordinatorEntity, SensorEntity):
    """Sensor to represent the MiWiFi configuration."""

    def __init__(self, updater: LuciUpdater) -> None:
        super().__init__(updater)
        self._updater = updater
        self._attr_name = "MiWiFi Config"
        self._attr_unique_id = f"{updater.entry_id}_config"
        self._attr_icon = "mdi:cog"
        self._attr_should_poll = False
        self._attr_native_value = "ok"
        self._extra_attrs: dict[str, Any] = {}

    @property
    def state(self) -> str:
        return self._attr_native_value

    @property
    def extra_state_attributes(self) -> dict[str, Any]:
        return self._extra_attrs

    async def async_added_to_hass(self) -> None:
        """Register the entity and set up the coordinator listener."""
        await super().async_added_to_hass()
        await self._update_attrs()
        self._unsub_coordinator_update = self._updater.async_add_listener(
            self._handle_coordinator_update
        )

    def _handle_coordinator_update(self) -> None:
        self.hass.async_create_task(self._update_attrs())

    async def _update_attrs(self) -> None:
        from .helper import get_global_log_level
        from .frontend import read_local_version

        log_level = await get_global_log_level(self._updater.hass)
        panel_version = await read_local_version(self._updater.hass)
        config = self._updater.config_entry.options

        self._extra_attrs = {
            "panel_active": config.get("enable_panel", True),
            "speed_unit": config.get("wan_speed_unit", "MB"),
            "log_level": log_level,
            "panel_version": panel_version,
            "last_checked": datetime.now().isoformat(),
        }

        self.async_write_ha_state()


async def _async_add_all_sensors_later(
    hass: HomeAssistant,
    config_entry: ConfigEntry,
    async_add_entities: AddEntitiesCallback,
) -> None:
    """Add all sensors after a short delay to avoid blocking startup."""
    await asyncio.sleep(0)

    updater: LuciUpdater = async_get_updater(hass, config_entry.entry_id)

    # Ensure we have data (topo_graph + devices) before deciding is_main and creating sensors
    for _ in range(6):
        try:
            await updater.async_request_refresh()
        except Exception:
            pass

        topo = (updater.data or {}).get("topo_graph", {}).get("graph", {})
        if "is_main" in topo:
            break

        await asyncio.sleep(2)

    entities: list[SensorEntity] = [
        MiWifiTopologyGraphSensor(updater),
        MiWifiConfigSensor(updater),
    ]

    if (updater.data or {}).get("topo_graph", {}).get("graph", {}).get("is_main", False):
        entities.append(MiWifiNATRulesSensor(updater))

    for description in MIWIFI_SENSORS:
        if description.key == ATTR_SENSOR_DEVICES_5_0_GAME and not updater.supports_game:
            continue

        if description.key in DISABLE_ZERO and updater.data.get(description.key, 0) == 0:
            continue

        if description.key in ONLY_WAN and not updater.supports_wan:
            continue

        entities.append(
            MiWifiSensor(
                f"{config_entry.entry_id}-{description.key}",
                description,
                updater,
            )
        )

    # Per-device sensors (clients) only from main router
    if CONF_ENABLE_DEVICE_SENSORS in (config_entry.options or {}):
        device_sensors_enabled = bool(
            config_entry.options.get(CONF_ENABLE_DEVICE_SENSORS, DEFAULT_ENABLE_DEVICE_SENSORS)
        )
    else:
        device_sensors_enabled = bool(
            (config_entry.data or {}).get(CONF_ENABLE_DEVICE_SENSORS, DEFAULT_ENABLE_DEVICE_SENSORS)
        )

    is_main_router: bool = bool(
        (updater.data or {}).get("topo_graph", {}).get("graph", {}).get("is_main", False)
    )

    if device_sensors_enabled and is_main_router:
        # IMPORTANT: do not use entity_registry existence to skip.
        # On restart those entities exist in registry but must be instantiated again.
        for device in (updater.devices or {}).values():
            mac = str(device.get(ATTR_TRACKER_MAC, "")).strip()
            if not mac:
                continue
            entities.extend(_build_device_sensors(updater, device))

    async_add_entities(entities)
