"""Device tracker component."""

from __future__ import annotations

import asyncio
import time
from functools import cached_property
from typing import Any, Final

from homeassistant.components.device_tracker import ENTITY_ID_FORMAT
from homeassistant.components.device_tracker.config_entry import ScannerEntity
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant, callback
from homeassistant.helpers import device_registry as dr, entity_registry as er
from homeassistant.helpers.dispatcher import async_dispatcher_connect
from homeassistant.helpers.entity import DeviceInfo
from homeassistant.helpers.entity_platform import (
    AddEntitiesCallback,
    EntityPlatform,
    async_get_current_platform,
)
from homeassistant.helpers.update_coordinator import CoordinatorEntity

from .const import (
    ATTRIBUTION,
    ATTR_STATE,
    ATTR_TRACKER_CONNECTION,
    ATTR_TRACKER_DOWN_SPEED,
    ATTR_TRACKER_ENTRY_ID,
    ATTR_TRACKER_FIRST_SEEN,
    ATTR_TRACKER_INTERNET_BLOCKED,
    ATTR_TRACKER_IP,
    ATTR_TRACKER_IS_RESTORED,
    ATTR_TRACKER_LAST_ACTIVITY,
    ATTR_TRACKER_MAC,
    ATTR_TRACKER_NAME,
    ATTR_TRACKER_ONLINE,
    ATTR_TRACKER_OPTIONAL_MAC,
    ATTR_TRACKER_ROUTER_MAC_ADDRESS,
    ATTR_TRACKER_SCANNER,
    ATTR_TRACKER_SIGNAL,
    ATTR_TRACKER_SIGNAL_QUALITY,
    ATTR_TRACKER_TOTAL_USAGE,
    ATTR_TRACKER_UP_SPEED,
    ATTR_TRACKER_UPDATER_ENTRY_ID,
    CONF_IS_TRACK_DEVICES,
    CONF_STAY_ONLINE,
    DEFAULT_CALL_DELAY,
    DEFAULT_STAY_ONLINE,
    DOMAIN,
    SIGNAL_NEW_DEVICE,
    SIGNAL_PURGE_DEVICE,
    UPDATER,
    CONF_ENABLE_PORT_PROBE,
    DEFAULT_ENABLE_PORT_PROBE,
)
from .enum import Connection, DeviceClass
from .helper import (
    detect_manufacturer,
    get_config_value,
    map_signal_quality,
    parse_last_activity,
    pretty_size,
)
from .logger import _LOGGER
from .update import MiWiFiNewDeviceNotifier
from .updater import LuciUpdater, async_get_updater

SOURCE_TYPE_ROUTER = "router"

PARALLEL_UPDATES = 0

ATTR_CHANGES: Final = (
    ATTR_TRACKER_IP,
    ATTR_TRACKER_ONLINE,
    ATTR_TRACKER_CONNECTION,
    ATTR_TRACKER_ROUTER_MAC_ADDRESS,
    ATTR_TRACKER_SIGNAL,
    ATTR_TRACKER_DOWN_SPEED,
    ATTR_TRACKER_UP_SPEED,
    ATTR_TRACKER_OPTIONAL_MAC,
    ATTR_TRACKER_INTERNET_BLOCKED,
)

CONFIGURATION_PORTS: Final = [80, 443]


async def async_setup_entry(
    hass: HomeAssistant,
    config_entry: ConfigEntry,
    async_add_entities: AddEntitiesCallback,
) -> None:
    """Set up MiWifi device tracker entry."""

    updater: LuciUpdater = async_get_updater(hass, config_entry.entry_id)

    @callback
    def add_device(new_device: dict) -> None:
        """Add device."""
        if (
            not get_config_value(config_entry, CONF_IS_TRACK_DEVICES, True)
            or new_device.get(ATTR_TRACKER_UPDATER_ENTRY_ID) != config_entry.entry_id
        ):
            return  # pragma: no cover

        mac = new_device.get(ATTR_TRACKER_MAC)
        if not mac:
            _LOGGER.warning("Device without MAC found: %s", new_device)
            return

        mac_norm = str(mac).lower().replace(":", "_")
        entity_id = f"device_tracker.miwifi_{mac_norm}"
        unique_id = f"{DOMAIN}-{config_entry.entry_id}-{mac}"

        # Prefer old behavior if platform context is available
        try:
            platform: EntityPlatform = async_get_current_platform()
            existing_entity = next(
                (e for e in platform.entities.values() if e.unique_id == unique_id),
                None,
            )

            if existing_entity:
                existing_entity._device = dict(new_device)  # noqa: SLF001
                existing_entity.async_write_ha_state()
            else:
                async_add_entities(
                    [
                        MiWifiDeviceTracker(
                            unique_id,
                            entity_id,
                            new_device,
                            updater,
                            get_config_value(
                                config_entry, CONF_STAY_ONLINE, DEFAULT_STAY_ONLINE
                            ),
                            enable_port_probe=get_config_value(config_entry, CONF_ENABLE_PORT_PROBE, DEFAULT_ENABLE_PORT_PROBE),

                        )
                    ]
                )

        except RuntimeError:
            # Fallback: use entity registry (safe outside platform context)
            registry = er.async_get(hass)
            existing_entity_id = registry.async_get_entity_id(
                "device_tracker", DOMAIN, unique_id
            )
            if existing_entity_id:
                return

            async_add_entities(
                [
                    MiWifiDeviceTracker(
                        unique_id,
                        entity_id,
                        new_device,
                        updater,
                        get_config_value(
                            config_entry, CONF_STAY_ONLINE, DEFAULT_STAY_ONLINE
                        ),
                        enable_port_probe=get_config_value(config_entry, CONF_ENABLE_PORT_PROBE, DEFAULT_ENABLE_PORT_PROBE),

                    )
                ]
            )

        # New-device notifier (kept as you had it)
        hass.data.setdefault(DOMAIN, {})
        hass.data[DOMAIN].setdefault("notified_macs_store", {})

        notified_store = hass.data[DOMAIN]["notified_macs_store"]
        router_ip = updater.ip.replace(".", "_")
        if router_ip not in notified_store:
            from homeassistant.helpers.storage import Store

            notified_store[router_ip] = Store(
                hass, 1, f"{DOMAIN}/{router_ip}_notified_macs.json"
            )

        async def _notify() -> None:
            notifier = MiWiFiNewDeviceNotifier(hass)
            await notifier.async_notify_new_device(
                router_ip, mac, new_device, notified_store
            )

        hass.async_create_task(_notify())

    for device in updater.devices.values():
        add_device(device)

    # Chain dispatcher unsubs safely
    _unsub_new_device = async_dispatcher_connect(hass, SIGNAL_NEW_DEVICE, add_device)
    _prev_unsub = getattr(updater, "new_device_callback", None)

    if _prev_unsub:

        def _unsub_all() -> None:
            try:
                _prev_unsub()
            finally:
                _unsub_new_device()

        updater.new_device_callback = _unsub_all
    else:
        updater.new_device_callback = _unsub_new_device

    @callback
    def _handle_purge(entry_id: str, mac: str) -> None:
        if entry_id != config_entry.entry_id:
            return

        registry = er.async_get(hass)
        unique_id = f"{DOMAIN}-{entry_id}-{mac}"
        entity_id = registry.async_get_entity_id("device_tracker", DOMAIN, unique_id)
        if not entity_id:
            return

        entity_entry = registry.async_get(entity_id)
        device_id = entity_entry.device_id if entity_entry else None

        registry.async_remove(entity_id)

        if device_id:
            dev_reg = dr.async_get(hass)
            ents = er.async_entries_for_device(
                registry, device_id, include_disabled_entities=True
            )
            if not ents:
                dev_reg.async_remove_device(device_id)

    async_dispatcher_connect(hass, SIGNAL_PURGE_DEVICE, _handle_purge)


class MiWifiDeviceTracker(ScannerEntity, CoordinatorEntity):
    """MiWifi device tracker entry."""

    _attr_attribution: str = ATTRIBUTION
    _attr_device_class: str = DeviceClass.DEVICE_TRACKER

    _configuration_port: int | None = None
    _is_connected: bool = False

    def __init__(
        self,
        unique_id: str,
        entity_id: str,
        device: dict,
        updater: LuciUpdater,
        stay_online: int,
        enable_port_probe: bool = False,
    ) -> None:
        """Initialize the tracker."""

        # Be explicit to avoid MRO surprises with ScannerEntity + CoordinatorEntity
        CoordinatorEntity.__init__(self, coordinator=updater)

        self._device = dict(device)
        self._updater = updater
        self._stay_online = max(int(stay_online or 0), 10)

        self.entity_id = entity_id
        self._attr_unique_id = unique_id

        # FIX: this MUST exist (HA reads device_info during add)
        self._attr_name = self._device.get(ATTR_TRACKER_NAME, self.mac_address)

        # Initial availability/connection
        self._attr_available = updater.data.get(ATTR_STATE, False)
        if self._attr_available:
            self._is_connected = not self._device.get(ATTR_TRACKER_IS_RESTORED, False)

        # Port probing optional
        self._enable_port_probe = enable_port_probe
        self._ports_checked: bool = False

    async def async_added_to_hass(self) -> None:
        """When entity is added to hass."""
        await CoordinatorEntity.async_added_to_hass(self)

        if not self._enable_port_probe:
            return

        self.hass.loop.call_later(
            DEFAULT_CALL_DELAY,
            lambda: self.hass.async_create_task(self.check_ports()),
        )

    @property
    def available(self) -> bool:
        """Is available."""
        return self._attr_available and self.coordinator.last_update_success

    @cached_property
    def mac_address(self) -> str:
        """Return the mac address of the device."""
        return str(self._device.get(ATTR_TRACKER_MAC))

    @property
    def manufacturer(self) -> str | None:
        """Return manufacturer of the device."""
        return detect_manufacturer(self.mac_address)

    @property
    def ip_address(self) -> str | None:
        """Return the primary ip address of the device."""
        return self._device.get(ATTR_TRACKER_IP, None)

    @property
    def is_connected(self) -> bool:
        """Return true if the device is connected to the network."""
        return self._is_connected

    @cached_property
    def unique_id(self) -> str:
        """Return unique ID of the entity."""
        return self._attr_unique_id

    @property
    def icon(self) -> str:
        """Return device icon."""
        return "mdi:lan-connect" if self.is_connected else "mdi:lan-disconnect"

    @property
    def extra_state_attributes(self) -> dict[str, Any]:
        """Return extra state attributes."""
        signal: Any = self._device.get(ATTR_TRACKER_SIGNAL, "")
        connection: Any = self._device.get(ATTR_TRACKER_CONNECTION, None)

        if not self.is_connected or connection == Connection.LAN:
            signal = ""

        if connection is not None and isinstance(connection, Connection):
            connection = connection.phrase  # type: ignore[assignment]

        signal_key = (
            map_signal_quality(int(signal)) if signal not in ("", None) else "no_signal"
        )

        total_bytes = int(self._device.get(ATTR_TRACKER_TOTAL_USAGE, 0) or 0)
        if self.is_connected and total_bytes > 0:
            mb = total_bytes / (1024 * 1024)
            if mb >= 1024:
                total_usage_str = f"{round(mb / 1024, 2)} GB"
            else:
                total_usage_str = f"{round(mb, 2)} MB"
        else:
            total_usage_str = "0 MB"

        return {
            ATTR_TRACKER_SCANNER: DOMAIN,
            ATTR_TRACKER_MAC: self.mac_address,
            ATTR_TRACKER_IP: self.ip_address,
            ATTR_TRACKER_ONLINE: self._device.get(ATTR_TRACKER_ONLINE, None)
            if self.is_connected
            else "",
            ATTR_TRACKER_CONNECTION: connection,
            ATTR_TRACKER_ROUTER_MAC_ADDRESS: self._device.get(
                ATTR_TRACKER_ROUTER_MAC_ADDRESS, None
            ),
            ATTR_TRACKER_SIGNAL: signal,
            ATTR_TRACKER_DOWN_SPEED: pretty_size(
                float(self._device.get(ATTR_TRACKER_DOWN_SPEED, 0.0))
            )
            if self.is_connected
            else "",
            ATTR_TRACKER_UP_SPEED: pretty_size(
                float(self._device.get(ATTR_TRACKER_UP_SPEED, 0.0))
            )
            if self.is_connected
            else "",
            ATTR_TRACKER_LAST_ACTIVITY: self._device.get(ATTR_TRACKER_LAST_ACTIVITY, None),
            ATTR_TRACKER_SIGNAL_QUALITY: signal_key,
            ATTR_TRACKER_TOTAL_USAGE: total_usage_str,
            ATTR_TRACKER_INTERNET_BLOCKED: self._device.get(
                ATTR_TRACKER_INTERNET_BLOCKED, False
            ),
            ATTR_TRACKER_FIRST_SEEN: self._device.get(ATTR_TRACKER_FIRST_SEEN, None),
        }

    @property
    def configuration_url(self) -> str | None:
        """Configuration url."""
        if self._configuration_port is None:
            return None

        _schema: str = "https" if self._configuration_port == 443 else "http"
        return (
            f"{_schema}://{self.ip_address}"
            if self._configuration_port in [80, 443]
            else f"{_schema}://{self.ip_address}:{self._configuration_port}"
        )

    @property
    def device_info(self) -> DeviceInfo:  # pylint: disable=overridden-final-method
        """Return device info."""
        _optional_mac = self._device.get(ATTR_TRACKER_OPTIONAL_MAC, None)
        if _optional_mac is not None:
            return DeviceInfo(
                connections={
                    (dr.CONNECTION_NETWORK_MAC, self.mac_address),
                    (dr.CONNECTION_NETWORK_MAC, _optional_mac),
                },
                identifiers={(DOMAIN, self._attr_unique_id)},
                name=self._attr_name,
            )

        return DeviceInfo(
            connections={(dr.CONNECTION_NETWORK_MAC, self.mac_address)},
            identifiers={(DOMAIN, self._attr_unique_id)},
            name=self._attr_name,
            configuration_url=self.configuration_url,
            manufacturer=self.manufacturer,
        )

    @cached_property
    def source_type(self) -> str:
        """Return source type."""
        return SOURCE_TYPE_ROUTER

    @cached_property
    def entity_registry_enabled_default(self) -> bool:
        """Force enabled."""
        return True

    def _handle_coordinator_update(self) -> None:
        """Update state."""
        is_available: bool = self._updater.data.get(ATTR_STATE, False)
        device = self._updater.devices.get(self.mac_address, None)

        if device is None or self._device is None:
            if self._attr_available:  # type: ignore[truthy-bool]
                self._attr_available = False
                self.async_write_ha_state()
            return

        device = self._update_entry(device)

        before: int = parse_last_activity(str(self._device.get(ATTR_TRACKER_LAST_ACTIVITY)))
        current: int = parse_last_activity(str(device.get(ATTR_TRACKER_LAST_ACTIVITY)))

        is_connected = current > before
        if before == current:
            is_connected = (int(time.time()) - current) <= self._stay_online

        attr_changed: list = [
            attr for attr in ATTR_CHANGES if self._device.get(attr) != device.get(attr)
        ]

        if (
            self._attr_available == is_available
            and self._is_connected == is_connected
            and not attr_changed
        ):
            return

        self._attr_available = is_available
        self._is_connected = is_connected
        self._device = dict(device)

        # Keep name updated if router reports new name
        self._attr_name = self._device.get(ATTR_TRACKER_NAME, self.mac_address)

        self.async_write_ha_state()

    def _update_entry(self, track_device: dict) -> dict:
        """Update device entry."""
        entry_id: str | None = track_device.get(ATTR_TRACKER_ENTRY_ID)

        device_registry: dr.DeviceRegistry = dr.async_get(self.hass)
        device: dr.DeviceEntry | None = device_registry.async_get_device(
            set(), {(dr.CONNECTION_NETWORK_MAC, self.mac_address)}
        )

        if device is not None:
            if len(device.config_entries) > 0 and entry_id not in device.config_entries:
                device_registry.async_update_device(device.id, add_config_entry_id=entry_id)

            if device.configuration_url is None and self.configuration_url is not None:
                device_registry.async_update_device(device.id, configuration_url=self.configuration_url)

            if device.manufacturer is None and self.manufacturer is not None:
                device_registry.async_update_device(device.id, manufacturer=self.manufacturer)

        if (
            entry_id in self.hass.data.get(DOMAIN, {})
            and self._updater != self.hass.data[DOMAIN][entry_id][UPDATER]
        ):
            self._updater = self.hass.data[DOMAIN][entry_id][UPDATER]
            self._device[ATTR_TRACKER_ENTRY_ID] = entry_id
            track_device = self._updater.devices.get(self.mac_address, track_device)

        return track_device

    async def check_ports(self) -> None:
        """Scan port to configuration URL (async-safe)."""
        if self.ip_address is None:
            return

        for port in CONFIGURATION_PORTS:
            try:
                reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(self.ip_address, port),
                    timeout=3,
                )
                writer.close()
                await writer.wait_closed()
                self._configuration_port = port
                break
            except (asyncio.TimeoutError, ConnectionRefusedError, OSError):
                continue
