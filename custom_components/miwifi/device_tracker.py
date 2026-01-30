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
    ATTR_DEVICE_MAC_ADDRESS,
    ATTR_DEVICE_NAME,
    ATTR_DEVICE_MANUFACTURER,
    ATTR_DEVICE_MODEL,
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
from .updater import LuciUpdater, async_get_updater, async_get_integrations

def _ensure_via_device_exists(
    hass: HomeAssistant, via_router_mac: Any
) -> tuple[str, str] | None:
    """Ensure the router/node device exists before using via_device.

    - Avoids HA 2025.12+ break by never referencing a non-existing via_device.
    - Creates the router device entry (minimal) if we can map MAC -> config_entry_id.
    - Safely ignores non-dict values inside hass.data[DOMAIN].
    """

    def _norm_mac(val: Any) -> str:
        """Normalize MAC values (also handles tuple/list/set)."""
        if val is None:
            return ""
        if isinstance(val, (tuple, list, set)):
            try:
                val = next(iter(val))
            except StopIteration:
                return ""
        return str(val).strip().lower()

    via_router_mac_lc = _norm_mac(via_router_mac)
    if not via_router_mac_lc or via_router_mac_lc in ("none", "null"):
        return None

    dev_reg = dr.async_get(hass)

    # If already exists, ok.
    existing = dev_reg.async_get_device(identifiers={(DOMAIN, via_router_mac_lc)})
    if existing:
        return (DOMAIN, via_router_mac_lc)

    # Map router-mac -> config_entry_id using hass.data[DOMAIN][entry_id][UPDATER]
    domain_data = hass.data.get(DOMAIN, {})
    if not isinstance(domain_data, dict):
        return None

    target_entry_id: str | None = None
    target_name: str | None = None
    target_manufacturer: str | None = None
    target_model: str | None = None

    for entry_id, entry_data in domain_data.items():
        # IMPORTANT: hass.data[DOMAIN] may include non-dict values (bool, etc.)
        if not isinstance(entry_data, dict):
            continue

        up = entry_data.get(UPDATER)
        if not up or not hasattr(up, "data"):
            continue

        udata = getattr(up, "data", {}) or {}

        router_mac = _norm_mac(
            udata.get(ATTR_DEVICE_MAC_ADDRESS) or udata.get("device_mac")
        )
        if router_mac and router_mac == via_router_mac_lc:
            target_entry_id = entry_id
            target_name = (
                udata.get(ATTR_DEVICE_NAME)
                or udata.get(ATTR_DEVICE_MODEL)
                or "MiWiFi Router"
            )
            target_manufacturer = udata.get(ATTR_DEVICE_MANUFACTURER) or "Xiaomi"
            target_model = udata.get(ATTR_DEVICE_MODEL)
            break

    # If we cannot map it to a known router updater, do NOT set via_device.
    if not target_entry_id:
        return None

    # Create minimal router device so HA can reference via_device safely
    dev_reg.async_get_or_create(
        config_entry_id=target_entry_id,
        identifiers={(DOMAIN, via_router_mac_lc)},
        connections={(dr.CONNECTION_NETWORK_MAC, via_router_mac_lc)},
        name=target_name,
        manufacturer=target_manufacturer,
        model=target_model,
    )

    return (DOMAIN, via_router_mac_lc)


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
    """Set up MiWiFi device tracker entry."""

    updater: LuciUpdater = async_get_updater(hass, config_entry.entry_id)

    # ------------------------------------------------------------------
    # Migration / cleanup (entity registry)
    #
    # Goal: one entity per client MAC across the entire mesh.
    # - Legacy scheme created entities per entry_id:  "miwifi-<entry_id>-<mac>-..."
    # - New scheme is stable per MAC:               "miwifi-<mac>"
    #
    # We keep changes minimal and only touch miwifi device_tracker entries.
    # ------------------------------------------------------------------
    registry = er.async_get(hass)

    # 1) Remove legacy per-entry unique IDs for THIS entry.
    legacy_prefix = f"{DOMAIN}-{config_entry.entry_id}-"
    for ent in list(registry.entities.values()):
        if ent.domain != "device_tracker" or ent.platform != DOMAIN:
            continue
        uid = ent.unique_id or ""
        if uid.startswith(legacy_prefix):
            _LOGGER.debug(
                "[MiWiFi] Removing legacy device_tracker entity: %s (uid=%s)",
                ent.entity_id,
                uid,
            )
            registry.async_remove(ent.entity_id)

    # 2) If multiple entities share the same stable unique_id, keep a single one.
    by_uid: dict[str, list[str]] = {}
    for ent in list(registry.entities.values()):
        if ent.domain != "device_tracker" or ent.platform != DOMAIN:
            continue
        uid = ent.unique_id or ""
        if uid.startswith(f"{DOMAIN}-") and ":" in uid:
            by_uid.setdefault(uid, []).append(ent.entity_id)

    for uid, ent_ids in by_uid.items():
        if len(ent_ids) <= 1:
            continue

        def _rank(eid: str) -> tuple[int, str]:
            # Prefer IDs without numeric suffix ("..._2", "..._3", ...)
            tail = eid.rsplit("_", 1)[-1]
            return (1, eid) if tail.isdigit() else (0, eid)

        keep = sorted(ent_ids, key=_rank)[0]
        for eid in ent_ids:
            if eid == keep:
                continue
            _LOGGER.debug(
                "[MiWiFi] Removing duplicate device_tracker entity: %s (uid=%s)",
                eid,
                uid,
            )
            registry.async_remove(eid)

    @callback
    def add_device(new_device: dict) -> None:
        """Add or update a device_tracker entity.

        IMPORTANT:
        - Entity identity must be stable per device (MAC), not per router.
        - In mesh setups, the same client can appear on multiple routers.
          We therefore create ONE entity per MAC and ignore further creations.
        - FIX: If the entity already exists in the entity registry (restored),
          we MUST instantiate it again on startup, otherwise it stays unavailable.
        """

        if (
            not get_config_value(config_entry, CONF_IS_TRACK_DEVICES, True)
            or new_device.get(ATTR_TRACKER_UPDATER_ENTRY_ID) != config_entry.entry_id
        ):
            return  # pragma: no cover

        mac = new_device.get(ATTR_TRACKER_MAC)
        if not mac:
            _LOGGER.warning("Device without MAC found: %s", new_device)
            return

        mac_lc = str(mac).strip().lower()
        mac_norm = mac_lc.replace(":", "_")

        unique_id = f"{DOMAIN}-{mac_lc}"

        # Use global map of live entities (cross-entry safe)
        hass.data.setdefault(DOMAIN, {})
        hass.data[DOMAIN].setdefault("device_tracker_entities", {})
        hass.data[DOMAIN].setdefault("device_tracker_creating", set())

        ent_map = hass.data[DOMAIN]["device_tracker_entities"]
        creating = hass.data[DOMAIN]["device_tracker_creating"]
        
        # --- Global devices cache (mesh-wide) ---
        hass.data.setdefault(DOMAIN, {})
        hass.data[DOMAIN].setdefault("devices_cache", {})
        mac_u = str(mac).strip().upper()
        hass.data[DOMAIN]["devices_cache"][mac_u] = dict(new_device)
        # ---------------------------------------


        # If live instance exists, update it and exit
        ent = ent_map.get(unique_id)
        if ent is not None:
            ent._device = dict(new_device)  # noqa: SLF001
            ent.async_write_ha_state()
            return

        # Avoid parallel duplicate creations across mesh nodes
        if unique_id in creating:
            return
        creating.add(unique_id)

        try:
            # If entity exists in registry, use that entity_id to re-instantiate after reboot
            existing_entity_id = registry.async_get_entity_id(
                "device_tracker", DOMAIN, unique_id
            )
            entity_id = existing_entity_id or f"device_tracker.miwifi_{mac_norm}"

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
                        enable_port_probe=get_config_value(
                            config_entry, CONF_ENABLE_PORT_PROBE, DEFAULT_ENABLE_PORT_PROBE
                        ),
                    )
                ]
            )

        finally:
            creating.discard(unique_id)

        # New-device notifier (kept as you had it)
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


    # Initial fill
    for device in updater.devices.values():
        add_device(device)

    # Dispatcher hook
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
        """Remove a device_tracker entity (and orphan device) safely."""

        if entry_id != config_entry.entry_id:
            return

        mac_lc = str(mac).strip().lower()
        uid_new = f"{DOMAIN}-{mac_lc}"
        uid_legacy = f"{DOMAIN}-{entry_id}-{mac}"

        registry = er.async_get(hass)

        # Remove current entity
        ent_id = registry.async_get_entity_id("device_tracker", DOMAIN, uid_new)
        if ent_id:
            entity_entry = registry.async_get(ent_id)
            device_id = entity_entry.device_id if entity_entry else None
            registry.async_remove(ent_id)
        else:
            device_id = None

        # Remove any remaining legacy entity for same MAC (defensive)
        ent_legacy = registry.async_get_entity_id("device_tracker", DOMAIN, uid_legacy)
        if ent_legacy:
            legacy_entry = registry.async_get(ent_legacy)
            device_id = device_id or (legacy_entry.device_id if legacy_entry else None)
            registry.async_remove(ent_legacy)

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

        # Keep a global map so any router entry can update the live entity
        # without trying to reach entities from another EntityPlatform.
        self.hass.data.setdefault(DOMAIN, {})
        self.hass.data[DOMAIN].setdefault("device_tracker_entities", {})
        self.hass.data[DOMAIN]["device_tracker_entities"][self.unique_id] = self

        if not self._enable_port_probe:
            return

        self.hass.loop.call_later(
            DEFAULT_CALL_DELAY,
            lambda: self.hass.async_create_task(self.check_ports()),
        )

    async def async_will_remove_from_hass(self) -> None:
        """Cleanup when entity is removed."""
        try:
            ent_map = self.hass.data.get(DOMAIN, {}).get("device_tracker_entities", {})
            ent_map.pop(self.unique_id, None)
        finally:
            await super().async_will_remove_from_hass()

    @property
    def available(self) -> bool:
        """Is available."""
        return self._attr_available and self.coordinator.last_update_success

    @cached_property
    def mac_address(self) -> str:
        """Return the mac address of the device."""
        mac = self._device.get(ATTR_TRACKER_MAC)
        return str(mac).strip().lower()


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

        connected_via_router_mac  = self._device.get(ATTR_TRACKER_ROUTER_MAC_ADDRESS, None)
        connected_via_entry_id  = self._device.get(ATTR_TRACKER_UPDATER_ENTRY_ID, None)

        return {
            ATTR_TRACKER_SCANNER: DOMAIN,
            ATTR_TRACKER_MAC: self.mac_address,
            ATTR_TRACKER_IP: self.ip_address,
            ATTR_TRACKER_ONLINE: self._device.get(ATTR_TRACKER_ONLINE, None)
            if self.is_connected
            else "",
            ATTR_TRACKER_CONNECTION: connection,

            # Mesh: "Connected via ..."
            ATTR_TRACKER_ROUTER_MAC_ADDRESS: connected_via_router_mac,
            ATTR_TRACKER_UPDATER_ENTRY_ID: connected_via_entry_id,

            # Opcional (si el panel ya usa estas keys o quieres compatibilidad)
            "connected_via_router_mac": connected_via_router_mac,
            "connected_via_entry_id": connected_via_entry_id,
            
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
        # If the router/node MAC is known, try to link the client device through it.
        # This enables "Connected via <node>" in the HA UI.
        via_router_mac_lc = str(
            self._device.get(ATTR_TRACKER_ROUTER_MAC_ADDRESS) or ""
        ).strip().lower()
        via_device = _ensure_via_device_exists(self.hass, via_router_mac_lc)

        _optional_mac = self._device.get(ATTR_TRACKER_OPTIONAL_MAC, None)
        if _optional_mac is not None:
            return DeviceInfo(
                connections={
                    (dr.CONNECTION_NETWORK_MAC, self.mac_address),
                    (dr.CONNECTION_NETWORK_MAC, str(_optional_mac).strip().lower()),
                },
                # Identify the device by its own MAC (stable across mesh)
                identifiers={(DOMAIN, self.mac_address)},
                name=self._attr_name,
                via_device=via_device,
                manufacturer=self.manufacturer,
            )

        return DeviceInfo(
            connections={(dr.CONNECTION_NETWORK_MAC, self.mac_address)},
            identifiers={(DOMAIN, self.mac_address)},
            name=self._attr_name,
            configuration_url=self.configuration_url,
            manufacturer=self.manufacturer,
            via_device=via_device,
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

        # Updater usually stores MAC keys in upper-case.
        mac_key = self.mac_address.upper()
        device = self._updater.devices.get(mac_key)

        # Fallback: optional MAC (some devices expose a second MAC).
        opt = str(self._device.get(ATTR_TRACKER_OPTIONAL_MAC) or "").strip()
        if device is None and opt:
            device = self._updater.devices.get(opt.upper())

        # Mesh-wide cache (updated by ANY router entry via add_device()).
        cache = self.hass.data.get(DOMAIN, {}).get("devices_cache", {})
        if device is None and isinstance(cache, dict):
            device = cache.get(mac_key)
            if device is None and opt:
                device = cache.get(opt.upper())

        # If device is not present in current refresh, keep last known attributes and
        # compute connectivity based on last_activity + stay_online window.
        if device is None:
            last_ts: int = parse_last_activity(
                str(self._device.get(ATTR_TRACKER_LAST_ACTIVITY))
            )
            is_connected = False
            if last_ts:
                is_connected = (int(time.time()) - last_ts) <= self._stay_online

            if (
                self._attr_available == is_available
                and self._is_connected == is_connected
            ):
                return

            self._attr_available = is_available
            self._is_connected = is_connected
            self.async_write_ha_state()
            return

        # Found device data (either from this updater or mesh-wide cache).
        device = self._update_entry(dict(device))

        # Connectivity: last_activity aging window. If router reports the device but we
        # can't parse a timestamp, treat it as connected.
        current_ts: int = parse_last_activity(
            str(device.get(ATTR_TRACKER_LAST_ACTIVITY))
        )
        if not current_ts:
            current_ts = parse_last_activity(
                str(self._device.get(ATTR_TRACKER_LAST_ACTIVITY))
            )

        if current_ts:
            is_connected = (int(time.time()) - current_ts) <= self._stay_online
        else:
            is_connected = True

        attr_changed: list = [
            attr for attr in ATTR_CHANGES if self._device.get(attr) != device.get(attr)
        ]
        if self._device.get(ATTR_TRACKER_LAST_ACTIVITY) != device.get(
            ATTR_TRACKER_LAST_ACTIVITY
        ):
            attr_changed.append(ATTR_TRACKER_LAST_ACTIVITY)

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
            mac_key = self.mac_address.upper()
            track_device = self._updater.devices.get(mac_key, track_device)

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
