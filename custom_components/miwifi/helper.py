from __future__ import annotations
from homeassistant.exceptions import ConfigEntryAuthFailed

import math
import time
from datetime import datetime
from typing import Any, Final

from homeassistant import config_entries
from homeassistant.core import HomeAssistant
from homeassistant.exceptions import HomeAssistantError
from homeassistant.helpers import device_registry as dr
from homeassistant.helpers import entity_registry as er
from homeassistant.helpers.json import JSONEncoder
from homeassistant.helpers.storage import Store
from homeassistant.loader import async_get_integration
from homeassistant.util import dt as dt_util, slugify
from httpx import codes, HTTPError, ConnectError, TimeoutException

from .const import (
    ATTR_DEVICE_MAC_ADDRESS,
    ATTR_DEVICE_NAME,
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
    CONF_ENABLE_DEVICE_SENSORS,
    DEFAULT_ENABLE_DEVICE_SENSORS,
    CONF_DEVICE_SENSORS_GLOBAL,
    UPDATER,
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


def _device_sensors_save(entry: config_entries.ConfigEntry) -> int:
    """Return the entry's save counter of the global client-sensor setting."""
    try:
        return max(int(get_config_value(entry, CONF_DEVICE_SENSORS_GLOBAL, 0) or 0), 0)
    except (TypeError, ValueError):
        return 0


def get_mesh_device_sensors_save(hass: HomeAssistant) -> int:
    """Return the latest save counter of the global client-sensor setting.

    0 means it was never saved, and the legacy per-entry values still apply.
    """
    return max(
        (
            _device_sensors_save(entry)
            for entry in hass.config_entries.async_entries(DOMAIN)
        ),
        default=0,
    )


def get_mesh_device_sensors_enabled(hass: HomeAssistant) -> bool:
    """Return the mesh-wide client-sensor setting.

    The global options step stores it with the entry it was saved from, with
    a save counter: the latest save wins, whichever entry it was made on.
    Until it is saved, the legacy rule applies: on when any entry enables it.
    """
    entries = hass.config_entries.async_entries(DOMAIN)
    latest = max(entries, key=_device_sensors_save, default=None)
    if latest is not None and _device_sensors_save(latest):
        return bool(
            get_config_value(
                latest,
                CONF_ENABLE_DEVICE_SENSORS,
                DEFAULT_ENABLE_DEVICE_SENSORS,
            )
        )

    return any(
        bool(
            get_config_value(
                entry,
                CONF_ENABLE_DEVICE_SENSORS,
                DEFAULT_ENABLE_DEVICE_SENSORS,
            )
        )
        for entry in entries
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
        await hass.async_add_executor_job(_LOGGER.debug, "[MiWiFi] Login OK - código %s", updater.code)
        return updater.code, ""
    
    except ConfigEntryAuthFailed:
        return codes.FORBIDDEN, "Invalid password"

    except (ConnectError, TimeoutException) as e:
        await hass.async_add_executor_job(_LOGGER.error, "[MiWiFi] Error de conexión o timeout con %s: %s", ip, str(e))
        return codes.REQUEST_TIMEOUT, str(e)

    except HTTPError as e:
        await hass.async_add_executor_job(_LOGGER.error, "[MiWiFi] Error HTTP con %s: %s", ip, str(e))
        return codes.SERVICE_UNAVAILABLE, str(e)

    except Exception as e:
        await hass.async_add_executor_job(_LOGGER.exception, "[MiWiFi] Error inesperado durante el login con %s", ip)
        return codes.INTERNAL_SERVER_ERROR, str(e)
    finally:
        # async_stop cancels polling before persistence/logout on every exit.
        await updater.async_stop()



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


# How far ahead of the clock a last activity may be and still be read as the
# later of the two times it names in the hour the clocks repeat: the clock can
# be set back a little after a router's list was read.
LAST_ACTIVITY_CLOCK_SLACK: Final = 60


def parse_last_activity(last_activity: str) -> int:
    """Convert last activity datetime string to timestamp.

    The string is Home Assistant's local time without an offset, as the updater
    writes it. In the hour the clocks repeat when they go back, it names two
    times an hour apart: it is the later one, unless that is still to come.
    Read as the earlier one, a client seen a moment ago was an hour old, and
    away, for the whole repeated hour. That holds while the value is new: one
    written in the first occurrence and read again from a minute before the
    clock reaches that time in the second gives the second, as if the client
    had just been seen. LastActivityReader keeps the first reading.
    """
    wall = datetime.strptime(last_activity, "%Y-%m-%dT%H:%M:%S").replace(
        tzinfo=dt_util.get_default_time_zone()
    )
    first, second = (int(wall.replace(fold=fold).timestamp()) for fold in (0, 1))
    if first < second <= time.time() + LAST_ACTIVITY_CLOCK_SLACK:
        return second
    return first


class LastActivityReader:
    """A client's last activity as a timestamp, each value read once.

    A tracker or a client sensor reads its client's last activity in the poll
    that writes it, or the next one for a new client, when parse_last_activity
    gets the repeated hour right, and keeps that reading while the value stays:
    a client last listed in the first occurrence is not seen again an hour
    later. Only an entity added in the second occurrence, at a restart or a
    reload, reads such a value afresh.
    """

    def __init__(self) -> None:
        """Nothing read yet."""
        self._value: str | None = None
        self._timestamp: int = 0

    def read(self, last_activity: str) -> int:
        """The timestamp of this value, as parse_last_activity first read it."""
        if last_activity != self._value:
            self._timestamp = parse_last_activity(last_activity)
            self._value = last_activity
        return self._timestamp


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

def map_signal_quality(signal: int, unit: str | None = None) -> str:
    """Map legacy percentage or explicit RSSI to a qualitative label.

    RSSI thresholds are presentation bands, not Xiaomi's wifi_quality flag.
    """
    if unit == "dBm":
        if signal >= -50:
            return "very_strong"
        if signal >= -60:
            return "strong"
        if signal >= -70:
            return "fair"
        return "weak"
    
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


def device_config_entry_ids(device: dr.DeviceEntry) -> set[str]:
    """Read device ownership without the deprecated collection on current HA."""
    if getattr(device, "is_composite_device", False):
        # Composite devices still have multiple owners; preserve every link.
        return set(device.config_entries)
    if hasattr(device, "config_entry_id"):
        entry_id = device.config_entry_id
        return {entry_id} if entry_id is not None else set()
    # Older cores allow one device row to be shared by multiple entries.
    return set(device.config_entries)


def device_registry_rows(
    dev_reg: dr.DeviceRegistry,
    *,
    identifiers: set[tuple[str, str]] | None = None,
    connections: set[tuple[str, str]] | None = None,
) -> list[dr.DeviceEntry]:
    """Every device registry row matching the lookup.

    From core 2026.9 a device row belongs to exactly one config entry, so the
    same identifier or MAC can name one row per entry that ever published it.
    `async_get_device` returns only one of them - whichever the registry indexed
    first - and is deprecated for that reason, which makes it useless for a mesh
    where one client is seen by several nodes. Older cores have no
    `async_get_devices`; there a single row is the whole truth anyway.

    :param dev_reg: dr.DeviceRegistry
    :param identifiers: set[tuple[str, str]] | None
    :param connections: set[tuple[str, str]] | None
    :return list[dr.DeviceEntry]: the matching rows
    """

    if (get_devices := getattr(dev_reg, "async_get_devices", None)) is not None:
        return list(get_devices(identifiers=identifiers, connections=connections))

    device = dev_reg.async_get_device(
        identifiers=identifiers, connections=connections
    )

    return [device] if device is not None else []


def async_remove_empty_client_device(hass: HomeAssistant, device_id: str | None) -> None:
    """Drop a client's device row once no entity is left on it.

    Tracker and client sensors share one row, and each platform removes only
    its own entities, so whichever runs last finds the row empty. A row that
    still holds any entity - the router's own, or another integration's - is
    kept. Only MiWiFi's link is dropped: a row that another integration also
    owns (older cores share rows between entries) loses the MiWiFi entry and
    stays.

    :param hass: HomeAssistant
    :param device_id: str | None: the row the removed entities were on
    """

    if not device_id:
        return

    dev_reg = dr.async_get(hass)
    if (device := dev_reg.async_get(device_id)) is None:
        return

    if er.async_entries_for_device(
        er.async_get(hass), device_id, include_disabled_entities=True
    ):
        return

    ours = {entry.entry_id for entry in hass.config_entries.async_entries(DOMAIN)}
    owners = device_config_entry_ids(device)
    if not owners & ours:
        return

    if owners <= ours:
        dev_reg.async_remove_device(device_id)
        return

    for entry_id in owners & ours:
        dev_reg.async_update_device(device_id, remove_config_entry_id=entry_id)


def async_purge_client_entities(hass: HomeAssistant, mac: str) -> int:
    """Remove every MiWiFi client entity of a MAC, whichever entry owns it.

    Works on the entity registry directly, so it does not depend on which
    entries have their platforms set up: a loaded entity is removed by Home
    Assistant along with its registry row. It matches only client unique IDs -
    the tracker (`miwifi-<mac>`, and the legacy per-entry
    `miwifi-<entry_id>-<mac>` of any MiWiFi entry) and the client sensors
    (`miwifi-dev-<mac>-<key>`), disabled ones included - so a router's own
    entities and other integrations' are never touched. The device rows they
    leave empty go too.

    :param hass: HomeAssistant
    :param mac: str: the client's MAC, in any case
    :return int: how many entities were removed
    """

    mac_lc = str(mac or "").strip().lower()
    if not mac_lc:
        return 0

    trackers: set[str] = {f"{DOMAIN}-{mac_lc}"} | {
        f"{DOMAIN}-{entry.entry_id}-{mac_lc}".lower()
        for entry in hass.config_entries.async_entries(DOMAIN)
    }
    sensor_prefix: str = f"{DOMAIN}-dev-{mac_lc}-"

    registry = er.async_get(hass)
    matches: list[er.RegistryEntry] = [
        entity
        for entity in list(registry.entities.values())
        if entity.platform == DOMAIN
        and (
            (entity.domain == "device_tracker" and (entity.unique_id or "").lower() in trackers)
            or (entity.domain == "sensor" and (entity.unique_id or "").lower().startswith(sensor_prefix))
        )
    ]

    device_ids: set[str] = set()
    for entity in matches:
        if entity.device_id:
            device_ids.add(entity.device_id)
        registry.async_remove(entity.entity_id)

    for device_id in device_ids:
        async_remove_empty_client_device(hass, device_id)

    return len(matches)


def async_register_backhaul_alias(
    hass: HomeAssistant, entry_id: str, device_mac: str, backhaul_mac: str
) -> str:
    """Record on a node's own device row the MAC its main lists it under.

    A main names the node serving a client by the MAC in the client's `parent`,
    and on some leaves that is not the MAC the leaf reports for itself: an RA82
    registers its hardware MAC and is listed by its LAN MAC. Nothing could find
    the node by that second MAC, so "Connected via" kept whatever it last was,
    and client attributes named a MAC no node row carries.

    The alias goes on the node's row as one more MAC connection, which is what
    `_ensure_via_device_exists` already resolves. The registry rejects a MAC
    that another row of the same entry already has - and, before core 2026.9,
    any other row at all, of any integration. That row is not ours to merge or
    drop, so the alias is simply not recorded: the node is still resolved
    through its updater, see `async_get_serving_node`.

    :param hass: HomeAssistant
    :param entry_id: str: the node's own config entry
    :param device_mac: str: the MAC the node reports for itself
    :param backhaul_mac: str: the MAC the main lists it under
    :return str: "added", "present", "missing" (no row for the node yet, or
        nothing to record) or "taken" (another row has the MAC)
    """

    device_lc = str(device_mac or "").strip().lower()
    backhaul_lc = str(backhaul_mac or "").strip().lower()
    if not device_lc or not backhaul_lc or device_lc == backhaul_lc:
        return "missing"

    dev_reg = dr.async_get(hass)
    row = next(
        (
            row
            for row in device_registry_rows(
                dev_reg, identifiers={(DOMAIN, device_lc)}
            )
            if entry_id in device_config_entry_ids(row)
        ),
        None,
    )

    alias = (dr.CONNECTION_NETWORK_MAC, backhaul_lc)
    if row is None:
        return "missing"
    if alias in row.connections:
        return "present"

    try:
        # The full set: `merge_connections` is deprecated from core 2026.10.
        dev_reg.async_update_device(row.id, new_connections=row.connections | {alias})
    except HomeAssistantError:
        # DeviceConnectionCollisionError: another row already has this MAC.
        return "taken"

    return "added"


def async_get_serving_node(
    hass: HomeAssistant, parent_mac: str | None
) -> tuple[str, str | None] | None:
    """The loaded node a client's parent MAC names: its own MAC and its name.

    The parent MAC is either the node's own MAC or the one its main lists it
    under (see `async_register_backhaul_alias`). The name is the one shown in
    Home Assistant when the user gave one, else the router's own name.

    :param hass: HomeAssistant
    :param parent_mac: str | None: the MAC in the client's `router_mac`
    :return tuple[str, str | None] | None: (node MAC, node name), or None
    """

    parent = str(parent_mac or "").strip().upper()
    if not parent or hass is None:
        return None

    for entry_id, entry_data in (hass.data.get(DOMAIN) or {}).items():
        if not isinstance(entry_data, dict):
            continue

        updater = entry_data.get(UPDATER)
        data = getattr(updater, "data", None) or {}
        own = str(data.get(ATTR_DEVICE_MAC_ADDRESS) or "").strip().upper()
        if not own or parent not in (own, getattr(updater, "backhaul_mac", None)):
            continue

        row = next(
            (
                row
                for row in device_registry_rows(
                    dr.async_get(hass), identifiers={(DOMAIN, own.lower())}
                )
                if entry_id in device_config_entry_ids(row)
            ),
            None,
        )
        name = (
            (row.name_by_user if row is not None else None)
            or data.get(ATTR_DEVICE_NAME)
            or (row.name if row is not None else None)
        )

        return own, name

    return None
