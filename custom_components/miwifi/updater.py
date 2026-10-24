"""Luci data updater."""


from __future__ import annotations

import asyncio
import aiohttp
import contextlib
from .logger import _LOGGER
from .notifier import MiWiFiNotifier
from .miwifi_utils import parse_memory_to_mb
from collections import defaultdict

from .unsupported import get_combined_unsupported
from datetime import datetime, timedelta
from functools import cached_property
from typing import Any, Final, Optional
from time import monotonic

from homeassistant.util import dt as dt_util

import homeassistant.components.persistent_notification as pn
from homeassistant.const import CONF_IP_ADDRESS
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import CALLBACK_TYPE, HomeAssistant, callback
from homeassistant.helpers import event
from homeassistant.helpers.device_registry import CONNECTION_NETWORK_MAC
from homeassistant.helpers.dispatcher import async_dispatcher_send
from homeassistant.helpers.entity import DeviceInfo
from homeassistant.helpers.httpx_client import get_async_client
from homeassistant.helpers.storage import Store
from homeassistant.helpers.update_coordinator import DataUpdateCoordinator
from homeassistant.helpers.translation import async_get_translations
from homeassistant.util import utcnow
from httpx import codes

from .const import (
    ATTR_BINARY_SENSOR_WAN_LINK,
    ATTR_BINARY_SENSOR_WAN_LINK_NAME,
    ATTR_BINARY_SENSOR_DUAL_BAND,
    ATTR_BINARY_SENSOR_VPN_STATE,
    ATTR_BINARY_SENSOR_WAN_STATE,
    ATTR_DEVICE_HW_VERSION,
    ATTR_DEVICE_MAC_ADDRESS,
    ATTR_DEVICE_MANUFACTURER,
    ATTR_DEVICE_MODEL,
    ATTR_DEVICE_NAME,
    ATTR_DEVICE_SW_VERSION,
    ATTR_LIGHT_LED,
    ATTR_MODEL,
    ATTR_SENSOR_AP_SIGNAL,
    ATTR_SENSOR_DEVICES,
    ATTR_SENSOR_DEVICES_2_4,
    ATTR_SENSOR_DEVICES_5_0,
    ATTR_SENSOR_DEVICES_5_0_GAME,
    ATTR_SENSOR_DEVICES_IOT,
    ATTR_SENSOR_DEVICES_GUEST,
    ATTR_SENSOR_DEVICES_LAN,
    ATTR_SENSOR_MEMORY_TOTAL,
    ATTR_SENSOR_MEMORY_USAGE,
    ATTR_SENSOR_MODE,
    ATTR_SENSOR_TEMPERATURE,
    ATTR_SENSOR_UPTIME,
    ATTR_SENSOR_VPN_UPTIME,
    ATTR_SENSOR_WAN_DOWNLOAD_SPEED,
    ATTR_SENSOR_WAN_UPLOAD_SPEED,
    ATTR_SENSOR_WAN_IP,
    ATTR_SENSOR_WAN_TYPE,
    ATTR_SENSOR_WAN_TYPE_NAME,
    ATTR_STATE,
    ATTR_SWITCH_WIFI_5_0_GAME,
    ATTR_TRACKER_CONNECTION,
    ATTR_TRACKER_DOWN_SPEED,
    ATTR_TRACKER_TOTAL_USAGE,
    ATTR_TRACKER_ENTRY_ID,
    ATTR_TRACKER_IP,
    ATTR_TRACKER_IS_RESTORED,
    ATTR_TRACKER_LAST_ACTIVITY,
    ATTR_TRACKER_MAC,
    ATTR_TRACKER_NAME,
    ATTR_TRACKER_ONLINE,
    ATTR_TRACKER_OPTIONAL_MAC,
    ATTR_TRACKER_ROUTER_MAC_ADDRESS,
    ATTR_TRACKER_SIGNAL,
    ATTR_TRACKER_UP_SPEED,
    ATTR_TRACKER_UPDATER_ENTRY_ID,
    ATTR_TRACKER_INTERNET_BLOCKED,
    ATTR_TRACKER_FIRST_SEEN,
    ATTR_UPDATE_CURRENT_VERSION,
    ATTR_UPDATE_DOWNLOAD_URL,
    ATTR_UPDATE_FILE_HASH,
    ATTR_UPDATE_FILE_SIZE,
    ATTR_UPDATE_FIRMWARE,
    ATTR_UPDATE_LATEST_VERSION,
    ATTR_UPDATE_RELEASE_URL,
    ATTR_UPDATE_TITLE,
    ATTR_WIFI_ADAPTER_LENGTH,
    ATTR_WIFI_DATA_FIELDS,
    DEFAULT_ACTIVITY_DAYS,
    DEFAULT_CALL_DELAY,
    DEFAULT_MANUFACTURER,
    DEFAULT_NAME,
    DEFAULT_PROTOCOL,
    DEFAULT_RETRY,
    DEFAULT_SCAN_INTERVAL,
    DEFAULT_TIMEOUT,
    DOMAIN,
    NAME,
    SIGNAL_NEW_DEVICE,
    SIGNAL_PURGE_DEVICE,
    UPDATER,
)
from .enum import (
    MESH_ROLE_MODES,
    Connection,
    DeviceAction,
    EncryptionAlgorithm,
    IfName,
    Mode,
    Model,
    Wifi,
)
from .exceptions import LuciAuthenticationError, LuciConnectionError, LuciError, LuciRequestError
from homeassistant.exceptions import ConfigEntryAuthFailed
from .luci import LuciClient
from .self_check import async_self_check
from .mesh_diagnostics import MeshTrace
from .purged_clients import get_purged_clients
from .mac_replacement import get_mac_replacement, async_retire_macs

PREPARE_METHODS: Final = (
    "init",
    "status",
    "vpn",
    "rom_update",
    "mode",
    "cpe_mobile",
    "wan",
    "multiwan",
    "led",
    "wifi",
    "channels",
    "devices",
    "device_list",
    "device_restore",
    "ap",
    "new_status",
)

# hass.data[DOMAIN] keys: MACs reported by a main router as mesh nodes (isap > 0),
# and those whose leftover client entities have already been purged.
MESH_NODE_MACS: Final = "mesh_node_macs"
MESH_NODE_PURGED: Final = "mesh_node_purged"

NEW_STATUS_MAP: Final = {
    "2g": ATTR_SENSOR_DEVICES_2_4,
    "5g": ATTR_SENSOR_DEVICES_5_0,
    "game": ATTR_SENSOR_DEVICES_5_0_GAME,
    "iot": ATTR_SENSOR_DEVICES_IOT,
}

def _find_leaf(graph: dict, ip: str) -> dict | None:
    """Find a node entry in a topology graph, including nested leaves."""

    for leaf in (graph.get("leafs") if isinstance(graph.get("leafs"), list) else []):
        if not isinstance(leaf, dict):
            continue
        leaf_ip = leaf.get("ip")
        if isinstance(leaf_ip, str) and leaf_ip.strip() == ip:
            return leaf
        found = _find_leaf(leaf, ip)
        if found is not None:
            return found
    return None


def _ap_macs_by_ip(response: dict) -> dict[str, str]:
    """Map mesh access-point addresses to the MAC used by client parents."""

    macs: dict[str, str] = {}
    for device in response.get("list", []):
        if not isinstance(device, dict):
            continue
        try:
            if int(device.get("isap") or 0) <= 0:
                continue
        except (TypeError, ValueError):
            continue

        mac = str(device.get("mac") or "").strip().upper()
        if not mac or not isinstance(device.get("ip"), list):
            continue

        fallback: str | None = None
        for address in device["ip"]:
            if not isinstance(address, dict):
                continue
            value = str(address.get("ip") or "").strip()
            if not value:
                continue
            fallback = fallback or value
            try:
                if int(address.get("active") or 0) == 1:
                    fallback = value
                    break
            except (TypeError, ValueError):
                continue
        if fallback:
            macs[fallback] = mac
    return macs


def _known_mesh_nodes(hass: HomeAssistant) -> tuple[set[str], set[str]]:
    """Return the MACs and IPs that belong to mesh nodes rather than clients.

    MACs: those a main router reported with ``isap`` > 0 since startup, plus the
    MAC of every node that is set up. IPs: the address of every MiWiFi entry,
    read from the entries so it does not depend on setup order.
    """

    macs: set[str] = set(hass.data.get(DOMAIN, {}).get(MESH_NODE_MACS, ()))
    ips: set[str] = set()

    for ip, integration in async_get_integrations(hass).items():
        ips.add(ip)
        mac = (getattr(integration.get(UPDATER), "data", None) or {}).get(
            ATTR_DEVICE_MAC_ADDRESS
        )
        if isinstance(mac, str) and mac.strip():
            macs.add(mac.strip().upper())

    for entry in hass.config_entries.async_entries(DOMAIN):
        ip = entry.options.get(CONF_IP_ADDRESS, entry.data.get(CONF_IP_ADDRESS))
        if isinstance(ip, str) and ip:
            ips.add(ip)

    return macs, ips


def _remember_mesh_node_macs(
    hass: HomeAssistant, macs: set[str], key: str = MESH_NODE_MACS
) -> set[str]:
    """Record MACs under a hass.data key and return the ones not recorded before."""

    known: set[str] = hass.data.setdefault(DOMAIN, {}).setdefault(key, set())
    learned = macs - known
    known |= learned
    return learned


def _channel_of(adapter: dict) -> str | None:
    """Read an adapter's channel, wherever this firmware chose to put it.

    `channelInfo.channel` is the usual place; provider firmwares answer at the
    top level instead. "0" is how a firmware says "unset" where it says anything
    at all, and is not a channel anyone can be shown or set.

    :param adapter: dict: one entry of a wifi detail or diagnostics response
    :return str | None: the channel, or None when this adapter does not state one
    """

    channel_info = adapter.get("channelInfo")
    channel = (
        channel_info.get("channel") if isinstance(channel_info, dict) else None
    )

    if str(channel or "").strip() in ("", "0"):
        channel = adapter.get("channel")

    if str(channel or "").strip() in ("", "0"):
        return None

    return str(channel)


# Wait after an ask of the diagnostics endpoint that recovered no channel. It
# doubles with every miss in a row, from the first value up to the second.
WIFI_DIAG_RETRY_FIRST: Final = timedelta(minutes=1)
WIFI_DIAG_RETRY_MAX: Final = timedelta(hours=1)


REPEATER_SKIP_ATTRS: Final = (
    ATTR_TRACKER_NAME,
    ATTR_TRACKER_IP,
    ATTR_TRACKER_DOWN_SPEED,
    ATTR_TRACKER_UP_SPEED,
    ATTR_TRACKER_ONLINE,
    ATTR_TRACKER_OPTIONAL_MAC,
    ATTR_TRACKER_CONNECTION,
    ATTR_TRACKER_ROUTER_MAC_ADDRESS,
    ATTR_TRACKER_SIGNAL,
    ATTR_TRACKER_LAST_ACTIVITY,
    ATTR_TRACKER_INTERNET_BLOCKED,
    ATTR_TRACKER_FIRST_SEEN,
    ATTR_TRACKER_TOTAL_USAGE,
    "wifi_protocol", "link_tx_rate", "link_rx_rate", "signal_unit", "signal_source",
)

# pylint: disable=too-many-branches,too-many-lines,too-many-arguments
class LuciUpdater(DataUpdateCoordinator):
    """Luci data updater for interaction with Luci API."""

    luci: LuciClient
    code: codes = codes.BAD_GATEWAY
    ip: str
    new_device_callback: CALLBACK_TYPE | None = None
    is_force_load: bool = False
    is_ap_mode: bool = False
    supports_guest: bool = True

    _store: Store | None = None

    _entry_id: str | None = None
    _scan_interval: int
    _activity_days: int
    _is_only_login: bool = False
    _is_reauthorization: bool = True
    _status_has_wan_speed: bool = False

    def __init__(
        self,
        hass: HomeAssistant,
        ip: str,
        password: str,
        encryption: str = EncryptionAlgorithm.SHA1,
        scan_interval: int = DEFAULT_SCAN_INTERVAL,
        timeout: int = DEFAULT_TIMEOUT,
        is_force_load: bool = False,
        activity_days: int = DEFAULT_ACTIVITY_DAYS,
        store: Store | None = None,
        is_only_login: bool = False,
        entry_id: str | None = None,
        protocol: str = DEFAULT_PROTOCOL,
        config_entry: ConfigEntry | None = None,
        is_ap_mode: bool = False,
    ) -> None:
        """Initialize updater.

        :rtype: object
        :param hass: HomeAssistant: Home Assistant object
        :param ip: str: device ip address
        :param password: str: device password
        :param encryption: str: password encryption algorithm
        :param scan_interval: int: Update interval
        :param timeout: int: Query execution timeout
        :param is_force_load: bool: Force boot devices when using repeater and mesh mode
        :param activity_days: int: Allowed number of days to wait after the last activity
        :param store: Store | None: Device store
        :param is_only_login: bool: Only config flow
        :param entry_id: str | None: Entry ID
        :param protocol: str: Connection protocol (auto, http, https)
        :param config_entry: ConfigEntry | None: Entry owning this coordinator
        :param is_ap_mode: bool: Node runs as access point / mesh node behind a foreign gateway
        """

        client_factory = lambda: get_async_client(hass, False)

        self.luci = LuciClient(
            client_factory(),
            ip,
            password,
            EncryptionAlgorithm(encryption),
            timeout,
            protocol,
            client_factory=client_factory,
        )

        self.ip = ip  # pylint: disable=invalid-name
        self.timeout = timeout
        self.is_force_load = is_force_load
        self.is_ap_mode = is_ap_mode
        self._entry_id = entry_id
        self._scan_interval = scan_interval
        self._activity_days = activity_days
        self._is_only_login = is_only_login
        self._unsupported: dict[str, list] = {}
        self._nat_rules_next_try = dt_util.utcnow()
        
        # macfilter_info throttling / cache
        self._macfilter_next_try = dt_util.utcnow()
        self._macfilter_warned_at = None
        self._macfilter_fail_count = 0
        self._filter_macs: dict[str, int] = {}
        self._counters_reset_this_cycle = False
        # One per poll. Listeners hear about a poll more than once - the topology
        # step publishes mid-cycle, then the coordinator at the end - so anything
        # that counts polls has to count this instead of its callbacks.
        self.update_cycle: int = 0
        self._parent_push_pending = False
        self._parent_census_at: float | None = None
        self._parent_census_source: LuciUpdater | None = None
        # The parent and time of the last push that had each client, and the
        # clients in this node's own last device list: see add_device.
        self._parent_census_clients: dict[str, tuple[LuciUpdater, float]] = {}
        self._device_list_macs: frozenset[str] = frozenset()
        # The MAC a main lists this node under in `parent`, when it is not the
        # one the node reports for itself. Set by the main's device list.
        self.backhaul_mac: str | None = None
        self._backhaul_alias_skipped: set[str] = set()
        
        # --- CB0401V2 / 5G CPE throttling ---
        self._is_cb0401v2: bool = False
        self._cpe_mobile_next_try = dt_util.utcnow()
        self._cpe_mobile_fail_count = 0
        self._cpe_detect_next_try = dt_util.utcnow()
        self._sms_next_try = dt_util.utcnow()
        self._cpe_newstatus_next_try = dt_util.utcnow()

        # The topology-derived role is reported once, not once per cycle.
        self._topology_role_logged: bool = False

        # Last (mapped, skipped) wifi adapter names reported at debug.
        self._wifi_adapters_logged: tuple | None = None

        # When the diagnostics endpoint may be asked again for missing channels,
        # and how many asks in a row have recovered nothing.
        self._wifi_diag_next_try: datetime = dt_util.utcnow()
        self._wifi_diag_misses: int = 0

        if store is None and entry_id:
            self._store = Store(hass, 1, f"miwifi/{entry_id}.json")
        else:
            self._store = store

        if hass is not None:
            super().__init__(
                hass,
                _LOGGER,
                name=f"{NAME} updater",
                update_interval=self._update_interval,
                update_method=self.update,
                **({"config_entry": config_entry} if config_entry is not None else {}),
            )

        self.data: dict[str, Any] = {}
        self.devices: dict[str, dict[str, Any]] = {}
        self._mesh_trace = MeshTrace()
        self._signals: dict[str, int | None] = {}
        self._moved_devices: list = []
        self._is_first_update: bool = True

    async def async_stop(self, clean_store: bool = False) -> None:
        """Stop updater

        :param clean_store: bool
        """

        # Cancel polling before saving or logging out, including failure paths.
        await self.async_shutdown()

        if self.new_device_callback is not None:
            self.new_device_callback()  # pylint: disable=not-callable

        if clean_store and self._store is not None:
            await self._store.async_remove()
        else:
            await self._async_save_devices()

        with contextlib.suppress(Exception, LuciError):
            await self.luci.logout()

    @cached_property
    def _update_interval(self) -> timedelta:
        """Update interval

        :return timedelta: update_interval
        """

        return timedelta(seconds=self._scan_interval)

    async def update(self, retry: int = 1) -> dict:
        """Let HA stop polling and start reauthentication after rejected credentials."""
        try:
            data = await self._async_update(retry)
        except LuciAuthenticationError as err:
            self.code = codes.FORBIDDEN
            raise ConfigEntryAuthFailed("Router rejected the login credentials") from err
        # Optional endpoint handlers may catch LuciError. Do not let them hide
        # a failed re-login or keep polling with the rejected credentials.
        if self.luci.authentication_failed is True:
            self.code = codes.FORBIDDEN
            raise ConfigEntryAuthFailed("Router rejected the login credentials")
        return data

    async def _async_update(self, retry: int = 1) -> dict:
        """Update miwifi information.

        :param retry: int: Retry count
        :return dict: dict with luci data.
        """

        self.code = codes.OK
        self._counters_reset_this_cycle = False
        self.update_cycle += 1

        _is_before_reauthorization: bool = self._is_reauthorization
        _err: LuciError | None = None
        _method: str = "login"

        try:
            if self._is_reauthorization or self._is_only_login or self._is_first_update:
                if self._is_first_update and retry == 1:
                    await self.luci.logout()
                    await asyncio.sleep(DEFAULT_CALL_DELAY)

                await self.luci.login()

            self._unsupported = await get_combined_unsupported(self.hass)

            for method in PREPARE_METHODS:
                if not self._is_only_login or method == "init":
                    # Routers with dedicated IoT WiFi (e.g. RC01 / RC06):
                    # count clients from device_list + parent, not from new_status.
                    if self.is_force_load and self._has_dedicated_iot_wifi() and method == "new_status":
                        continue

                    if method in ("devices", "device_list") and "new_status" in self.data and self.is_force_load:
                        continue

                    _method = method
                    await self._async_prepare(method, self.data)

        except LuciConnectionError as _e:
            _err = _e
            self._is_reauthorization = False
            self.code = codes.NOT_FOUND
            await self.hass.async_add_executor_job(_LOGGER.warning, "[MiWiFi] LuciConnectionError on %s: %s", _method, _e)

        except LuciRequestError as _e:
            _err = _e
            self._is_reauthorization = True
            self.code = codes.FORBIDDEN
            await self.hass.async_add_executor_job(_LOGGER.warning, "[MiWiFi] LuciRequestError on %s: %s", _method, _e)


        else:
            self._is_reauthorization = False

            if self._is_first_update:
                self._is_first_update = False

        self.data[ATTR_STATE] = codes.is_success(self.code)

        if (
            not self._is_first_update
            and not _is_before_reauthorization
            and self._is_reauthorization
        ):
            self.data[ATTR_STATE] = True

        if (
            not self._is_only_login
            and self._is_first_update
            and not self.data[ATTR_STATE]
        ):
            if retry > DEFAULT_RETRY and _err is not None:
                raise _err

            if retry <= DEFAULT_RETRY:
                await self.hass.async_add_executor_job(_LOGGER.warning, 
                    "Error connecting to router (attempt #%s of %s): %r",
                    retry,
                    DEFAULT_RETRY,
                    _err,
                )

                await asyncio.sleep(retry)

                return await self.update(retry + 1)

        if not self._is_only_login:
            self._clean_devices()

        await self._async_prepare_topo()
        await self._async_apply_leaf_client_count()

        await self._async_prepare_compatibility()
        
        if isinstance(getattr(self, "capabilities", None), dict) and self.capabilities.get("portforward", False):
            await self._async_prepare_nat_rules()
        
        if self._is_only_login:
            await self.hass.async_add_executor_job(_LOGGER.debug, "[MiWiFi] Finalizó login (is_only_login), código=%s, data[ATTR_STATE]=%s", self.code, self.data.get(ATTR_STATE))

        self._mesh_trace.event("update_complete", self.data,
                               parent_push_pending=self._parent_push_pending,
                               counters_reset=self._counters_reset_this_cycle)
        return self.data

    def _topology_role(self) -> Mode | None:
        """The role the topology graph gives this node, if it gives one.

        `xqnetwork/mode` answers `default` on a wired-backhaul leaf, which types
        it as a standalone gateway and sends the coordinator asking it for WAN
        and MAC filter data it cannot serve. The graph knows better, from two
        independent directions: what the node says about itself, and what the
        node above it says about the node.

        Only a positive identification counts. Nothing here can push a node
        towards `default`, so a missing graph - not read yet, or its request
        failed - simply leaves the endpoint in charge.

        :return Mode | None: the mesh role, or None when the graph cannot tell
        """

        topology = self.data.get("topo_graph")
        graph = topology.get("graph") if isinstance(topology, dict) else None
        if not isinstance(graph, dict):
            graph = {}

        # The main is never a leaf, whoever else lists it.
        if graph.get("is_main"):
            return None

        with contextlib.suppress(KeyError, TypeError, ValueError):
            if (own_role := Mode(int(graph["mode"]))) in MESH_ROLE_MODES:
                return own_role

        if (leaf := self._leaf_entry_from_other_nodes()) is not None:
            # A leaf reports its own mode as 1 in the main's graph, which is
            # this integration's REPEATER - a different thing, with an upstream
            # link and an ap signal. Listed as a leaf means mesh node.
            with contextlib.suppress(KeyError, TypeError, ValueError):
                if (listed_role := Mode(int(leaf["mode"]))) in MESH_ROLE_MODES:
                    return listed_role

            return Mode.MESH_NODE

        return None

    @property
    def is_repeater(self) -> bool:
        """Is repeater property

        :return bool: is_repeater
        """

        return self.data.get(ATTR_SENSOR_MODE, Mode.DEFAULT).value > 0

    @property
    def _counters_pushed_by_parent(self) -> bool:
        """Are this node's client counters owned by the node above it?

        A repeater or access point without force load does not reset its
        counters at the start of every cycle: the main pushes its clients in
        through add_device(is_from_parent=True), having forced a reset first.
        Resetting here as well would blank the pushed values on the next poll.

        :return bool: counters are maintained by the parent
        """

        return self.is_repeater and not self.is_force_load

    @property
    def _counts_own_clients(self) -> bool:
        """Does this leaf keep client counters the parent's push cannot rebuild?

        A force-load repeater counts its clients itself (new_status), and
        add_device(is_from_parent=True) only counts for it on firmwares with
        dedicated IoT Wi-Fi.

        :return bool: the parent must not reset this node's counters
        """

        return (
            self.is_repeater
            and self.is_force_load
            and not self._has_dedicated_iot_wifi()
        )

    @property
    def supports_wan(self) -> bool:
        """Is supports wan

        With the AP option wan_info is never asked, so there is no WAN state to
        go by. The speed sensors read misystem/status, which an access point
        still answers, so they follow its WAN counters instead.

        :return bool
        """

        if self.is_ap_mode:
            return self._status_has_wan_speed

        return self.data.get(ATTR_BINARY_SENSOR_WAN_STATE, False)
    
    def _is_cb0401v2_device(self, data: dict | None = None) -> bool:
        if getattr(self, "_is_cb0401v2", False):
            return True
        d = data or self.data or {}
        model = str(d.get(ATTR_DEVICE_MODEL) or "").lower()
        return "cb0401" in model

    @property
    def supports_game(self) -> bool:
        """Is supports game mode

        :return bool
        """

        return self.data.get(ATTR_SWITCH_WIFI_5_0_GAME, None) is not None

    def _has_dedicated_iot_wifi(self) -> bool:
        """Return True for firmwares with dedicated IoT WiFi."""
        features = self.data.get("features", {})
        wifi_features = features.get("wifi", {}) if isinstance(features, dict) else {}

        if isinstance(wifi_features, dict) and str(wifi_features.get("iot_dev", "0")) == "1":
            return True

        model_enum = self.data.get(ATTR_MODEL)
        model_str = str(self.data.get(ATTR_DEVICE_MODEL) or "").strip().lower()

        return (
            model_enum in (Model.RC01, Model.RC06)
            or "rc01" in model_str
            or "rc06" in model_str
            or "be10000" in model_str
            or "be7000" in model_str
        )

    def _resolve_connection(self, device: dict) -> Connection | None:
        """Resolve connection type safely.

        Generic routers:
        - keep current behavior
        - wifiIndex=3 may still map to 5G Game

        Routers with dedicated IoT WiFi:
        - type 5 => 5G Game
        - type 6 => IoT dedicated WiFi
        """
        # A parent's census has already been decoded using the reporting
        # router's schema. Do not reinterpret it using a different leaf model.
        if "_miwifi_connection" in device:
            connection = device["_miwifi_connection"]
            return connection if isinstance(connection, Connection) else None

        raw_type = device.get("type")

        try:
            raw_type_int = int(raw_type) if raw_type not in ("", None) else None
        except Exception:
            raw_type_int = None

        model = str(self.data.get(ATTR_MODEL) or "").strip().lower()
        device_model = str(self.data.get(ATTR_DEVICE_MODEL) or "").strip().lower()
        if model == Model.RD08.value or device_model == "xiaomi.router.rd08":
            # RD08 1.1.96 devicelist uses 1=LAN, 2=2.4 GHz, 3=5 GHz.
            # Verified against the native UI and wifi_connect_devices in #356.
            # Guest=7 and IoT=9 were verified with connected clients in #356.
            rd08_connections = {
                1: Connection.LAN,
                2: Connection.WIFI_2_4,
                3: Connection.WIFI_5_0,
                7: Connection.GUEST,
                9: Connection.WIFI_IOT,
            }
            if raw_type_int in rd08_connections:
                return rd08_connections[raw_type_int]

        if self._has_dedicated_iot_wifi():
            if raw_type_int == 5:
                return Connection.WIFI_5_0_GAME
            if raw_type_int == 6:
                return Connection.WIFI_IOT

            with contextlib.suppress(ValueError, TypeError):
                return Connection(raw_type_int) if raw_type_int is not None else None

            return None

        if self.is_force_load and "wifiIndex" in device:
            try:
                wifi_index = int(device["wifiIndex"])
                if wifi_index == 3:
                    return Connection.WIFI_5_0_GAME
                with contextlib.suppress(ValueError, TypeError):
                    return Connection(wifi_index)
            except Exception:
                pass

        with contextlib.suppress(ValueError, TypeError):
            return Connection(raw_type_int) if raw_type_int is not None else None

        return None

    @property
    def supports_update(self) -> bool:
        """Is supports update

        :return bool
        """

        return len(self.data.get(ATTR_UPDATE_FIRMWARE, {})) != 0

    @property
    def device_info(self):
        """Device info.

        :return DeviceInfo: Service DeviceInfo.
        """

        return DeviceInfo(
            identifiers={(DOMAIN, self.data.get(ATTR_DEVICE_MAC_ADDRESS, self.ip))},
            connections={
                (
                    CONNECTION_NETWORK_MAC,
                    self.data.get(ATTR_DEVICE_MAC_ADDRESS, self.ip),
                ),
                (CONF_IP_ADDRESS, self.ip),
            },
            name=self.data.get(ATTR_DEVICE_NAME, DEFAULT_NAME),
            manufacturer=self.data.get(ATTR_DEVICE_MANUFACTURER, DEFAULT_MANUFACTURER),
            model=self.data.get(ATTR_DEVICE_MODEL, None),
            sw_version=self.data.get(ATTR_DEVICE_SW_VERSION, None),
            hw_version=self.data.get(ATTR_DEVICE_HW_VERSION, None),
            configuration_url=f"http://{self.ip}/",
        )

    def schedule_refresh(self, offset: timedelta) -> None:
        """Schedule refresh.

        :param offset: timedelta
        """

        unsub = getattr(self, "_unsub_refresh", None)
        if unsub:
            unsub()
            self._unsub_refresh = None  # type: ignore[attr-defined]

        self._unsub_refresh = event.async_track_point_in_utc_time(
            self.hass,
            self._handle_refresh_interval,
            utcnow().replace(microsecond=0) + offset,
        )

    async def _async_prepare(self, method: str, data: dict) -> None:
        """Prepare data.

        :param method: str
        :param data: dict
        """
        if data is None:
            data = self.data  # o {}

        if not isinstance(data, dict):
            data = self.data = {}

        unsupported = getattr(self, "_unsupported", {}) or {}

        # ✅ Never skip cpe_mobile due to unsupported registry/storage
        if (
            method != "cpe_mobile"
            and method in unsupported
            and data.get(ATTR_MODEL, Model.NOT_KNOWN) in unsupported[method]
        ):
            await self.hass.async_add_executor_job(
                _LOGGER.debug,
                "[MiWiFi] Skipping '%s' for model '%s' (unsupported by registry/storage)",
                method,
                data.get(ATTR_MODEL),
            )
            return

        action = getattr(self, f"_async_prepare_{method}", None)
        if action is None:
            await self.hass.async_add_executor_job(
                _LOGGER.debug,
                "[MiWiFi] No handler for prepare method '%s' (skipping)",
                method,
            )
            return

        await action(data)

        
    def _macfilter_call_timeout(self) -> float:
        """Timeout razonable para macfilter_info (capado para no bloquear ciclos)."""
        try:
            t = int(getattr(self, "_timeout", DEFAULT_TIMEOUT) or DEFAULT_TIMEOUT)
        except Exception:
            t = DEFAULT_TIMEOUT
        # mínimo 6s, máximo 10s (usa opción del usuario como guía)
        return float(min(10, max(6, t)))


    async def _async_prepare_init(self, data: dict) -> None:
        """Prepare init info.

        :param data: dict
        """

        '''if not self._is_first_update:
            return'''
        if (
            not self._is_first_update
            and ATTR_DEVICE_NAME in data
            and ATTR_DEVICE_MODEL in data
            and ATTR_DEVICE_MANUFACTURER in data
        ):
            return

        response: dict = await self.luci.init_info()

        if "features" in response and isinstance(response["features"], dict):
            data["features"] = response["features"]

        if "model" in response:
            data[ATTR_DEVICE_MODEL] = response["model"]

            manufacturer: list = response["model"].split(".")
            data[ATTR_DEVICE_MANUFACTURER] = manufacturer[0].title()
        elif "hardware" in response:
            data[ATTR_DEVICE_MODEL] = response["hardware"]

        if "routername" in response:
            data[ATTR_DEVICE_NAME] = response["routername"]

        if "romversion" in response and "countrycode" in response:
            data[
                ATTR_DEVICE_SW_VERSION
            ] = f"{response['romversion']} ({response['countrycode']})"

        if "hardware" in response:
            hw = str(response.get("hardware") or "").strip()
            hw_l = hw.lower()

            # ✅ CB0401V2 / 5G CPE (provider firmwares) - do not block integration
            if "cb0401" in hw_l:
                self._is_cb0401v2 = True
                data["cpe_profile"] = "CB0401V2"
                data[ATTR_DEVICE_MANUFACTURER] = DEFAULT_MANUFACTURER
                data.setdefault(ATTR_DEVICE_MODEL, hw)
                data[ATTR_MODEL] = Model.NOT_KNOWN
                return

            try:
                data[ATTR_MODEL] = Model(hw_l)
            except ValueError as _e:
                await async_self_check(self.hass, self.luci, response["hardware"])

                if not self._is_only_login:
                    raise LuciError(f"Router {self.ip} not supported") from _e

                self.code = codes.CONFLICT

            return
        

        notifier = MiWiFiNotifier(self.hass)
        translations = await notifier.get_translations()

        title = translations.get("notifications", {}).get(
            "unsupported_router_title", "Unsupported Router"
        )
        message_template = translations.get("notifications", {}).get(
            "unsupported_router_message",
            f"⚠️ Router at {self.ip} is not supported by the MiWiFi integration."
        )
        message = message_template.replace("{ip}", self.ip)

        await notifier.notify(
            message=message,
            title=title,
            notification_id=f"miwifi_unsupported_router_{self.ip.replace('.', '_')}"
        )

        if not self._is_only_login:
            raise LuciError(f"Router {self.ip} not supported")

        self.code = codes.CONFLICT

    async def _async_prepare_status(self, data: dict) -> None:
        """Prepare status (hardened numeric parsing)."""

        def _to_float(v, default=None):
            try:
                if v in ("", None):
                    return default
                return float(str(v))
            except Exception:
                return default

        def _to_int(v, default=None):
            try:
                if v in ("", None):
                    return default
                return int(float(str(v)))
            except Exception:
                return default

        try:
            response: dict = await self.luci.status()
        except LuciError:
            # ✅ CB0401V2 provider firmwares may fail on misystem/status → don't break the cycle
            if self._is_cb0401v2_device(data):
                return
            raise

        if isinstance(response.get("hardware"), dict):
            hw = response["hardware"]
            if "mac" in hw:
                data[ATTR_DEVICE_MAC_ADDRESS] = hw["mac"]
            if "sn" in hw:
                data[ATTR_DEVICE_HW_VERSION] = hw["sn"]
            if "version" in hw:
                data[ATTR_UPDATE_CURRENT_VERSION] = hw["version"]

        up = _to_float(response.get("upTime"))
        if up is not None:
            data[ATTR_SENSOR_UPTIME] = str(timedelta(seconds=int(up)))

        mem = response.get("mem") if isinstance(response.get("mem"), dict) else {}
        if isinstance(mem, dict):
            usage = _to_float(mem.get("usage"))
            if usage is not None:
                data[ATTR_SENSOR_MEMORY_USAGE] = int(usage * 100)

            if "total" in mem:
                with contextlib.suppress(Exception):
                    data[ATTR_SENSOR_MEMORY_TOTAL] = parse_memory_to_mb(mem.get("total"))

        temp = _to_float(response.get("temperature"))
        if temp is not None:
            data[ATTR_SENSOR_TEMPERATURE] = temp

        wan = response.get("wan") if isinstance(response.get("wan"), dict) else {}
        self._status_has_wan_speed = "downspeed" in wan or "upspeed" in wan
        if isinstance(wan, dict):
            data[ATTR_SENSOR_WAN_DOWNLOAD_SPEED] = _to_float(wan.get("downspeed"), 0.0) or 0.0
            data[ATTR_SENSOR_WAN_UPLOAD_SPEED] = _to_float(wan.get("upspeed"), 0.0) or 0.0


    async def _async_prepare_vpn(self, data: dict) -> None:
        """Prepare vpn.

        :param data: dict
        """

        with contextlib.suppress(LuciError):
            response: dict = await self.luci.vpn_status()

            data |= {
                ATTR_SENSOR_VPN_UPTIME: 0,
                ATTR_BINARY_SENSOR_VPN_STATE: False,
            }

            if "uptime" in response:
                data |= {
                    ATTR_SENSOR_VPN_UPTIME: str(
                        timedelta(seconds=int(float(response["uptime"])))
                    ),
                    ATTR_BINARY_SENSOR_VPN_STATE: int(float(response["uptime"])) > 0,
                }

    async def _async_prepare_rom_update(self, data: dict) -> None:
        """Prepare rom update.

        CB0401V2 provider firmwares often restrict or disable ROM update checks.
        This must not spam errors nor block refresh.
        """

        if ATTR_UPDATE_CURRENT_VERSION not in data:
            return

        _rom_info: dict = {
            ATTR_UPDATE_CURRENT_VERSION: data[ATTR_UPDATE_CURRENT_VERSION],
            ATTR_UPDATE_LATEST_VERSION: data[ATTR_UPDATE_CURRENT_VERSION],
            ATTR_UPDATE_TITLE: f"{data.get(ATTR_DEVICE_MANUFACTURER, DEFAULT_MANUFACTURER)}"
            + f" {data.get(ATTR_MODEL, Model.NOT_KNOWN).name}"
            + f" ({data.get(ATTR_DEVICE_NAME, DEFAULT_NAME)})",
        }

        # ✅ CB0401V2: skip ROM update endpoint (often 404/restricted on provider firmware)
        if self._is_cb0401v2_device(data):
            data[ATTR_UPDATE_FIRMWARE] = _rom_info
            return

        try:
            response: dict = await asyncio.wait_for(self.luci.rom_update(), timeout=6)
        except (asyncio.TimeoutError, LuciError, LuciConnectionError):
            response = {}
        except Exception:
            response = {}

        if (
            not isinstance(response, dict)
            or response.get("needUpdate") != 1
        ):
            data[ATTR_UPDATE_FIRMWARE] = _rom_info
            return

        # Only set extended info when keys exist and are valid
        payload = {}
        v = response.get("version")
        if isinstance(v, str) and v.strip():
            payload[ATTR_UPDATE_LATEST_VERSION] = v

        durl = response.get("downloadUrl")
        if isinstance(durl, str) and durl.strip():
            payload[ATTR_UPDATE_DOWNLOAD_URL] = durl

        rurl = response.get("changelogUrl")
        if isinstance(rurl, str) and rurl.strip():
            payload[ATTR_UPDATE_RELEASE_URL] = rurl

        fsize = response.get("fileSize")
        if fsize not in ("", None):
            payload[ATTR_UPDATE_FILE_SIZE] = fsize

        fhash = response.get("fullHash")
        if isinstance(fhash, str) and fhash.strip():
            payload[ATTR_UPDATE_FILE_HASH] = fhash

        data[ATTR_UPDATE_FIRMWARE] = _rom_info | payload
        

    async def _async_prepare_mode(self, data: dict) -> None:
        """Prepare mode (safe for CB0401V2/provider firmwares)."""

        # Keep mesh-shortcut behavior
        if data.get(ATTR_SENSOR_MODE, Mode.DEFAULT) == Mode.MESH:
            return

        # Declared access point: the gateway mode probe has nothing to answer,
        # and the node must stop being treated as a gateway. is_repeater reads
        # ATTR_SENSOR_MODE, so this is also what stops the leaf from persisting
        # its own device list and resetting the client counters.
        if self.is_ap_mode:
            data[ATTR_SENSOR_MODE] = Mode.ACCESS_POINT
            await self.hass.async_add_executor_job(
                _LOGGER.debug, "[MiWiFi] AP mode: skipping 'mode'"
            )
            return

        # ✅ CB0401V2: skip mode endpoint (often dead/404 on provider firmware)
        if self._is_cb0401v2_device(data):
            data[ATTR_SENSOR_MODE] = Mode.DEFAULT
            return

        # The topology graph is the authoritative view of the mesh, and a leaf
        # behind a foreign gateway answers `default` here. Take the role from the
        # graph when it has one, and skip a gateway probe the node cannot answer.
        topology_role = self._topology_role()

        # Our own graph is read at the end of a cycle, and on a full restart the
        # main has not read its own yet either: with nothing to go by, a wired
        # leaf would be a gateway for its whole first cycle. Read ours now.
        if topology_role is None and "topo_graph" not in self.data:
            await self._async_prepare_topo()
            topology_role = self._topology_role()

        if topology_role is not None:
            data[ATTR_SENSOR_MODE] = topology_role

            if not self._topology_role_logged:
                self._topology_role_logged = True
                await self.hass.async_add_executor_job(
                    _LOGGER.debug,
                    "[MiWiFi] topology role is %s: skipping the gateway mode probe",
                    topology_role.phrase,
                )

            return

        try:
            response: dict = await asyncio.wait_for(self.luci.mode(), timeout=6)
        except (asyncio.TimeoutError, LuciError, LuciConnectionError):
            data[ATTR_SENSOR_MODE] = Mode.DEFAULT
            return
        except Exception:
            data[ATTR_SENSOR_MODE] = Mode.DEFAULT
            return

        if isinstance(response, dict) and "mode" in response:
            try:
                data[ATTR_SENSOR_MODE] = Mode(int(response["mode"]))
                return
            except Exception:
                data[ATTR_SENSOR_MODE] = Mode.DEFAULT
                return

        data[ATTR_SENSOR_MODE] = Mode.DEFAULT

        
    async def _async_prepare_cpe_mobile(self, data: dict) -> None:
        """Prepare CB0401V2 (5G CPE) data: signal/usage/ipv4 + SIM + SMS."""

        if not self._is_cb0401v2_device(data):
            return

        self._is_cb0401v2 = True
        now = dt_util.utcnow()

        def _to_float(v):
            try:
                if v in ("", None):
                    return None
                return float(str(v))
            except Exception:
                return None

        def _to_int(v):
            try:
                if v in ("", None):
                    return None
                return int(float(str(v)))
            except Exception:
                return None

        # --- 1) mobile_net_info (critical) ---
        if now >= getattr(self, "_cpe_mobile_next_try", now):
            try:
                resp: dict = await asyncio.wait_for(
                    self.luci.get_mobile_net_info(), timeout=6
                )
                if isinstance(resp, dict):
                    data["mobile_net_info"] = resp

                    info = resp.get("info") if isinstance(resp.get("info"), dict) else {}
                    ipv4info = resp.get("ipv4info") if isinstance(resp.get("ipv4info"), dict) else {}

                    data["mobile_info"] = info
                    data["mobile_ipv4info"] = ipv4info

                    # Flat fields (easy sensors later)
                    data["mobile_linktype"] = info.get("linktype")
                    data["mobile_operator"] = info.get("operator")
                    data["mobile_level"] = info.get("level")

                    # Keep raw strings (compat) + normalized numeric (GB/float)
                    data["mobile_datausage"] = info.get("datausage")
                    data["mobile_data_limit"] = info.get("dataLimit")
                    data["mobile_datausage_gb"] = _to_float(info.get("datausage"))
                    data["mobile_datalimit_gb"] = _to_float(info.get("dataLimit"))

                    data["mobile_flowstat_enable"] = info.get("flowstatEnable")

                    # Normalize to float if possible
                    data["mobile_rsrp_5g"] = _to_float(info.get("rsrp_5g"))
                    data["mobile_snr_5g"] = _to_float(info.get("snr_5g"))

                    data["mobile_band_5g"] = info.get("cell_band_5g")
                    data["mobile_band"] = info.get("cell_band")
                    data["mobile_pci_5g"] = info.get("pci_5g")
                    data["mobile_arfcn"] = info.get("arfcn")

                    ipv4_list = ipv4info.get("ipv4") if isinstance(ipv4info.get("ipv4"), list) else []
                    ipv4_0 = ipv4_list[0] if ipv4_list and isinstance(ipv4_list[0], dict) else {}
                    data["mobile_ipv4"] = ipv4_0.get("ip")
                    data["mobile_netmask"] = ipv4_0.get("mask")
                    data["mobile_gw"] = ipv4info.get("gw")
                    data["mobile_dns"] = ipv4info.get("dns")

                self._cpe_mobile_fail_count = 0
                self._cpe_mobile_next_try = now

            except asyncio.TimeoutError:
                self._cpe_mobile_fail_count = int(getattr(self, "_cpe_mobile_fail_count", 0) or 0) + 1
                cooldown = timedelta(minutes=2) if self._cpe_mobile_fail_count < 3 else timedelta(minutes=10)
                self._cpe_mobile_next_try = now + cooldown
                await self.hass.async_add_executor_job(
                    _LOGGER.debug,
                    "[MiWiFi] CB0401V2 mobile_net_info timed out for %s (cooldown %s)",
                    self.ip,
                    cooldown,
                )
            except Exception as e:
                self._cpe_mobile_fail_count = int(getattr(self, "_cpe_mobile_fail_count", 0) or 0) + 1
                cooldown = timedelta(minutes=5)
                self._cpe_mobile_next_try = now + cooldown
                await self.hass.async_add_executor_job(
                    _LOGGER.debug,
                    "[MiWiFi] CB0401V2 mobile_net_info failed for %s (cooldown %s): %s",
                    self.ip,
                    cooldown,
                    e,
                )

        # --- 2) cpe_newstatus (grab MAC if standard status doesn't provide it) ---
        if not data.get(ATTR_DEVICE_MAC_ADDRESS) and now >= getattr(self, "_cpe_newstatus_next_try", now):
            try:
                resp = await asyncio.wait_for(self.luci.cpe_newstatus(), timeout=6)
                if isinstance(resp, dict):
                    hw = resp.get("hardware") if isinstance(resp.get("hardware"), dict) else {}
                    mac = hw.get("mac")
                    if isinstance(mac, str) and mac.strip():
                        data[ATTR_DEVICE_MAC_ADDRESS] = mac.strip().upper()
                    data["cpe_newstatus"] = resp
                self._cpe_newstatus_next_try = now + timedelta(hours=6)
            except Exception:
                self._cpe_newstatus_next_try = now + timedelta(minutes=10)

        # --- 3) cpe_detect (SIM/registration) every ~2 minutes ---
        if now >= getattr(self, "_cpe_detect_next_try", now):
            try:
                resp = await asyncio.wait_for(self.luci.cpe_detect(), timeout=6)
                if isinstance(resp, dict):
                    data["cpe_detect"] = resp

                    # Flatten SIM fields for easy sensors
                    sim = resp.get("sim") if isinstance(resp.get("sim"), dict) else {}
                    if isinstance(sim, dict):
                        data["sim_status"] = _to_int(sim.get("status"))
                        data["sim_pinlock"] = _to_int(sim.get("pinlock"))
                        data["sim_pinretry"] = _to_int(sim.get("pinretry"))
                        data["sim_pukretry"] = _to_int(sim.get("pukretry"))

                    # Optional fallback for operator/linktype if mobile_net_info missing
                    net_info = (
                        resp.get("net", {}).get("info")
                        if isinstance(resp.get("net"), dict)
                        else {}
                    )
                    if isinstance(net_info, dict):
                        if not data.get("mobile_linktype"):
                            data["mobile_linktype"] = net_info.get("linktype")
                        if not data.get("mobile_operator"):
                            data["mobile_operator"] = net_info.get("operator")

                self._cpe_detect_next_try = now + timedelta(minutes=2)
            except Exception:
                self._cpe_detect_next_try = now + timedelta(minutes=10)

        # --- 4) SMS count every ~2 minutes ---
        if now >= getattr(self, "_sms_next_try", now):
            try:
                resp = await asyncio.wait_for(self.luci.msgbox_count(), timeout=6)
                if isinstance(resp, dict):
                    data["sms"] = resp

                    # Try to derive a flat sms_count
                    sms_count = None
                    for cand in ("count", "total", "msg_count", "sms_count"):
                        if cand in resp:
                            sms_count = _to_int(resp.get(cand))
                            if sms_count is not None:
                                break
                    if sms_count is None and isinstance(resp.get("data"), dict):
                        sms_count = _to_int(resp["data"].get("count"))

                    if sms_count is not None:
                        data["sms_count"] = sms_count

                self._sms_next_try = now + timedelta(minutes=2)
            except Exception:
                self._sms_next_try = now + timedelta(minutes=10)


    async def _async_prepare_wan(self, data: dict) -> None:
        """Prepare WAN state, link status, IP address and type."""

        def _get(d: dict, *keys, default=None):
            for k in keys:
                if isinstance(d, dict) and k in d:
                    return d.get(k)
            return default

        def _first_nonempty(*vals):
            for v in vals:
                if isinstance(v, str) and v.strip():
                    return v.strip()
                if v not in (None, "", [], {}):
                    return v
            return None

        if self.is_ap_mode:
            # wan_info is not asked, so what only it tells is unknown, not a
            # WAN that is down. The speed sensors read misystem/status instead
            # (see supports_wan).
            data[ATTR_BINARY_SENSOR_WAN_STATE] = None
            data[ATTR_BINARY_SENSOR_WAN_LINK] = None
            data[ATTR_SENSOR_WAN_IP] = None
            data[ATTR_SENSOR_WAN_TYPE] = None
            await self.hass.async_add_executor_job(
                _LOGGER.debug, "[MiWiFi] AP mode: skipping 'wan'"
            )
            return

        try:
            response: dict = await asyncio.wait_for(self.luci.wan_info(), timeout=6)

            # --- sanitize secrets for logs (do NOT mutate original response) ---
            safe = response
            try:
                if isinstance(response, dict):
                    safe = dict(response)
                    info_safe = dict(safe.get("info") or {}) if isinstance(safe.get("info"), dict) else {}
                    details_safe = dict(info_safe.get("details") or {}) if isinstance(info_safe.get("details"), dict) else {}

                    # mask common secret fields
                    for k in ("password", "passwd", "pppoe_passwd", "token", "stok", "key"):
                        if k in details_safe and details_safe[k]:
                            details_safe[k] = "***"

                    info_safe["details"] = details_safe
                    safe["info"] = info_safe
            except Exception:
                # if anything goes wrong, just don't break WAN processing
                safe = {"_log_sanitize": "failed"}

            await self.hass.async_add_executor_job(_LOGGER.debug, "WAN info response: %s", safe)
            # --- end sanitize ---

            info = response.get("info") if isinstance(response, dict) else {}
            if not isinstance(info, dict):
                info = {}

            link = int(_get(info, "link", default=0) or 0)
            status = int(_get(info, "status", "estado", default=0) or 0)

            details = info.get("details") if isinstance(info.get("details"), dict) else {}
            wan_type = _get(details, "wanType", default="unknown") or "unknown"

            # IP fallback (PPPoE firmwares can put it outside ipv4[0].ip)
            ipv4_list = info.get("ipv4", [])
            ipv4_0 = ipv4_list[0] if isinstance(ipv4_list, list) and ipv4_list and isinstance(ipv4_list[0], dict) else {}

            ip = _first_nonempty(
                _get(ipv4_0, "ip"),
                _get(info, "ip"),
                _get(info, "wan_ip"),
                _get(info, "pppoe_ip"),
                _get(details, "ip"),
                _get(details, "pppoe_ip"),
            )

            gateway = _first_nonempty(_get(info, "gateWay"), _get(info, "gateway"))
            dns = _first_nonempty(_get(info, "dnsAddrs"), _get(info, "dnsAddrs1"))

            # ✅ WAN DOWN solo si TODO está realmente vacío y además flags dicen down
            wan_down = (link == 0 and status == 0 and not ip and not gateway and not dns)

            if wan_down:
                # ✅ CB0401V2: fallback to mobile_ipv4 if available
                if self._is_cb0401v2_device(data):
                    mobile_ip = data.get("mobile_ipv4")
                    if isinstance(mobile_ip, str) and mobile_ip.strip():
                        data[ATTR_BINARY_SENSOR_WAN_STATE] = True
                        data[ATTR_BINARY_SENSOR_WAN_LINK] = True
                        data[ATTR_SENSOR_WAN_IP] = mobile_ip.strip()
                        data[ATTR_SENSOR_WAN_TYPE] = "mobile"
                        return

                data[ATTR_BINARY_SENSOR_WAN_STATE] = False
                data[ATTR_BINARY_SENSOR_WAN_LINK] = False
                data[ATTR_SENSOR_WAN_IP] = None
                data[ATTR_SENSOR_WAN_TYPE] = wan_type
                return

            # WAN UP (o al menos usable)
            data[ATTR_BINARY_SENSOR_WAN_STATE] = True
            data[ATTR_BINARY_SENSOR_WAN_LINK] = (link == 1 or status == 1)
            data[ATTR_SENSOR_WAN_IP] = ip
            data[ATTR_SENSOR_WAN_TYPE] = wan_type

        except asyncio.TimeoutError:
            await self.hass.async_add_executor_job(
                _LOGGER.debug,
                "[MiWiFi] WAN info timed out for %s (skipping this cycle)",
                self.ip,
            )
            data[ATTR_BINARY_SENSOR_WAN_STATE] = False
            data[ATTR_BINARY_SENSOR_WAN_LINK] = False
            data[ATTR_SENSOR_WAN_IP] = None
            data[ATTR_SENSOR_WAN_TYPE] = "unknown"
            if self._is_cb0401v2_device(data):
                mobile_ip = data.get("mobile_ipv4")
                if isinstance(mobile_ip, str) and mobile_ip.strip():
                    data[ATTR_BINARY_SENSOR_WAN_STATE] = True
                    data[ATTR_BINARY_SENSOR_WAN_LINK] = True
                    data[ATTR_SENSOR_WAN_IP] = mobile_ip.strip()
                    data[ATTR_SENSOR_WAN_TYPE] = "mobile"

        # LuciError derives from BaseException: without naming it here a WAN
        # failure escaped this handler and aborted the whole update cycle, so
        # every prepare step after "wan" (devices included) was skipped.
        except (Exception, LuciError) as e:
            await self.hass.async_add_executor_job(_LOGGER.error, "Error while preparing WAN info: %s", e)
            data[ATTR_BINARY_SENSOR_WAN_STATE] = False
            data[ATTR_BINARY_SENSOR_WAN_LINK] = False
            data[ATTR_SENSOR_WAN_IP] = None
            data[ATTR_SENSOR_WAN_TYPE] = "unknown"
            if self._is_cb0401v2_device(data):
                mobile_ip = data.get("mobile_ipv4")
                if isinstance(mobile_ip, str) and mobile_ip.strip():
                    data[ATTR_BINARY_SENSOR_WAN_STATE] = True
                    data[ATTR_BINARY_SENSOR_WAN_LINK] = True
                    data[ATTR_SENSOR_WAN_IP] = mobile_ip.strip()
                    data[ATTR_SENSOR_WAN_TYPE] = "mobile"

    async def _async_prepare_multiwan(self, data: dict) -> None:
        """Read RD08 WAN2 independently of the primary WAN and client census."""
        from .multiwan import is_rd08, parse_service, parse_wan2

        data["multiwan"] = {}
        if not is_rd08(data) or self.is_repeater:
            self._multiwan_enabled = None
            self._multiwan_next_try = 0
            return

        now = monotonic()
        enabled = getattr(self, "_multiwan_enabled", None)
        if now >= getattr(self, "_multiwan_next_try", 0):
            # Cache capability checks, including failures, to avoid repeatedly
            # probing restricted endpoints. WAN2 itself refreshes every cycle.
            self._multiwan_next_try = now + 300
            try:
                enabled = parse_service(await asyncio.wait_for(
                    self.luci.multiwan_info(), timeout=6,
                ))
            except (Exception, LuciError):
                enabled = None
            self._multiwan_enabled = enabled

        if enabled is None:
            return
        data["multiwan"] = {"enabled": enabled, "wan2": None}
        if not enabled:
            return
        try:
            data["multiwan"]["wan2"] = parse_wan2(await asyncio.wait_for(
                self.luci.wan_info("WAN2"), timeout=6,
            ))
        except (Exception, LuciError):
            # Do not retain an old address/status or mark WAN1 offline.
            # Deliberately do not log response bodies or session URLs.
            return

    async def _async_prepare_led(self, data: dict) -> None:
        """Prepare led.

        CB0401V2 provider firmwares often return empty/non-JSON payloads for LED endpoints.
        LED must NEVER break setup or refresh cycles.
        """

        # ✅ CB0401V2: skip LED endpoint entirely (commonly restricted / non-JSON)
        if self._is_cb0401v2_device(data):
            data[ATTR_LIGHT_LED] = False
            return

        try:
            response: dict = await asyncio.wait_for(self.luci.led(), timeout=6)
        except asyncio.TimeoutError as e:
            await self.hass.async_add_executor_job(
                _LOGGER.debug,
                "[MiWiFi] led() timed out for %s: %s",
                self.ip,
                e,
            )
            data[ATTR_LIGHT_LED] = False
            return
        except LuciError as e:
            await self.hass.async_add_executor_job(
                _LOGGER.debug,
                "[MiWiFi] led() failed/unsupported for %s: %s",
                self.ip,
                e,
            )
            data[ATTR_LIGHT_LED] = False
            return
        except Exception as e:
            await self.hass.async_add_executor_job(
                _LOGGER.debug,
                "[MiWiFi] led() unexpected error for %s: %s",
                self.ip,
                e,
            )
            data[ATTR_LIGHT_LED] = False
            return

        if isinstance(response, dict) and "status" in response:
            try:
                data[ATTR_LIGHT_LED] = int(response["status"]) == 1
                return
            except Exception:
                pass

        data[ATTR_LIGHT_LED] = False


    async def _async_prepare_wifi(self, data: dict) -> None:
        """Prepare wifi.

        :param data: dict
        """

        try:
            response: dict = await self.luci.wifi_detail_all()
        except LuciError:
            return

        # fmt: off
        data[ATTR_BINARY_SENSOR_DUAL_BAND] = int(response["bsd"]) == 1 \
            if "bsd" in response else False
        # fmt: on

        if "info" not in response or len(response["info"]) == 0:
            return

        _adapters: list = await self._async_prepare_wifi_guest(response["info"])

        length: int = 0
        _mapped: list[str] = []
        _skipped: list[str] = []
        _no_channel: list[IfName] = []

        # Support only 5G , 2.4G, 5G Game and Guest
        for wifi in _adapters:
            if "ifname" not in wifi:
                continue

            try:
                adapter: IfName = IfName(wifi["ifname"])
            except ValueError:
                _skipped.append(str(wifi["ifname"]))
                continue

            _mapped.append(str(wifi["ifname"]))

            # Guest network is not an adapter
            if adapter != IfName.WL14:
                length += 1

            if "status" in wifi:
                data[adapter.phrase] = int(wifi["status"]) > 0  # type: ignore

            if _channel_of(wifi) is not None:
                data[f"{adapter.phrase}_channel"] = _channel_of(wifi)  # type: ignore
            elif adapter != IfName.WL14:
                # The RA82 leaves answer wifi_detail_all with an adapter that
                # carries power and status but no channel at all, which left the
                # channel picker sitting there reading `unknown`.
                _no_channel.append(adapter)

            if "bandwidth" in wifi:
                data[f"{adapter.phrase}_bandwidth"] = str(wifi["bandwidth"])  # type: ignore

            if "txpwr" in wifi:
                data[f"{adapter.phrase}_signal_strength"] = wifi["txpwr"]  # type: ignore

            if wifi_data := self._prepare_wifi_data(wifi):
                data[f"{adapter.phrase}_data"] = wifi_data  # type: ignore

        data[ATTR_WIFI_ADAPTER_LENGTH] = length

        _filled: list[str] = await self._async_fill_missing_channels(data, _no_channel)

        # Report the picture once, and again whenever it changes: a radio that
        # never shows up is the difference between a node with a 5G switch and a
        # node without one, and a band with no channel is the difference between
        # a channel picker you can use and one that reads `unknown`.
        _fingerprint: tuple = (
            tuple(_mapped),
            tuple(_skipped),
            tuple(a.value for a in _no_channel),
            tuple(_filled),
        )
        if _fingerprint != self._wifi_adapters_logged:
            self._wifi_adapters_logged = _fingerprint
            await self.hass.async_add_executor_job(
                _LOGGER.debug,
                "[MiWiFi] wifi adapters for %s: mapped %s, skipped %s,"
                " no channel reported %s, filled from diagnostics %s",
                self.ip,
                _mapped or "none",
                _skipped or "none",
                [a.value for a in _no_channel] or "none",
                _filled or "none",
            )

    async def _async_fill_missing_channels(
        self, data: dict, adapters: list[IfName]
    ) -> list[str]:
        """Ask the diagnostics endpoint for channels the detail one omitted.

        `xqnetwork/wifi_detail_all` and `xqnetwork/wifi_diag_detail_all` are
        complementary - the panel's own `ws_api.websocket_get_wifis` merges both
        for exactly this reason - but the updater only ever read the first, and
        touched the second solely to find the guest network. On the RA82 leaves
        that costs the 5 GHz channel: the adapter is there, with power and
        status, and no channel at all.

        Only called with a gap to fill. An ask that recovers nothing is not
        repeated every cycle: the wait before the next one doubles with each
        miss in a row, from WIFI_DIAG_RETRY_FIRST up to WIFI_DIAG_RETRY_MAX, and
        the first recovered channel resets it. It is never given up for good,
        because a miss proves nothing lasting: a timeout or a radio restarting
        (channel 0 or absent) clears up on its own, and a firmware without the
        endpoint cannot be told apart from a timeout - its error page fails to
        parse and arrives as the same LuciConnectionError. So a node that never
        publishes its channel costs a request an hour, and a transient miss is
        recovered a minute later without reloading the entry.

        :param data: dict: the data being prepared, updated in place
        :param adapters: list[IfName]: adapters that reported no channel
        :return list[str]: the ifnames whose channel was recovered
        """

        now: datetime = dt_util.utcnow()

        if not adapters or now < self._wifi_diag_next_try:
            return []

        try:
            response: dict = await self.luci.wifi_diag_detail_all()
        except LuciError as _e:
            self._wifi_diag_missed(now)
            await self.hass.async_add_executor_job(
                _LOGGER.debug,
                "[MiWiFi] wifi_diag_detail_all unavailable for %s: %s",
                self.ip,
                _e,
            )
            return []

        by_ifname: dict[str, dict] = {
            entry["ifname"]: entry
            for entry in (response.get("info") or [])
            if isinstance(entry, dict) and "ifname" in entry
        }

        filled: list[str] = []

        for adapter in adapters:
            channel = _channel_of(by_ifname.get(adapter.value) or {})
            if channel is None:
                continue

            data[f"{adapter.phrase}_channel"] = channel  # type: ignore

            # The selects and switches read their availability from this dict,
            # so it has to learn the channel too or the picker stays hidden.
            wifi_data = data.get(f"{adapter.phrase}_data")  # type: ignore
            if isinstance(wifi_data, dict):
                wifi_data["channel"] = channel

            filled.append(adapter.value)

        if filled:
            self._wifi_diag_misses = 0
            self._wifi_diag_next_try = now
        else:
            self._wifi_diag_missed(now)

        return filled

    def _wifi_diag_missed(self, now: datetime) -> None:
        """Push the next diagnostics ask back after one that recovered nothing.

        :param now: datetime: when the ask was made
        """

        self._wifi_diag_misses += 1
        # The exponent is capped too: misses keep counting for as long as the
        # node runs, and the wait stops growing long before that.
        wait: timedelta = WIFI_DIAG_RETRY_FIRST * 2 ** min(self._wifi_diag_misses - 1, 12)
        self._wifi_diag_next_try = now + min(wait, WIFI_DIAG_RETRY_MAX)

    async def _async_prepare_wifi_guest(self, adapters: list) -> list:
        """Prepare wifi guest.

        :param adapters: list
        :return list: adapters
        """

        if not self.supports_guest:  # pragma: no cover
            return adapters

        self.supports_guest = False

        with contextlib.suppress(LuciError):
            response_diag = await self.luci.wifi_diag_detail_all()
            _adapters_len: int = len(adapters)

            if "info" in response_diag:
                adapters += [
                    _adapter
                    for _adapter in response_diag["info"]
                    if "ifname" in _adapter and _adapter["ifname"] == IfName.WL14.value
                ]

            if _adapters_len < len(adapters):
                self.supports_guest = True

        return adapters

    @staticmethod
    def _prepare_wifi_data(data: dict) -> dict:
        """Prepare wifi data

        :param data:
        :return: dict: wifi data
        
        
        """

        wifi_data: dict = {}

        for data_field, field in ATTR_WIFI_DATA_FIELDS.items():
            if data_field.startswith("channelInfo."):
                channel_info = data.get("channelInfo")
                nested_field = data_field.removeprefix("channelInfo.")
                if isinstance(channel_info, dict) and nested_field in channel_info:
                    wifi_data[field] = channel_info[nested_field]
            elif data_field in data and field not in wifi_data:
                # Provider firmware may only expose these fields at the top
                # level. Keep the same nested-value precedence as the read path.
                wifi_data[field] = data[data_field]

        return wifi_data

    async def _async_prepare_channels(self, data: dict) -> None:
        """Prepare channels.

        :param data: dict
        """

        if not self._is_first_update or ATTR_WIFI_ADAPTER_LENGTH not in data:
            return

        for index in range(1, data.get(ATTR_WIFI_ADAPTER_LENGTH, 2) + 1):
            try:
                response: dict = await self.luci.avaliable_channels(index)
            except LuciError as _e:
                # LuciError derives from BaseException: unhandled, it escapes the
                # prepare loop and takes every later step of the cycle with it -
                # here devices, device_list, device_restore, ap and new_status.
                await self.hass.async_add_executor_job(
                    _LOGGER.debug,
                    "[MiWiFi] channels unavailable (adapter %s): %s",
                    index,
                    type(_e).__name__,
                )
                continue

            if "list" not in response or len(response["list"]) == 0:
                continue

            data[f"{Wifi(index).phrase}_channels"] = [  # type: ignore
                str(channel["c"])
                for channel in response["list"]
                if "c" in channel and int(channel["c"]) > 0
            ]

    async def _async_prepare_devices(self, data: dict) -> None:
        """Prepare devices."""

        # En nodos mesh force_load, el conteo agregado lo gobierna el router principal
        # vía device_list + parent. No resetees aquí o dejarás el leaf a 0 entre pushes.
        if not (self.is_repeater and self.is_force_load):
            self.reset_counter()

        response: dict = await self.luci.wifi_connect_devices()
        trace = getattr(self, "_mesh_trace", None)
        if trace is not None:
            trace.census(response, {}, source="xqnetwork/wifi_connect_devices")

        # A fresh successful Wi-Fi census must not retain obsolete signals.
        self._signals.clear()
        now = dt_util.utcnow()
        macfilter_info: Optional[dict] = None

        # cooldown: si falló hace poco, no insistimos cada scan
        next_try = getattr(self, "_macfilter_next_try", now)
        # MAC filtering lives on the gateway, never on an access point node.
        if self.is_ap_mode:
            await self.hass.async_add_executor_job(
                _LOGGER.debug, "[MiWiFi] AP mode: skipping macfilter_info"
            )
        elif now >= next_try:
            call_timeout = self._macfilter_call_timeout()
            try:
                # Usa timeout real del request (httpx) y evita doble timeout agresivo
                macfilter_info = await self.luci.macfilter_info(timeout=call_timeout)
                self._macfilter_fail_count = 0
                self._macfilter_next_try = now  # sin cooldown en éxito

            except (asyncio.TimeoutError, LuciConnectionError) as e:
                self._macfilter_fail_count = int(getattr(self, "_macfilter_fail_count", 0) or 0) + 1
                cooldown = timedelta(minutes=10) if self._macfilter_fail_count < 3 else timedelta(minutes=30)
                self._macfilter_next_try = now + cooldown

                # rate-limit: 1 warning / hora
                last_warn = getattr(self, "_macfilter_warned_at", None)
                if (last_warn is None) or (now - last_warn > timedelta(hours=1)):
                    _LOGGER.warning(
                        "[MiWiFi] macfilter_info timed out for %s (cooldown %s, fail_count=%s): %s",
                        self.ip,
                        cooldown,
                        self._macfilter_fail_count,
                        e,
                    )
                    self._macfilter_warned_at = now
                else:
                    _LOGGER.debug("[MiWiFi] macfilter_info timed out for %s: %s", self.ip, e)

            except (LuciRequestError, LuciError) as e:
                # Si el endpoint no existe / no está soportado, no tiene sentido insistir
                self._macfilter_fail_count = int(getattr(self, "_macfilter_fail_count", 0) or 0) + 1
                self._macfilter_next_try = now + timedelta(hours=6)

                last_warn = getattr(self, "_macfilter_warned_at", None)
                if (last_warn is None) or (now - last_warn > timedelta(hours=6)):
                    _LOGGER.warning(
                        "[MiWiFi] macfilter_info not available for %s (cooldown 6h): %s",
                        self.ip,
                        e,
                    )
                    self._macfilter_warned_at = now
                else:
                    _LOGGER.debug("[MiWiFi] macfilter_info not available for %s: %s", self.ip, e)

            except Exception as e:
                # hard fallback: no romper devices por esto
                self._macfilter_fail_count = int(getattr(self, "_macfilter_fail_count", 0) or 0) + 1
                self._macfilter_next_try = now + timedelta(minutes=30)
                last_warn = getattr(self, "_macfilter_warned_at", None)
                if (last_warn is None) or (now - last_warn > timedelta(hours=1)):
                    _LOGGER.warning("[MiWiFi] macfilter_info failed for %s (cooldown 30m): %s", self.ip, e)
                    self._macfilter_warned_at = now
                else:
                    _LOGGER.debug("[MiWiFi] macfilter_info failed for %s: %s", self.ip, e)

        # ✅ Cache: si no hubo éxito, usamos el último mapa válido
        filter_macs: dict[str, int] = getattr(self, "_filter_macs", {}) or {}

        # ✅ Si hemos obtenido datos nuevos, reconstruimos y guardamos
        if isinstance(macfilter_info, dict):
            new_filter_macs: dict[str, int] = {}

            for entry in macfilter_info.get("flist", []) or []:
                if not isinstance(entry, dict):
                    continue
                mac = str(entry.get("mac", "")).upper()
                wan = (entry.get("authority") or {}).get("wan", 1)
                new_filter_macs[mac] = wan

            for entry in macfilter_info.get("list", []) or []:
                if not isinstance(entry, dict):
                    continue
                mac = str(entry.get("mac", "")).upper()
                wan = (entry.get("authority") or {}).get("wan", 1)
                new_filter_macs[mac] = wan

            self._filter_macs = new_filter_macs
            filter_macs = new_filter_macs

        if "list" in response:
            integrations: dict[str, dict] = {}
            node_macs: set[str] = set()

            if self.is_repeater and self.is_force_load:
                integrations = async_get_integrations(self.hass)
                node_macs, _ = _known_mesh_nodes(self.hass)

            for device in response["list"]:
                if not isinstance(device, dict):
                    continue
                mac = device.get(ATTR_TRACKER_MAC)
                if not isinstance(mac, str) or not mac.strip():
                    continue
                mac = mac.strip().upper()

                if mac in node_macs:
                    self._forget_mesh_node(mac, integrations)
                    continue

                self._signals[mac] = device.get("signal")

                if mac in self.devices:
                    self.devices[mac][ATTR_TRACKER_LAST_ACTIVITY] = (
                        datetime.now().replace(microsecond=0).isoformat()
                    )

                if mac in filter_macs:
                    device[ATTR_TRACKER_INTERNET_BLOCKED] = (filter_macs[mac] == 0)
                else:
                    device[ATTR_TRACKER_INTERNET_BLOCKED] = False

                if self.is_repeater and self.is_force_load:
                    device |= {
                        ATTR_TRACKER_ENTRY_ID: self._entry_id,
                        ATTR_TRACKER_UPDATER_ENTRY_ID: self._entry_id,
                    }

                    action: DeviceAction = DeviceAction.ADD
                    if self._mass_update_device(device, integrations):
                        action = DeviceAction.SKIP

                    if ATTR_TRACKER_MAC in device:
                        await self.add_device(device, action=action)


    async def _async_record_backhaul_aliases(
        self, integrations: dict, ap_macs: dict[str, str], mac_to_ip: dict[str, str]
    ) -> None:
        """Let a node be found by the MAC this device list names it with.

        Clients are routed by that MAC already (`mac_to_ip`); nothing else knew
        it. The node keeps it, so client attributes can name the node, and its
        device row gets it as a connection, so "Connected via" can point at it.
        A MAC that already belongs to another node is left alone.

        :param integrations: dict: loaded entries by IP
        :param ap_macs: dict[str, str]: listed node MACs by IP
        :param mac_to_ip: dict[str, str]: routing map built from both
        """

        from .helper import async_register_backhaul_alias

        for ip, integration in integrations.items():
            updater = integration.get(UPDATER)
            backhaul = ap_macs.get(ip)
            if not isinstance(updater, LuciUpdater) or not backhaul:
                continue

            own = str((updater.data or {}).get(ATTR_DEVICE_MAC_ADDRESS) or "").strip().upper()
            if not own or backhaul == own or mac_to_ip.get(backhaul) != ip:
                continue

            updater.backhaul_mac = backhaul

            entry_id = integration.get(ATTR_TRACKER_ENTRY_ID)
            if not entry_id or backhaul in self._backhaul_alias_skipped:
                continue

            outcome = async_register_backhaul_alias(self.hass, entry_id, own, backhaul)
            if outcome == "added":
                await self.hass.async_add_executor_job(
                    _LOGGER.debug,
                    "[MiWiFi] %s is listed by its mesh under a second MAC;"
                    " recorded it on the node's device",
                    ip,
                )
            elif outcome == "taken":
                # Not retried every cycle: only the purge of a node's client
                # row, `_purge_pending_mesh_nodes`, frees the MAC again and
                # clears the skip on every loaded updater.
                self._backhaul_alias_skipped.add(backhaul)
                await self.hass.async_add_executor_job(
                    _LOGGER.debug,
                    "[MiWiFi] %s: its second MAC already belongs to another"
                    " device; clients are still linked through the node itself",
                    ip,
                )

    async def _async_prepare_device_list(self, data: dict) -> None:
        """Prepare MiWiFi device list (api/misystem/devicelist)."""

        try:
            response: dict = await self.luci.device_list()
        except LuciError as _e:
            # Losing the client list must not also cost us device_restore, ap and
            # new_status: a node that is really gone already failed at status.
            # With force load, the radio list refreshes its clients again.
            self._device_list_macs = frozenset()
            await self.hass.async_add_executor_job(
                _LOGGER.debug,
                "[MiWiFi] device_list unavailable (%s)",
                type(_e).__name__,
            )
            return

        await asyncio.sleep(DEFAULT_CALL_DELAY)

        # Enrich only the existing active census, never create or remove clients
        # from device_list: its schema and offline records differ by firmware.
        details_by_mac: dict[str, dict] = {}
        detail_reader = getattr(self.luci, "client_details", None)
        if callable(detail_reader) and monotonic() >= getattr(self, "_client_details_retry_at", 0):
            try:
                payload = await detail_reader()
                if not isinstance(payload, dict) or payload.get("code", 0) != 0 or not isinstance(payload.get("devices"), list):
                    self._client_details_retry_at = monotonic() + 3600
                else:
                    for row in payload["devices"]:
                        if not isinstance(row, dict) or row.get("online") not in (1, "1"):
                            continue
                        mac = row.get("mac")
                        if isinstance(mac, str) and mac.strip():
                            details_by_mac[mac.strip().upper()] = row
            except (LuciConnectionError, asyncio.TimeoutError):
                self._client_details_retry_at = monotonic() + 60
                _LOGGER.debug("[MiWiFi] extended client metrics temporarily unavailable")
            except (LuciError, Exception):
                self._client_details_retry_at = monotonic() + 3600
                _LOGGER.debug("[MiWiFi] extended client metrics unavailable; using legacy census")

        integrations = async_get_integrations(self.hass)

        # Capture the complete list before routing mutates individual records.
        replacement_clients = [dict(row) for row in response.get("list", []) if isinstance(row, dict)]

        # Register both the entry MAC and the backhaul MAC used in `parent`.
        ap_macs = _ap_macs_by_ip(response)
        mac_to_ip: dict[str, str] = {}
        for ip, integration in integrations.items():
            updater = integration.get(UPDATER)
            if isinstance(updater, LuciUpdater):
                mac = (updater.data or {}).get(ATTR_DEVICE_MAC_ADDRESS)
                if isinstance(mac, str) and mac:
                    mac_to_ip[mac.strip().upper()] = ip
                if (backhaul := ap_macs.get(ip)) and backhaul not in mac_to_ip:
                    mac_to_ip[backhaul] = ip

        await self._async_record_backhaul_aliases(integrations, ap_macs, mac_to_ip)

        trace = getattr(self, "_mesh_trace", None)
        if trace is not None:
            trace.census(response, mac_to_ip)

        node_macs, node_ips = _known_mesh_nodes(self.hass)
        node_macs |= set(mac_to_ip)
        reported_nodes: set[str] = set()

        # Collect devices that should be pushed to a leaf updater (key = integration IP)
        add_to: dict[str, list[dict]] = {}
        listed: set[str] = set()

        for device in response.get("list", []):
            if not isinstance(device, dict):
                continue

            mac = device.get(ATTR_TRACKER_MAC)
            if not isinstance(mac, str) or not mac.strip():
                continue
            device[ATTR_TRACKER_MAC] = mac.strip().upper()

            # Keep the reporting router's interpretation when this raw record
            # is pushed to a leaf with a different firmware/model schema.
            device.pop("_miwifi_connection", None)
            device["_miwifi_connection"] = self._resolve_connection(device)

            # Skip mesh/AP nodes from client counters and trackers
            try:
                if int(device.get("isap", 0) or 0) > 0:
                    if node_mac := str(device.get("mac") or "").strip().upper():
                        reported_nodes.add(node_mac)
                    continue
            except Exception:
                pass

            # Use only ACTIVE IP entry (avoid stale/offline snapshots causing flapping)
            ip_list = device.get("ip") if isinstance(device.get("ip"), list) else []
            active_ip = next(
                (
                    x
                    for x in ip_list
                    if isinstance(x, dict) and int(x.get("active", 0) or 0) == 1
                ),
                None,
            )
            if not active_ip:
                continue

            # A mesh node can also be listed with isap 0, e.g. while it rejoins
            # the mesh. It is still a node, not a client.
            mac_u = str(device.get(ATTR_TRACKER_MAC, "") or "").strip().upper()
            if mac_u in node_macs or active_ip.get("ip") in node_ips:
                self._forget_mesh_node(mac_u, integrations)
                continue

            # Metrics travel with the record when the main forwards it to a
            # leaf. A conflicting parent/IP is a roaming snapshot, not a match.
            detail = details_by_mac.get(mac_u, {})
            if detail and (
                str(detail.get("parent") or "").strip().upper() != str(device.get("parent") or "").strip().upper()
                or detail.get("ip") != active_ip.get("ip")
            ):
                detail = {}
            device["_miwifi_details"] = detail

            # Keep only the active IP entry
            device["ip"] = [active_ip]

            # ✅ WAN access (devicelist reports authority.wan: 0=blocked, 1=allowed)
            # Keep tracker attribute consistent across refreshes/screens.
            try:
                auth = device.get("authority")
                if isinstance(auth, dict) and "wan" in auth:
                    wan = auth.get("wan", 1)
                    device[ATTR_TRACKER_INTERNET_BLOCKED] = int(wan or 0) == 0

                    # Keep local cache consistent for other paths (macfilter cooldown/timeouts)
                    fm = getattr(self, "_filter_macs", None)
                    mac_u = str(device.get(ATTR_TRACKER_MAC, "") or "").strip().upper()
                    if isinstance(fm, dict) and mac_u:
                        fm[mac_u] = 0 if device[ATTR_TRACKER_INTERNET_BLOCKED] else 1
            except Exception:
                pass

            parent_mac = device.get("parent")
            parent_mac = parent_mac.strip().upper() if isinstance(parent_mac, str) else ""

            if parent_mac and parent_mac in mac_to_ip:
                # ✅ If this client now belongs to a leaf node, remove any stale
                # local copy from the current updater immediately.
                mac_u = str(device.get(ATTR_TRACKER_MAC, "") or "").strip().upper()
                if mac_u and mac_u in self.devices:
                    del self.devices[mac_u]
                    with contextlib.suppress(ValueError):
                        self._moved_devices.remove(mac_u)

                target_ip = mac_to_ip[parent_mac]
                add_to.setdefault(target_ip, []).append(device)
                continue

            # Otherwise, belongs to THIS updater (main/current)
            device.setdefault(ATTR_TRACKER_ENTRY_ID, self._entry_id)
            device.setdefault(ATTR_TRACKER_UPDATER_ENTRY_ID, self._entry_id)

            mac = device.get("mac", "").upper()

            # Refresh last_activity only when seen online this cycle
            if mac and mac in self.devices:
                self.devices[mac][ATTR_TRACKER_LAST_ACTIVITY] = datetime.now().replace(
                    microsecond=0
                ).isoformat()

            action: DeviceAction = DeviceAction.ADD
            if self._mass_update_device(device, integrations):
                action = DeviceAction.SKIP

            if ATTR_TRACKER_MAC in device:
                listed.add(device[ATTR_TRACKER_MAC])
                await self.add_device(device, action=action)

        self._device_list_macs = frozenset(listed)

        for mac in _remember_mesh_node_macs(self.hass, reported_nodes):
            self._forget_mesh_node(mac, integrations)

        # A node may still have a client tracker and sensors from an earlier
        # cycle or a device store. Purge them once per session, but not during
        # the first refresh: it runs before the platforms are set up.
        if not self._is_first_update:
            self._purge_pending_mesh_nodes(integrations)

        # No client of our own this cycle. A leaf keeps what the main pushed in,
        # but a node no other node lists as a leaf - e.g. the main of a mesh in
        # access point mode - has nobody to push its counters: zero is the count.
        if (
            self._counters_pushed_by_parent
            and not self._counters_reset_this_cycle
            and not self._parent_push_pending
            and self._leaf_entry_from_other_nodes() is None
        ):
            self.reset_counter(is_force=True)

        # Push per-leaf device list to each leaf updater
        for ip, devices in add_to.items():
            integration = integrations.get(ip)
            if not integration:
                continue

            updater = integration.get(UPDATER)
            if not isinstance(updater, LuciUpdater):
                continue

            # ✅ Reset counters ONCE per parent refresh before recounting -
            # unless the leaf counts its own clients: add_device() does not
            # recount for it, so a reset would leave zero until its next refresh.
            if not updater._counts_own_clients:
                updater._parent_push_pending = True
                updater.reset_counter(is_force=True)

            leaf_entry_id = getattr(updater, "_entry_id", None) or self._entry_id

            for device in devices:
                if not isinstance(device, dict):
                    continue

                # Ensure required keys for _build_device() exist on leaf side too
                device.setdefault(ATTR_TRACKER_ENTRY_ID, leaf_entry_id)
                device.setdefault(ATTR_TRACKER_UPDATER_ENTRY_ID, leaf_entry_id)

                await updater.add_device(
                    device,
                    is_from_parent=True,
                    action=DeviceAction.ADD,
                )
            updater._parent_census_at = monotonic()
            updater._parent_census_source = self
            # A client stays the parent's for the window after the last push
            # that had it (see add_device): a census can miss a client the
            # next one has again, and a node that lists clients under itself
            # also pushes to itself. Kept while the node has a record of it.
            updater._parent_census_clients = {
                mac: census
                for mac, census in getattr(updater, "_parent_census_clients", {}).items()
                if mac in updater.devices
            } | dict.fromkeys(
                (row[ATTR_TRACKER_MAC] for row in devices),
                (self, updater._parent_census_at),
            )
            trace = getattr(updater, "_mesh_trace", None)
            if trace is not None:
                trace.event("parent_push_complete", updater.data,
                            source_ip=self.ip, pushed_clients=len(devices))

        if isinstance(response.get("list"), list) and response.get("code", 0) == 0:
            # A node whose counters hold our last push, and that this complete
            # census routes no client to, gets no push: its last client left,
            # and nothing else resets a pushed node. Zero its counters, or the
            # per-band ones keep that push while the total follows the topology
            # down to 0. Unlike a push this is not stamped as a census: the
            # total goes back to the topology, which can count clients
            # devicelist does not list, and has no per-band split to give.
            routed_ips = set(mac_to_ip.values())
            for ip, integration in integrations.items():
                updater = integration.get(UPDATER)
                # Skipped: a node whose MAC we do not know (its clients could
                # not be routed to it), one whose counters are not from our
                # push (by IP, so our push from before a reload still counts),
                # and one that counts its own clients.
                if (
                    ip in add_to
                    or ip not in routed_ips
                    or not isinstance(updater, LuciUpdater)
                    or getattr(updater, "_parent_census_at", None) is None
                    or getattr(updater._parent_census_source, "ip", None) != self.ip
                    or updater._counts_own_clients
                ):
                    continue
                updater.reset_counter(is_force=True)
                trace = getattr(updater, "_mesh_trace", None)
                if trace is not None:
                    trace.event("parent_census_empty", updater.data, source_ip=self.ip)

            updaters = [row[UPDATER] for row in integrations.values() if row.get(UPDATER)]
            if self not in updaters:
                updaters.append(self)
            retired = await get_mac_replacement(self.hass).async_candidates(self.ip, replacement_clients, updaters)
            await async_retire_macs(self.hass, retired, updaters)

    async def _async_prepare_device_restore(self, data: dict) -> None:
        """Restore devices

        :param data: dict
        """

        if not self._is_first_update:
            return

        devices: dict | None = await self._async_load_devices()

        if devices is None:
            return

        integrations: dict = async_get_integrations(self.hass)
        node_macs, node_ips = _known_mesh_nodes(self.hass)

        # A force-load node enumerates and saves its own radio clients, so it
        # restores them as well, and only them: a record names the node that
        # saw the client last, and the other nodes leave this node's records
        # alone below.
        own_clients_only: bool = self.is_repeater and self.is_force_load
        other_updaters: list = [
            integration[UPDATER]
            for integration in integrations.values()
            if integration[UPDATER] is not self
        ]

        for mac, device in devices.items():
            if await get_purged_clients(self.hass).async_blocked(mac):
                continue
            if mac in self.devices:
                continue

            # A store can hold a node's MAC, saved while the node was listed as
            # a client; restoring it would recreate a client that never comes online.
            if (
                str(mac).strip().upper() in node_macs
                or device.get(ATTR_TRACKER_IP) in node_ips
            ):
                continue

            # A client another node already holds, live or restored, keeps that
            # owner whichever entry set up first: it is not added or moved here
            # as well. A record of a force-load entry still lends that node its
            # name and IP below.
            held_elsewhere: bool = any(
                mac in (getattr(updater, "devices", None) or {})
                for updater in other_updaters
            )

            if own_clients_only and (
                device.get(ATTR_TRACKER_ENTRY_ID) != self._entry_id or held_elsewhere
            ):
                continue

            try:
                # fmt: off
                device[ATTR_TRACKER_CONNECTION] = Connection(int(device[ATTR_TRACKER_CONNECTION])) \
                    if ATTR_TRACKER_CONNECTION in device \
                    and device[ATTR_TRACKER_CONNECTION] is not None \
                    else None
                # fmt: on
            except ValueError:
                device[ATTR_TRACKER_CONNECTION] = None

            _is_add: bool = not held_elsewhere
            if device[ATTR_TRACKER_ENTRY_ID] != self._entry_id:
                for integration in integrations.values():
                    if (
                        integration[ATTR_TRACKER_ENTRY_ID]
                        != device[ATTR_TRACKER_ENTRY_ID]
                    ):
                        continue

                    if integration[UPDATER].is_force_load:
                        if mac in integration[UPDATER].devices:
                            integration[UPDATER].devices[mac] |= {
                                attr: device[attr]
                                for attr in [ATTR_TRACKER_NAME, ATTR_TRACKER_IP]
                                if attr in device and device[attr] is not None
                            }

                        _is_add = False

                        break

                    if not held_elsewhere:
                        device |= {
                            ATTR_TRACKER_ROUTER_MAC_ADDRESS: integration[
                                UPDATER
                            ].data.get(
                                ATTR_DEVICE_MAC_ADDRESS,
                                device[ATTR_TRACKER_ROUTER_MAC_ADDRESS],
                            ),
                            ATTR_TRACKER_UPDATER_ENTRY_ID: self._entry_id,
                        }

                        integration[UPDATER].devices[mac] = device

                        self._moved_devices.append(mac)

                        break

            if not _is_add:
                continue

            if mac not in self._moved_devices:
                device |= {
                    ATTR_TRACKER_UPDATER_ENTRY_ID: self._entry_id,
                    ATTR_TRACKER_ENTRY_ID: self._entry_id,
                }

            # This runs in the first refresh, before the tracker platform is
            # set up: the signal goes unheard, and the platform adds the
            # tracker from self.devices. The flag has to be on the record for
            # the tracker to start from its last state rather than as
            # connected. add_device drops it.
            device[ATTR_TRACKER_IS_RESTORED] = True
            self.devices[mac] = device

            async_dispatcher_send(self.hass, SIGNAL_NEW_DEVICE, device)

            #await self.hass.async_add_executor_job(_LOGGER.debug, "Restore device: %s, %s", mac, device)

        self._clean_devices()

    async def add_device(
        self,
        device: dict,
        is_from_parent: bool = False,
        action: DeviceAction = DeviceAction.ADD,
        integrations: dict[str, Any] | None = None,
    ) -> None:
        """Prepare device.

        :param device: dict
        :param is_from_parent: bool: The call came from a third party integration
        :param action: DeviceAction: Device action
        :param integrations: dict[str, Any]: Integrations list
        """

        if await get_purged_clients(self.hass).async_blocked(device[ATTR_TRACKER_MAC], device):
            return
        is_new: bool = device[ATTR_TRACKER_MAC] not in self.devices
        _device: dict[str, Any] = self._build_device(device, integrations)

        # A completed parent census routes active clients to their current node.
        # A restore/previous move marker must not suppress a client that returned.
        if is_from_parent:
            mac = device[ATTR_TRACKER_MAC]
            while mac in self._moved_devices:
                self._moved_devices.remove(mac)

        if (
            self.is_repeater
            and self.is_force_load
            and device[ATTR_TRACKER_MAC] in self.devices
        ):
            if is_from_parent:
                # El principal es la fuente autoritativa para clientes del leaf
                self.devices[device[ATTR_TRACKER_MAC]] |= {
                    key: value for key, value in _device.items()
                    if value is not None or key in (
                        ATTR_TRACKER_SIGNAL, "wifi_protocol", "link_tx_rate", "link_rx_rate", "signal_unit", "signal_source"
                    )
                }
            else:
                # A device list knows more than this node's own lists. The
                # parent's keeps what it pushed, while its last push of the
                # client is recent; this node's own keeps what it listed
                # against its radio list, whose rows have no address and come
                # first in a poll. Anything else this census refreshes, but
                # for what the row only defaults: the MAC that stands in for a
                # name the row does not give, and "not blocked" for a client
                # neither this node's filter list nor its device list has a
                # state for.
                mac = device[ATTR_TRACKER_MAC]
                skip: tuple = ()
                if self._has_recent_parent_census(mac) or (
                    not device.get("ip")
                    and mac in getattr(self, "_device_list_macs", ())
                ):
                    skip = REPEATER_SKIP_ATTRS
                else:
                    if "name" not in device:
                        skip += (ATTR_TRACKER_NAME,)
                    if mac not in getattr(self, "_filter_macs", {}):
                        skip += (ATTR_TRACKER_INTERNET_BLOCKED,)
                self.devices[mac] |= {
                    key: value
                    for key, value in _device.items()
                    if key not in skip and value is not None
                }
        else:
            self.devices[device[ATTR_TRACKER_MAC]] = _device

        # Reported again: the record is no longer only what a store held.
        self.devices[device[ATTR_TRACKER_MAC]].pop(ATTR_TRACKER_IS_RESTORED, None)

        # Another node's copy that only its store held is stale now: the client
        # is here. Drop it, or a tracker that reads that node's records keeps
        # the client away until activity_days expires the copy.
        for integration in async_get_integrations(self.hass).values():
            other = integration.get(UPDATER)
            if other is self or not isinstance(other, LuciUpdater):
                continue
            row = other.devices.get(device[ATTR_TRACKER_MAC])
            if isinstance(row, dict) and row.get(ATTR_TRACKER_IS_RESTORED):
                del other.devices[device[ATTR_TRACKER_MAC]]
                with contextlib.suppress(ValueError):
                    other._moved_devices.remove(device[ATTR_TRACKER_MAC])
            
        # ✅ Keep a mesh-wide latest snapshot so stable device_tracker entities
        # can follow the client even when it moves between main router and leaf nodes.
        tracker_missing = False
        try:
            self.hass.data.setdefault(DOMAIN, {})
            self.hass.data[DOMAIN].setdefault("devices_cache", {})

            mac_u = str(device[ATTR_TRACKER_MAC]).strip().upper()
            latest = dict(self.devices[mac_u])

            # Global cache used by device_tracker fallback logic
            self.hass.data[DOMAIN]["devices_cache"][mac_u] = latest

            # If a live device_tracker entity for this MAC already exists, update it now
            ent_map = self.hass.data[DOMAIN].get("device_tracker_entities", {})
            uid = f"{DOMAIN}-{mac_u.lower()}"
            ent = ent_map.get(uid)
            tracker_missing = ent is None

            if ent is not None:
                ent.update_from_router(latest)

        except Exception:
            _LOGGER.exception(
                "[MiWiFi] Could not update client tracker %s",
                device[ATTR_TRACKER_MAC],
            )

        if not is_from_parent and action == DeviceAction.MOVE:
            self._moved_devices.append(device[ATTR_TRACKER_MAC])
            action = DeviceAction.ADD

        if (
            (is_new or tracker_missing)
            and action == DeviceAction.ADD
            and self.new_device_callback is not None
        ):
            async_dispatcher_send(
                self.hass, SIGNAL_NEW_DEVICE, self.devices[device[ATTR_TRACKER_MAC]]
            )

        # Re-providing a known client's tracker after its original platform
        # unloads must not announce it as a newly discovered device.
        if is_new and action == DeviceAction.ADD and self.new_device_callback is not None:
            await self.hass.async_add_executor_job(_LOGGER.debug, "Found new device: %s", self.devices[device[ATTR_TRACKER_MAC]])

            if ATTR_TRACKER_FIRST_SEEN not in self.devices[device[ATTR_TRACKER_MAC]]:
                self.hass.async_create_task(
                    self._async_notify_new_device(
                        device.get("name", device[ATTR_TRACKER_MAC]),
                        device[ATTR_TRACKER_MAC],
                    )
                )

        elif action == DeviceAction.MOVE:
            await self.hass.async_add_executor_job(_LOGGER.debug, "Move device: %s", device[ATTR_TRACKER_MAC])

        if device[ATTR_TRACKER_MAC] in self._moved_devices:
            return

        # Keep legacy behavior for older routers.
        # Only allow leaf counters to be updated from parent in routers with dedicated IoT WiFi.
        if self.is_repeater and self.is_force_load:
            if not (is_from_parent and self._has_dedicated_iot_wifi()):
                return

        if not is_from_parent and self._parent_push_pending:
            self._parent_push_pending = False
            self.reset_counter(is_force=True)
        elif (
            not is_from_parent
            and self._counters_pushed_by_parent
            and not self._counters_reset_this_cycle
        ):
            # A node whose counters are pushed by the parent skips the reset at
            # the top of the cycle, but it still enumerates its own clients
            # through misystem/devicelist, and every one of them lands here.
            # Without a reset the counters would only ever grow. Reset on the
            # first client we count for ourselves in this cycle.
            self.reset_counter(is_force=True)

        if "new_status" not in self.data:
            self.data.setdefault(ATTR_SENSOR_DEVICES, 0)
            self.data.setdefault(ATTR_SENSOR_DEVICES_LAN, 0)
            self.data.setdefault(ATTR_SENSOR_DEVICES_GUEST, 0)
            self.data.setdefault(ATTR_SENSOR_DEVICES_2_4, 0)
            self.data.setdefault(ATTR_SENSOR_DEVICES_5_0, 0)
            self.data.setdefault(ATTR_SENSOR_DEVICES_5_0_GAME, 0)
            self.data.setdefault(ATTR_SENSOR_DEVICES_IOT, 0)

            self.data[ATTR_SENSOR_DEVICES] += 1

            connection = _device.get(ATTR_TRACKER_CONNECTION)

            # ✅ Defensive fallback only for routers with dedicated IoT WiFi
            if (
                connection is None
                and "_miwifi_connection" not in device
                and self._has_dedicated_iot_wifi()
            ):
                try:
                    raw_type = int(device.get("type")) if device.get("type") not in ("", None) else None
                except Exception:
                    raw_type = None

                if raw_type == 5:
                    connection = Connection.WIFI_5_0_GAME
                elif raw_type == 6:
                    connection = Connection.WIFI_IOT

            code: str = (connection or Connection.LAN).name.replace("WIFI_", "")
            code = f"{ATTR_SENSOR_DEVICES}_{code}".lower()
            self.data.setdefault(code, 0)
            self.data[code] += 1

    def _build_device(
        self, device: dict, integrations: dict[str, Any] | None = None
    ) -> dict[str, Any]:

        def _to_float(v, default: float = 0.0) -> float:
            try:
                if v in ("", None):
                    return default
                return float(str(v))
            except Exception:
                return default

        ip_attr: dict | None = device["ip"][0] if "ip" in device and device["ip"] else None

        connection: Connection | None = self._resolve_connection(device)

        existing = self.devices.get(device[ATTR_TRACKER_MAC], {})
        total_usage = device.get(
            ATTR_TRACKER_TOTAL_USAGE,
            existing.get(ATTR_TRACKER_TOTAL_USAGE),
        )

        # Mesh: si el dispositivo reporta 'parent', ese es el nodo/AP real al que está asociado
        router_mac = self.data.get(ATTR_DEVICE_MAC_ADDRESS, None)
        parent_mac = device.get("parent")
        if isinstance(parent_mac, str) and parent_mac.strip():
            router_mac = parent_mac.strip().upper()

        # ✅ Determinar online REAL (devicelist)
        try:
            online_flag = int(device.get("online", 1) or 0)
        except Exception:
            online_flag = 1

        active_flag = 1
        if isinstance(ip_attr, dict) and "active" in ip_attr:
            try:
                active_flag = int(ip_attr.get("active", 1) or 0)
            except Exception:
                active_flag = 1

        is_online = (online_flag == 1) and (active_flag == 1)

        # ✅ last_activity: solo “now” si está online.
        # Si está offline, mantenemos el último valor real (o ponemos uno antiguo si no existe).
        now_iso = datetime.now().replace(microsecond=0).isoformat()
        last_activity = None

        if is_online:
            last_activity = now_iso
        else:
            last_activity = existing.get(ATTR_TRACKER_LAST_ACTIVITY)
            if not last_activity:
                last_activity = (datetime.now() - timedelta(days=365)).replace(microsecond=0).isoformat()

        # ✅ online uptime: solo si online (si no, vacío)
        online_uptime = ""
        if is_online and ip_attr:
            try:
                online_uptime = str(timedelta(seconds=int(ip_attr.get("online", 0) or 0)))
            except Exception:
                online_uptime = ""

        ip_value = ip_attr.get("ip") if isinstance(ip_attr, dict) else None

        # Speeds come only from the devicelist entry. A client listed only by a
        # node's Wi-Fi list (force load) has none: that is unknown, not idle.
        down_speed: float | None = 0.0
        up_speed: float | None = 0.0
        if is_online:
            if isinstance(ip_attr, dict):
                down_speed = _to_float(ip_attr.get("downspeed"))
                up_speed = _to_float(ip_attr.get("upspeed"))
            else:
                down_speed = up_speed = None

        # ✅ WAN access state (keep stable across refreshes):
        # - Preferred: explicit internet_blocked already computed upstream
        # - Fallback: devicelist authority.wan (0=blocked, 1=allowed)
        # - Fallback: cached macfilter map (_filter_macs)
        internet_blocked = device.get(ATTR_TRACKER_INTERNET_BLOCKED)
        if internet_blocked is None:
            try:
                auth = device.get("authority")
                if isinstance(auth, dict) and "wan" in auth:
                    internet_blocked = int(auth.get("wan", 1) or 0) == 0
            except Exception:
                internet_blocked = None

        if internet_blocked is None:
            try:
                mac_u = str(device.get(ATTR_TRACKER_MAC, "") or "").strip().upper()
                fm = getattr(self, "_filter_macs", None)
                if isinstance(fm, dict) and mac_u and mac_u in fm:
                    internet_blocked = int(fm[mac_u] or 0) == 0
            except Exception:
                internet_blocked = None

        if internet_blocked is None:
            internet_blocked = False

        # device_list supplies RSSI as text and PHY rates with units. Retain
        # legacy signal semantics when unavailable; never interpret -50 as 0%.
        signal = self._signals.get(device[ATTR_TRACKER_MAC]) if is_online else None
        metrics = {"wifi_protocol": None, "link_tx_rate": None, "link_rx_rate": None,
                   "signal_unit": "%" if signal is not None else None,
                   "signal_source": "wifi_connect_devices" if signal is not None else None}
        detail = device.get("_miwifi_details")
        if isinstance(detail, dict) and is_online:
            try:
                rssi = int(detail.get("signal"))
            except (TypeError, ValueError, OverflowError):
                rssi = None
            if rssi is not None and -127 <= rssi < 0:
                signal = rssi
                metrics["signal_unit"] = "dBm"
                metrics["signal_source"] = "misystem/device_list"
            protocol = detail.get("wifiprotocol")
            if isinstance(protocol, str) and protocol.strip():
                metrics["wifi_protocol"] = protocol.strip()
            for raw_key, key in (("nego_tx_rate", "link_tx_rate"), ("nego_rx_rate", "link_rx_rate")):
                value = detail.get(raw_key)
                if isinstance(value, str) and value.endswith("Mbps"):
                    rate = _to_float(value[:-4], default=-1)
                    if 0 <= rate <= 100000:
                        metrics[key] = rate

        if getattr(connection, "name", None) == "LAN":
            signal = None
            metrics = dict.fromkeys(metrics)

        return {
            **metrics,
            ATTR_TRACKER_ENTRY_ID: device[ATTR_TRACKER_ENTRY_ID],
            ATTR_TRACKER_UPDATER_ENTRY_ID: device.get(
                ATTR_TRACKER_UPDATER_ENTRY_ID, device[ATTR_TRACKER_ENTRY_ID]
            ),
            ATTR_TRACKER_MAC: device[ATTR_TRACKER_MAC],
            ATTR_TRACKER_ROUTER_MAC_ADDRESS: router_mac,
            ATTR_TRACKER_SIGNAL: signal,
            ATTR_TRACKER_NAME: device.get("name", device[ATTR_TRACKER_MAC]),
            ATTR_TRACKER_IP: ip_value,
            ATTR_TRACKER_CONNECTION: connection,
            ATTR_TRACKER_DOWN_SPEED: down_speed,
            ATTR_TRACKER_UP_SPEED: up_speed,
            ATTR_TRACKER_ONLINE: online_uptime,
            ATTR_TRACKER_LAST_ACTIVITY: last_activity,
            ATTR_TRACKER_FIRST_SEEN: self.devices.get(
                device[ATTR_TRACKER_MAC], {}
            ).get(
                ATTR_TRACKER_FIRST_SEEN,
                datetime.now().replace(microsecond=0).isoformat(),
            ),
            # ✅ Avoid KeyError when ip is missing / not in integrations
            ATTR_TRACKER_OPTIONAL_MAC: integrations[ip_value][UPDATER]
            .data.get(ATTR_DEVICE_MAC_ADDRESS, None)
            if integrations
            and isinstance(ip_value, str)
            and ip_value in integrations
            else None,
            ATTR_TRACKER_INTERNET_BLOCKED: bool(internet_blocked),
            ATTR_TRACKER_TOTAL_USAGE: total_usage,
        }


    def _mass_update_device(self, device: dict, integrations: dict) -> bool:
        """Mass update devices

        :param device: dict: Device data
        :param integrations: dict: Integration list
        :return bool: is found
        """

        is_found: bool = False

        for _ip, integration in integrations.items():
            if (
                device[ATTR_TRACKER_MAC] not in integration[UPDATER].devices
                or _ip == self.ip
            ):
                continue

            _device: dict[str, Any] = self._build_device(device, integrations)
            if self.is_repeater and self.is_force_load:
                for attr in REPEATER_SKIP_ATTRS:
                    if attr in _device:
                        del _device[attr]

            integration[UPDATER].devices[device[ATTR_TRACKER_MAC]] |= _device
            is_found = True

        return is_found

    async def _async_prepare_ap(self, data: dict) -> None:
        """Prepare wifi ap.

        :param data: dict
        """

        if self.data.get(ATTR_SENSOR_MODE, Mode.DEFAULT) != Mode.REPEATER:
            return

        try:
            response: dict = await self.luci.wifi_ap_signal()
        except LuciError as _e:
            await self.hass.async_add_executor_job(
                _LOGGER.debug,
                "[MiWiFi] wifi_ap_signal unavailable (%s)",
                type(_e).__name__,
            )
            return

        if "signal" in response and isinstance(response["signal"], int):
            data[ATTR_SENSOR_AP_SIGNAL] = response["signal"]

    async def _async_prepare_new_status(self, data: dict) -> None:
        """Prepare new status.

        :param data: dict
        """

        if not self.is_force_load:
            #await self.hass.async_add_executor_job(_LOGGER.warning, "⚠️ [new_status] is_force_load is False. Skipping new_status.")
            return

        try:
            response: dict = await self.luci.new_status()
        except LuciError as _e:
            await self.hass.async_add_executor_job(
                _LOGGER.debug,
                "[MiWiFi] new_status unavailable (%s)",
                type(_e).__name__,
            )
            return

        if "count" in response:
            data[ATTR_SENSOR_DEVICES] = response["count"]
            #await self.hass.async_add_executor_job(_LOGGER.warning, "📶 Total devices count: %s", response["count"])

        for key, attr in NEW_STATUS_MAP.items():
            if key in response and "online_sta_count" in response[key]:
                data[attr] = response[key]["online_sta_count"]
                #await self.hass.async_add_executor_job(_LOGGER.warning, "📶 Set %s = %s", attr, response[key]["online_sta_count"])

        _other_devices = sum(
            int(data[attr]) for attr in NEW_STATUS_MAP.values() if attr in data
        )

        if _other_devices > 0 and ATTR_SENSOR_DEVICES in data:
            _other_devices = int(data[ATTR_SENSOR_DEVICES]) - _other_devices
            data[ATTR_SENSOR_DEVICES_LAN] = max(_other_devices, 0)
            #await self.hass.async_add_executor_job(_LOGGER.warning, "📶 Calculated LAN devices: %s", data[ATTR_SENSOR_DEVICES_LAN])

        trace = getattr(self, "_mesh_trace", None)
        if trace is not None:
            trace.event("new_status_applied", data)


    def _clean_devices(self) -> None:
        """Clean devices."""

        if self._activity_days == 0 or len(self.devices) == 0:
            return

        now = datetime.now().replace(microsecond=0)
        integrations: dict[str, dict] = async_get_integrations(self.hass)

        # Recorremos copia para poder borrar
        for mac, device in list(self.devices.items()):
            if ATTR_TRACKER_LAST_ACTIVITY not in device or not isinstance(
                device[ATTR_TRACKER_LAST_ACTIVITY], str
            ):
                self.devices[mac][ATTR_TRACKER_LAST_ACTIVITY] = (
                    datetime.now().replace(microsecond=0).isoformat()
                )
                continue

            delta = now - datetime.strptime(
                device[ATTR_TRACKER_LAST_ACTIVITY], "%Y-%m-%dT%H:%M:%S"
            )

            if int(delta.days) <= self._activity_days:
                continue

            # Si el dispositivo existe en OTRO updater, NO hacemos purge de entidades
            # (roaming mesh / moved). Solo eliminamos de este updater.
            still_present_elsewhere = False
            for _ip, integration in integrations.items():
                up = integration.get(UPDATER)
                if not up or up is self:
                    continue
                if mac in (getattr(up, "devices", {}) or {}):
                    still_present_elsewhere = True
                    break

            # Eliminamos del store interno del updater
            del self.devices[mac]
            if mac in self._moved_devices:
                with contextlib.suppress(ValueError):
                    self._moved_devices.remove(mac)

            # Purga REAL (device_tracker + sensores por MAC) solo si NO está en ningún otro nodo
            if not still_present_elsewhere:
                entry_id = self._entry_id or ""
                async_dispatcher_send(self.hass, SIGNAL_PURGE_DEVICE, entry_id, mac)


    def _purge_pending_mesh_nodes(self, integrations: dict[str, dict]) -> None:
        """Remove the client entities of every node not purged yet this session.

        The pending set is every MAC a main router has reported with isap > 0,
        not only this cycle's: a node seen as one during the first refresh, when
        nothing may be purged yet, can be listed with isap 0 or not at all by the
        time a purge is allowed. A node recognised only by its address is never
        purged: an IP alone does not identify a device whose entities may go.

        The removal works on the entity registry across every MiWiFi entry, so it
        is complete when it returns, whatever entries have their platforms up.

        :param integrations: dict[str, dict]: Integrations list
        """

        # helper imports this module, so it cannot be imported at the top.
        from .helper import async_purge_client_entities

        domain_data: dict = self.hass.data.setdefault(DOMAIN, {})
        pending: set[str] = set(domain_data.get(MESH_NODE_MACS, ())) - set(
            domain_data.get(MESH_NODE_PURGED, ())
        )

        for mac in sorted(pending):
            self._forget_mesh_node(mac, integrations)
            if async_purge_client_entities(self.hass, mac):
                # A client row under a node's second MAC blocks its alias, see
                # `_async_record_backhaul_aliases`. It is gone: let the next
                # census record the alias. Pending purges are shared across
                # entries: the updater doing the cleanup need not be the one
                # whose earlier census cached the collision.
                self._backhaul_alias_skipped.discard(mac)
                for integration in integrations.values():
                    updater = integration.get(UPDATER)
                    if isinstance(updater, LuciUpdater):
                        updater._backhaul_alias_skipped.discard(mac)
            _remember_mesh_node_macs(self.hass, {mac}, MESH_NODE_PURGED)

    def _forget_mesh_node(self, mac: str, integrations: dict[str, dict]) -> None:
        """Stop tracking a mesh node's MAC as a client on every node.

        :param mac: str: Upper-case MAC of the node
        :param integrations: dict[str, dict]: Integrations list
        """

        if not mac:
            return

        updaters = [self] + [
            integration.get(UPDATER)
            for integration in integrations.values()
            if isinstance(integration.get(UPDATER), LuciUpdater)
            and integration.get(UPDATER) is not self
        ]
        for updater in updaters:
            updater.devices.pop(mac, None)
            with contextlib.suppress(ValueError):
                updater._moved_devices.remove(mac)

        self.hass.data.get(DOMAIN, {}).get("devices_cache", {}).pop(mac, None)

    def reset_counter(self, is_force: bool = False, is_remove: bool = False) -> None:
        """Reset counter

        :param is_force: bool: Force reset
        :param is_remove: bool: Force remove
        """

        if self._counters_pushed_by_parent and not is_force:
            return

        self._parent_census_at = None
        trace = getattr(self, "_mesh_trace", None)
        if trace is not None:
            trace.event("before_reset", self.data, force=is_force, remove=is_remove)
        self._counters_reset_this_cycle = True
        for attr in [
            ATTR_SENSOR_DEVICES,
            ATTR_SENSOR_DEVICES_LAN,
            ATTR_SENSOR_DEVICES_GUEST,
            ATTR_SENSOR_DEVICES_2_4,
            ATTR_SENSOR_DEVICES_5_0,
            ATTR_SENSOR_DEVICES_5_0_GAME,
            ATTR_SENSOR_DEVICES_IOT,
        ]:
            if attr in self.data and is_remove:
                del self.data[attr]
            elif not is_remove:
                self.data[attr] = 0

    def _leaf_entry_from_other_nodes(self) -> dict | None:
        """Return this node's entry from another configured node's graph."""

        for ip, integration in async_get_integrations(self.hass).items():
            if ip == self.ip:
                continue
            updater = integration.get(UPDATER)
            if not isinstance(updater, LuciUpdater):
                continue
            topology = (updater.data or {}).get("topo_graph")
            graph = topology.get("graph") if isinstance(topology, dict) else None
            if isinstance(graph, dict):
                leaf = _find_leaf(graph, self.ip)
                if leaf is not None:
                    return leaf
        return None

    def _has_recent_parent_census(self, mac: str | None = None) -> bool:
        """Prefer a recent completed census from a still-loaded parent.

        :param mac: str | None: judge the last census that had this client
        """

        if mac is None:
            observed_at = getattr(self, "_parent_census_at", None)
            source = getattr(self, "_parent_census_source", None)
        else:
            source, observed_at = getattr(self, "_parent_census_clients", {}).get(
                mac, (None, None)
            )
        if observed_at is None or source is None:
            return False
        integration = async_get_integrations(self.hass).get(source.ip)
        if not integration or integration.get(UPDATER) is not source:
            return False
        # Allow several parent refreshes and one request timeout before falling
        # back. A monotonic clock avoids wall-clock adjustments changing freshness.
        ttl = max(60, 3 * source._scan_interval + source.timeout)
        return monotonic() - observed_at <= ttl

    async def _async_apply_leaf_client_count(self) -> None:
        """Use the main node's topology count when this leaf has no census."""

        if not self.is_repeater:
            return
        handed_by_parent = self._parent_push_pending
        self._parent_push_pending = False
        if self._counters_reset_this_cycle or self._has_recent_parent_census():
            return

        leaf = self._leaf_entry_from_other_nodes()
        if not isinstance(leaf, dict):
            return
        try:
            count = int(leaf["onlines"])
        except (KeyError, TypeError, ValueError):
            return
        if count < 0:
            return
        current = self.data.get(ATTR_SENSOR_DEVICES)
        if current == count:
            return
        self.data[ATTR_SENSOR_DEVICES] = count
        trace = getattr(self, "_mesh_trace", None)
        if trace is not None:
            trace.event("topology_count_applied", self.data,
                        handed_by_parent=handed_by_parent)

    async def async_purge_clients(self, macs: set[str]) -> None:
        """Forget purged clients in this node, including dormant stored copies."""
        for mac in list(self.devices):
            if mac.strip().upper() in macs:
                self.devices.pop(mac, None)
        self._moved_devices[:] = [mac for mac in self._moved_devices if mac.strip().upper() not in macs]
        cache = self.hass.data.get(DOMAIN, {}).get("devices_cache", {})
        for mac in list(cache):
            if mac.strip().upper() in macs:
                cache.pop(mac, None)
        if self._store is not None:
            stored = await self._store.async_load()
            if isinstance(stored, dict):
                remaining = {mac: row for mac, row in stored.items() if mac.strip().upper() not in macs}
                await self._store.async_save(remaining)

    async def _async_load_devices(self) -> dict | None:
        """Async load devices from Store"""

        if self._store is None:
            return None

        devices: dict | None = await self._store.async_load()

        if devices is None or not isinstance(devices, dict) or len(devices) == 0:
            return None

        return devices

    async def _async_save_devices(self) -> None:
        """Async save devices to Store"""

        if (
            self._store is None
            or (self.is_repeater and not self.is_force_load)
            or len(self.devices) == 0
        ):
            return

        await self._store.async_save(self.devices)

    async def _async_prepare_topo(self) -> None:
        """Prepare topology graph information.

        IMPORTANT:
        - Never store self.data["topo_graph"] as None.
          Some code paths use `.get("topo_graph", {})` and would break if the value is None.
        - Always keep a stable dict structure: {"show": 0, "graph": {}, "code": 0}
        """

        def _empty_topo(reason: str | None = None) -> dict:
            topo = {"show": 0, "graph": {}, "code": 0}
            if reason:
                topo["_reason"] = reason

            mac = self.data.get(ATTR_DEVICE_MAC_ADDRESS)
            if isinstance(mac, str) and mac.strip():
                topo["graph"]["mac"] = mac.strip().upper()

            # Keep a predictable shape
            topo["graph"].setdefault("is_main", False)
            topo["graph"].setdefault("is_main_auto", False)
            return topo

        try:
            topo_data = await asyncio.wait_for(self.luci.topo_graph(), timeout=6)
        except (asyncio.TimeoutError, LuciError, LuciConnectionError) as e:
            await self.hass.async_add_executor_job(
                _LOGGER.debug,
                "[MiWiFi] topo_graph unavailable for %s: %s",
                self.ip,
                e,
            )
            topo_data = _empty_topo("fetch_failed")
        except Exception as e:
            await self.hass.async_add_executor_job(
                _LOGGER.debug,
                "[MiWiFi] topo_graph unexpected error for %s: %s",
                self.ip,
                e,
            )
            topo_data = _empty_topo("unexpected_error")

        # Normalize topo_data shape
        if not isinstance(topo_data, dict):
            topo_data = _empty_topo("invalid_type")

        graph = topo_data.get("graph")
        if not isinstance(graph, dict):
            topo_data = dict(topo_data)
            topo_data["graph"] = {}
            graph = topo_data["graph"]

        # Ensure show exists
        if "show" not in topo_data:
            topo_data["show"] = 0

        # Ensure MAC is present when we know it
        if self.data.get(ATTR_DEVICE_MAC_ADDRESS):
            graph["mac"] = self.data[ATTR_DEVICE_MAC_ADDRESS]
            await self.hass.async_add_executor_job(
                _LOGGER.debug,
                "[MiWiFi] MAC added to topo_graph: %s",
                graph.get("mac"),
            )

        auto_main = False

        # --------------------------
        # Original auto-main logic (hardened)
        # --------------------------
        try:
            show = int(topo_data.get("show", -1)) if str(topo_data.get("show", "")).strip() != "" else -1
            mode = int(graph.get("mode", -1)) if str(graph.get("mode", "")).strip() != "" else -1

            assoc_raw = graph.get("assoc", None)
            assoc = None
            if assoc_raw is not None and str(assoc_raw).strip() != "":
                try:
                    assoc = int(str(assoc_raw).strip())
                except Exception:
                    assoc = None

            leafs = graph.get("leafs")
            nodes = graph.get("nodes")
            has_leafs = isinstance(leafs, list) and len(leafs) > 0
            has_nodes = isinstance(nodes, list) and len(nodes) > 0

            await self.hass.async_add_executor_job(
                _LOGGER.debug,
                "[MiWiFi] Topo debug – show=%s, mode=%s, assoc=%s, leafs=%s, nodes=%s",
                show,
                mode,
                assoc if assoc is not None else assoc_raw,
                len(leafs) if isinstance(leafs, list) else 0,
                len(nodes) if isinstance(nodes, list) else 0,
            )

            # ✅ Root graph => MAIN
            if has_leafs or has_nodes:
                graph["is_main"] = True
                auto_main = True
            elif show == 1:
                if mode in (0, 4) or (assoc == 1):
                    graph["is_main"] = True
                    auto_main = True

            graph["is_main_auto"] = auto_main
            graph["auto_reason"] = (
                f"leafs={len(leafs) if isinstance(leafs, list) else 0}, "
                f"nodes={len(nodes) if isinstance(nodes, list) else 0}, "
                f"show={show}, mode={mode}, assoc={assoc}"
            )

            await self.hass.async_add_executor_job(
                _LOGGER.debug,
                "[MiWiFi] Auto-main => %s (%s)",
                auto_main,
                graph.get("auto_reason"),
            )

        except Exception as e:
            await self.hass.async_add_executor_job(
                _LOGGER.debug,
                "[MiWiFi] Error interpreting topology: %s",
                e,
            )

        # --------------------------
        # Manual main / single integration fallback (keep behavior)
        # --------------------------
        try:
            if not auto_main:
                from custom_components.miwifi.frontend import async_load_manual_main_mac

                manual_mac = await async_load_manual_main_mac(self.hass)
                if manual_mac:
                    if (manual_mac or "").lower() == (graph.get("mac") or "").lower():
                        graph["is_main"] = True
                        await self.hass.async_add_executor_job(
                            _LOGGER.debug,
                            "[MiWiFi] Main router restored from saved MAC: %s",
                            manual_mac,
                        )
                    else:
                        graph.pop("is_main", None)
                else:
                    from .updater import async_get_integrations

                    integrations = async_get_integrations(self.hass)
                    if len(integrations) == 1:
                        graph["is_main"] = True
                        graph["is_main_auto"] = True
                        graph["auto_reason"] = "single_integration_fallback"
                        auto_main = True
                        await self.hass.async_add_executor_job(
                            _LOGGER.debug,
                            "[MiWiFi] Main router set by single integration fallback",
                        )
                    else:
                        graph.pop("is_main", None)
            else:
                graph["is_main"] = True

            graph["is_main_auto"] = bool(graph.get("is_main_auto", auto_main))

        except Exception as e:
            await self.hass.async_add_executor_job(
                _LOGGER.debug,
                "[MiWiFi] Topo manual/single fallback error: %s",
                e,
            )

        # Store ALWAYS as dict (never None)
        self.data["topo_graph"] = topo_data

        await self.hass.async_add_executor_job(
            _LOGGER.debug,
            "[MiWiFi] Topology graph data received for router at %s: %s",
            self.ip,
            topo_data,
        )

        # Best-effort: sync topology sensor attrs if present (do not ever break)
        with contextlib.suppress(Exception):
            for entity in self.hass.states.async_all("sensor"):
                eid = entity.entity_id or ""
                if eid.startswith("sensor.topologia_miwifi") or eid.startswith("sensor.miwifi_topology"):
                    g = entity.attributes.get("graph", {}) or {}
                    mac_entity = (g.get("mac") or "").lower()
                    mac_graph = (graph.get("mac") or "").lower()
                    if mac_entity and mac_entity == mac_graph:
                        clean_attributes = {
                            "graph": dict(graph),
                            "code": entity.attributes.get("code", 0),
                            "icon": entity.attributes.get("icon", "mdi:network"),
                            "friendly_name": entity.attributes.get("friendly_name", "Topología MiWiFi"),
                        }
                        self.hass.states.async_set(eid, entity.state, clean_attributes)

        with contextlib.suppress(AttributeError):
            self.async_set_updated_data(self.data)

        # Mesh node detection (safe)
        nodes = graph.get("nodes")
        if isinstance(nodes, list):
            for node in nodes:
                if isinstance(node, dict):
                    node_ip = node.get("ip")
                    node_mac = node.get("mac")
                    if node_ip and node_ip != self.ip:
                        if node_ip not in self.hass.data.get(DOMAIN, {}):
                            await self.hass.async_add_executor_job(
                                _LOGGER.warning,
                                "[MiWiFi] 🆕 Non-integrated Mesh Node: IP=%s, MAC=%s",
                                node_ip,
                                node_mac,
                            )


    @property
    def entry_id(self) -> str | None:
        """Return the config entry ID."""
        return self._entry_id
    
    async def _async_prepare_compatibility(self) -> None:
        """Run compatibility detection if main and not already checked."""

        if not isinstance(self.data, dict):
            await self.hass.async_add_executor_job(
                _LOGGER.warning,
                "[MiWiFi] Skipping compatibility: updater data is not ready (likely after router reboot)"
            )
            return

        graph_data = self.data.get("topo_graph")
        if not graph_data or not isinstance(graph_data, dict):
            await self.hass.async_add_executor_job(
                _LOGGER.debug,
                "[MiWiFi] Skipping compatibility: no topology graph data (router may be rebooting)"
            )
            return

        graph = graph_data.get("graph")
        if not graph or not isinstance(graph, dict):
            await self.hass.async_add_executor_job(
                _LOGGER.debug,
                "[MiWiFi] Skipping compatibility: invalid graph data"
            )
            return

        if not graph.get("is_main"):
            await self.hass.async_add_executor_job(
                _LOGGER.debug,
                "[MiWiFi] Skipping compatibility: not main router"
            )
            return

        if self._is_first_update:
            await self.hass.async_add_executor_job(
                _LOGGER.debug,
                "[MiWiFi] Skipping compatibility: first update still in progress"
            )
            return

        is_manual_main = not graph.get("is_main_auto", False)

        if getattr(self, "capabilities", None):
            await self.hass.async_add_executor_job(
                _LOGGER.debug,
                "[MiWiFi] Capabilities already detected, skipping"
            )
            return

        try:
            from .compatibility import CompatibilityChecker
            checker = CompatibilityChecker(self.hass, self.luci)
            checker.silent_mode = is_manual_main

            self.capabilities = await checker.run() or {}

            router_ip = graph.get("ip", "unknown")
            router_model = self.data.get("model", self.data.get(ATTR_MODEL, "unknown"))

            await self.hass.async_add_executor_job(
                _LOGGER.info,
                "[MiWiFi] ✅ Capabilities detected (final) for %s (%s) → %s",
                router_ip,
                router_model,
                self.capabilities
            )

            if not is_manual_main and ATTR_MODEL in self.data:
                from .diagnostics import suggest_unsupported_issue
                await suggest_unsupported_issue(
                    self.hass,
                    self.data[ATTR_MODEL],
                    self.capabilities,
                    getattr(checker, "mode", None),
                )

        except Exception as e:
            await self.hass.async_add_executor_job(
                _LOGGER.warning,
                "[MiWiFi] Compatibility check failed (final): %s",
                e
            )


                    
    async def _async_prepare_nat_rules(self) -> None:
        """Prepare NAT rules for the main router."""
        now = dt_util.utcnow()

        if now < getattr(self, "_nat_rules_next_try", now):
            return

        try:
            data1 = await asyncio.wait_for(self.luci.portforward(ftype=1), timeout=6)
            data2 = await asyncio.wait_for(self.luci.portforward(ftype=2), timeout=6)

            self.data["nat_rules"] = {
                "ftype_1": (data1 or {}).get("list", []),
                "ftype_2": (data2 or {}).get("list", []),
                "total": len((data1 or {}).get("list", [])) + len((data2 or {}).get("list", [])),
            }

            # success -> sin cooldown
            self._nat_rules_next_try = now
            await self.hass.async_add_executor_job(
                _LOGGER.debug, "[MiWiFi] NAT rules loaded for sensor: %s", self.data["nat_rules"]
            )
            return

        except LuciRequestError as e:
            msg = str(e).lower()

            if "invalid token" in msg:
                await self.hass.async_add_executor_job(
                    _LOGGER.debug,
                    "[MiWiFi] NAT rules: invalid token -> re-login and retry once",
                )
                try:
                    await self.luci.login()

                    data1 = await asyncio.wait_for(self.luci.portforward(ftype=1), timeout=6)
                    data2 = await asyncio.wait_for(self.luci.portforward(ftype=2), timeout=6)

                    self.data["nat_rules"] = {
                        "ftype_1": (data1 or {}).get("list", []),
                        "ftype_2": (data2 or {}).get("list", []),
                        "total": len((data1 or {}).get("list", [])) + len((data2 or {}).get("list", [])),
                    }

                    self._nat_rules_next_try = now
                    await self.hass.async_add_executor_job(
                        _LOGGER.debug, "[MiWiFi] NAT rules loaded after re-login: %s", self.data["nat_rules"]
                    )
                    return

                except (LuciConnectionError, LuciRequestError, Exception) as e2:
                    await self.hass.async_add_executor_job(
                        _LOGGER.debug,
                        "[MiWiFi] NAT rules retry after re-login failed: %s (cooldown 1m)",
                        e2,
                    )
                    # A failed read must not replace the last successful snapshot.
                    self._nat_rules_next_try = now + timedelta(minutes=1)
                    return

            await self.hass.async_add_executor_job(
                _LOGGER.warning,
                "[MiWiFi] NAT rules failed: %s (cooldown 10m)",
                e,
            )
            self.data["nat_rules"] = {"ftype_1": [], "ftype_2": [], "total": 0}
            self._nat_rules_next_try = now + timedelta(minutes=10)
            return

        except LuciConnectionError as e:
            # Luci errors derive from BaseException, so Exception below does
            # not catch them. NAT reads must not abort the coordinator refresh.
            _LOGGER.warning("[MiWiFi] NAT rules connection failed (retry in 1m): %s", e)
            self._nat_rules_next_try = now + timedelta(minutes=1)
            return

        except asyncio.TimeoutError:
            await self.hass.async_add_executor_job(
                _LOGGER.debug,
                "[MiWiFi] NAT rules timed out for %s (cooldown 10m)",
                self.ip,
            )
            self.data["nat_rules"] = {"ftype_1": [], "ftype_2": [], "total": 0}
            self._nat_rules_next_try = now + timedelta(minutes=10)
            return

        except Exception as e:
            await self.hass.async_add_executor_job(
                _LOGGER.warning,
                "[MiWiFi] Error while retrieving NAT rules for sensor (cooldown 10m): %s",
                e,
            )
            self.data["nat_rules"] = {"ftype_1": [], "ftype_2": [], "total": 0}
            self._nat_rules_next_try = now + timedelta(minutes=10)
            return

                    
    async def _async_notify_new_device(self, name: str, mac: str) -> None:
        notifier = MiWiFiNotifier(self.hass)
        translations = await notifier.get_translations()

        notify_trans = translations.get("notifications", {})
        title = notify_trans.get("new_device_title", "New Device Detected on MiWiFi")

        message_template = notify_trans.get(
            "new_device_message",
            "📶 New device connected: {name} ({mac})"
        )
        message = message_template.replace("{name}", name).replace("{mac}", mac)

        await notifier.notify(
            message,
            title=title,
            notification_id=f"miwifi_new_{mac.replace(':', '_')}",
        )


@callback
def async_get_integrations(hass: HomeAssistant) -> dict[str, dict]:
    """Return integrations map.

    :param hass: HomeAssistant
    :return dict[str, dict]
    """
    integrations: dict[str, dict] = {}

    for entry_id, integration in hass.data.get(DOMAIN, {}).items():
        if (
            isinstance(integration, dict)
            and CONF_IP_ADDRESS in integration
            and UPDATER in integration
        ):
            integrations[integration[CONF_IP_ADDRESS]] = {
                UPDATER: integration[UPDATER],
                ATTR_TRACKER_ENTRY_ID: entry_id,
            }

    return integrations



@callback
def async_get_updater(hass: HomeAssistant, identifier: str) -> LuciUpdater:
    """Return LuciUpdater for ip address or entry id.

    :param hass: HomeAssistant
    :param identifier: str
    :return LuciUpdater
    """

    _error: str = f"Integration with identifier: {identifier} not found."

    if DOMAIN not in hass.data:
        raise ValueError(_error)

    if identifier in hass.data[DOMAIN] and UPDATER in hass.data[DOMAIN][identifier]:
        return hass.data[DOMAIN][identifier][UPDATER]

    if integrations := [
        integration[UPDATER]
        for integration in hass.data[DOMAIN].values()
        if isinstance(integration, dict)
        and CONF_IP_ADDRESS in integration
        and UPDATER in integration
        and integration[CONF_IP_ADDRESS] == identifier
    ]:
        return integrations[0]

    raise ValueError(_error)
