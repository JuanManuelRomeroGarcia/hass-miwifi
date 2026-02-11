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

from homeassistant.util import dt as dt_util

import homeassistant.components.persistent_notification as pn
from homeassistant.const import CONF_IP_ADDRESS
from homeassistant.core import CALLBACK_TYPE, HomeAssistant, callback
from homeassistant.helpers import event
from homeassistant.helpers.device_registry import CONNECTION_NETWORK_MAC
from homeassistant.helpers.dispatcher import async_dispatcher_send
from homeassistant.helpers.entity import DeviceInfo
from homeassistant.helpers import entity_registry as er
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
    Connection,
    DeviceAction,
    EncryptionAlgorithm,
    IfName,
    Mode,
    Model,
    Wifi,
)
from .exceptions import LuciConnectionError, LuciError, LuciRequestError
from .luci import LuciClient
from .self_check import async_self_check

PREPARE_METHODS: Final = (
    "init",
    "status",
    "vpn",
    "rom_update",
    "mode",
    "cpe_mobile",
    "wan",
    "led",
    "wifi",
    "channels",
    "devices",
    "device_list",
    "device_restore",
    "ap",
    "new_status",
)

NEW_STATUS_MAP: Final = {
    "2g": ATTR_SENSOR_DEVICES_2_4,
    "5g": ATTR_SENSOR_DEVICES_5_0,
    "game": ATTR_SENSOR_DEVICES_5_0_GAME,
}

REPEATER_SKIP_ATTRS: Final = (
    ATTR_TRACKER_NAME,
    ATTR_TRACKER_IP,
    ATTR_TRACKER_DOWN_SPEED,
    ATTR_TRACKER_UP_SPEED,
    ATTR_TRACKER_ONLINE,
    ATTR_TRACKER_OPTIONAL_MAC,
)

# pylint: disable=too-many-branches,too-many-lines,too-many-arguments
class LuciUpdater(DataUpdateCoordinator):
    """Luci data updater for interaction with Luci API."""

    luci: LuciClient
    code: codes = codes.BAD_GATEWAY
    ip: str
    new_device_callback: CALLBACK_TYPE | None = None
    is_force_load: bool = False
    supports_guest: bool = True

    _store: Store | None = None

    _entry_id: str | None = None
    _scan_interval: int
    _activity_days: int
    _is_only_login: bool = False
    _is_reauthorization: bool = True

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
        
        # --- CB0401V2 / 5G CPE throttling ---
        self._is_cb0401v2: bool = False
        self._cpe_mobile_next_try = dt_util.utcnow()
        self._cpe_mobile_fail_count = 0
        self._cpe_detect_next_try = dt_util.utcnow()
        self._sms_next_try = dt_util.utcnow()
        self._cpe_newstatus_next_try = dt_util.utcnow()


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
            )

        self.data: dict[str, Any] = {}
        self.devices: dict[str, dict[str, Any]] = {}
        self._signals: dict[str, int] = {}
        self._moved_devices: list = []
        self._is_first_update: bool = True

    async def async_stop(self, clean_store: bool = False) -> None:
        """Stop updater

        :param clean_store: bool
        """

        if self.new_device_callback is not None:
            self.new_device_callback()  # pylint: disable=not-callable

        if clean_store and self._store is not None:
            await self._store.async_remove()
        else:
            await self._async_save_devices()

        with contextlib.suppress(Exception):
            await self.luci.logout()

    @cached_property
    def _update_interval(self) -> timedelta:
        """Update interval

        :return timedelta: update_interval
        """

        return timedelta(seconds=self._scan_interval)

    async def update(self, retry: int = 1) -> dict:
        """Update miwifi information.

        :param retry: int: Retry count
        :return dict: dict with luci data.
        """

        self.code = codes.OK

        _is_before_reauthorization: bool = self._is_reauthorization
        _err: LuciError | None = None

        try:
            if self._is_reauthorization or self._is_only_login or self._is_first_update:
                if self._is_first_update and retry == 1:
                    await self.luci.logout()
                    await asyncio.sleep(DEFAULT_CALL_DELAY)

                await self.luci.login()

            self._unsupported = await get_combined_unsupported(self.hass)

            for method in PREPARE_METHODS:
                if not self._is_only_login or method == "init":
                    
                    if method in ("devices", "device_list") and "new_status" in self.data and self.is_force_load:
                        continue
                    await self._async_prepare(method, self.data)

        except LuciConnectionError as _e:
            _err = _e
            self._is_reauthorization = False
            self.code = codes.NOT_FOUND
            await self.hass.async_add_executor_job(_LOGGER.warning, "[MiWiFi] LuciConnectionError en login: %s", _e)
            
        except LuciRequestError as _e:
            _err = _e
            self._is_reauthorization = True
            self.code = codes.FORBIDDEN
            await self.hass.async_add_executor_job(_LOGGER.warning, "[MiWiFi] LuciRequestError en login: %s", _e)


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

        if "new_status" not in self.data:
            await self._async_prepare_new_status(self.data)
            
        await self._async_prepare_topo()

        await self._async_prepare_compatibility()
        
        if isinstance(getattr(self, "capabilities", None), dict) and self.capabilities.get("portforward", False):
            await self._async_prepare_nat_rules()
        
        # Panel frontend version check (local + remote)
        try:
            from .frontend import read_local_version, read_remote_version
            async with aiohttp.ClientSession() as session:
                local = await read_local_version(self.hass)
                remote = await read_remote_version(session)
                self.data["panel_local_version"] = local
                self.data["panel_remote_version"] = remote
        except Exception as e:
            await self.hass.async_add_executor_job(_LOGGER.warning, "[MiWiFi] The frontend panel version could not be updated: %s", e)

        if self._is_only_login:
            await self.hass.async_add_executor_job(_LOGGER.debug, "[MiWiFi] Finalizó login (is_only_login), código=%s, data[ATTR_STATE]=%s", self.code, self.data.get(ATTR_STATE))

        return self.data

    @property
    def is_repeater(self) -> bool:
        """Is repeater property

        :return bool: is_repeater
        """

        return self.data.get(ATTR_SENSOR_MODE, Mode.DEFAULT).value > 0

    @property
    def supports_wan(self) -> bool:
        """Is supports wan

        :return bool
        """

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
            self._job,
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

        # ✅ CB0401V2: skip mode endpoint (often dead/404 on provider firmware)
        if self._is_cb0401v2_device(data):
            data[ATTR_SENSOR_MODE] = Mode.DEFAULT
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

        except Exception as e:
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

        # Support only 5G , 2.4G, 5G Game and Guest
        for wifi in _adapters:
            if "ifname" not in wifi:
                continue

            try:
                adapter: IfName = IfName(wifi["ifname"])
            except ValueError:
                continue

            # Guest network is not an adapter
            if adapter != IfName.WL14:
                length += 1

            if "status" in wifi:
                data[adapter.phrase] = int(wifi["status"]) > 0  # type: ignore

            if "channelInfo" in wifi and "channel" in wifi["channelInfo"]:
                data[f"{adapter.phrase}_channel"] = str(  # type: ignore
                    wifi["channelInfo"]["channel"]
                )
            elif "channel" in wifi:
                # CB0401V2 provider firmwares can return channel at top-level
                data[f"{adapter.phrase}_channel"] = str(wifi["channel"])  # type: ignore

            if "bandwidth" in wifi:
                data[f"{adapter.phrase}_bandwidth"] = str(wifi["bandwidth"])  # type: ignore

            if "txpwr" in wifi:
                data[f"{adapter.phrase}_signal_strength"] = wifi["txpwr"]  # type: ignore

            if wifi_data := self._prepare_wifi_data(wifi):
                data[f"{adapter.phrase}_data"] = wifi_data  # type: ignore

        data[ATTR_WIFI_ADAPTER_LENGTH] = length

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
            if "channelInfo" in data_field and "channelInfo" in data:
                data_field = data_field.replace("channelInfo.", "")

                if data_field in data["channelInfo"]:
                    wifi_data[field] = data["channelInfo"][data_field]
            elif data_field in data:
                wifi_data[field] = data[data_field]

        return wifi_data

    async def _async_prepare_channels(self, data: dict) -> None:
        """Prepare channels.

        :param data: dict
        """

        if not self._is_first_update or ATTR_WIFI_ADAPTER_LENGTH not in data:
            return

        for index in range(1, data.get(ATTR_WIFI_ADAPTER_LENGTH, 2) + 1):
            response: dict = await self.luci.avaliable_channels(index)

            if "list" not in response or len(response["list"]) == 0:
                continue

            data[f"{Wifi(index).phrase}_channels"] = [  # type: ignore
                str(channel["c"])
                for channel in response["list"]
                if "c" in channel and int(channel["c"]) > 0
            ]

    async def _async_prepare_devices(self, data: dict) -> None:
        """Prepare devices."""

        self.reset_counter()

        response: dict = await self.luci.wifi_connect_devices()

        now = dt_util.utcnow()
        macfilter_info: Optional[dict] = None

        # cooldown: si falló hace poco, no insistimos cada scan
        next_try = getattr(self, "_macfilter_next_try", now)
        if now >= next_try:
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

            if self.is_repeater and self.is_force_load:
                integrations = async_get_integrations(self.hass)

            for device in response["list"]:
                mac = device.get("mac", "").upper()

                self._signals[mac] = device["signal"] if "signal" in device else 0

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


    async def _async_prepare_device_list(self, data: dict) -> None:
        """Prepare MiWiFi device list (api/misystem/devicelist)."""

        response: dict = await self.luci.device_list()
        await asyncio.sleep(DEFAULT_CALL_DELAY)

        integrations = async_get_integrations(self.hass)

        # Map router MAC -> integration IP (routers / leaf nodes)
        mac_to_ip: dict[str, str] = {}
        for ip, integration in integrations.items():
            updater = integration.get(UPDATER)
            if isinstance(updater, LuciUpdater):
                mac = (updater.data or {}).get(ATTR_DEVICE_MAC_ADDRESS)
                if isinstance(mac, str) and mac:
                    mac_to_ip[mac.strip().upper()] = ip

        # Collect devices that should be pushed to a leaf updater (key = integration IP)
        add_to: dict[str, list[dict]] = {}

        for device in response.get("list", []):
            if not isinstance(device, dict):
                continue

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

            # If parent is a known leaf router MAC, this device belongs to that leaf updater
            if parent_mac and parent_mac in mac_to_ip:
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
                await self.add_device(device, action=action)

        # Push per-leaf device list to each leaf updater
        for ip, devices in add_to.items():
            integration = integrations.get(ip)
            if not integration:
                continue

            updater = integration.get(UPDATER)
            if not isinstance(updater, LuciUpdater):
                continue

            leaf_entry_id = getattr(updater, "_entry_id", None) or self._entry_id

            for device in devices:
                if not isinstance(device, dict):
                    continue

                # Ensure required keys for _build_device() exist on leaf side too
                device.setdefault(ATTR_TRACKER_ENTRY_ID, leaf_entry_id)
                device.setdefault(ATTR_TRACKER_UPDATER_ENTRY_ID, leaf_entry_id)

                await updater.add_device(device, action=DeviceAction.ADD)


    async def _async_prepare_device_restore(self, data: dict) -> None:
        """Restore devices

        :param data: dict
        """

        if not self._is_first_update or (self.is_repeater and self.is_force_load):
            return

        devices: dict | None = await self._async_load_devices()

        if devices is None:
            return

        integrations: dict = async_get_integrations(self.hass)

        for mac, device in devices.items():
            if mac in self.devices:
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

            _is_add: bool = True
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

                    if mac not in integration[UPDATER].devices:
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

            self.devices[mac] = device

            async_dispatcher_send(
                self.hass, SIGNAL_NEW_DEVICE, device | {ATTR_TRACKER_IS_RESTORED: True}
            )

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

        is_new: bool = device[ATTR_TRACKER_MAC] not in self.devices
        _device: dict[str, Any] = self._build_device(device, integrations)

        if (
            self.is_repeater
            and self.is_force_load
            and device[ATTR_TRACKER_MAC] in self.devices
        ):
            self.devices[device[ATTR_TRACKER_MAC]] |= {
                key: value
                for key, value in _device.items()
                if (
                    (not is_from_parent and key not in REPEATER_SKIP_ATTRS)
                    or (is_from_parent and key in REPEATER_SKIP_ATTRS)
                )
                and value is not None
            }
        else:
            self.devices[device[ATTR_TRACKER_MAC]] = _device

        if not is_from_parent and action == DeviceAction.MOVE:
            self._moved_devices.append(device[ATTR_TRACKER_MAC])
            action = DeviceAction.ADD

        if (
            is_new
            and action == DeviceAction.ADD
            and self.new_device_callback is not None
        ):
            async_dispatcher_send(
                self.hass, SIGNAL_NEW_DEVICE, self.devices[device[ATTR_TRACKER_MAC]]
            )
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

        if device[ATTR_TRACKER_MAC] in self._moved_devices or (
            self.is_repeater and self.is_force_load
        ):
            return

        if "new_status" not in self.data:
            # Defensive defaults to avoid KeyError on cold start / edge-cases
            self.data.setdefault(ATTR_SENSOR_DEVICES, 0)
            self.data.setdefault(ATTR_SENSOR_DEVICES_LAN, 0)
            self.data.setdefault(ATTR_SENSOR_DEVICES_GUEST, 0)
            self.data.setdefault(ATTR_SENSOR_DEVICES_2_4, 0)
            self.data.setdefault(ATTR_SENSOR_DEVICES_5_0, 0)
            self.data.setdefault(ATTR_SENSOR_DEVICES_5_0_GAME, 0)

            self.data[ATTR_SENSOR_DEVICES] += 1
            connection = _device.get(ATTR_TRACKER_CONNECTION)
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

        if self.is_force_load and "wifiIndex" in device:
            device["type"] = 6 if device["wifiIndex"] == 3 else device["wifiIndex"]

        connection: Connection | None = None

        with contextlib.suppress(ValueError):
            connection = Connection(int(device["type"])) if "type" in device else None

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

        return {
            ATTR_TRACKER_ENTRY_ID: device[ATTR_TRACKER_ENTRY_ID],
            ATTR_TRACKER_UPDATER_ENTRY_ID: device.get(
                ATTR_TRACKER_UPDATER_ENTRY_ID, device[ATTR_TRACKER_ENTRY_ID]
            ),
            ATTR_TRACKER_MAC: device[ATTR_TRACKER_MAC],
            ATTR_TRACKER_ROUTER_MAC_ADDRESS: router_mac,
            ATTR_TRACKER_SIGNAL: self._signals.get(device[ATTR_TRACKER_MAC]),
            ATTR_TRACKER_NAME: device.get("name", device[ATTR_TRACKER_MAC]),
            ATTR_TRACKER_IP: ip_value,
            ATTR_TRACKER_CONNECTION: connection,
            # ✅ Safe numeric parsing (handles "" / None)
            ATTR_TRACKER_DOWN_SPEED: _to_float(ip_attr.get("downspeed")) if (is_online and isinstance(ip_attr, dict)) else 0.0,
            ATTR_TRACKER_UP_SPEED: _to_float(ip_attr.get("upspeed")) if (is_online and isinstance(ip_attr, dict)) else 0.0,
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

        response: dict = await self.luci.wifi_ap_signal()

        if "signal" in response and isinstance(response["signal"], int):
            data[ATTR_SENSOR_AP_SIGNAL] = response["signal"]

    async def _async_prepare_new_status(self, data: dict) -> None:
        """Prepare new status.

        :param data: dict
        """

        if not self.is_force_load:
            #await self.hass.async_add_executor_job(_LOGGER.warning, "⚠️ [new_status] is_force_load is False. Skipping new_status.")
            return

        response: dict = await self.luci.new_status()
        #await self.hass.async_add_executor_job(_LOGGER.warning, "📶 [new_status] Raw response: %s", response)

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


    def reset_counter(self, is_force: bool = False, is_remove: bool = False) -> None:
        """Reset counter

        :param is_force: bool: Force reset
        :param is_remove: bool: Force remove
        """

        if self.is_repeater and not self.is_force_load and not is_force:
            return

        for attr in [
            ATTR_SENSOR_DEVICES,
            ATTR_SENSOR_DEVICES_LAN,
            ATTR_SENSOR_DEVICES_GUEST,
            ATTR_SENSOR_DEVICES_2_4,
            ATTR_SENSOR_DEVICES_5_0,
            ATTR_SENSOR_DEVICES_5_0_GAME,
        ]:
            if attr in self.data and is_remove:
                del self.data[attr]
            elif not is_remove:
                self.data[attr] = 0

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

                except Exception as e2:
                    await self.hass.async_add_executor_job(
                        _LOGGER.debug,
                        "[MiWiFi] NAT rules retry after re-login failed: %s (cooldown 1m)",
                        e2,
                    )
                    self.data["nat_rules"] = {"ftype_1": [], "ftype_2": [], "total": 0}
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


async def async_update_panel_entity(hass: HomeAssistant, updater: LuciUpdater, async_add_entities=None):
    from .update import MiWifiPanelUpdate
    """Handle dynamic creation/removal of panel update entity."""

    entity_registry = er.async_get(hass)
    mac = updater.data.get(ATTR_DEVICE_MAC_ADDRESS)
    entity_id = f"update.miwifi_{mac.replace(':','_')}_miwifi_panel_frontend"

    topo_graph = (((updater.data or {}).get("topo_graph") or {}).get("graph") or {})
    is_main = topo_graph.get("is_main")
    is_auto = topo_graph.get("is_main_auto", False)

    entry = entity_registry.async_get(entity_id)

    if is_main:
        source = "auto" if is_auto else "manual"
        if not entry and async_add_entities:
            await hass.async_add_executor_job(_LOGGER.debug, "[MiWiFi] 🟢 Creating update panel (%s main selection)", source)
            panel_entity = MiWifiPanelUpdate(f"{updater.entry_id}_miwifi_panel", updater)
            async_add_entities([panel_entity])
        elif not entry:
            await hass.async_add_executor_job(_LOGGER.debug, "[MiWiFi] ⚠ Cannot create update panel (%s main) because async_add_entities is not available", source)
    else:
        if entry:
            await hass.async_add_executor_job(_LOGGER.debug, "[MiWiFi] 🔴 Removing update panel because it is no longer main")
            entity_registry.async_remove(entity_id)
