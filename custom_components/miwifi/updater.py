
"""Luci data updater (dispatch inline + device scan toggle + async_stop)."""
from __future__ import annotations
import asyncio
import aiohttp
import contextlib
import time
from datetime import datetime, timedelta
from functools import cached_property
from typing import Any, Final

from .logger import _LOGGER
from .notifier import MiWiFiNotifier
from .miwifi_utils import parse_memory_to_mb
from .unsupported import UNSUPPORTED
from homeassistant.util import dt as dt_util  # noqa: F401
import homeassistant.components.persistent_notification as pn  # noqa: F401
from homeassistant.const import CONF_IP_ADDRESS
from homeassistant.core import CALLBACK_TYPE, HomeAssistant, callback
from homeassistant.helpers import event
from homeassistant.helpers.device_registry import CONNECTION_NETWORK_MAC
from homeassistant.helpers.dispatcher import async_dispatcher_send
from homeassistant.helpers.entity import DeviceInfo
from homeassistant.helpers import entity_registry as er
from homeassistant.helpers.httpx_client import get_async_client
from homeassistant.helpers.storage import Store, STORAGE_DIR  # noqa: F401
from homeassistant.helpers.update_coordinator import DataUpdateCoordinator
from homeassistant.helpers.translation import async_get_translations  # noqa: F401
from homeassistant.util import utcnow
from homeassistant.config_entries import ConfigEntry
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
    UPDATER,
    CONF_IS_TRACK_DEVICES,
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
    disable_device_scan: bool = False

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
        self.luci = LuciClient(
            get_async_client(hass, False),
            ip,
            password,
            EncryptionAlgorithm(encryption),
            timeout,
            protocol,
        )
        self.ip = ip
        self.is_force_load = is_force_load
        self._entry_id = entry_id
        self._scan_interval = scan_interval
        self._activity_days = activity_days
        self._is_only_login = is_only_login
        # WAN counters cache for delta fallback
        self._last_wan_counters: dict[str, int] | None = None
        self._last_wan_t: float | None = None

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
        self._moved_devices: list[str] = []
        self._is_first_update: bool = True

        # Read option: is_track_devices; convert to disable flag
        if self._entry_id:
            entry: ConfigEntry | None = self.hass.config_entries.async_get_entry(self._entry_id)
            if entry is not None:
                is_track_devices = entry.options.get(
                    CONF_IS_TRACK_DEVICES,
                    entry.data.get(CONF_IS_TRACK_DEVICES, True),
                )
                self.disable_device_scan = not bool(is_track_devices)
                _LOGGER.debug("[MiWiFi] disable_device_scan=%s (entry_id=%s)", self.disable_device_scan, self._entry_id)
                if self.disable_device_scan:
                    if len(self.devices) > 0:
                        _LOGGER.debug("[MiWiFi] Purging %s remembered devices because tracking is disabled", len(self.devices))
                    self.devices.clear()
                    self.reset_counter(is_remove=True)

    async def async_stop(self, clean_store: bool = False) -> None:
        """Stop updater and optionally clean stored devices."""
        if self.new_device_callback is not None:
            try:
                self.new_device_callback()  # type: ignore[misc]
            except Exception:
                pass
        try:
            if clean_store and self._store is not None:
                await self._store.async_remove()
            else:
                await self._async_save_devices()
        except Exception:
            pass
        with contextlib.suppress(Exception):
            await self.luci.logout()

    @cached_property
    def _update_interval(self) -> timedelta:
        return timedelta(seconds=self._scan_interval)

    async def update(self, retry: int = 1) -> dict:
        self.code = codes.OK
        _is_before_reauthorization: bool = self._is_reauthorization
        _err: LuciError | None = None
        try:
            if self._is_reauthorization or self._is_only_login or self._is_first_update:
                if self._is_first_update and retry == 1:
                    await self.luci.logout()
                    await asyncio.sleep(DEFAULT_CALL_DELAY)
                await self.luci.login()
                # Init defaults
                self.data = self.data or {}
                for _k in (
                    ATTR_SENSOR_DEVICES,
                    ATTR_SENSOR_DEVICES_LAN,
                    ATTR_SENSOR_DEVICES_GUEST,
                    ATTR_SENSOR_DEVICES_2_4,
                    ATTR_SENSOR_DEVICES_5_0,
                    ATTR_SENSOR_DEVICES_5_0_GAME,
                ):
                    self.data.setdefault(_k, 0)
                self.data.setdefault("new_status", None)
                # Ensure WAN speed keys exist to avoid 'unknown'
                self.data.setdefault(ATTR_SENSOR_WAN_DOWNLOAD_SPEED, 0)
                self.data.setdefault(ATTR_SENSOR_WAN_UPLOAD_SPEED, 0)

                # Dispatch inline with device-scan skip
                methods = PREPARE_METHODS
                if self.disable_device_scan:
                    methods = tuple(m for m in methods if m not in ("devices", "device_list", "new_status"))
                    _LOGGER.debug("[MiWiFi] device_scan_disabled=True; skipping devices/device_list/new_status")

                for method in methods:
                    if not self._is_only_login or method == "init":
                        if (
                            method in ("devices", "device_list")
                            and self.is_force_load
                            and self.data.get("new_status") is not None
                        ):
                            continue
                        if (
                            method in UNSUPPORTED
                            and self.data.get(ATTR_MODEL, Model.NOT_KNOWN) in UNSUPPORTED[method]
                        ):
                            await self.hass.async_add_executor_job(
                                _LOGGER.debug,
                                "[MiWiFi] Skipping '%s' for model '%s' (unsupported)",
                                method,
                                self.data.get(ATTR_MODEL),
                            )
                            continue
                        action = getattr(self, f"_async_prepare_{method}", None)
                        if action is None:
                            _LOGGER.debug("[MiWiFi] No existe handler '_async_prepare_%s'; se omite.", method)
                            continue
                        await action(self.data)
        except LuciConnectionError as _e:
            _err = _e
            self._is_reauthorization = False
            self.code = codes.NOT_FOUND
            await self.hass.async_add_executor_job(
                _LOGGER.warning, "[MiWiFi] LuciConnectionError en login: %s", _e
            )
        except LuciRequestError as _e:
            _err = _e
            self._is_reauthorization = True
            self.code = codes.FORBIDDEN
            await self.hass.async_add_executor_job(
                _LOGGER.warning, "[MiWiFi] LuciRequestError en login: %s", _e
            )
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
                await self.hass.async_add_executor_job(
                    _LOGGER.warning,
                    "Error connecting to router (attempt #%s of %s): %r",
                    retry,
                    DEFAULT_RETRY,
                    _err,
                )
                await asyncio.sleep(retry)
                return await self.update(retry + 1)

        if not self._is_only_login:
            self._clean_devices()
            if "new_status" not in self.data and not self.disable_device_scan:
                await self._async_prepare_new_status(self.data)
            await self._async_prepare_topo()
            await self._async_prepare_compatibility()
            if isinstance(getattr(self, "capabilities", None), dict) and self.capabilities.get("portforward", False):
                await self._async_prepare_nat_rules()

        # Panel frontend version check
        try:
            from .frontend import read_local_version, read_remote_version

            async with aiohttp.ClientSession() as session:
                local = await read_local_version(self.hass)
                remote = await read_remote_version(session)
            self.data["panel_local_version"] = local
            self.data["panel_remote_version"] = remote
        except Exception as e:
            await self.hass.async_add_executor_job(
                _LOGGER.warning,
                "[MiWiFi] The frontend panel version could not be updated: %s",
                e,
            )

        self.data.setdefault("miwifi_flags", {})
        self.data["miwifi_flags"]["disable_device_scan"] = self.disable_device_scan

        # Always refresh WAN speeds in every cycle to avoid stale/unknown
        try:
            await self._async_prepare_status(self.data)
        except Exception as e:
            await self.hass.async_add_executor_job(
                _LOGGER.debug, "[MiWiFi] status refresh failed: %s", e
            )

        if self._is_only_login:
            await self.hass.async_add_executor_job(
                _LOGGER.debug,
                "[MiWiFi] Finalizó login (is_only_login), código=%s, data[ATTR_STATE]=%s",
                self.code,
                self.data.get(ATTR_STATE),
            )
        return self.data

    @property
    def is_repeater(self) -> bool:
        return self.data.get(ATTR_SENSOR_MODE, Mode.DEFAULT).value > 0

    @property
    def supports_wan(self) -> bool:
        return self.data.get(ATTR_BINARY_SENSOR_WAN_STATE, False)

    @property
    def supports_game(self) -> bool:
        return self.data.get(ATTR_SWITCH_WIFI_5_0_GAME, None) is not None

    @property
    def supports_update(self) -> bool:
        return len(self.data.get(ATTR_UPDATE_FIRMWARE, {})) != 0

    @property
    def device_info(self):
        return DeviceInfo(
            identifiers={(DOMAIN, self.data.get(ATTR_DEVICE_MAC_ADDRESS, self.ip))},
            connections={
                (CONNECTION_NETWORK_MAC, self.data.get(ATTR_DEVICE_MAC_ADDRESS, self.ip)),
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
        if getattr(self, "_unsub_refresh", None):  # type: ignore[attr-defined]
            self._unsub_refresh()  # type: ignore[attr-defined]
        self._unsub_refresh = None
        self._unsub_refresh = event.async_track_point_in_utc_time(
            self.hass,
            self._job,  # type: ignore[attr-defined]
            utcnow().replace(microsecond=0) + offset,
        )

    # ----- Handlers -----
    async def _async_prepare_init(self, data: dict) -> None:
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
            manufacturer: list[str] = response["model"].split(".")
            data[ATTR_DEVICE_MANUFACTURER] = manufacturer[0].title()
        elif "hardware" in response:
            data[ATTR_DEVICE_MODEL] = response["hardware"]
        if "routername" in response:
            data[ATTR_DEVICE_NAME] = response["routername"]
        if "romversion" in response and "countrycode" in response:
            data[ATTR_DEVICE_SW_VERSION] = f"{response['romversion']} ({response['countrycode']})"
        if "hardware" in response:
            try:
                data[ATTR_MODEL] = Model(response["hardware"].lower())
            except ValueError as _e:
                # Solo si el modelo NO se reconoce, notificar y marcar como no compatible
                await async_self_check(self.hass, self.luci, response["hardware"])
                if not self._is_only_login:
                    notifier = MiWiFiNotifier(self.hass)
                    translations = await notifier.get_translations()
                    title = translations.get("notifications", {}).get("unsupported_router_title", "Unsupported Router")
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
                    raise LuciError(f"Router {self.ip} not supported") from _e
                self.code = codes.CONFLICT
                return
        # Si llegamos aquí, el modelo es válido: NO notificar, continuar flujo normal

    async def _async_prepare_status(self, data: dict) -> None:
        response: dict = await self.luci.status()
        if "hardware" in response and isinstance(response["hardware"], dict):
            if "mac" in response["hardware"]:
                data[ATTR_DEVICE_MAC_ADDRESS] = response["hardware"]["mac"]
            if "sn" in response["hardware"]:
                data[ATTR_DEVICE_HW_VERSION] = response["hardware"]["sn"]
            if "version" in response["hardware"]:
                data[ATTR_UPDATE_CURRENT_VERSION] = response["hardware"]["version"]
        if "upTime" in response:
            data[ATTR_SENSOR_UPTIME] = str(timedelta(seconds=int(float(response["upTime"])) ))
        if "mem" in response and isinstance(response["mem"], dict):
            if "usage" in response["mem"]:
                data[ATTR_SENSOR_MEMORY_USAGE] = int(float(response["mem"]["usage"]) * 100)
            if "total" in response["mem"]:
                data[ATTR_SENSOR_MEMORY_TOTAL] = parse_memory_to_mb(response["mem"]["total"])
        if "temperature" in response:
            data[ATTR_SENSOR_TEMPERATURE] = float(response["temperature"])  # <- FIX: sin barra de continuación

        # ---- WAN speeds from misystem/status with fallback to wan_statistics ----
        def _to_int(v) -> int:
            try:
                if v is None:
                    return 0
                # Accept strings and floats
                return int(float(v))
            except Exception:
                return 0

        wan = response.get("wan", {}) if isinstance(response, dict) else {}
        down_bps = _to_int(wan.get("downspeed"))
        up_bps = _to_int(wan.get("upspeed"))

        if down_bps == 0 and up_bps == 0:
            # Try xqnetwork/wan_statistics
            try:
                stats = await self.luci.wan_statistics()
            except Exception as e:
                await self.hass.async_add_executor_job(
                    _LOGGER.debug, "[MiWiFi] wan_statistics failed: %s", e
                )
                stats = {}
            st = stats.get("statistics", {}) if isinstance(stats, dict) else {}
            down_bps = _to_int(st.get("downspeed")) or 0
            up_bps = _to_int(st.get("upspeed")) or 0

            # Optional third fallback: compute from counters delta
            now = time.time()
            download_c = _to_int(st.get("download"))
            upload_c = _to_int(st.get("upload"))
            if (down_bps == 0 and up_bps == 0) and download_c and upload_c:
                if self._last_wan_counters and self._last_wan_t:
                    dt = max(1.0, now - self._last_wan_t)
                    down_bps = max(0, int((download_c - self._last_wan_counters.get("download", 0)) / dt))
                    up_bps = max(0, int((upload_c - self._last_wan_counters.get("upload", 0)) / dt))
                # update cache
                self._last_wan_counters = {"download": download_c, "upload": upload_c}
                self._last_wan_t = now

        # Save values (B/s) for sensors.py to convert if needed
        down_bps = int(down_bps or 0)
        up_bps = int(up_bps or 0)
        data[ATTR_SENSOR_WAN_DOWNLOAD_SPEED] = down_bps
        data[ATTR_SENSOR_WAN_UPLOAD_SPEED] = up_bps
        await self.hass.async_add_executor_job(
            _LOGGER.debug,
            "[MiWiFi] WAN speeds → down=%s B/s, up=%s B/s",
            down_bps,
            up_bps,
        )

    async def _async_prepare_vpn(self, data: dict) -> None:
        with contextlib.suppress(LuciError):
            response: dict = await self.luci.vpn_status()
            data = {ATTR_SENSOR_VPN_UPTIME: 0, ATTR_BINARY_SENSOR_VPN_STATE: False}
            if "uptime" in response:
                data = {
                    ATTR_SENSOR_VPN_UPTIME: str(timedelta(seconds=int(float(response["uptime"])) )),
                    ATTR_BINARY_SENSOR_VPN_STATE: int(float(response["uptime"])) > 0,
                }

    async def _async_prepare_rom_update(self, data: dict) -> None:
        if ATTR_UPDATE_CURRENT_VERSION not in data:
            return
        _rom_info: dict = {
            ATTR_UPDATE_CURRENT_VERSION: data[ATTR_UPDATE_CURRENT_VERSION],
            ATTR_UPDATE_LATEST_VERSION: data[ATTR_UPDATE_CURRENT_VERSION],
            ATTR_UPDATE_TITLE: f"{data.get(ATTR_DEVICE_MANUFACTURER, DEFAULT_MANUFACTURER)}"
            f" {data.get(ATTR_MODEL, Model.NOT_KNOWN).name}"
            f" ({data.get(ATTR_DEVICE_NAME, DEFAULT_NAME)})",
        }
        try:
            response: dict = await self.luci.rom_update()
        except LuciError:
            response = {}
        if not isinstance(response, dict) or "needUpdate" not in response or response["needUpdate"] != 1:
            data[ATTR_UPDATE_FIRMWARE] = _rom_info
            return
        with contextlib.suppress(KeyError):
            data[ATTR_UPDATE_FIRMWARE] = {
                **_rom_info,
                ATTR_UPDATE_LATEST_VERSION: response["version"],
                ATTR_UPDATE_DOWNLOAD_URL: response["downloadUrl"],
                ATTR_UPDATE_RELEASE_URL: response["changelogUrl"],
                ATTR_UPDATE_FILE_SIZE: response["fileSize"],
                ATTR_UPDATE_FILE_HASH: response["fullHash"],
            }

    async def _async_prepare_mode(self, data: dict) -> None:
        if data.get(ATTR_SENSOR_MODE, Mode.DEFAULT) == Mode.MESH:
            return
        response: dict = await self.luci.mode()
        if "mode" in response:
            with contextlib.suppress(ValueError):
                try:
                    data[ATTR_SENSOR_MODE] = Mode(int(response["mode"]))
                except Exception:
                    data[ATTR_SENSOR_MODE] = Mode(0)
                return
        data[ATTR_SENSOR_MODE] = Mode.DEFAULT

    async def _async_prepare_wan(self, data: dict) -> None:
        try:
            response: dict = await self.luci.wan_info()
            await self.hass.async_add_executor_job(_LOGGER.debug, "WAN info response: %s", response)
            info = response.get("info") if isinstance(response, dict) else {}
            if not isinstance(info, dict):
                await self.hass.async_add_executor_job(_LOGGER.debug, "WAN info['info'] is not a dict, got: %s", type(info))
                info = {}
            elif not info:
                await self.hass.async_add_executor_job(_LOGGER.debug, "WAN info['info'] is empty.")

            data[ATTR_BINARY_SENSOR_WAN_STATE] = info.get("uptime", 0) > 0
            data[ATTR_BINARY_SENSOR_WAN_LINK] = info.get("link", 0) == 1

            ipv4_list = info.get("ipv4", [])
            if isinstance(ipv4_list, list) and ipv4_list and isinstance(ipv4_list[0], dict):
                data[ATTR_SENSOR_WAN_IP] = ipv4_list[0].get("ip")
            else:
                data[ATTR_SENSOR_WAN_IP] = None

            details = info.get("details")
            if isinstance(details, dict):
                data[ATTR_SENSOR_WAN_TYPE] = details.get("wanType", "unknown")
            else:
                data[ATTR_SENSOR_WAN_TYPE] = "unknown"
        except Exception as e:
            await self.hass.async_add_executor_job(_LOGGER.error, "Error while preparing WAN info: %s", e)
            data[ATTR_BINARY_SENSOR_WAN_STATE] = False
            data[ATTR_BINARY_SENSOR_WAN_LINK] = False
            data[ATTR_SENSOR_WAN_IP] = None
            data[ATTR_SENSOR_WAN_TYPE] = "unknown"

    async def _async_prepare_led(self, data: dict) -> None:
        response: dict = await self.luci.led()
        if "status" in response:
            data[ATTR_LIGHT_LED] = response["status"] == 1
            return
        data[ATTR_LIGHT_LED] = False

    async def _async_prepare_wifi(self, data: dict) -> None:
        try:
            response: dict = await self.luci.wifi_detail_all()
        except LuciError:
            return
        data[ATTR_BINARY_SENSOR_DUAL_BAND] = int(response.get("bsd", 0)) == 1 if "bsd" in response else False
        if "info" not in response or len(response["info"]) == 0:
            return
        _adapters: list = await self._async_prepare_wifi_guest(response["info"])
        length: int = 0
        for wifi in _adapters:
            if "ifname" not in wifi:
                continue
            try:
                adapter: IfName = IfName(wifi["ifname"])
            except ValueError:
                continue
            if adapter != IfName.WL14:
                length += 1
            if "status" in wifi:
                data[adapter.phrase] = int(wifi["status"]) > 0  # type: ignore
            if "channelInfo" in wifi and "channel" in wifi["channelInfo"]:
                data[f"{adapter.phrase}_channel"] = str(wifi["channelInfo"]["channel"])  # type: ignore
            if "txpwr" in wifi:
                data[f"{adapter.phrase}_signal_strength"] = wifi["txpwr"]  # type: ignore
            if wifi_data := self._prepare_wifi_data(wifi):
                data[f"{adapter.phrase}_data"] = wifi_data  # type: ignore
        data[ATTR_WIFI_ADAPTER_LENGTH] = length

    async def _async_prepare_wifi_guest(self, adapters: list) -> list:
        if not self.supports_guest:
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
        wifi_data: dict = {}
        for data_field, field in ATTR_WIFI_DATA_FIELDS.items():
            if "channelInfo" in data_field and "channelInfo" in data:
                key = data_field.replace("channelInfo.", "")
                if key in data["channelInfo"]:
                    wifi_data[field] = data["channelInfo"][key]
            elif data_field in data:
                wifi_data[field] = data[data_field]
        return wifi_data

    async def _async_prepare_channels(self, data: dict) -> None:
        if not self._is_first_update or ATTR_WIFI_ADAPTER_LENGTH not in data:
            return
        for index in range(1, data.get(ATTR_WIFI_ADAPTER_LENGTH, 2) + 1):
            response: dict = await self.luci.avaliable_channels(index)
            if "list" not in response or len(response["list"]) == 0:
                continue
            data[f"{Wifi(index).phrase}_channels"] = [  # type: ignore
                str(channel["c"]) for channel in response["list"] if "c" in channel and int(channel["c"]) > 0
            ]

    async def _async_prepare_devices(self, data: dict) -> None:
        if self.disable_device_scan:
            return
        self.reset_counter()
        response: dict = await self.luci.wifi_connect_devices()
        macfilter_info: dict = {}
        try:
            macfilter_info = await self.luci.macfilter_info()
        except Exception as e:
            await self.hass.async_add_executor_job(
                _LOGGER.warning,
                "[MiWiFi] macfilter_info failed for %s: %s",
                self.ip,
                e,
            )
        filter_macs: dict[str, int] = {}
        for entry in macfilter_info.get("flist", []):
            mac = entry.get("mac", "").upper()
            wan = entry.get("authority", {}).get("wan", 1)
            filter_macs[mac] = wan
        for entry in macfilter_info.get("list", []):
            mac = entry.get("mac", "").upper()
            wan = entry.get("authority", {}).get("wan", 1)
            filter_macs[mac] = wan

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
                    device = {ATTR_TRACKER_ENTRY_ID: self._entry_id, ATTR_TRACKER_UPDATER_ENTRY_ID: self._entry_id}
                    action: DeviceAction = DeviceAction.ADD
                    if self._mass_update_device(device, integrations):
                        action = DeviceAction.SKIP
                    if ATTR_TRACKER_MAC in device:
                        await self.add_device(device, action=action)

    async def _async_prepare_device_list(self, data: dict) -> None:
        if self.disable_device_scan:
            return
        if self.is_repeater:
            return
        totals_by_mac: dict[str, int] = {}
        try:
            misystem = await self.luci.misystem_info()
        except Exception as e:
            await self.hass.async_add_executor_job(
                _LOGGER.warning,
                "[MiWiFi] misystem_info failed for %s (device_list): %s",
                self.ip,
                e,
            )
            misystem = {}
        else:
            for dev in misystem.get("dev", []):
                mac_dev = (dev.get("mac") or "").upper()
                if not mac_dev:
                    continue
                try:
                    down = int(dev.get("download") or 0)
                    up = int(dev.get("upload") or 0)
                except (TypeError, ValueError):
                    continue
                total = down + up
                if total >= 0:
                    totals_by_mac[mac_dev] = total

        response: dict = await self.luci.device_list()
        if "list" not in response or len(response["list"]) == 0:
            if len(self._signals) > 0 and not self.is_repeater:
                self.reset_counter(is_remove=True)
            data[ATTR_SENSOR_MODE] = Mode.MESH
            if self.is_force_load:
                await self._async_prepare_devices(data)
            return

        macfilter_info: dict = {}
        try:
            macfilter_info = await self.luci.macfilter_info()
        except Exception as e:
            await self.hass.async_add_executor_job(
                _LOGGER.warning,
                "[MiWiFi] macfilter_info failed for %s (device_list): %s",
                self.ip,
                e,
            )
        filter_macs: dict[str, int] = {}
        for entry in macfilter_info.get("flist", []):
            mac = entry.get("mac", "").upper()
            wan = entry.get("authority", {}).get("wan", 1)
            filter_macs[mac] = wan
        for entry in macfilter_info.get("list", []):
            mac = entry.get("mac", "").upper()
            wan = entry.get("authority", {}).get("wan", 1)
            filter_macs[mac] = wan

        integrations: dict[str, dict] = async_get_integrations(self.hass)
        mac_to_ip: dict[str, str] = {
            device[ATTR_TRACKER_MAC]: device["ip"][0]["ip"]
            for device in response["list"]
            if "ip" in device and len(device["ip"]) > 0 and ATTR_TRACKER_MAC in device
        }
        add_to: dict[str, dict] = {}
        self.reset_counter(is_force=True)
        for device in response["list"]:
            action: DeviceAction = DeviceAction.ADD
            if (
                "parent" in device
                and len(device["parent"]) > 0
                and device["parent"] in mac_to_ip
                and mac_to_ip[device["parent"]] in integrations
                and mac_to_ip[device["parent"]] != self.ip
            ):
                integration: dict = integrations[mac_to_ip[device["parent"]]]
                if (
                    ATTR_TRACKER_MAC in device
                    and device[ATTR_TRACKER_MAC] not in integration[UPDATER].devices
                    and not integration[UPDATER].is_force_load
                ):
                    action = DeviceAction.MOVE
                else:
                    action = DeviceAction.SKIP
                device[ATTR_TRACKER_ENTRY_ID] = integration[ATTR_TRACKER_ENTRY_ID]
                if ATTR_DEVICE_MAC_ADDRESS in integration[UPDATER].data:
                    if mac_to_ip[device["parent"]] not in add_to:
                        add_to[mac_to_ip[device["parent"]]] = {}
                    add_to[mac_to_ip[device["parent"]]][device[ATTR_TRACKER_MAC]] = (device, action)
                if integration[UPDATER].is_force_load:
                    continue
            else:
                device[ATTR_TRACKER_ENTRY_ID] = self._entry_id
            if (
                ATTR_TRACKER_MAC in device
                and device[ATTR_TRACKER_MAC] in self._moved_devices
            ):
                device[ATTR_TRACKER_UPDATER_ENTRY_ID] = self._entry_id
                device[ATTR_TRACKER_ROUTER_MAC_ADDRESS] = (self.data.get(ATTR_DEVICE_MAC_ADDRESS, None),)
                if self._mass_update_device(device, integrations):
                    action = DeviceAction.SKIP
                self._moved_devices.remove(device[ATTR_TRACKER_MAC])
            if (
                ATTR_TRACKER_MAC in device
                and device[ATTR_TRACKER_MAC] not in self._moved_devices
            ):
                device[ATTR_TRACKER_UPDATER_ENTRY_ID] = self._entry_id
                mac = device.get("mac", "").upper()
                if mac in filter_macs:
                    device[ATTR_TRACKER_INTERNET_BLOCKED] = (filter_macs[mac] == 0)
                else:
                    device[ATTR_TRACKER_INTERNET_BLOCKED] = False
                total_usage = totals_by_mac.get(mac)
                if total_usage is not None:
                    device[ATTR_TRACKER_TOTAL_USAGE] = total_usage
                await self.add_device(device, action=action, integrations=integrations)

        if not add_to:
            return
        await asyncio.sleep(DEFAULT_CALL_DELAY)
        for _ip, devices in add_to.items():
            if not integrations[_ip][UPDATER].is_force_load:
                integrations[_ip][UPDATER].reset_counter(is_force=True)
            for device, action in devices.values():
                if ATTR_TRACKER_MAC in device:
                    await integrations[_ip][UPDATER].add_device(
                        device, True, action, integrations,
                    )

    async def _async_prepare_device_restore(self, data: dict) -> None:
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
                device[ATTR_TRACKER_CONNECTION] = (
                    Connection(int(device[ATTR_TRACKER_CONNECTION]))
                    if ATTR_TRACKER_CONNECTION in device and device[ATTR_TRACKER_CONNECTION] is not None
                    else None
                )
            except ValueError:
                device[ATTR_TRACKER_CONNECTION] = None
            _is_add: bool = True
            if device[ATTR_TRACKER_ENTRY_ID] != self._entry_id:
                for integration in integrations.values():
                    if integration[ATTR_TRACKER_ENTRY_ID] != device[ATTR_TRACKER_ENTRY_ID]:
                        continue
                    if integration[UPDATER].is_force_load:
                        if mac in integration[UPDATER].devices:
                            integration[UPDATER].devices[mac] = {
                                attr: device[attr]
                                for attr in [ATTR_TRACKER_NAME, ATTR_TRACKER_IP]
                                if attr in device and device[attr] is not None
                            }
                            _is_add = False
                            break
                        if mac not in integration[UPDATER].devices:
                            _dev = {
                                ATTR_TRACKER_ROUTER_MAC_ADDRESS: integration[UPDATER].data.get(
                                    ATTR_DEVICE_MAC_ADDRESS,
                                    device[ATTR_TRACKER_ROUTER_MAC_ADDRESS],
                                ),
                                ATTR_TRACKER_UPDATER_ENTRY_ID: self._entry_id,
                            }
                            integration[UPDATER].devices[mac] = _dev
                            self._moved_devices.append(mac)
                            break
            if not _is_add:
                continue
            if mac not in self._moved_devices:
                _dev2 = {ATTR_TRACKER_UPDATER_ENTRY_ID: self._entry_id, ATTR_TRACKER_ENTRY_ID: self._entry_id}
                self.devices[mac] = _dev2
                async_dispatcher_send(
                    self.hass, SIGNAL_NEW_DEVICE, self.devices[mac] | {ATTR_TRACKER_IS_RESTORED: True}
                )
        self._clean_devices()

    async def add_device(
        self,
        device: dict,
        is_from_parent: bool = False,
        action: DeviceAction = DeviceAction.ADD,
        integrations: dict[str, Any] | None = None,
    ) -> None:
        is_new: bool = device[ATTR_TRACKER_MAC] not in self.devices
        _device: dict[str, Any] = self._build_device(device, integrations)
        if (
            self.is_repeater
            and self.is_force_load
            and device[ATTR_TRACKER_MAC] in self.devices
        ):
            self.devices[device[ATTR_TRACKER_MAC]] = {
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
            await self.hass.async_add_executor_job(
                _LOGGER.debug, "Found new device: %s", self.devices[device[ATTR_TRACKER_MAC]]
            )
            if ATTR_TRACKER_FIRST_SEEN not in self.devices[device[ATTR_TRACKER_MAC]]:
                self.hass.async_create_task(
                    self._async_notify_new_device(
                        device.get("name", device[ATTR_TRACKER_MAC]),
                        device[ATTR_TRACKER_MAC],
                    )
                )
        elif action == DeviceAction.MOVE:
            await self.hass.async_add_executor_job(
                _LOGGER.debug, "Move device: %s", device[ATTR_TRACKER_MAC]
            )
        if device[ATTR_TRACKER_MAC] in self._moved_devices or (
            self.is_repeater and self.is_force_load
        ):
            return
        if "new_status" not in self.data:
            self.data[ATTR_SENSOR_DEVICES] = self.data.get(ATTR_SENSOR_DEVICES, 0) + 1
            connection = _device.get(ATTR_TRACKER_CONNECTION)
            code: str = (connection or Connection.LAN).name.replace("WIFI_", "")
            code = f"{ATTR_SENSOR_DEVICES}_{code}".lower()
            self.data[code] = self.data.get(code, 0) + 1

    def _build_device(
        self, device: dict, integrations: dict[str, Any] | None = None
    ) -> dict[str, Any]:
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
        return {
            ATTR_TRACKER_ENTRY_ID: device[ATTR_TRACKER_ENTRY_ID],
            ATTR_TRACKER_UPDATER_ENTRY_ID: device.get(
                ATTR_TRACKER_UPDATER_ENTRY_ID, device[ATTR_TRACKER_ENTRY_ID]
            ),
            ATTR_TRACKER_MAC: device[ATTR_TRACKER_MAC],
            ATTR_TRACKER_ROUTER_MAC_ADDRESS: self.data.get(
                ATTR_DEVICE_MAC_ADDRESS, None
            ),
            ATTR_TRACKER_SIGNAL: self._signals.get(device[ATTR_TRACKER_MAC]),
            ATTR_TRACKER_NAME: device.get("name", device[ATTR_TRACKER_MAC]),
            ATTR_TRACKER_IP: ip_attr["ip"] if ip_attr is not None else None,
            ATTR_TRACKER_CONNECTION: connection,
            ATTR_TRACKER_DOWN_SPEED: float(ip_attr["downspeed"]) if ip_attr and "downspeed" in ip_attr else 0.0,
            ATTR_TRACKER_UP_SPEED: float(ip_attr["upspeed"]) if ip_attr and "upspeed" in ip_attr else 0.0,
            ATTR_TRACKER_ONLINE: str(
                timedelta(
                    seconds=int(ip_attr["online"] if ip_attr else 0)
                )
            ),
            ATTR_TRACKER_LAST_ACTIVITY: datetime.now().replace(microsecond=0).isoformat(),
            ATTR_TRACKER_FIRST_SEEN: self.devices.get(
                device[ATTR_TRACKER_MAC], {}
            ).get(
                ATTR_TRACKER_FIRST_SEEN,
                datetime.now().replace(microsecond=0).isoformat(),
            ),
            ATTR_TRACKER_OPTIONAL_MAC: integrations[ip_attr["ip"]][UPDATER].data.get(ATTR_DEVICE_MAC_ADDRESS, None)
            if integrations and ip_attr and ip_attr["ip"] in integrations
            else None,
            ATTR_TRACKER_INTERNET_BLOCKED: device.get(
                ATTR_TRACKER_INTERNET_BLOCKED, False
            ),
            ATTR_TRACKER_TOTAL_USAGE: total_usage,
        }

    def _mass_update_device(self, device: dict, integrations: dict) -> bool:
        is_found: bool = False
        for _ip, integration in integrations.items():
            if device[ATTR_TRACKER_MAC] not in integration[UPDATER].devices or _ip == self.ip:
                continue
            _device: dict[str, Any] = self._build_device(device, integrations)
            if self.is_repeater and self.is_force_load:
                for attr in REPEATER_SKIP_ATTRS:
                    if attr in _device:
                        del _device[attr]
            integration[UPDATER].devices[device[ATTR_TRACKER_MAC]] = _device
            is_found = True
        return is_found

    async def _async_prepare_ap(self, data: dict) -> None:
        if self.data.get(ATTR_SENSOR_MODE, Mode.DEFAULT) != Mode.REPEATER:
            return
        response: dict = await self.luci.wifi_ap_signal()
        if "signal" in response and isinstance(response["signal"], int):
            data[ATTR_SENSOR_AP_SIGNAL] = response["signal"]

    async def _async_prepare_new_status(self, data: dict) -> None:
        if self.disable_device_scan:
            return
        if not self.is_force_load:
            return
        response: dict = await self.luci.new_status()
        if "count" in response:
            data[ATTR_SENSOR_DEVICES] = response["count"]
        for key, attr in NEW_STATUS_MAP.items():
            if key in response and "online_sta_count" in response[key]:
                data[attr] = response[key]["online_sta_count"]
        _other_devices = sum(int(data[attr]) for attr in NEW_STATUS_MAP.values() if attr in data)
        if _other_devices > 0 and ATTR_SENSOR_DEVICES in data:
            _other_devices = int(data[ATTR_SENSOR_DEVICES]) - _other_devices
            data[ATTR_SENSOR_DEVICES_LAN] = max(_other_devices, 0)

    def _clean_devices(self) -> None:
        if self._activity_days == 0 or len(self.devices) == 0:
            return
        now = datetime.now().replace(microsecond=0)
        devices: dict = self.devices.copy()
        for mac, device in devices.items():
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
            del self.devices[mac]

    def reset_counter(self, is_force: bool = False, is_remove: bool = False) -> None:
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
        if self._store is None:
            return None
        devices: dict | None = await self._store.async_load()
        if devices is None or not isinstance(devices, dict) or len(devices) == 0:
            return None
        return devices

    async def _async_save_devices(self) -> None:
        if self._store is None or (self.is_repeater and not self.is_force_load) or len(self.devices) == 0:
            return
        await self._store.async_save(self.devices)

    async def _async_prepare_topo(self) -> None:
        try:
            topo_data = await self.luci.topo_graph()
            if not topo_data or not isinstance(topo_data, dict) or "graph" not in topo_data:
                await self.hass.async_add_executor_job(_LOGGER.info, "[MiWiFi] No topology graph data available for router at %s", self.ip)
                self.data["topo_graph"] = None
                return
            graph = topo_data["graph"]
            if not isinstance(graph, dict):
                await self.hass.async_add_executor_job(_LOGGER.error, "[MiWiFi] ❌ Invalid topology graph format (not dict): %s", graph)
                self.data["topo_graph"] = None
                return
            if self.data.get(ATTR_DEVICE_MAC_ADDRESS):
                graph["mac"] = self.data[ATTR_DEVICE_MAC_ADDRESS]
                await self.hass.async_add_executor_job(_LOGGER.debug, "[MiWiFi] MAC added to topo_graph: %s", graph["mac"])

            auto_main = False
            try:
                show = int(topo_data.get("show", -1))
                mode = int(graph.get("mode", -1))
                assoc_raw = graph.get("assoc", None)
                assoc = None
                if assoc_raw is not None and str(assoc_raw).strip() != "":
                    try:
                        assoc = int(str(assoc_raw).strip())
                    except Exception:
                        assoc = None
                await self.hass.async_add_executor_job(
                    _LOGGER.debug,
                    "[MiWiFi] Topo debug – show=%s, mode=%s, assoc=%s",
                    show, mode, assoc if assoc is not None else assoc_raw
                )
                if assoc is not None:
                    if assoc == 1 and ((show == 1) or (show == 0 and mode in (0, 3))):
                        graph["is_main"] = True
                        auto_main = True
                else:
                    if show == 1 and mode in (0, 4):
                        graph["is_main"] = True
                        auto_main = True
                graph["is_main_auto"] = auto_main
                graph["auto_reason"] = f"show={show}, mode={mode}, assoc={assoc}"
                await self.hass.async_add_executor_job(_LOGGER.debug, "[MiWiFi] Auto-main => %s (%s)", auto_main, graph["auto_reason"])
            except Exception as e:
                await self.hass.async_add_executor_job(_LOGGER.warning, "[MiWiFi] Error interpreting topology: %s", e)
            if not auto_main:
                from custom_components.miwifi.frontend import async_load_manual_main_mac
                manual_mac = await async_load_manual_main_mac(self.hass)
                if manual_mac:
                    if (manual_mac or "").lower() == (graph.get("mac") or "").lower():
                        graph["is_main"] = True
                        await self.hass.async_add_executor_job(_LOGGER.debug, "[MiWiFi] Main router restored from saved MAC: %s", manual_mac)
                    else:
                        graph.pop("is_main", None)
                else:
                    from .updater import async_get_integrations
                    integrations = async_get_integrations(self.hass)
                    if len(integrations) == 1:
                        graph["is_main"] = True
                        auto_main = True
                        graph["is_main_auto"] = True
                        graph["auto_reason"] = "single_integration_fallback"
                        await self.hass.async_add_executor_job(_LOGGER.debug, "[MiWiFi] Main router set by single integration fallback")
                    else:
                        graph.pop("is_main", None)
            else:
                graph["is_main"] = True
            graph["is_main_auto"] = auto_main
            self.data["topo_graph"] = topo_data
            await self.hass.async_add_executor_job(_LOGGER.debug, "[MiWiFi] Topology graph data received for router at %s: %s", self.ip, topo_data)

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
            try:
                self.async_set_updated_data(self.data)
            except AttributeError:
                pass

            nodes = graph.get("nodes")
            if isinstance(nodes, list):
                for node in nodes:
                    if isinstance(node, dict):
                        node_ip = node.get("ip")
                        node_mac = node.get("mac")
                        if node_ip and node_ip != self.ip:
                            if node_ip not in self.hass.data.get(DOMAIN, {}):
                                await self.hass.async_add_executor_job(_LOGGER.warning, "[MiWiFi] 🆕 Non-integrated Mesh Node: IP=%s, MAC=%s", node_ip, node_mac)
        except LuciError as e:
            await self.hass.async_add_executor_job(_LOGGER.warning, "[MiWiFi] Failed to get topology graph for router at %s: %s", self.ip, e)
            self.data["topo_graph"] = None
        except Exception as e:
            await self.hass.async_add_executor_job(_LOGGER.error, "[MiWiFi] Unexpected error while getting topology graph for router at %s: %s", self.ip, e)
            self.data["topo_graph"] = None

    @property
    def entry_id(self) -> str | None:
        return self._entry_id

    async def _async_prepare_compatibility(self) -> None:
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
        try:
            data1 = await self.luci.portforward(ftype=1)
            data2 = await self.luci.portforward(ftype=2)
            self.data["nat_rules"] = {
                "ftype_1": data1.get("list", []),
                "ftype_2": data2.get("list", []),
                "total": len(data1.get("list", [])) + len(data2.get("list", [])),
            }
            await self.hass.async_add_executor_job(_LOGGER.debug, "[MiWiFi] NAT rules loaded for sensor: %s", self.data["nat_rules"])
        except Exception as e:
            await self.hass.async_add_executor_job(_LOGGER.warning, "[MiWiFi] Error while retrieving NAT rules for sensor: %s", e)
            self.data["nat_rules"] = {"ftype_1": [], "ftype_2": [], "total": 0}

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
def async_get_updater(hass: HomeAssistant, identifier: str) -> "LuciUpdater":
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


async def async_update_panel_entity(hass: HomeAssistant, updater: "LuciUpdater", async_add_entities=None):
    from .update import MiWifiPanelUpdate

    entity_registry = er.async_get(hass)
    mac = updater.data.get(ATTR_DEVICE_MAC_ADDRESS)
    entity_id = f"update.miwifi_{mac.replace(':','_')}_miwifi_panel_frontend"

    topo_graph = (updater.data or {}).get("topo_graph", {}).get("graph", {})
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
