from __future__ import annotations

import asyncio
from .luci import LuciClient
from .exceptions import LuciError, LuciConnectionError
from .logger import _LOGGER
from .enum import Mode, Model
from .unsupported import get_combined_unsupported
from homeassistant.core import HomeAssistant

class CompatibilityChecker:
    """Main compatibility detector with retries and better logging."""

    def __init__(self, hass: HomeAssistant, client: LuciClient, max_retries: int = 5) -> None:
        self.hass = hass
        self.client = client
        self.result: dict[str, bool | None] = {}
        self.mode: Mode | None = None
        self.model: Model | None = None
        self.silent_mode: bool = False
        self.max_retries = max_retries

    async def _safe_call(self, func, name: str, timeout: float = 6.0) -> bool:
        """Run a call with retries, timeout and safe cancellation handling."""
        for attempt in range(1, self.max_retries + 1):
            try:
                resp = await asyncio.wait_for(func(), timeout=timeout)
                if isinstance(resp, dict) or resp is True:
                    return True
            except asyncio.TimeoutError:
                await self.hass.async_add_executor_job(_LOGGER.debug,"[MiWiFi] '%s' timeout (%ss) (attempt %d/%d)",name, timeout, attempt, self.max_retries)
            except asyncio.CancelledError:
                await self.hass.async_add_executor_job(_LOGGER.warning,"[MiWiFi] '%s' cancelada por HA durante el setup (attempt %d/%d).",name, attempt, self.max_retries)
                return False
            except LuciConnectionError as e:
                await self.hass.async_add_executor_job(_LOGGER.debug,"[MiWiFi] '%s' connection error (attempt %d/%d): %s",name, attempt, self.max_retries, e)
            except LuciError as e:
                await self.hass.async_add_executor_job(_LOGGER.debug,"[MiWiFi] '%s' luci error (attempt %d/%d): %s",name, attempt, self.max_retries, e)
            except Exception as e:
                await self.hass.async_add_executor_job(_LOGGER.debug,"[MiWiFi] '%s' unexpected error (attempt %d/%d): %s",name, attempt, self.max_retries, e)
            await asyncio.sleep(1)
        return False

    async def run(self) -> dict[str, bool | None]:
        """Run full compatibility checks with retries."""

        # Detect mode
        try:
            raw_mode = await self.client.mode()
            await self.hass.async_add_executor_job(_LOGGER.debug,f"[MiWiFi] Raw mode response from client: {raw_mode}")

            if isinstance(raw_mode, dict):
                raw_mode = raw_mode.get("netmode") or raw_mode.get("mode", "default")

            MODE_MAP = {
                "repeater": Mode.REPEATER,
                "access_point": Mode.ACCESS_POINT,
                "ap": Mode.ACCESS_POINT,
                "mesh": Mode.MESH,
                "router": Mode.DEFAULT,
                "default": Mode.DEFAULT,
                "8": Mode.MESH_LEAF,
                "3": Mode.MESH_NODE,
            }

            self.mode = MODE_MAP.get(str(raw_mode).lower(), Mode.DEFAULT)
            await self.hass.async_add_executor_job(_LOGGER.debug,f"[MiWiFi] Parsed mode: {self.mode}")

        except (LuciError, KeyError, ValueError, AttributeError) as e:
            await self.hass.async_add_executor_job(_LOGGER.debug,f"[MiWiFi] Could not detect mode: {e}")
            self.mode = None

        # Detect model
        try:
            info = await self.client.init_info()
            if "hardware" in info:
                self.model = Model(info["hardware"].lower())
        except Exception as e:
            await self.hass.async_add_executor_job(_LOGGER.debug,f"[MiWiFi] Could not detect model: {e}")
            self.model = None

        # Get combined unsupported (base + user)
        combined_unsupported = await get_combined_unsupported(self.hass)

        # Feature checks
        features: dict[str, callable] = {
            "mac_filter": self._check_mac_filter,
            "mac_filter_info": self._check_mac_filter_info,
            "per_device_qos": self._check_qos_info,
            "rom_update": self._check_rom_update,
            "flash_permission": self._check_flash_permission,
            "led_control": self._check_led,
            "guest_wifi": self._check_guest_wifi,
            "wifi_config": self._check_wifi_config,
            "device_list": self._check_device_list,
            "topo_graph": self._check_topo_graph,
            "portforward": self._check_portforward,
        }

        for feature, func in features.items():
            unsupported_models = combined_unsupported.get(feature, [])
            if self.model and self.model in unsupported_models:
                await self.hass.async_add_executor_job(_LOGGER.debug,
                    "[MiWiFi] ⏭️ Skipping '%s' check for model '%s' (predefined unsupported)",
                    feature, self.model)
                continue

            supported = await self._safe_call(func, feature)
            self.result[feature] = supported

            if supported is False and not self.silent_mode:
                await self.hass.async_add_executor_job(_LOGGER.warning,
                                                       "[MiWiFi] ❌ Feature '%s' failed after %d attempts for model %s (mode %s).",
                                                       feature, self.max_retries, self.model, self.mode)
                await self.hass.async_add_executor_job(_LOGGER.warning,
                                                       "➡️ Please add it to unsupported.py if confirmed unsupported.")

        return self.result

    async def _check_mac_filter(self) -> bool | None:
        """Check RW support (inferred, no write during setup)."""
        try:
            await self.client.macfilter_info()
            return True
        except LuciError:
            return False
        except Exception:
            return None

    async def _check_mac_filter_info(self) -> bool:
        """Check RO support (real info endpoint)."""
        try:
            await self.client.macfilter_info()
            return True
        except LuciError:
            return False

    async def _check_qos_info(self) -> bool | None:
        if self.mode in {Mode.REPEATER, Mode.ACCESS_POINT, Mode.MESH, Mode.MESH_LEAF, Mode.MESH_NODE}:
            return None
        try:
            await self.client.qos_info()
            return True
        except LuciError:
            return False

    async def _check_rom_update(self) -> bool | None:

        if self.mode in {Mode.REPEATER, Mode.ACCESS_POINT, Mode.MESH, Mode.MESH_LEAF, Mode.MESH_NODE}:
            return None
        try:
            await self.client.rom_update()
            return True
        except LuciError:
            return False

    async def _check_flash_permission(self) -> bool:
        """Check flash permission support using read-only endpoint."""
        try:
            await self.client.flash_permission()
            return True
        except LuciError:
            return False

    async def _check_led(self) -> bool:
        """Check LED control support using read-only endpoint."""
        try:
            await self.client.led()
            return True
        except LuciError:
            return False

    async def _check_guest_wifi(self) -> bool:
        """Check Guest Wi-Fi support using read-only endpoints."""
       
        try:
            await self.client.wifi_diag_detail_all()
            return True
        except LuciError:
            pass

        try:
            await self.client.wifi_detail_all()
            return True
        except LuciError:
          return False

    async def _check_wifi_config(self) -> bool:
        """Check Wi-Fi config support using read-only endpoint."""
        try:
            await self.client.wifi_detail_all()
            return True
        except LuciError:
            return False

    async def _check_device_list(self) -> bool:
        """Check device list support using read-only endpoint."""
        try:
            await self.client.device_list()
            return True
        except LuciError:
            return False

    async def _check_topo_graph(self) -> bool:
        """Check topology graph support using read-only endpoint."""
        try:
            await self.client.topo_graph()
            return True
        except LuciError:
            return False

    async def _check_portforward(self) -> bool:
        """Check port forwarding support and discover correct paths."""
        try:
            # This will use the default path from luci.py
            await self.client.portforward(ftype=1)
            return True
        except (LuciError, LuciConnectionError):
            await self.hass.async_add_executor_job(_LOGGER.debug, "[MiWiFi] Default portforward path failed, trying fallback.")
            try:
                # Manually try the fallback path
                fallback_path = "xqsystem/portforward"
                await self.client.get(fallback_path, {"ftype": 1})
                
                # Fallback worked, update client's api_paths for the whole group
                overrides = {
                    "portforward": "xqsystem/portforward",
                    "add_redirect": "xqsystem/add_redirect",
                    "add_range_redirect": "xqsystem/add_range_redirect",
                    "redirect_apply": "xqsystem/redirect_apply",
                    "delete_redirect": "xqsystem/delete_redirect",
                }
                self.client._api_paths.update(overrides)
                await self.hass.async_add_executor_job(_LOGGER.debug, "[MiWiFi] Using fallback portforward paths.")
                return True
            except (LuciError, LuciConnectionError) as e:
                await self.hass.async_add_executor_job(_LOGGER.debug, "[MiWiFi] Fallback portforward path also failed: %s", e)
                return False
        except Exception as e:
            await self.hass.async_add_executor_job(_LOGGER.warning, "[MiWiFi] Unexpected error during portforward check: %s", e)
            return False
