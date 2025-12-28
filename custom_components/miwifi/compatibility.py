from __future__ import annotations

import asyncio
from typing import Any, Callable, Awaitable
from .luci import LuciClient
from .exceptions import LuciError, LuciConnectionError
from .logger import _LOGGER
from .enum import Mode, Model
from .unsupported import get_combined_unsupported
from homeassistant.core import HomeAssistant

class CompatibilityChecker:
    """Main compatibility detector with retries and robust mode handling."""

    def __init__(
        self,
        hass_or_client: HomeAssistant | LuciClient,
        client: LuciClient | None = None,
        max_retries: int = 5,
    ) -> None:
        # Backward compatible:
        # - old: CompatibilityChecker(client)
        # - new: CompatibilityChecker(hass, client)
        if client is None:
            self.hass: HomeAssistant | None = None
            self.client: LuciClient = hass_or_client  # type: ignore[assignment]
        else:
            self.hass = hass_or_client  # type: ignore[assignment]
            self.client = client

        self.max_retries = max_retries
        self.silent_mode: bool = False

        self.mode: Mode | None = None
        self.model: Model | None = None
        self.result: dict[str, bool | None] = {}

    async def _log(self, log_func: Callable[..., Any], msg: str, *args: Any) -> None:
        """Log with or without hass (keeps compatibility with older call site)."""
        if self.hass is not None:
            await self.hass.async_add_executor_job(log_func, msg, *args)
        else:
            log_func(msg, *args)

    def _parse_mode(self, raw_mode: Any) -> Mode:
        """Parse router mode using Mode enum as source of truth."""
        if isinstance(raw_mode, dict):
            raw_mode = raw_mode.get("netmode") or raw_mode.get("mode", "default")

        s = str(raw_mode).strip().lower()

        # Prefer numeric parsing: "0","1","2","3","8","9"
        try:
            return Mode(int(s))
        except Exception:
            pass

        # Phrase-based parsing using enum phrases
        phrase_map = {m.phrase.lower(): m for m in Mode}
        alias = {
            "router": Mode.DEFAULT,
            "default": Mode.DEFAULT,
            "ap": Mode.ACCESS_POINT,
        }
        return phrase_map.get(s) or alias.get(s) or Mode.DEFAULT

    async def _safe_call(
        self,
        func: Callable[[], Awaitable[bool | None]],
        name: str,
        timeout: float = 6.0,
    ) -> bool | None:
        """Run a call with retries.

        Returns:
          - True  -> supported
          - False -> failed after retries
          - None  -> skipped / not applicable
        """
        for attempt in range(1, self.max_retries + 1):
            try:
                resp = await asyncio.wait_for(func(), timeout=timeout)

                # IMPORTANT: None means "skip / not applicable"
                if resp is None:
                    return None

                if resp is True:
                    return True

            except asyncio.TimeoutError:
                await self._log(_LOGGER.debug,"[MiWiFi] '%s' timeout (%ss) (attempt %d/%d)",name,timeout,attempt,self.max_retries,)
            except asyncio.CancelledError:
                await self._log(_LOGGER.warning,
                    "[MiWiFi] '%s' cancelada por HA durante el setup (attempt %d/%d).",name,attempt,self.max_retries,)
                return False
            except LuciConnectionError as e:
                await self._log(_LOGGER.debug,"[MiWiFi] '%s' connection error (attempt %d/%d): %s",name,attempt,self.max_retries,e,)
            except LuciError as e:
                await self._log(_LOGGER.debug,"[MiWiFi] '%s' luci error (attempt %d/%d): %s",name,attempt,self.max_retries,e,)
            except Exception as e:
                await self._log(_LOGGER.debug,"[MiWiFi] '%s' unexpected error (attempt %d/%d): %s",name,attempt,self.max_retries,e,)
            await asyncio.sleep(1)
        return False

    async def run(self) -> dict[str, bool | None]:
        """Run full compatibility checks with retries."""

        # Detect mode
        try:
            raw_mode = await self.client.mode()
            await self._log(_LOGGER.debug, "[MiWiFi] Raw mode response from client: %s", raw_mode)
            self.mode = self._parse_mode(raw_mode)
            await self._log(_LOGGER.debug, "[MiWiFi] Parsed mode: %s", self.mode)
        except (LuciError, KeyError, ValueError, AttributeError) as e:
            await self._log(_LOGGER.debug, "[MiWiFi] Could not detect mode: %s", e)
            self.mode = None

        # Detect model
        try:
            info = await self.client.init_info()
            if "hardware" in info:
                self.model = Model(str(info["hardware"]).lower())
        except Exception as e:
            await self._log(_LOGGER.debug, "[MiWiFi] Could not detect model: %s", e)
            self.model = None

        # Combined unsupported (base + user)
        combined_unsupported = await get_combined_unsupported(self.hass) if self.hass is not None else {}

        # Feature checks
        features: dict[str, Callable[[], Awaitable[bool | None]]] = {
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
                # IMPORTANT: keep key present for downstream code/diagnostics
                self.result[feature] = False
                await self._log(_LOGGER.debug,"[MiWiFi] ⏭️ Skipping '%s' check for model '%s' (predefined unsupported)",feature,self.model,)
                continue

            supported = await self._safe_call(func, feature)
            self.result[feature] = supported

            if supported is False and not self.silent_mode:
                await self._log(_LOGGER.warning,"[MiWiFi] ❌ Feature '%s' failed after %d attempts for model %s (mode %s).",feature,self.max_retries,self.model,self.mode,)
                await self._log(_LOGGER.warning,"➡️ Please add it to unsupported.py if confirmed unsupported.",)

        return self.result

    # -----------------------
    # Individual feature checks
    # -----------------------

    async def _check_mac_filter(self) -> bool | None:
        """Check RW support (inferred) without writing during setup."""
        try:
            await self.client.macfilter_info()
            return True
        except LuciError:
            return False
        except Exception:
            return None

    async def _check_mac_filter_info(self) -> bool | None:
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
        except Exception:
            return None

    async def _check_rom_update(self) -> bool | None:
        if self.mode in {Mode.REPEATER, Mode.ACCESS_POINT, Mode.MESH, Mode.MESH_LEAF, Mode.MESH_NODE}:
            return None
        try:
            await self.client.rom_update()
            return True
        except LuciError:
            return False
        except Exception:
            return None

    async def _check_flash_permission(self) -> bool | None:
        try:
            await self.client.flash_permission()
            return True
        except LuciError:
            return False

    async def _check_led(self) -> bool | None:
        try:
            await self.client.led()
            return True
        except LuciError:
            return False

    async def _check_guest_wifi(self) -> bool | None:
        try:
            await self.client.guest_wifi()
            return True
        except LuciError:
            return False

    async def _check_wifi_config(self) -> bool | None:
        try:
            await self.client.wifi_detail_all()
            return True
        except LuciError:
            return False

    async def _check_device_list(self) -> bool | None:
        # In AP/repeater/mesh, device_list is often not applicable / unreliable
        if self.mode in {Mode.REPEATER, Mode.ACCESS_POINT, Mode.MESH, Mode.MESH_LEAF, Mode.MESH_NODE}:
            return None
        try:
            await self.client.device_list()
            return True
        except LuciError:
            return False

    async def _check_topo_graph(self) -> bool | None:
        if self.mode in {Mode.REPEATER, Mode.ACCESS_POINT, Mode.MESH, Mode.MESH_LEAF, Mode.MESH_NODE}:
            return None
        try:
            await self.client.topo_graph()
            return True
        except LuciError:
            return False

    async def _check_portforward(self) -> bool | None:
        if self.mode in {Mode.REPEATER, Mode.ACCESS_POINT, Mode.MESH, Mode.MESH_LEAF, Mode.MESH_NODE}:
            return None

        try:
            await self.client.portforward(ftype=1)
            return True
        except (LuciError, LuciConnectionError):
            await self._log(_LOGGER.debug, "[MiWiFi] Default portforward path failed, trying fallback.")
            try:
                fallback_path = "xqsystem/portforward"
                await self.client.get(fallback_path, {"ftype": 1})

                overrides = {
                    "portforward": "xqsystem/portforward",
                    "add_redirect": "xqsystem/add_redirect",
                    "add_range_redirect": "xqsystem/add_range_redirect",
                    "redirect_apply": "xqsystem/redirect_apply",
                    "delete_redirect": "xqsystem/delete_redirect",
                }
                self.client._api_paths.update(overrides)
                await self._log(_LOGGER.debug, "[MiWiFi] Using fallback portforward paths.")
                return True
            except (LuciError, LuciConnectionError) as e:
                await self._log(_LOGGER.debug, "[MiWiFi] Fallback portforward path also failed: %s", e)
                return False
        except Exception as e:
            await self._log(_LOGGER.warning, "[MiWiFi] Unexpected error during portforward check: %s", e)
            return False