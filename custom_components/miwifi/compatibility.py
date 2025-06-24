from __future__ import annotations

from .luci import LuciClient
from .exceptions import LuciError
from .logger import _LOGGER
from .enum import Mode

class CompatibilityChecker:
    """Main compatibility detector."""

    def __init__(self, client: LuciClient) -> None:
        self.client = client
        self.result: dict[str, bool | None] = {}
        self.mode: Mode | None = None

    async def run(self) -> dict[str, bool | None]:
        """Run full compatibility checks."""

        try:
            raw_mode = await self.client.mode()
            _LOGGER.debug(f"[MiWiFi] Raw mode response from client: {raw_mode}")

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

            self.mode = MODE_MAP.get(str(raw_mode).lower(), Mode.DEFAULT) if raw_mode is not None else None
            _LOGGER.debug(f"[MiWiFi] Parsed mode: {self.mode}")

        except (LuciError, KeyError, ValueError, AttributeError):
            self.mode = None

        self.result = {
            "mac_filter": await self._check_mac_filter(),
            "mac_filter_info": await self._check_mac_filter_info(),
            "per_device_qos": await self._check_qos_info(),
            "rom_update": await self._check_rom_update(),
            "flash_permission": await self._check_flash_permission(),
            "led_control": await self._check_led(),
            "guest_wifi": await self._check_guest_wifi(),
            "wifi_config": await self._check_wifi_config(),
            "device_list": await self._check_device_list(),
            "topo_graph": await self._check_topo_graph(),
        }

        _LOGGER.info(f"[MiWiFi] Compatibility detection finished (mode={self.mode}): {self.result}")
        return self.result

    async def _check_mac_filter(self) -> bool:
        try:
            await self.client.set_mac_filter("00:00:00:00:00:00", True)
            return True
        except LuciError:
            return False

    async def _check_mac_filter_info(self) -> bool:
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
        try:
            await self.client.flash_permission()
            return True
        except LuciError:
            return False

    async def _check_led(self) -> bool:
        try:
            await self.client.led()
            return True
        except LuciError:
            return False

    async def _check_guest_wifi(self) -> bool:
        try:
            await self.client.set_guest_wifi({})
            return True
        except LuciError:
            return False

    async def _check_wifi_config(self) -> bool:
        try:
            await self.client.set_wifi({})
            return True
        except LuciError:
            return False

    async def _check_device_list(self) -> bool:
        try:
            await self.client.device_list()
            return True
        except LuciError:
            return False

    async def _check_topo_graph(self) -> bool:
        try:
            await self.client.topo_graph()
            return True
        except LuciError:
            return False
