from __future__ import annotations

from .luci import LuciClient
from .exceptions import LuciError
from .logger import _LOGGER
from .enum import Mode, Model
from .unsupported import UNSUPPORTED

class CompatibilityChecker:
    """Main compatibility detector."""

    def __init__(self, client: LuciClient) -> None:
        self.client = client
        self.result: dict[str, bool | None] = {}
        self.mode: Mode | None = None
        self.model: Model | None = None

    async def run(self) -> dict[str, bool | None]:
        """Run full compatibility checks."""

        # Detect mode
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

            self.mode = MODE_MAP.get(str(raw_mode).lower(), Mode.DEFAULT)
            _LOGGER.debug(f"[MiWiFi] Parsed mode: {self.mode}")

        except (LuciError, KeyError, ValueError, AttributeError):
            self.mode = None

        # Detect model
        try:
            info = await self.client.init_info()
            if "hardware" in info:
                self.model = Model(info["hardware"].lower())
        except Exception as e:
            _LOGGER.debug(f"[MiWiFi] Could not detect model: {e}")
            self.model = None

        # Run all checks with UNSUPPORTED filtering
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
        }

        for feature, check_func in features.items():
            unsupported_models = UNSUPPORTED.get(feature, [])

            if self.model and self.model in unsupported_models:
                _LOGGER.debug(
                    "[MiWiFi] ⏭️ Skipping '%s' check for model '%s' (already UNSUPPORTED)",
                    feature, self.model
                )
                self.result[feature] = False
                continue

            try:
                supported = await check_func()
                self.result[feature] = supported

                if supported is False:
                    _LOGGER.warning(
                        "[MiWiFi] 🚫 Detected unsupported feature '%s' for model: %s (mode: %s).",
                        feature, self.model, self.mode
                    )
                    _LOGGER.warning(
                        "➡️ Please add it to unsupported.py to silence this warning."
                    )

            except Exception as e:
                self.result[feature] = False
                _LOGGER.warning("[MiWiFi] ❌ Error during '%s' check: %s", feature, e)
                
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
