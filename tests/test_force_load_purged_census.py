"""A live force-load Wi-Fi census can restore a previously purged client."""

from unittest.mock import AsyncMock, patch

import pytest

from custom_components.miwifi.enum import Connection, Mode
from custom_components.miwifi.purged_clients import PurgedClients, get_purged_clients
from custom_components.miwifi.updater import LuciUpdater


MAC = "D6:0B:BE:26:F0:8B"
OTHER = "CE:F2:A4:A0:37:46"


@pytest.mark.parametrize("connected", [False, True])
async def test_force_load_census_releases_only_connected_purged_clients(
    hass, connected
):
    with patch("custom_components.miwifi.updater.LuciClient"):
        leaf = LuciUpdater(
            hass, "192.0.2.2", "test", entry_id="leaf", is_force_load=True
        )
    try:
        leaf.data = {"mode": Mode.MESH_NODE}
        leaf.luci.wifi_connect_devices = AsyncMock(
            return_value={
                "code": 0,
                "list": [{"mac": MAC, "wifiIndex": 2, "signal": 64}]
                if connected
                else [],
            }
        )
        leaf.luci.macfilter_info = AsyncMock(return_value={})
        await get_purged_clients(hass).async_mark({MAC, OTHER})
        with (
            patch(
                "custom_components.miwifi.updater.async_get_integrations",
                return_value={},
            ),
            patch(
                "custom_components.miwifi.updater._known_mesh_nodes",
                return_value=(set(), {}),
            ),
            patch.object(leaf, "_mass_update_device", return_value=False),
            patch.object(
                leaf,
                "_build_device",
                return_value={"mac": MAC, "connection": Connection.WIFI_2_4},
            ),
        ):
            await leaf._async_prepare_devices(leaf.data)

        assert (MAC in leaf.devices) is connected
        reloaded = PurgedClients(hass)
        assert await reloaded.async_blocked(MAC) is not connected
        assert await reloaded.async_blocked(OTHER)
    finally:
        await leaf.async_shutdown()
