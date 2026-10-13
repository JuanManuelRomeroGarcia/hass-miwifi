"""Route a real updater census using distinct main, node and client MACs."""
import json
from unittest.mock import AsyncMock, Mock, patch

import pytest
from pytest_homeassistant_custom_component.common import load_fixture

from custom_components.miwifi.const import ATTR_DEVICE_MAC_ADDRESS
from custom_components.miwifi.enum import Mode
from tests.setup import async_first_refresh, async_mock_luci_client, async_setup, load_leaf_status


@pytest.mark.parametrize("mode", [Mode.ACCESS_POINT, Mode.REPEATER, Mode.MESH])
@pytest.mark.parametrize("force", [False, True])
async def test_parent_routes_client_to_matching_node_and_keeps_count(hass, mode, force):
    with patch("custom_components.miwifi.updater.LuciClient") as client, patch(
        "custom_components.miwifi.updater.asyncio.sleep", return_value=None
    ), patch(
        "custom_components.miwifi.compatibility.CompatibilityChecker.run",
        return_value={"device_list": True, "wifi_config": True, "portforward": False},
    ):
        await async_mock_luci_client(client)
        client.return_value.mode = AsyncMock(return_value={"code": 0, "mode": mode.value})
        client.return_value.status = AsyncMock(return_value=load_leaf_status())
        client.return_value.device_list = AsyncMock(return_value={"code": 0, "list": []})
        client.return_value.wifi_connect_devices = AsyncMock(
            return_value=json.loads(load_fixture("wifi_connect_devices_parent_data.json"))
        )
        client.return_value.new_status = AsyncMock(
            return_value=json.loads(load_fixture("new_status_parent_data.json"))
        )
        leaf, _ = await async_setup(hass, "192.168.31.100", is_force=force, without_store=True)
        await async_first_refresh(leaf)

        # Each updater keeps its own client instance, just like separate routers.
        client.return_value = Mock()
        await async_mock_luci_client(client)
        client.return_value.device_list = AsyncMock(
            side_effect=lambda: json.loads(load_fixture("device_list_parent_data.json"))
        )
        main, _ = await async_setup(hass, without_store=True)
        try:
            await async_first_refresh(main)
            client_mac = "00:00:00:00:00:01"
            assert len({main.data[ATTR_DEVICE_MAC_ADDRESS], leaf.data[ATTR_DEVICE_MAC_ADDRESS], client_mac}) == 3
            for _ in range(3):
                await main.update()
                await leaf.update()
                assert client_mac not in main.devices
                assert leaf.devices[client_mac]["router_mac"] == leaf.data[ATTR_DEVICE_MAC_ADDRESS]
                assert leaf.devices[client_mac]["entry_id"] == leaf._entry_id
                assert leaf.devices[client_mac]["updater_entry_id"] == leaf._entry_id
                assert leaf.devices[client_mac]["ip"] == "192.168.31.2"
                assert leaf.data["devices"] == 1
        finally:
            await main.async_stop()
            await leaf.async_stop()
