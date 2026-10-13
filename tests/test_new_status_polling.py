"""A force-load poll reads counters once and handles endpoint failures."""
import json
from unittest.mock import AsyncMock, patch

from httpx import codes
from pytest_homeassistant_custom_component.common import load_fixture

from custom_components.miwifi.exceptions import LuciRequestError
from tests.setup import async_first_refresh, async_mock_luci_client, async_setup


async def test_force_load_counter_request_is_once_per_cycle_and_recovers(hass):
    with patch("custom_components.miwifi.updater.LuciClient") as client, patch(
        "custom_components.miwifi.updater.asyncio.sleep", return_value=None
    ), patch(
        "custom_components.miwifi.compatibility.CompatibilityChecker.run",
        return_value={"device_list": True, "wifi_config": True, "portforward": False},
    ):
        await async_mock_luci_client(client)
        counters = json.loads(load_fixture("new_status_data.json"))
        client.return_value.new_status = AsyncMock(
            side_effect=[counters, LuciRequestError(), counters]
        )
        updater, _ = await async_setup(hass, is_force=True, without_store=True)
        try:
            await async_first_refresh(updater)
            assert client.return_value.new_status.await_count == 1
            assert updater.data["devices"] == counters["count"]
            await updater.update()
            assert client.return_value.new_status.await_count == 2
            assert updater.code == codes.FORBIDDEN
            await updater.update()
            assert client.return_value.new_status.await_count == 3
            assert updater.code == codes.OK
            assert updater.data["devices"] == counters["count"]
        finally:
            await updater.async_stop()
