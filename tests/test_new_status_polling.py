"""A force-load poll reads counters once and recovers optional endpoint failures."""
import json
from unittest.mock import AsyncMock, patch

import pytest
from httpx import codes
from pytest_homeassistant_custom_component.common import load_fixture

from custom_components.miwifi.exceptions import LuciConnectionError, LuciRequestError
from tests.setup import async_first_refresh, async_mock_luci_client, async_setup


@pytest.mark.parametrize("error", [LuciRequestError, LuciConnectionError])
async def test_force_load_counter_request_is_once_per_cycle_and_recovers(hass, error):
    with patch("custom_components.miwifi.updater.LuciClient") as client, patch(
        "custom_components.miwifi.updater.asyncio.sleep", return_value=None
    ), patch(
        "custom_components.miwifi.compatibility.CompatibilityChecker.run",
        return_value={"device_list": True, "wifi_config": True, "portforward": False},
    ):
        await async_mock_luci_client(client)
        counters = json.loads(load_fixture("new_status_data.json"))
        recovered = {**counters, "count": counters["count"] + 1}
        client.return_value.new_status = AsyncMock(
            side_effect=[counters, error(), recovered]
        )
        updater, _ = await async_setup(hass, is_force=True, without_store=True)
        try:
            await async_first_refresh(updater)
            assert client.return_value.new_status.await_count == 1
            assert updater.data["devices"] == counters["count"]
            await updater.update()
            assert client.return_value.new_status.await_count == 2
            # This counter endpoint is optional: a failure must not trigger
            # login reauthorization or make the otherwise healthy router fail.
            assert updater.code == codes.OK
            assert not updater._is_reauthorization
            assert updater.data["state"] is True
            await updater.update()
            assert client.return_value.new_status.await_count == 3
            assert updater.code == codes.OK
            assert updater.data["devices"] == recovered["count"]
        finally:
            await updater.async_stop()
