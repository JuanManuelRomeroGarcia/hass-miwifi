"""The guest form receives operational status, including RC06's off network."""
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

import pytest
from homeassistant.components import websocket_api

from custom_components.miwifi.ws_api import websocket_get_wifis


@pytest.mark.parametrize("status", ["0", 0, False, "1", 1, True, None])
async def test_guest_operational_status_survives_websocket(hass, hass_ws_client, status):
    guest = {"ifname": "wl14", "iftype": 3, "enabled": "1", "ssid": "Synthetic guest",
             "password": "synthetic-secret"}
    if status is not None:
        guest["status"] = status
    luci = SimpleNamespace(
        wifi_diag_detail_all=AsyncMock(return_value={"info": [guest]}),
        wifi_detail_all=AsyncMock(return_value={"info": []}),
    )
    websocket_api.async_register_command(hass, websocket_get_wifis)
    client = await hass_ws_client(hass)
    with patch("custom_components.miwifi.ws_api._pick_updater", return_value=SimpleNamespace(luci=luci)):
        await client.send_json({"id": 1, "type": "miwifi/get_wifis", "hide_sensitive": True})
        response = await client.receive_json()
    assert response["success"]
    result = response["result"]["wifis"]["guest"]
    assert "status" in result
    assert result["status"] == status
    assert type(result["status"]) is type(status)
    assert result["enabled"] is True  # Preserve the existing configured flag.
    assert result["ssid"] == "Synthetic guest"
    assert result["password"] is None
