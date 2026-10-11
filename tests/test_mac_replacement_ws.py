"""Panel reads all nodes and cannot expose identity configuration to non-admins."""

from types import SimpleNamespace
from unittest.mock import AsyncMock

from homeassistant.components import websocket_api
from custom_components.miwifi.ws_api import websocket_get_mac_replacement
from custom_components.miwifi.mac_replacement import get_mac_replacement


async def test_panel_read_current_rules_and_names_from_all_nodes(hass, hass_ws_client):
    hass.data["miwifi"] = {
        "main": {"ip_address": "192.0.2.1", "updater": SimpleNamespace(
            devices={"a": {"name": "Reloj JuanMa", "password": "private"}},
            _async_load_devices=AsyncMock(return_value={"b": {"name": "SM-L315F"}}))},
        "leaf": {"ip_address": "192.0.2.2", "updater": SimpleNamespace(
            devices={"c": {"name": "Laptop"}}, _async_load_devices=AsyncMock(return_value=None))},
    }
    manager = get_mac_replacement(hass)
    await manager.async_configure({"watch": ["SM-L315F", "Reloj JuanMa"]}, [])
    websocket_api.async_register_command(hass, websocket_get_mac_replacement)
    client = await hass_ws_client(hass)
    await client.send_json({"id": 1, "type": "miwifi/get_mac_replacement"})
    result = await client.receive_json()
    assert result["success"]
    assert result["result"] == {"clients": {"watch": ["Reloj JuanMa", "SM-L315F"]},
        "available_names": ["Laptop", "Reloj JuanMa", "SM-L315F"]}
    copy = await manager.async_configuration()
    copy["watch"].clear()
    assert len((await manager.async_configuration())["watch"]) == 2


async def test_panel_read_requires_admin(hass, hass_ws_client, hass_read_only_user):
    websocket_api.async_register_command(hass, websocket_get_mac_replacement)
    refresh_token = await hass.auth.async_create_refresh_token(hass_read_only_user, client_id="https://test.example")
    client = await hass_ws_client(hass, hass.auth.async_create_access_token(refresh_token))
    await client.send_json({"id": 1, "type": "miwifi/get_mac_replacement"})
    result = await client.receive_json()
    assert not result["success"]
    assert result["error"]["code"] == "unauthorized"
