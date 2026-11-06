"""Model and role isolation, telemetry semantics and panel access control."""
from types import SimpleNamespace
from unittest.mock import AsyncMock
import pytest

from homeassistant.components import websocket_api
from homeassistant.helpers import entity_registry as er
from pytest_homeassistant_custom_component.common import MockConfigEntry

from custom_components.miwifi import ws_api
from custom_components.miwifi.const import DOMAIN, UPDATER
from custom_components.miwifi.router_panel import async_panel_reads, panel_metrics
from custom_components.miwifi.sensor import MiWifiTopologyGraphSensor


def router(model, main=False):
    return SimpleNamespace(ip="192.0.2.1", data={"model": model,
        "topo_graph": {"graph": {"is_main": main}}},
        luci=SimpleNamespace(get=AsyncMock(return_value={"code": 0})))


def test_wifi_unification_metadata_is_per_router_and_does_not_mutate_graph():
    main, leaf = router("rc01", True), router("rc06")
    main.entry_id, leaf.entry_id = "main", "leaf"
    main.data["dual_band"], leaf.data["dual_band"] = True, False
    main_sensor, leaf_sensor = MiWifiTopologyGraphSensor(main), MiWifiTopologyGraphSensor(leaf)
    assert main_sensor.extra_state_attributes["wifi_unified"] is True
    assert leaf_sensor.extra_state_attributes["wifi_unified"] is False
    assert "wifi_unified" not in main.data["topo_graph"]
    del leaf.data["dual_band"]
    assert "wifi_unified" not in leaf_sensor.extra_state_attributes


async def test_panel_queries_only_reviewed_models_and_role_specific_reads():
    main, leaf, other = router("rc01", True), router("rc06"), router("rd08", True)
    rows = await async_panel_reads([main, leaf, other])
    assert [row["model"] for row in rows] == ["rc01", "rc06"]
    other.luci.get.assert_not_awaited()
    main_paths = {call.args[0] for call in main.luci.get.await_args_list}
    leaf_paths = {call.args[0] for call in leaf.luci.get.await_args_list}
    assert main_paths == {"misystem/get_ps_map", "misystem/get_temp_control",
        "xqnetwork/get_multiwan_basic_info", "misystem/get_mesh_bh_mode",
        "xqnetwork/get_wps_info", "xqnetwork/get_nfc_info"}
    assert leaf_paths == {"misystem/get_ps_map", "misystem/get_mesh_bh_mode",
        "xqnetwork/get_aimesh_config", "xqnetwork/get_wps_info", "xqnetwork/get_nfc_info"}


def test_metric_projection_preserves_zero_and_false_without_exposing_configuration():
    def read(key, payload, outcome="ok"):
        return {"id": key, "response": payload, "outcome": outcome}
    result = panel_metrics([
        read("thermal_control", {"temp": {"curr": 75}, "fan": {"speed": 0, "mode": 1}, "token": "secret"}),
        read("multiwan_basic", {"info": {"enable": 0, "password": "secret"}}),
        read("mesh_backhaul_preference", {"bhmode": "wired"}),
        read("mesh_steering", {"roaming_rssi_thr": {"2g": "-65", "5g": "nan", "extra": "secret"}}),
        read("wps_info", {"wps_enable": 0, "wpa3_only": 1}),
        read("nfc_info", {"nfc_enable": 1}),
        read("port_map", {"ports": [{"label": "1(2.5G)", "speed": "2.5G", "service": "LAN", "secret": "hidden"}]}),
    ])
    assert result == {"temperature": 75, "fan_speed": 0, "multiwan": False,
        "backhaul": "wired", "roaming": {"2g": -65}, "wps": False, "nfc": True,
        "ports": [{"label": "1(2.5G)", "speed": "2.5G", "service": "LAN"}]}
    assert panel_metrics([read("thermal_control", {"temp": {"curr": 99}}, "error")]) == {}
    assert panel_metrics([read("thermal_control", {"temp": [], "fan": {"speed": "nan"}})]) == {}


@pytest.mark.parametrize("command,handler", [
    ("miwifi/router_specific", ws_api.websocket_router_specific),
    ("miwifi/router_wifi_state", ws_api.websocket_router_wifi_state),
])
async def test_panel_websocket_denies_non_admin(hass, hass_ws_client, hass_read_only_user, command, handler):
    websocket_api.async_register_command(hass, handler)
    token = await hass.auth.async_create_refresh_token(hass_read_only_user, client_id="https://test.example")
    client = await hass_ws_client(hass, hass.auth.async_create_access_token(token))
    await client.send_json({"id": 1, "type": command})
    response = await client.receive_json()
    assert response["error"]["code"] == "unauthorized"


async def test_wifi_metadata_covers_other_models_without_router_requests(hass, hass_ws_client):
    entries = [MockConfigEntry(domain=DOMAIN, title=f"Router {i}") for i in range(3)]
    updaters = [router(model) for model in ("rc01", "rc06", "ra82")]
    hass.data[DOMAIN] = {}
    for index, (entry, updater) in enumerate(zip(entries, updaters)):
        entry.add_to_hass(hass)
        updater.data["device_mac_address"] = f"02:00:00:00:00:0{index + 1}"
        if index < 2:
            updater.data["dual_band"] = index == 0
        hass.data[DOMAIN][entry.entry_id] = {UPDATER: updater}
    websocket_api.async_register_command(hass, ws_api.websocket_router_wifi_state)
    registry = er.async_get(hass)
    unified = registry.async_get_or_create("switch", DOMAIN, f"{entries[0].entry_id}-wifi_2_4",
                                         config_entry=entries[0], suggested_object_id="house_wifi")
    secondary = registry.async_get_or_create("switch", DOMAIN, f"{entries[0].entry_id}-wifi_5_0",
                                           config_entry=entries[0], suggested_object_id="radio_b")
    client = await hass_ws_client(hass)
    await client.send_json({"id": 1, "type": "miwifi/router_wifi_state"})
    response = await client.receive_json()
    assert response["success"]
    assert [r["unified"] for r in response["result"]["routers"]] == [True, False, None]
    assert response["result"]["routers"][0]["switches"] == {"2g": unified.entity_id, "5g": secondary.entity_id}
    assert [r["mac"] for r in response["result"]["routers"]] == [f"02:00:00:00:00:0{i}" for i in (1, 2, 3)]
    for updater in updaters:
        updater.luci.get.assert_not_awaited()


async def test_panel_websocket_caches_reads_and_invalidates_on_reload(hass, hass_ws_client):
    entry = MockConfigEntry(domain=DOMAIN, title="Test BE10000")
    entry.add_to_hass(hass)
    main = router("rc01", True)
    main.data["device_mac_address"] = "02:00:00:00:00:01"
    hass.data[DOMAIN] = {entry.entry_id: {UPDATER: main}}
    websocket_api.async_register_command(hass, ws_api.websocket_router_specific)
    client = await hass_ws_client(hass)
    for number in (1, 2):
        await client.send_json({"id": number, "type": "miwifi/router_specific"})
        response = await client.receive_json()
        assert response["success"]
        assert response["result"]["routers"][0]["name"] == "Test BE10000"
        assert response["result"]["routers"][0]["is_main"] is True
        assert response["result"]["routers"][0]["mac"] == "02:00:00:00:00:01"
    assert main.luci.get.await_count == 6
    replacement = router("rc01", True)
    hass.data[DOMAIN][entry.entry_id][UPDATER] = replacement
    await client.send_json({"id": 3, "type": "miwifi/router_specific"})
    assert (await client.receive_json())["success"]
    assert replacement.luci.get.await_count == 6
