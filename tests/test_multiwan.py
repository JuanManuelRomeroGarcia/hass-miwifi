"""Read-only RD08 dual WAN: synthetic addresses, no reporter/session data."""

import asyncio
from copy import deepcopy
from unittest.mock import AsyncMock, patch

import pytest

from custom_components.miwifi.const import ATTR_SENSOR_MODE, ATTR_STATE
from custom_components.miwifi.enum import Mode
from custom_components.miwifi.exceptions import LuciError
from custom_components.miwifi.luci import LuciClient
from custom_components.miwifi.multiwan import parse_service, parse_wan2
from custom_components.miwifi.sensor import MiWifiWan2Sensor
from custom_components.miwifi.updater import LuciUpdater


WAN2 = {"code": 0, "info": {
    "link": 1, "status": 1,
    "ipv4": [{"ip": "192.0.2.20", "mask": "255.255.255.0"}],
    "details": {"wanType": "dhcp", "password": "synthetic-secret"},
}}


def updater(hass, *, model="rd08", mode=Mode.DEFAULT):
    instance = LuciUpdater.__new__(LuciUpdater)
    instance.hass = hass
    instance.data = {"model": model, "device_model": f"xiaomi.router.{model}",
                     ATTR_SENSOR_MODE: mode, ATTR_STATE: True,
                     "wan_ip": "192.0.2.10", "wan_state": True}
    instance.luci = AsyncMock()
    instance.luci.multiwan_info.return_value = {"code": 0, "multiwan": {"enable": 1}}
    instance.luci.wan_info.return_value = deepcopy(WAN2)
    instance.ip = "192.0.2.1"
    instance.last_update_success = True
    return instance


async def test_named_wan_requests_preserve_default_endpoint():
    client = LuciClient.__new__(LuciClient)
    client._api_paths = {"wan_info": "xqnetwork/wan_info"}
    client.get = AsyncMock(return_value={})
    await client.wan_info()
    client.get.assert_awaited_once_with("xqnetwork/wan_info")
    client.get.reset_mock()
    await client.wan_info("WAN2")
    client.get.assert_awaited_once_with("xqnetwork/wan_info", {"wan_name": "WAN2"})
    client.get.reset_mock()
    await client.multiwan_info()
    client.get.assert_awaited_once_with("misystem/get_ps_service", {"service": "multiwan"})


@pytest.mark.parametrize("flag,expected", [(0, False), (1, True), ("0", False), ("1", True)])
def test_explicit_service_flags(flag, expected):
    assert parse_service({"code": 0, "multiwan": {"enable": flag}}) is expected


@pytest.mark.parametrize("response", [None, {}, {"code": 0},
    {"code": 0, "multiwan": {"enable": 2}}, {"code": 1, "multiwan": {"enable": 1}}])
def test_incomplete_service_is_not_reported_disabled(response):
    with pytest.raises(ValueError):
        parse_service(response)


def test_wan_fields_are_allowlisted_and_input_is_unchanged():
    response = deepcopy(WAN2)
    assert parse_wan2(response) == {
        "ip": "192.0.2.20", "type": "dhcp", "link": True, "connected": True,
    }
    assert response == WAN2


@pytest.mark.parametrize("response", [None, {}, {"code": 0},
    {"code": 0, "info": {}}, {"code": 1, "info": WAN2["info"]}])
def test_missing_wan_status_is_not_reported_offline(response):
    with pytest.raises(ValueError):
        parse_wan2(response)


def test_disconnected_wan_drops_old_lease():
    response = deepcopy(WAN2)
    response["info"].update(link=0, status=0)
    assert parse_wan2(response)["ip"] is None


@pytest.mark.parametrize("model,mode", [("rc01", Mode.DEFAULT), ("rd28", Mode.DEFAULT),
                                          ("rd08", Mode.MESH_NODE)])
async def test_unsupported_models_and_mesh_nodes_are_not_probed(hass, model, mode):
    instance = updater(hass, model=model, mode=mode)
    instance.data["multiwan"] = {"enabled": True, "wan2": {"ip": "192.0.2.99"}}
    await instance._async_prepare_multiwan(instance.data)
    instance.luci.multiwan_info.assert_not_awaited()
    instance.luci.wan_info.assert_not_awaited()
    assert instance.data["multiwan"] == {}


async def test_capability_is_cached_but_wan2_refreshes(hass):
    instance = updater(hass)
    with patch("custom_components.miwifi.updater.monotonic", return_value=100):
        await instance._async_prepare_multiwan(instance.data)
        await instance._async_prepare_multiwan(instance.data)
    instance.luci.multiwan_info.assert_awaited_once()
    assert instance.luci.wan_info.await_count == 2
    assert instance.data["multiwan"]["wan2"]["ip"] == "192.0.2.20"


@pytest.mark.parametrize("error", [asyncio.TimeoutError(), LuciError(), ValueError("bad payload")])
async def test_secondary_failures_clear_stale_values_without_harming_primary(hass, error):
    instance = updater(hass)
    await instance._async_prepare_multiwan(instance.data)
    instance.luci.wan_info.side_effect = error
    await instance._async_prepare_multiwan(instance.data)
    assert instance.data["multiwan"] == {"enabled": True, "wan2": None}
    assert instance.data["wan_ip"] == "192.0.2.10"
    assert instance.data["wan_state"] is True


async def test_disable_and_enable_are_detected_after_cache_expires(hass):
    instance = updater(hass)
    for now, enabled in [(1, 0), (302, 1), (603, 0)]:
        instance.luci.multiwan_info.return_value = {"code": 0, "multiwan": {"enable": enabled}}
        with patch("custom_components.miwifi.updater.monotonic", return_value=now):
            await instance._async_prepare_multiwan(instance.data)
        assert instance.data["multiwan"]["enabled"] is bool(enabled)
        assert (instance.data["multiwan"]["wan2"] is not None) is bool(enabled)
    instance.luci.wan_info.assert_awaited_once_with("WAN2")


async def test_failed_discovery_is_cached_and_retried(hass):
    instance = updater(hass)
    instance.luci.multiwan_info.side_effect = LuciError()
    for now in (1, 2, 302):
        with patch("custom_components.miwifi.updater.monotonic", return_value=now):
            await instance._async_prepare_multiwan(instance.data)
        assert instance.data["multiwan"] == {}
    assert instance.luci.multiwan_info.await_count == 2
    instance.luci.wan_info.assert_not_awaited()


async def test_cancellation_propagates(hass):
    instance = updater(hass)
    instance.luci.multiwan_info.side_effect = asyncio.CancelledError()
    with pytest.raises(asyncio.CancelledError):
        await instance._async_prepare_multiwan(instance.data)


async def test_sensor_status_changes_write_even_with_same_ip(hass):
    instance = updater(hass)
    await instance._async_prepare_multiwan(instance.data)
    sensor = MiWifiWan2Sensor(instance, "synthetic-entry")
    assert sensor.available
    assert sensor.native_value == "192.0.2.20"
    assert sensor.extra_state_attributes == {
        "enabled": True, "type": "dhcp", "link": True, "connected": True,
    }
    with patch.object(sensor, "async_write_ha_state") as write:
        instance.data["multiwan"]["wan2"]["connected"] = False
        sensor._handle_coordinator_update()
        write.assert_called_once()
    assert sensor.extra_state_attributes["connected"] is False
    instance.data["multiwan"]["wan2"] = None
    assert not sensor.available
    assert sensor.native_value is None
    assert sensor.extra_state_attributes["link"] is None
