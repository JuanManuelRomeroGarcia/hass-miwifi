"""Regression coverage for issue 402; addresses are documentation examples."""
import pytest
from custom_components.miwifi.cpe_ipv6 import is_cb0401v2, parse_ipv6


def test_ipv6_nested_values_and_no_guessed_prefix():
    result = parse_ipv6({"up": True, "ip6addr": ["2001:db8:1::1/64", "2001:db8:1::2/64"],
                         "lan_ip6addr": [["2001:db8:2::1/64"]],
                         "lan_ip6prefix": ["2001:db8:2::"], "ipv6_mode": "pi_relay",
                         "ip6gw": "fe80::1", "dns": ["2001:db8:3::1"]})
    assert result["up"] is True
    assert result["wan"] == "2001:db8:1::1/64"
    assert result["lan"] == "2001:db8:2::1/64"
    assert result["prefix"] == "2001:db8:2::"
    assert result["mode"] == "pi_relay"
    assert result["gateway"] == "fe80::1"
    assert result["dns"] == ["2001:db8:3::1"]
    assert len(result["wan_addresses"]) == 2


@pytest.mark.parametrize("value,expected", [(False, False), (True, True), (None, None), ("0", False), ("1", True), ("unknown", None), ([], None)])
def test_interface_state(value, expected):
    assert parse_ipv6({"up": value})["up"] is expected


def test_missing_or_invalid_values_are_unknown():
    assert parse_ipv6(None)["up"] is None
    result = parse_ipv6({"ip6addr": ["10.0.0.1", "broken"], "lan_ip6addr": [], "lan_ip6prefix": [{}], "dns": ["bad"], "ipv6_mode": {}})
    assert result["wan"] is None and result["lan"] is None and result["prefix"] is None
    assert result["dns"] == [] and result["mode"] is None

from datetime import timedelta
from unittest.mock import AsyncMock, Mock, patch
from homeassistant.util import dt as dt_util
from homeassistant.components.binary_sensor import BinarySensorEntityDescription
from custom_components.miwifi.binary_sensor import MiWifiIPv6Interface, async_setup_entry as setup_binary
from custom_components.miwifi.sensor import IPV6_SENSORS, MiWifiIPv6Sensor, _is_cb0401v2, _async_add_all_sensors_later
from custom_components.miwifi.enum import Mode
from custom_components.miwifi.exceptions import LuciAuthenticationError, LuciConnectionError
from tests.test_force_load_client_refresh import nodes


@pytest.mark.parametrize("model,expected", [("CB0401V2", True), ("xiaomi.router.cb0401v2", True), ("CB0401V2-pro", False), ("RC06", False), ("CB0401V3", False), ("", False)])
async def test_binary_creation_is_restricted_to_exact_model(hass, nodes, model, expected):
    updater = nodes("192.0.2.1", "02:00:00:00:00:01", Mode.DEFAULT)
    updater.data["device_model"] = model
    assert is_cb0401v2(updater) is expected
    entry = hass.config_entries.async_get_entry(updater.entry_id)
    found = []
    await setup_binary(hass, entry, found.extend)
    assert any(isinstance(entity, MiWifiIPv6Interface) for entity in found) is expected
    updater.data["topo_graph"] = {"graph": {"is_main": False}}
    found = []
    with patch("custom_components.miwifi.sensor._device_sensors_enabled", return_value=False):
        await _async_add_all_sensors_later(hass, entry, found.extend)
    assert sum(isinstance(entity, MiWifiIPv6Sensor) for entity in found) == (4 if expected else 0)


async def test_legacy_broad_cpe_profile_does_not_enable_ipv6_for_other_models(hass, nodes):
    updater = nodes("192.0.2.1", "02:00:00:00:00:01", Mode.DEFAULT)
    updater.data.update({"device_model": "CB0401V3", "cpe_profile": "CB0401V2", "topo_graph": {"graph": {"is_main": False}}})
    entry = hass.config_entries.async_get_entry(updater.entry_id)
    entities = []
    await setup_binary(hass, entry, entities.extend)
    with patch("custom_components.miwifi.sensor._device_sensors_enabled", return_value=False):
        await _async_add_all_sensors_later(hass, entry, entities.extend)
    assert not any(isinstance(entity, (MiWifiIPv6Sensor, MiWifiIPv6Interface)) for entity in entities)


async def test_exact_hardware_identification_precedes_generic_model_name(hass, nodes):
    updater = nodes("192.0.2.1", "02:00:00:00:00:01", Mode.DEFAULT)
    updater._is_first_update = True
    updater.luci.init_info = AsyncMock(return_value={"model": "Xiaomi 5G CPE Pro", "hardware": "CB0401V2"})
    await updater._async_prepare_init(updater.data)
    assert is_cb0401v2(updater)
    updater.luci.init_info.return_value = {"model": "CB0401V2", "hardware": "CB0401V3"}
    await updater._async_prepare_init(updater.data)
    assert not is_cb0401v2(updater)


async def test_sensor_states_switch_and_query_failure(hass, nodes):
    updater = nodes("192.0.2.1", "02:00:00:00:00:01", Mode.DEFAULT)
    updater.data["device_model"] = "CB0401V2"
    updater.luci.get_mobile_net_info = AsyncMock(side_effect=[
        {"code": 0, "ipv6info": {"up": True, "ip6addr": ["2001:db8::1/64"]}},
        {"code": 0, "ipv6info": {"up": False}},
        {"code": 0},
        LuciConnectionError("synthetic failure"),
        {"code": 0, "ipv6info": {"up": True, "ip6addr": ["2001:db8::2/64"]}},
    ])
    updater._cpe_detect_next_try = dt_util.utcnow() + timedelta(hours=1)
    updater._sms_next_try = dt_util.utcnow() + timedelta(hours=1)
    await updater._async_prepare_cpe_mobile(updater.data)
    binary = MiWifiIPv6Interface("id-ipv6", BinarySensorEntityDescription(key="mobile_ipv6_interface", name="IPv6 interface"), updater)
    sensor = MiWifiIPv6Sensor("id-wan", IPV6_SENSORS[0], updater)
    assert binary.is_on is True and sensor.native_value == "2001:db8::1/64"
    assert sensor.available and binary.available
    await updater._async_prepare_cpe_mobile(updater.data)
    assert binary.is_on is False and sensor.native_value is None
    await updater._async_prepare_cpe_mobile(updater.data)
    assert binary.is_on is None and sensor.available and binary.available
    await updater._async_prepare_cpe_mobile(updater.data)
    assert not sensor.available and not binary.available
    updater._cpe_mobile_next_try = dt_util.utcnow() - timedelta(seconds=1)
    await updater._async_prepare_cpe_mobile(updater.data)
    assert binary.is_on is True and sensor.available and sensor.native_value == "2001:db8::2/64"
    assert updater.luci.get_mobile_net_info.await_count == 5


async def test_diagnostics_redact_full_cpe_payload_and_requests(hass, nodes):
    import json
    from custom_components.miwifi.diagnostics import async_get_config_entry_diagnostics
    updater = nodes("192.0.2.1", "02:00:00:00:00:01", Mode.DEFAULT)
    entry = hass.config_entries.async_get_entry(updater.entry_id)
    secret = "2001:db8:1234::123"
    updater.data.update({"device_model": "CB0401V2", "mobile_net_info": {"ipv6info": {"ip6addr": [secret]}, "info": {"imei": "synthetic-imei"}},
                         "mobile_ipv4": "192.0.2.123"})
    updater.luci.diagnostics = {"xqdtcustom/get_mobile_net_info": {"content": "raw " + secret + " synthetic-imei"}}
    with patch("custom_components.miwifi.diagnostics.async_get_integration", new=AsyncMock(return_value=Mock(version="test"))), patch("custom_components.miwifi.diagnostics.build_mesh_support", return_value={}):
        result = await async_get_config_entry_diagnostics(hass, entry)
    exported = json.dumps(result)
    assert secret not in exported and "synthetic-imei" not in exported and "192.0.2.123" not in exported
    assert "192.0.2.1" not in exported
    assert "02:00:00:00:00:01" not in exported
    assert updater.data["mobile_net_info"]["ipv6info"]["ip6addr"] == [secret]


async def test_authentication_error_remains_visible_to_coordinator(hass, nodes):
    updater = nodes("192.0.2.1", "02:00:00:00:00:01", Mode.DEFAULT)
    updater.data["device_model"] = "CB0401V2"
    updater.luci.get_mobile_net_info = AsyncMock(side_effect=LuciAuthenticationError("synthetic"))
    with pytest.raises(LuciAuthenticationError):
        await updater._async_prepare_cpe_mobile(updater.data)
    assert updater.data["mobile_ipv6_query_ok"] is False
    assert updater.luci.get_mobile_net_info.await_count == 1


async def test_legacy_cpe_errors_are_unchanged_for_other_models(hass, nodes):
    updater = nodes("192.0.2.1", "02:00:00:00:00:01", Mode.DEFAULT)
    updater.data.update({"device_model": "CB0401V3", "cpe_ipv6_model_exact": False})
    updater.luci.get_mobile_net_info = AsyncMock(side_effect=LuciConnectionError("synthetic"))
    with pytest.raises(LuciConnectionError):
        await updater._async_prepare_cpe_mobile(updater.data)
    assert "mobile_ipv6_query_ok" not in updater.data
