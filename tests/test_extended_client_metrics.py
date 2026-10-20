"""Extended metrics must not change the authoritative client census or routing."""
from copy import deepcopy
from types import SimpleNamespace
from unittest.mock import AsyncMock, Mock, patch

import pytest
from pytest_homeassistant_custom_component.common import MockConfigEntry

from custom_components.miwifi.const import DOMAIN, UPDATER
from custom_components.miwifi.enum import Connection, Mode, Model
from custom_components.miwifi.exceptions import LuciConnectionError, LuciError
from custom_components.miwifi.helper import map_signal_quality
from custom_components.miwifi.luci import LuciClient
from custom_components.miwifi.sensor import MIWIFI_DEVICE_SENSORS, MiWifiDeviceAttributeSensor
from custom_components.miwifi.updater import LuciUpdater

MAC = "02:00:00:00:00:41"
NODE = "02:00:00:00:00:02"
ROW = {"mac": MAC, "name": "Test client", "online": 1, "type": 5,
       "parent": "", "ip": [{"ip": "192.0.2.41", "active": 1, "online": "100", "upspeed": "12"}]}
DETAIL = {"mac": MAC.lower(), "online": 1, "parent": "", "ip": "192.0.2.41",
          "signal": "-43", "wifiprotocol": "Wi-Fi 6(802.11ax)",
          "nego_tx_rate": "2401Mbps", "nego_rx_rate": "2161Mbps"}


def make_updater(hass, ip="192.0.2.1", mac="02:00:00:00:00:01"):
    entry = MockConfigEntry(domain=DOMAIN, data={"ip_address": ip})
    entry.add_to_hass(hass)
    updater = LuciUpdater(hass, ip, "synthetic", entry_id=entry.entry_id)
    updater.update_interval = None
    updater.data = {"state": True, "mode": Mode.DEFAULT, "device_mac_address": mac,
                    "model": Model.RC01, "features": {"wifi": {"iot_dev": "1"}}}
    updater._signals = {MAC: 82}
    updater._is_first_update = True
    updater._mass_update_device = Mock(return_value=False)

    async def record(row, **kwargs):
        updater.devices[row["mac"]] = updater._build_device(row)
    updater.add_device = AsyncMock(side_effect=record)
    return updater


async def census(updater, rows, payload, integrations):
    reader = AsyncMock(side_effect=payload) if isinstance(payload, BaseException) else AsyncMock(return_value=payload)
    updater.luci = SimpleNamespace(device_list=AsyncMock(return_value={"code": 0, "list": deepcopy(rows)}), client_details=reader)
    with (
        patch("custom_components.miwifi.updater.async_get_integrations", return_value=integrations),
        patch("custom_components.miwifi.updater.asyncio.sleep", AsyncMock()),
        patch("custom_components.miwifi.updater.get_mac_replacement", return_value=Mock(async_candidates=AsyncMock(return_value=set()))),
        patch("custom_components.miwifi.updater.async_retire_macs", AsyncMock()),
    ):
        await updater._async_prepare_device_list(updater.data)
    return reader


async def test_live_metrics_are_enrichment_not_a_second_census(hass):
    updater = make_updater(hass)
    extra = {**DETAIL, "mac": "02:00:00:00:00:99", "online": 1}
    await census(updater, [ROW], {"devices": [DETAIL, extra]}, {updater.ip: {UPDATER: updater}})
    assert set(updater.devices) == {MAC}
    device = updater.devices[MAC]
    assert device["signal"] == -43
    assert device["signal_unit"] == "dBm"
    assert device["wifi_protocol"] == "Wi-Fi 6(802.11ax)"
    assert (device["link_tx_rate"], device["link_rx_rate"]) == (2401, 2161)
    assert device["connection"] == Connection.WIFI_5_0_GAME
    assert device["up_speed"] == 12  # PHY rate must not replace traffic speed.
    assert device["online"] == "0:01:40"


async def test_main_forwards_metrics_to_leaf_without_importing_extra_clients(hass):
    main = make_updater(hass)
    leaf = make_updater(hass, "192.0.2.2", NODE)
    rows = [{**ROW, "parent": NODE}]
    integrations = {main.ip: {UPDATER: main}, leaf.ip: {UPDATER: leaf}}
    await census(main, rows, {"devices": [{**DETAIL, "parent": NODE}]}, integrations)
    assert not main.devices
    assert leaf.devices[MAC]["signal"] == -43
    assert leaf.devices[MAC]["link_rx_rate"] == 2161
    assert leaf.devices[MAC]["router_mac"] == NODE


@pytest.mark.parametrize("payload", [
    {"devices": [{**DETAIL, "online": 0}]},
    {"devices": [{**DETAIL, "parent": NODE}]},
    {"devices": [{**DETAIL, "ip": "192.0.2.99"}]},
    {"devices": []}, {"code": 0}, {"code": 1, "devices": [DETAIL]},
    LuciConnectionError("synthetic timeout"), LuciError("synthetic unsupported"),
])
async def test_missing_failed_offline_or_roaming_metrics_keep_legacy_census(hass, payload):
    updater = make_updater(hass)
    updater.devices[MAC] = {"wifi_protocol": "old", "link_tx_rate": 9999, "signal": -20}
    reader = await census(updater, [ROW], payload, {updater.ip: {UPDATER: updater}})
    device = updater.devices[MAC]
    assert device["signal"] == 82
    assert device["signal_unit"] == "%"
    assert device["wifi_protocol"] is None
    assert device["link_tx_rate"] is None
    assert device["ip"] == "192.0.2.41"
    if isinstance(payload, BaseException) or "devices" not in payload or payload.get("code", 0) != 0:
        # No repeated unsupported/timeout requests on the immediately next scan.
        with patch("custom_components.miwifi.updater.async_get_integrations", return_value={}):
            updater.luci.device_list.return_value = {"list": []}
            updater._client_details_retry_at += 1
            with patch("custom_components.miwifi.updater.get_mac_replacement", return_value=Mock(async_candidates=AsyncMock(return_value=set()))), patch("custom_components.miwifi.updater.async_retire_macs", AsyncMock()):
                await updater._async_prepare_device_list({})
        reader.assert_awaited_once()


@pytest.mark.parametrize("signal,rate", [("", ""), ("invalid", "badMbps"), ("82", "nanMbps"), ("-200", "-1Mbps")])
async def test_invalid_extended_numbers_do_not_become_zero(hass, signal, rate):
    updater = make_updater(hass)
    await census(updater, [ROW], {"devices": [{**DETAIL, "signal": signal, "nego_tx_rate": rate}]}, {})
    assert updater.devices[MAC]["signal"] == 82
    assert updater.devices[MAC]["link_tx_rate"] is None


@pytest.mark.parametrize("rssi,label", [(-43, "very_strong"), (-54, "strong"), (-67, "fair"), (-77, "weak"), (-90, "weak")])
def test_rssi_quality_has_its_own_scale(rssi, label):
    assert map_signal_quality(rssi, "dBm") == label
    assert map_signal_quality(82) == "very_strong"


async def test_api_uses_distinct_path_and_bounded_timeout():
    client = LuciClient(Mock(), ip="192.0.2.1", password="synthetic")
    client.get = AsyncMock(return_value={"devices": []})
    await client.client_details()
    client.get.assert_awaited_once_with("misystem/device_list", timeout=5.0)


async def test_force_load_parent_can_clear_obsolete_metrics(hass):
    leaf = make_updater(hass, "192.0.2.2", NODE)
    leaf.is_force_load = True
    leaf.data["mode"] = Mode.REPEATER
    leaf._signals.clear()
    leaf.devices[MAC] = {"signal": -43, "signal_unit": "dBm",
                         "wifi_protocol": "Wi-Fi 6(802.11ax)", "link_tx_rate": 2401}
    row = {**ROW, "entry_id": leaf._entry_id, "_miwifi_details": {}}
    with (
        patch("custom_components.miwifi.updater.get_purged_clients", return_value=Mock(async_blocked=AsyncMock(return_value=False))),
        patch("custom_components.miwifi.updater.async_get_integrations", return_value={leaf.ip: {UPDATER: leaf}}),
    ):
        await LuciUpdater.add_device(leaf, row, is_from_parent=True)
    for key in ("signal", "signal_unit", "wifi_protocol", "link_tx_rate", "link_rx_rate"):
        assert leaf.devices[MAC][key] is None
        assert hass.data[DOMAIN]["devices_cache"][MAC][key] is None


async def test_lan_client_cannot_retain_wifi_metrics_even_with_stale_api_fields(hass):
    updater = make_updater(hass)
    updater.devices[MAC] = {"signal": -43, "signal_unit": "dBm", "wifi_protocol": "Wi-Fi 6(802.11ax)", "link_tx_rate": 2401}
    row = {**ROW, "type": 0, "entry_id": updater._entry_id, "_miwifi_details": DETAIL}
    device = updater._build_device(row)
    assert device["connection"] == Connection.LAN
    assert device["up_speed"] == 12
    for key in ("signal", "signal_unit", "signal_source", "wifi_protocol", "link_tx_rate", "link_rx_rate"):
        assert device[key] is None


@pytest.mark.parametrize("key,value", [("signal", -43), ("signal_quality", "very_strong"), ("wifi_protocol", "Wi-Fi 6(802.11ax)"), ("link_tx_rate", 2401), ("link_rx_rate", 2161)])
async def test_existing_and_new_ha_sensors_read_extended_values(hass, key, value):
    updater = make_updater(hass)
    row = {**ROW, "entry_id": updater._entry_id, "_miwifi_details": DETAIL}
    device = updater._build_device(row)
    updater.devices[MAC] = device
    description = next(d for d in MIWIFI_DEVICE_SENSORS if d.key == key)
    sensor = MiWifiDeviceAttributeSensor(updater, device, description)
    sensor.hass = hass
    assert sensor.native_value == value
