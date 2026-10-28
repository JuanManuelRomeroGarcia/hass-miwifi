"""Regressions for parent freshness, replacement and wired client sensors."""
from unittest.mock import patch

import pytest

from custom_components.miwifi.const import ATTR_TRACKER_CONNECTION, ATTR_TRACKER_SIGNAL
from custom_components.miwifi.enum import Connection, Mode
from custom_components.miwifi.sensor import MIWIFI_DEVICE_SENSORS, MiWifiDeviceAttributeSensor
from tests.test_force_load_client_refresh import (
    nodes,
    FIRST, LEAF_IP, LEAF_MAC, MAIN_IP, MAIN_MAC, PUSHED, WIFI,
    _census, _main_census, _poll, _push, _radio, _row,
)


@pytest.mark.parametrize("age,signal,unit", [(109, -43, "dBm"), (110, -43, "dBm"), (111, 35, "%")])
async def test_parent_snapshot_expires_at_the_actual_default_boundary(nodes, age, signal, unit):
    main = nodes(MAIN_IP, MAIN_MAC, Mode.ACCESS_POINT, ap_mode=True)
    leaf = nodes(LEAF_IP, LEAF_MAC, Mode.MESH_NODE)
    # Use an exactly representable clock origin: adding 110 to an arbitrary
    # fractional monotonic value can round its subtraction just above 110.
    observed = 1024.0
    with patch("custom_components.miwifi.updater.monotonic", return_value=observed):
        await _push(main)
    _radio(leaf, {PUSHED: 35}, band=2)
    with patch("custom_components.miwifi.updater.monotonic", return_value=observed + age):
        await _poll(leaf)
    assert leaf.devices[PUSHED][ATTR_TRACKER_SIGNAL] == signal
    assert leaf.devices[PUSHED]["signal_unit"] == unit


async def test_replaced_main_does_not_keep_ownership_of_its_old_snapshot(nodes):
    main = nodes(MAIN_IP, MAIN_MAC, Mode.ACCESS_POINT, ap_mode=True)
    leaf = nodes(LEAF_IP, LEAF_MAC, Mode.MESH_NODE)
    await _push(main)
    replacement = nodes(MAIN_IP, MAIN_MAC, Mode.ACCESS_POINT, ap_mode=True)
    _radio(leaf, {PUSHED: 35}, band=2)
    await _poll(leaf)
    assert leaf.devices[PUSHED][ATTR_TRACKER_SIGNAL] == 35
    assert leaf.devices[PUSHED]["signal_unit"] == "%"
    await _push(replacement, rssi=-65)
    await _poll(leaf)
    assert leaf.devices[PUSHED][ATTR_TRACKER_SIGNAL] == -65
    assert leaf.devices[PUSHED]["signal_unit"] == "dBm"


@pytest.mark.parametrize("key", ["signal", "signal_quality", "wifi_protocol", "link_tx_rate", "link_rx_rate"])
async def test_wifi_metrics_are_hidden_after_client_changes_to_lan(hass, nodes, key):
    main = nodes(MAIN_IP, MAIN_MAC, Mode.ACCESS_POINT, ap_mode=True)
    await _main_census(main, FIRST)
    _radio(main, {})
    _census(main, [_row(WIFI, ip="192.0.2.141", uptime=200, speed=30, wired=True)])
    await _poll(main)
    device = main.devices[WIFI]
    assert device[ATTR_TRACKER_CONNECTION] == Connection.LAN
    description = next(d for d in MIWIFI_DEVICE_SENSORS if d.key == key)
    sensor = MiWifiDeviceAttributeSensor(main, device, description)
    sensor.hass = hass
    assert sensor.native_value is None
