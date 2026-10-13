"""The main's push must not blank the counters of a leaf that counts its own clients.

A force-load leaf without dedicated IoT Wi-Fi takes its counters from its own
`new_status`, and `add_device(is_from_parent=True)` does not count for it. If
the main's push resets those counters, they stay at zero until the leaf's next
refresh, and any state write in between - entity creation at startup, for
example - shows zero clients.
"""

from __future__ import annotations

from unittest.mock import AsyncMock, Mock, patch

import pytest

from homeassistant.const import CONF_IP_ADDRESS
from pytest_homeassistant_custom_component.common import MockConfigEntry

from custom_components.miwifi.const import (
    ATTR_DEVICE_MAC_ADDRESS,
    ATTR_SENSOR_DEVICES,
    ATTR_SENSOR_DEVICES_2_4,
    ATTR_SENSOR_MODE,
    ATTR_STATE,
    DOMAIN,
    UPDATER,
)
from custom_components.miwifi.enum import Mode
from custom_components.miwifi.updater import LuciUpdater

MAIN_IP = "192.0.2.1"
LEAF_IP = "192.0.2.2"
LEAF_MAC = "02:00:00:00:00:02"
CLIENT_MAC = "02:00:00:00:00:41"


@pytest.fixture
def router_doubles():
    with (
        patch("custom_components.miwifi.updater.LuciClient"),
        patch("custom_components.miwifi.updater.get_async_client", return_value=Mock()),
        patch(
            "custom_components.miwifi.update.MiWiFiNewDeviceNotifier.async_notify_new_device",
            new_callable=AsyncMock,
        ),
        patch.object(LuciUpdater, "_build_device", side_effect=lambda device, integrations: dict(device)),
    ):
        yield


def _updater(hass, ip, *, mode, force_load=False, data=None):
    entry = MockConfigEntry(domain=DOMAIN, title=ip, data={CONF_IP_ADDRESS: ip})
    entry.add_to_hass(hass)
    updater = LuciUpdater(hass, ip, "test-password", entry_id=entry.entry_id, is_force_load=force_load)
    updater.update_interval = None
    updater.data = {ATTR_STATE: True, ATTR_SENSOR_MODE: mode, **(data or {})}
    hass.data.setdefault(DOMAIN, {})[entry.entry_id] = {CONF_IP_ADDRESS: ip, UPDATER: updater}
    return updater


async def _main_refresh(main):
    main.luci.device_list = AsyncMock(return_value={"code": 0, "list": [{
        "mac": CLIENT_MAC, "isap": 0, "parent": LEAF_MAC, "online": 1,
        "ip": [{"ip": "192.0.2.50", "active": 1}],
    }]})
    with patch("custom_components.miwifi.updater.asyncio.sleep", AsyncMock()):
        await main._async_prepare_device_list(main.data)


async def test_push_keeps_the_counters_of_a_self_counting_force_load_leaf(hass, router_doubles):
    main = _updater(hass, MAIN_IP, mode=Mode.ACCESS_POINT)
    # As left by the leaf's own refresh: new_status counted 17 clients.
    leaf = _updater(hass, LEAF_IP, mode=Mode.MESH_NODE, force_load=True, data={
        ATTR_DEVICE_MAC_ADDRESS: LEAF_MAC, ATTR_SENSOR_DEVICES: 17, ATTR_SENSOR_DEVICES_2_4: 14,
    })
    try:
        await _main_refresh(main)

        assert CLIENT_MAC in leaf.devices  # the client data still reaches the leaf
        assert leaf.data[ATTR_SENSOR_DEVICES] == 17
        assert leaf.data[ATTR_SENSOR_DEVICES_2_4] == 14
    finally:
        await main.async_shutdown()
        await leaf.async_shutdown()


@pytest.mark.parametrize("leaf_kind", ["not_force_load", "force_load_with_iot_wifi"])
async def test_push_still_recounts_a_leaf_whose_counters_the_main_owns(hass, router_doubles, leaf_kind):
    main = _updater(hass, MAIN_IP, mode=Mode.ACCESS_POINT)
    data = {ATTR_DEVICE_MAC_ADDRESS: LEAF_MAC, ATTR_SENSOR_DEVICES: 17}
    if leaf_kind == "force_load_with_iot_wifi":
        data["features"] = {"wifi": {"iot_dev": "1"}}
    leaf = _updater(hass, LEAF_IP, mode=Mode.MESH_NODE, force_load=leaf_kind != "not_force_load", data=data)
    try:
        await _main_refresh(main)

        # Reset, then counted from the push: one client.
        assert leaf.data[ATTR_SENSOR_DEVICES] == 1
    finally:
        await main.async_shutdown()
        await leaf.async_shutdown()
