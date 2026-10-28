"""A parent's push reads the signal of a node's clients from a complete census.

A node keeps the signal of each client on its radios, from its radio list
(xqnetwork/wifi_connect_devices), in `_signals`. `_build_device()` reads that
map, also when the main's device list pushes the node's clients to it. Since
v3.13.0 the node emptied the map as soon as its radio list returned and
refilled it row by row, awaiting macfilter_info before the first row and
add_device for each. A push that landed in between found no signal and wrote
None for signal, signal_unit and signal_source. A force-load node's own census
does not write those back, so they stayed unknown until the main's next push.

Runs the real census steps of LuciUpdater over scripted router APIs. The
main's push runs inside one of the node's awaits, where the event loop can
run it.
"""

from __future__ import annotations

from unittest.mock import AsyncMock, Mock, patch

import pytest

from homeassistant.const import CONF_IP_ADDRESS
from pytest_homeassistant_custom_component.common import MockConfigEntry

from custom_components.miwifi.const import (
    ATTR_DEVICE_MAC_ADDRESS,
    ATTR_SENSOR_MODE,
    ATTR_STATE,
    ATTR_TRACKER_SIGNAL,
    DOMAIN,
    UPDATER,
)
from custom_components.miwifi.enum import Mode
from custom_components.miwifi.exceptions import LuciConnectionError
from custom_components.miwifi.updater import LuciUpdater

MAIN_IP, NODE_IP = "192.0.2.1", "192.0.2.2"
MAIN_MAC, NODE_MAC = "02:00:00:00:00:01", "02:00:00:00:00:02"
PHONE = "02:00:00:00:00:41"  # on the node's radio; the main routes it there
LAPTOP = "02:00:00:00:00:42"  # another client on the node's radio

SIGNAL = (ATTR_TRACKER_SIGNAL, "signal_unit", "signal_source")


@pytest.fixture
async def mesh(hass):
    """A main with the access point option and a mesh node, both force load."""
    made: list[LuciUpdater] = []

    def make(ip, mac, mode, *, ap_mode=False):
        entry = MockConfigEntry(domain=DOMAIN, title=ip, data={CONF_IP_ADDRESS: ip})
        entry.add_to_hass(hass)
        updater = LuciUpdater(
            hass, ip, "test-password", entry_id=entry.entry_id,
            is_force_load=True, is_ap_mode=ap_mode,
        )
        updater.update_interval = None
        updater.data = {ATTR_STATE: True, ATTR_SENSOR_MODE: mode, ATTR_DEVICE_MAC_ADDRESS: mac}
        updater.luci = Mock(macfilter_info=AsyncMock(return_value={}))
        hass.data.setdefault(DOMAIN, {})[entry.entry_id] = {CONF_IP_ADDRESS: ip, UPDATER: updater}
        made.append(updater)
        return updater

    with (
        patch("custom_components.miwifi.updater.LuciClient"),
        patch("custom_components.miwifi.updater.get_async_client", return_value=Mock()),
        patch("custom_components.miwifi.updater.asyncio.sleep", AsyncMock()),
    ):
        main = make(MAIN_IP, MAIN_MAC, Mode.ACCESS_POINT, ap_mode=True)
        node = make(NODE_IP, NODE_MAC, Mode.MESH_NODE)
        yield main, node
        for updater in made:
            await updater.async_shutdown()


def _radio(node, signals):
    """The node's radio list: only MAC, band and signal."""
    node.luci.wifi_connect_devices = AsyncMock(return_value={"code": 0, "list": [
        {"mac": mac, "wifiIndex": 2, "signal": signal} for mac, signal in signals.items()
    ]})


def _routes(main, *clients):
    """The main's device list: the node, and clients it routes to the node."""
    rows = [{"mac": NODE_MAC, "isap": 8, "parent": "", "ip": [{"ip": NODE_IP, "active": 1}]}]
    rows += [
        {"mac": mac, "name": f"Client {mac[-2:]}", "isap": 0, "parent": NODE_MAC,
         "online": 1, "type": 2,
         "ip": [{"ip": f"192.0.2.{mac[-2:]}", "active": 1, "online": "100",
                 "upspeed": "1", "downspeed": "2"}]}
        for mac in clients
    ]
    main.luci.device_list = AsyncMock(side_effect=lambda: {"code": 0, "list": [dict(r) for r in rows]})
    main.luci.client_details = AsyncMock(return_value={"code": 0, "devices": []})


async def _census(node):
    await node._async_prepare_devices(node.data)


async def _push(main):
    """The main's device list, which pushes the node's clients to it."""
    await main._async_prepare_device_list(main.data)


def _push_during(main, result):
    """A call of the node that the main's push lands in before it returns."""

    async def call(*args, **kwargs):
        await _push(main)
        return result

    return AsyncMock(side_effect=call)


def _signal(record):
    return {key: record.get(key) for key in SIGNAL}


def _radio_signal(value):
    return {ATTR_TRACKER_SIGNAL: value, "signal_unit": "%", "signal_source": "wifi_connect_devices"}


async def _settled(mesh, signals):
    """An earlier refresh: the node's census, then the main's push."""
    main, node = mesh
    _routes(main, *signals)
    _radio(node, signals)
    await _census(node)
    await _push(main)
    for mac, signal in signals.items():
        assert _signal(node.devices[mac]) == _radio_signal(signal)


async def test_push_while_the_node_reads_its_filter_list(hass, mesh):
    """The push lands while the node waits on macfilter_info."""
    main, node = mesh
    await _settled(mesh, {PHONE: 70})

    _radio(node, {PHONE: 55})
    node.luci.macfilter_info = _push_during(main, {})
    await _census(node)

    node.luci.macfilter_info.assert_awaited_once()
    assert _signal(node.devices[PHONE]) == _radio_signal(55)
    assert _signal(hass.data[DOMAIN]["devices_cache"][PHONE]) == _radio_signal(55)


async def test_push_while_the_node_adds_a_client(mesh):
    """The push lands while add_device awaits for an earlier row.

    add_device awaits the purged-clients store, which loads on first use and
    saves when a purged client returns, and logs a new client through the
    executor.
    """
    main, node = mesh
    await _settled(mesh, {PHONE: 70})

    landed: list[str] = []

    async def blocked(mac, reported=None):
        if mac == LAPTOP and not landed:
            landed.append(mac)
            await _push(main)
        return False

    _radio(node, {LAPTOP: 60, PHONE: 55})
    with patch(
        "custom_components.miwifi.updater.get_purged_clients",
        return_value=Mock(async_blocked=blocked),
    ):
        await _census(node)

    assert landed == [LAPTOP]
    assert _signal(node.devices[PHONE]) == _radio_signal(55)
    assert _signal(node.devices[LAPTOP]) == _radio_signal(60)


async def test_census_drops_the_signal_of_a_client_that_left_the_radio(mesh):
    """A push in the window still finds no signal for a client the radio lost."""
    main, node = mesh
    await _settled(mesh, {PHONE: 70, LAPTOP: 60})

    # The main still routes the laptop to the node; the node's radio no
    # longer lists it.
    _radio(node, {PHONE: 55})
    node.luci.macfilter_info = _push_during(main, {})
    await _census(node)

    assert node._signals == {PHONE: 55}
    assert _signal(node.devices[LAPTOP]) == dict.fromkeys(SIGNAL)


async def test_failed_radio_list_keeps_the_last_census(mesh):
    """A radio list that fails is no census: the last one stands."""
    main, node = mesh
    await _settled(mesh, {PHONE: 70})

    node.luci.wifi_connect_devices = AsyncMock(side_effect=LuciConnectionError("timeout"))
    with pytest.raises(LuciConnectionError):
        await _census(node)
    await _push(main)

    assert node._signals == {PHONE: 70}
    assert _signal(node.devices[PHONE]) == _radio_signal(70)
