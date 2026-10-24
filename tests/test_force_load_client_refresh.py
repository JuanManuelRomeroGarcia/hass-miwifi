"""A force-load node refreshes the clients no other node pushes to it.

A force-load repeater - a mesh node, or a main typed access point - lists the
clients on its own radios (xqnetwork/wifi_connect_devices) and in its own
misystem/devicelist. Once a client was known, a later report of it from the
node's own lists was merged without name, address, uptime, speeds, signal or
Wi-Fi metrics: those were left to the main's push. Only a client the main
pushed got them again. A main in access point mode has no node above it, and
a mesh node's radio list has clients the main's device list does not route
to it: their first record stayed until Home Assistant restarted.

Runs the real census steps of LuciUpdater, in a poll's order, over scripted
router APIs.
"""

from __future__ import annotations

from time import monotonic
from types import SimpleNamespace
from unittest.mock import AsyncMock, Mock, patch

import pytest

from homeassistant.const import CONF_IP_ADDRESS
from pytest_homeassistant_custom_component.common import MockConfigEntry

from custom_components.miwifi.const import (
    ATTR_DEVICE_MAC_ADDRESS,
    ATTR_SENSOR_MODE,
    ATTR_STATE,
    ATTR_TRACKER_CONNECTION,
    ATTR_TRACKER_DOWN_SPEED,
    ATTR_TRACKER_ENTRY_ID,
    ATTR_TRACKER_IP,
    ATTR_TRACKER_IS_RESTORED,
    ATTR_TRACKER_NAME,
    ATTR_TRACKER_ONLINE,
    ATTR_TRACKER_SIGNAL,
    ATTR_TRACKER_UP_SPEED,
    ATTR_TRACKER_UPDATER_ENTRY_ID,
    DOMAIN,
    UPDATER,
)
from custom_components.miwifi.enum import Connection, Mode
from custom_components.miwifi.exceptions import LuciConnectionError
from custom_components.miwifi.updater import LuciUpdater

MAIN_IP, LEAF_IP = "192.0.2.1", "192.0.2.2"
MAIN_MAC, LEAF_MAC = "02:00:00:00:00:01", "02:00:00:00:00:02"
WIFI = "02:00:00:00:00:41"  # on the main's radio, in its device list
WIRED = "02:00:00:00:00:42"  # wired to the main, in its device list
PUSHED = "02:00:00:00:00:43"  # on the node; the main's device list routes it there
OWN = "02:00:00:00:00:44"  # on the node's radio only
OTHER = "02:00:00:00:00:45"  # another client the main routes to the node

LISTED = (
    ATTR_TRACKER_NAME, ATTR_TRACKER_IP, ATTR_TRACKER_ONLINE, ATTR_TRACKER_UP_SPEED,
    ATTR_TRACKER_DOWN_SPEED, ATTR_TRACKER_SIGNAL, "signal_unit", "signal_source",
    "wifi_protocol", "link_tx_rate", "link_rx_rate",
)
RADIO = (ATTR_TRACKER_SIGNAL, "signal_unit", "signal_source", ATTR_TRACKER_CONNECTION)


@pytest.fixture
async def nodes(hass):
    """Make nodes over scripted router APIs; no notifications."""
    made: list[LuciUpdater] = []

    def make(ip, mac, mode, *, force_load=True, ap_mode=False):
        entry = MockConfigEntry(domain=DOMAIN, title=ip, data={CONF_IP_ADDRESS: ip})
        entry.add_to_hass(hass)
        updater = LuciUpdater(
            hass, ip, "test-password", entry_id=entry.entry_id,
            is_force_load=force_load, is_ap_mode=ap_mode,
        )
        updater.update_interval = None
        updater.data = {ATTR_STATE: True, ATTR_SENSOR_MODE: mode, ATTR_DEVICE_MAC_ADDRESS: mac}
        updater.luci = Mock(macfilter_info=AsyncMock(return_value={}))
        _radio(updater, {})
        _census(updater, [])
        hass.data.setdefault(DOMAIN, {})[entry.entry_id] = {CONF_IP_ADDRESS: ip, UPDATER: updater}
        made.append(updater)
        return updater

    with (
        patch("custom_components.miwifi.updater.LuciClient"),
        patch("custom_components.miwifi.updater.get_async_client", return_value=Mock()),
        patch("custom_components.miwifi.updater.asyncio.sleep", AsyncMock()),
        patch(
            "custom_components.miwifi.update.MiWiFiNewDeviceNotifier.async_notify_new_device",
            new_callable=AsyncMock,
        ),
    ):
        yield make
        for updater in made:
            await updater.async_shutdown()


def _radio(updater, signals, band=1):
    """The node's own radio list: only MAC, band and signal."""
    updater.luci.wifi_connect_devices = AsyncMock(return_value={"code": 0, "list": [
        {"mac": mac, "wifiIndex": band, "signal": signal} for mac, signal in signals.items()
    ]})


def _row(mac, *, ip, uptime, speed, parent="", name=None, wired=False):
    """A client as misystem/devicelist lists it."""
    return {
        "mac": mac, "name": name or f"Client {mac[-2:]}", "isap": 0, "parent": parent,
        "online": 1, "type": 0 if wired else 1,
        "ip": [{"ip": ip, "active": 1, "online": str(uptime),
                "upspeed": str(speed), "downspeed": str(2 * speed)}],
    }


def _detail(mac, *, ip, rssi, rate, parent=""):
    """The extended metrics of a Wi-Fi client (misystem/device_list)."""
    return {
        "mac": mac.lower(), "online": 1, "parent": parent, "ip": ip, "signal": str(rssi),
        "wifiprotocol": "Wi-Fi 6(802.11ax)", "nego_tx_rate": f"{rate}Mbps",
        "nego_rx_rate": f"{rate // 2}Mbps",
    }


def _census(updater, rows, details=()):
    updater.luci.device_list = AsyncMock(return_value={"code": 0, "list": rows})
    updater.luci.client_details = AsyncMock(return_value={"code": 0, "devices": list(details)})


async def _poll(updater):
    """The client steps of a poll, in LuciUpdater.update()'s order."""
    updater._counters_reset_this_cycle = False
    await updater._async_prepare_devices(updater.data)
    await updater._async_prepare_device_list(updater.data)


def _values(record, keys):
    return {key: record.get(key) for key in keys}


def _listed(name, ip, online, speed, rssi, rate):
    """What the device list and its metrics say about a Wi-Fi client."""
    return {
        ATTR_TRACKER_NAME: name, ATTR_TRACKER_IP: ip, ATTR_TRACKER_ONLINE: online,
        ATTR_TRACKER_UP_SPEED: float(speed), ATTR_TRACKER_DOWN_SPEED: float(2 * speed),
        ATTR_TRACKER_SIGNAL: rssi, "signal_unit": "dBm", "signal_source": "misystem/device_list",
        "wifi_protocol": "Wi-Fi 6(802.11ax)", "link_tx_rate": float(rate),
        "link_rx_rate": float(rate // 2),
    }


async def _main_census(main, census):
    """A census of the access point main: one Wi-Fi client, one wired."""
    name, ip, uptime, speed, signal, rssi, rate = census
    _radio(main, {WIFI: signal})
    _census(
        main,
        [_row(WIFI, ip=ip, uptime=uptime, speed=speed, name=name),
         _row(WIRED, ip="192.0.2.142", uptime=uptime + 1000, speed=speed + 1, wired=True)],
        [_detail(WIFI, ip=ip, rssi=rssi, rate=rate)],
    )
    await _poll(main)


FIRST = ("Phone", "192.0.2.141", 100, 10, 80, -43, 2401)
SECOND = ("Phone renamed", "192.0.2.151", 200, 30, 40, -71, 1200)


async def test_access_point_main_refreshes_its_own_clients(nodes):
    """No node pushes to the main: its own census is all there is."""
    main = nodes(MAIN_IP, MAIN_MAC, Mode.ACCESS_POINT, ap_mode=True)
    await _main_census(main, FIRST)
    await _main_census(main, SECOND)

    assert main.is_repeater and main.is_force_load
    assert _values(main.devices[WIFI], LISTED) == _listed(
        "Phone renamed", "192.0.2.151", "0:03:20", 30, -71, 1200
    )
    assert _values(main.devices[WIRED], LISTED[:5]) == {
        ATTR_TRACKER_NAME: "Client 42", ATTR_TRACKER_IP: "192.0.2.142",
        ATTR_TRACKER_ONLINE: "0:20:00", ATTR_TRACKER_UP_SPEED: 31.0, ATTR_TRACKER_DOWN_SPEED: 62.0,
    }


async def test_radio_list_does_not_undo_the_device_list_within_a_poll(hass, nodes):
    """The radio list comes first in a poll and has no name, uptime or RSSI.

    The tracker is told of every merge: it must not see the client renamed to
    its MAC, its uptime blanked or its signal switched to the radio's scale,
    each time only until the device list comes.
    """
    main = nodes(MAIN_IP, MAIN_MAC, Mode.ACCESS_POINT, ap_mode=True)
    await _main_census(main, FIRST)
    seen: list[dict] = []
    hass.data[DOMAIN]["device_tracker_entities"] = {
        f"{DOMAIN}-{WIFI.lower()}": SimpleNamespace(update_from_router=seen.append),
    }
    await _main_census(main, SECOND)
    await _main_census(main, FIRST)

    assert len(seen) == 4
    assert [_values(record, LISTED) for record in seen] == [
        _listed("Phone", "192.0.2.141", "0:01:40", 10, -43, 2401),
        _listed("Phone renamed", "192.0.2.151", "0:03:20", 30, -71, 1200),
        _listed("Phone renamed", "192.0.2.151", "0:03:20", 30, -71, 1200),
        _listed("Phone", "192.0.2.141", "0:01:40", 10, -43, 2401),
    ]


async def test_own_census_without_a_value_keeps_the_last_one(nodes):
    """Off the radio list this time and no metrics: the device list still lists it."""
    main = nodes(MAIN_IP, MAIN_MAC, Mode.ACCESS_POINT, ap_mode=True)
    await _main_census(main, FIRST)
    _radio(main, {})
    _census(main, [_row(WIFI, ip="192.0.2.141", uptime=200, speed=30, name="Phone")])
    await _poll(main)

    assert _values(main.devices[WIFI], LISTED) == _listed(
        "Phone", "192.0.2.141", "0:03:20", 30, -43, 2401
    )


async def test_radio_list_takes_over_while_the_device_list_fails(nodes):
    """Without a device list, the clients the last one held follow the radio list."""
    main = nodes(MAIN_IP, MAIN_MAC, Mode.ACCESS_POINT, ap_mode=True)
    await _main_census(main, FIRST)
    main.luci.device_list = AsyncMock(side_effect=LuciConnectionError("Connection error"))
    for signal in (40, 30):
        _radio(main, {WIFI: signal})
        await _poll(main)

    assert _values(main.devices[WIFI], (ATTR_TRACKER_NAME, *RADIO)) == {
        ATTR_TRACKER_NAME: "Phone", ATTR_TRACKER_SIGNAL: 30, "signal_unit": "%",
        "signal_source": "wifi_connect_devices", ATTR_TRACKER_CONNECTION: Connection.WIFI_2_4,
    }


async def test_node_refreshes_a_client_the_main_does_not_push(nodes):
    """The main pushes the node other clients, so its census is recent."""
    main = nodes(MAIN_IP, MAIN_MAC, Mode.ACCESS_POINT, ap_mode=True)
    leaf = nodes(LEAF_IP, LEAF_MAC, Mode.MESH_NODE)
    pushed = _row(PUSHED, ip="192.0.2.143", uptime=100, speed=10, parent=LEAF_MAC)
    for signal, band in ((60, 1), (35, 2)):
        _census(main, [dict(pushed)])
        await _poll(main)
        _radio(leaf, {OWN: signal, PUSHED: 70}, band=band)
        await _poll(leaf)

    assert leaf._has_recent_parent_census()
    assert _values(leaf.devices[OWN], RADIO) == {
        ATTR_TRACKER_SIGNAL: 35, "signal_unit": "%", "signal_source": "wifi_connect_devices",
        ATTR_TRACKER_CONNECTION: Connection.WIFI_5_0,
    }


PUSHED_VALUES = _listed("Client 43", "192.0.2.143", "0:01:40", 10, -43, 2401)


async def _push(main, rssi=-43):
    _census(
        main,
        [_row(PUSHED, ip="192.0.2.143", uptime=100, speed=10, parent=LEAF_MAC)],
        [_detail(PUSHED, ip="192.0.2.143", rssi=rssi, rate=2401, parent=LEAF_MAC)],
    )
    await _poll(main)


@pytest.mark.parametrize("node_lists", ["radio", "radio_and_device_list"])
@pytest.mark.parametrize("first", ["main", "node"])
async def test_pushed_client_keeps_what_the_main_pushed(nodes, node_lists, first):
    main = nodes(MAIN_IP, MAIN_MAC, Mode.ACCESS_POINT, ap_mode=True)
    leaf = nodes(LEAF_IP, LEAF_MAC, Mode.MESH_NODE)
    _radio(leaf, {PUSHED: 70})
    if node_lists == "radio_and_device_list":
        # Some nodes list their clients too, with less than the main has.
        _census(leaf, [_row(PUSHED, ip="192.0.2.143", uptime=5, speed=0, name="Old name")])
    if first == "node":
        await _poll(leaf)
    await _push(main)
    await _poll(leaf)
    await _poll(leaf)

    assert _values(leaf.devices[PUSHED], LISTED) == PUSHED_VALUES


@pytest.mark.parametrize("meanwhile", ["main_census_misses_it", "node_pushes_to_itself"])
async def test_pushed_client_keeps_what_the_main_pushed_between_its_pushes(
    hass, nodes, meanwhile
):
    """The node's last census is not one that has the client, the main's push of it is recent.

    The main's device list can miss a client for a poll, e.g. without an active
    address that time, and a node that lists clients under itself pushes them
    to itself. The tracker must not see the client switch to the radio's data
    and back at each of them.
    """
    main = nodes(MAIN_IP, MAIN_MAC, Mode.ACCESS_POINT, ap_mode=True)
    leaf = nodes(LEAF_IP, LEAF_MAC, Mode.MESH_NODE)
    seen: list[dict] = []
    hass.data[DOMAIN]["device_tracker_entities"] = {
        f"{DOMAIN}-{PUSHED.lower()}": SimpleNamespace(update_from_router=seen.append),
    }
    other = _row(OTHER, ip="192.0.2.145", uptime=100, speed=10, parent=LEAF_MAC)
    _radio(leaf, {PUSHED: 70, OTHER: 50})
    if meanwhile == "node_pushes_to_itself":
        _census(leaf, [other])
    for _ in range(2):
        await _push(main)
        await _poll(leaf)
        if meanwhile == "main_census_misses_it":
            _census(main, [other])
            await _poll(main)
        await _poll(leaf)

    assert len(seen) == 6
    assert [_values(record, LISTED) for record in seen] == [PUSHED_VALUES] * 6


@pytest.mark.parametrize("push_ends", ["dropped_from_census", "census_stale"])
async def test_node_refreshes_a_client_again_once_the_main_stops_pushing_it(nodes, push_ends):
    main = nodes(MAIN_IP, MAIN_MAC, Mode.ACCESS_POINT, ap_mode=True)
    leaf = nodes(LEAF_IP, LEAF_MAC, Mode.MESH_NODE)
    await _push(main)
    _radio(leaf, {PUSHED: 70})
    await _poll(leaf)
    assert _values(leaf.devices[PUSHED], LISTED) == PUSHED_VALUES

    _radio(leaf, {PUSHED: 50}, band=2)
    # Past the window after the main's last push of the client.
    with patch("custom_components.miwifi.updater.monotonic", return_value=monotonic() + 3600):
        if push_ends == "dropped_from_census":
            # The main's census, recent, has not routed the client to the node since.
            _census(main, [_row(OTHER, ip="192.0.2.145", uptime=100, speed=10, parent=LEAF_MAC)])
            await _poll(main)
            assert leaf._has_recent_parent_census()
        await _poll(leaf)

    record = leaf.devices[PUSHED]
    assert _values(record, RADIO) == {
        ATTR_TRACKER_SIGNAL: 50, "signal_unit": "%", "signal_source": "wifi_connect_devices",
        ATTR_TRACKER_CONNECTION: Connection.WIFI_5_0,
    }
    # The radio list has no uptime: the main's is not current any more.
    assert record[ATTR_TRACKER_ONLINE] == ""
    # Nor a name or an address: those the main gave are kept.
    assert _values(record, (ATTR_TRACKER_NAME, ATTR_TRACKER_IP)) == {
        ATTR_TRACKER_NAME: "Client 43", ATTR_TRACKER_IP: "192.0.2.143",
    }


async def test_restored_client_keeps_its_name_and_address_from_the_radio_list(nodes):
    """A record restored from the store, reported again by the node's radio only."""
    leaf = nodes(LEAF_IP, LEAF_MAC, Mode.MESH_NODE)
    leaf.devices[OWN] = {
        ATTR_TRACKER_ENTRY_ID: leaf._entry_id, ATTR_TRACKER_UPDATER_ENTRY_ID: leaf._entry_id,
        "mac": OWN, "router_mac": LEAF_MAC, ATTR_TRACKER_SIGNAL: 60, ATTR_TRACKER_NAME: "Client named",
        ATTR_TRACKER_IP: "192.0.2.144", ATTR_TRACKER_CONNECTION: Connection.WIFI_2_4,
        ATTR_TRACKER_ONLINE: "", "last_activity": "2026-01-01T10:00:00",
        "first_seen": "2026-01-01T10:00:00", ATTR_TRACKER_IS_RESTORED: True,
    }
    _radio(leaf, {OWN: 35}, band=2)
    await _poll(leaf)

    record = leaf.devices[OWN]
    assert ATTR_TRACKER_IS_RESTORED not in record
    assert _values(record, (ATTR_TRACKER_NAME, ATTR_TRACKER_IP, *RADIO)) == {
        ATTR_TRACKER_NAME: "Client named", ATTR_TRACKER_IP: "192.0.2.144",
        ATTR_TRACKER_SIGNAL: 35, "signal_unit": "%", "signal_source": "wifi_connect_devices",
        ATTR_TRACKER_CONNECTION: Connection.WIFI_5_0,
    }


@pytest.mark.parametrize(
    ("mode", "force_load"),
    [(Mode.DEFAULT, True), (Mode.ACCESS_POINT, False)],
    ids=["router_with_force_load", "access_point_without_force_load"],
)
async def test_nodes_without_the_merge_take_each_census_whole(nodes, mode, force_load):
    main = nodes(MAIN_IP, MAIN_MAC, mode, force_load=force_load, ap_mode=mode == Mode.ACCESS_POINT)
    await _main_census(main, FIRST)
    await _main_census(main, SECOND)

    assert not (main.is_repeater and main.is_force_load)
    assert _values(main.devices[WIFI], LISTED) == _listed(
        "Phone renamed", "192.0.2.151", "0:03:20", 30, -71, 1200
    )
    assert main.devices[WIRED][ATTR_TRACKER_ONLINE] == "0:20:00"
