"""A force-load node restores the clients it saved, and only those.

A force-load mesh node enumerates its own radio clients and saves them in its
device store when Home Assistant stops. It never read that store back, and the
other nodes skip the records it owns, so after a restart the trackers of its
absent clients were not provided by anyone: unavailable until the client came
back, where before the restart they were not_home.

Runs on a real Home Assistant core: real LuciUpdater polls over a scripted
router API, real device stores and purge state, and the real device_tracker
platform on a mock entity platform.
"""

from __future__ import annotations

from datetime import datetime, timedelta
import json
from unittest.mock import AsyncMock, Mock, patch

import pytest

from homeassistant.const import CONF_IP_ADDRESS, STATE_HOME, STATE_NOT_HOME
from homeassistant.helpers import entity_registry as er
from pytest_homeassistant_custom_component.common import (
    MockConfigEntry,
    MockEntityPlatform,
    load_fixture,
)

from custom_components.miwifi import device_tracker
from custom_components.miwifi.const import (
    ATTR_DEVICE_MAC_ADDRESS,
    ATTR_SENSOR_DEVICES,
    ATTR_SENSOR_DEVICES_2_4,
    ATTR_SENSOR_MODE,
    ATTR_STATE,
    ATTR_TRACKER_ENTRY_ID,
    ATTR_TRACKER_UPDATER_ENTRY_ID,
    CONF_IS_TRACK_DEVICES,
    DOMAIN,
    UPDATER,
)
from custom_components.miwifi.enum import Mode
from custom_components.miwifi.helper import get_store
from custom_components.miwifi.purged_clients import get_purged_clients
from custom_components.miwifi.updater import LuciUpdater
from tests.setup import async_mock_luci_client

MAIN_IP, LEAF_IP = "192.0.2.1", "192.0.2.2"
MAIN_MAC, LEAF_MAC = "02:00:00:00:00:01", "02:00:00:00:00:02"
PRESENT = "02:00:00:00:00:41"  # on the node's radio at startup
ABSENT = "02:00:00:00:00:42"  # in the node's store, away at startup
# What the node's own new_status counts: the one client on its radio.
NEW_STATUS = {"code": 0, "count": 1, "2g": {"online_sta_count": 1}, "5g": {"online_sta_count": 0}}


@pytest.fixture
def router():
    """A scripted router API; no notifications. Everything else is real."""
    with (
        patch("custom_components.miwifi.updater.LuciClient") as client,
        patch("custom_components.miwifi.updater.get_async_client", return_value=Mock()),
        patch("custom_components.miwifi.updater.asyncio.sleep", AsyncMock()),
        patch(
            "custom_components.miwifi.compatibility.CompatibilityChecker.run",
            return_value={"device_list": True, "wifi_config": True, "portforward": False},
        ),
        patch(
            "custom_components.miwifi.update.MiWiFiNewDeviceNotifier.async_notify_new_device",
            new_callable=AsyncMock,
        ) as notifier,
    ):
        yield client, notifier


def _entry(hass, ip):
    entry = MockConfigEntry(
        domain=DOMAIN, title=ip, data={CONF_IP_ADDRESS: ip}, options={CONF_IS_TRACK_DEVICES: True}
    )
    entry.add_to_hass(hass)
    return entry


def _main(hass):
    """The mesh's main: lists the node as its leaf; polled only through its device list."""
    entry = _entry(hass, MAIN_IP)
    main = LuciUpdater(hass, MAIN_IP, "test-password", entry_id=entry.entry_id)
    main.update_interval = None
    main.luci = Mock()
    main.data = {
        ATTR_STATE: True,
        ATTR_SENSOR_MODE: Mode.ACCESS_POINT,
        ATTR_DEVICE_MAC_ADDRESS: MAIN_MAC,
        "topo_graph": {"graph": {"is_main": 1, "leafs": [{"ip": LEAF_IP, "mode": 3}]}},
    }
    hass.data.setdefault(DOMAIN, {})[entry.entry_id] = {CONF_IP_ADDRESS: MAIN_IP, UPDATER: main}
    return entry, main


async def _leaf(hass, client, *, iot_wifi=False):
    """A force-load mesh node, built the way a restart builds it."""
    await async_mock_luci_client(client)
    status = json.loads(load_fixture("status_data.json"))
    status["hardware"]["mac"] = LEAF_MAC
    api = client.return_value
    api.status = AsyncMock(return_value=status)
    api.device_list = AsyncMock(return_value={"code": 0, "list": []})
    api.new_status = AsyncMock(return_value=NEW_STATUS)
    api.topo_graph = AsyncMock(return_value={"code": 0, "show": 0, "graph": {"ip": LEAF_IP, "mode": 3}})
    _radio(client, PRESENT)
    if iot_wifi:
        init_info = json.loads(load_fixture("init_info_data.json"))
        init_info["features"] = {"wifi": {"iot_dev": "1"}}
        api.init_info = AsyncMock(return_value=init_info)

    entry = _entry(hass, LEAF_IP)
    leaf = LuciUpdater(
        hass, LEAF_IP, "test-password", is_force_load=True,
        store=get_store(hass, LEAF_IP), entry_id=entry.entry_id,
    )
    leaf.update_interval = None
    hass.data.setdefault(DOMAIN, {})[entry.entry_id] = {CONF_IP_ADDRESS: LEAF_IP, UPDATER: leaf}
    return entry, leaf


def _radio(client, *macs):
    """The node's own radio client list (xqnetwork/wifi_connect_devices)."""
    client.return_value.wifi_connect_devices = AsyncMock(return_value={
        "code": 0, "list": [{"mac": mac, "wifiIndex": 1, "signal": 60} for mac in macs],
    })


def _stored(mac, entry, *, days_ago=2):
    """A record as the node saved it at its last stop."""
    seen = (datetime.now() - timedelta(days=days_ago)).replace(microsecond=0).isoformat()
    return {
        ATTR_TRACKER_ENTRY_ID: entry.entry_id,
        ATTR_TRACKER_UPDATER_ENTRY_ID: entry.entry_id,
        "mac": mac,
        "router_mac": LEAF_MAC,
        "signal": 60,
        "name": f"Client {mac[-2:]}",
        "ip": f"192.0.2.{int(mac[-2:], 16)}",
        "connection": 1,
        "down_speed": 0.0,
        "up_speed": 0.0,
        "online": "",
        "last_activity": seen,
        "first_seen": "2026-01-01T10:00:00",
        "optional_mac": None,
        "internet_blocked": False,
        "total_usage": None,
    }


async def _poll(hass, updater):
    """One poll, with its listeners told, as the coordinator's timer runs it."""
    await updater.async_refresh()
    await hass.async_block_till_done()
    assert updater.last_update_success


async def _setup_trackers(hass, entry):
    platform = MockEntityPlatform(hass, domain="device_tracker", platform_name=DOMAIN)
    platform.config_entry = entry
    platform.async_prepare()
    await device_tracker.async_setup_entry(hass, entry, platform._async_schedule_add_entities)
    await hass.async_block_till_done()
    return platform


def _tracker(hass, mac):
    return er.async_get(hass).async_get_entity_id("device_tracker", DOMAIN, f"{DOMAIN}-{mac.lower()}")


async def _push(hass, main, mac, parent=LEAF_MAC):
    """The main lists the client as online behind a node."""
    main.luci.device_list = AsyncMock(return_value={"code": 0, "list": [{
        "mac": mac, "isap": 0, "parent": parent, "online": 1, "type": 1,
        "ip": [{"ip": "192.0.2.66", "active": 1}],
    }]})
    await main._async_prepare_device_list(main.data)
    await hass.async_block_till_done()


async def _stop(*updaters):
    for updater in updaters:
        await updater.async_shutdown()


@pytest.mark.parametrize("back_via", ["own_radio_list", "main_push"])
async def test_absent_client_is_restored_not_home_and_returns_home(hass, router, caplog, back_via):
    client, notifier = router
    main_entry, main = _main(hass)
    leaf_entry, leaf = await _leaf(hass, client)
    await get_store(hass, LEAF_IP).async_save({ABSENT: _stored(ABSENT, leaf_entry)})
    try:
        # Restart: the node's first refresh, then its platforms.
        await _poll(hass, leaf)
        assert leaf.is_repeater and leaf.is_force_load
        assert set(leaf.devices) == {PRESENT, ABSENT}
        await _setup_trackers(hass, leaf_entry)
        absent_id = _tracker(hass, ABSENT)
        assert absent_id
        assert hass.states.get(absent_id).state == STATE_NOT_HOME
        await _poll(hass, leaf)

        assert hass.states.get(absent_id).state == STATE_NOT_HOME
        assert hass.states.get(_tracker(hass, PRESENT)).state == STATE_HOME
        # A restored client is not online: the node's own count stands.
        assert leaf.data[ATTR_SENSOR_DEVICES] == 1
        assert leaf.data[ATTR_SENSOR_DEVICES_2_4] == 1
        announced = notifier.await_count

        with patch.object(leaf, "_async_notify_new_device", new_callable=AsyncMock) as notify:
            if back_via == "own_radio_list":
                _radio(client, PRESENT, ABSENT)
            else:
                await _push(hass, main, ABSENT)
            await _poll(hass, leaf)
            notify.assert_not_awaited()

        assert hass.states.get(absent_id).state == STATE_HOME
        assert _tracker(hass, ABSENT) == absent_id
        trackers = [
            row for row in er.async_entries_for_config_entry(er.async_get(hass), leaf_entry.entry_id)
            if row.domain == "device_tracker"
        ]
        assert sorted(row.entity_id for row in trackers) == sorted([absent_id, _tracker(hass, PRESENT)])
        assert "does not generate unique IDs" not in caplog.text
        assert notifier.await_count == announced
        assert leaf.data[ATTR_SENSOR_DEVICES] == 1
    finally:
        await _stop(leaf, main)


@pytest.mark.parametrize("case", ["other_entry", "held_by_other_node", "purged", "mesh_node"])
async def test_records_the_node_does_not_own_are_not_restored(hass, router, case):
    client, _ = router
    main_entry, main = _main(hass)
    leaf_entry, leaf = await _leaf(hass, client)
    other = "02:00:00:00:00:43"
    record = _stored(other, leaf_entry)
    if case == "other_entry":
        # Last seen through another node: that node's record, not this one's.
        record = _stored(other, main_entry)
    elif case == "held_by_other_node":
        # Another node set up first and already holds the client.
        main.devices[other] = _stored(other, main_entry)
    elif case == "purged":
        await get_purged_clients(hass).async_mark({other})
    else:
        hass.data[DOMAIN]["mesh_node_macs"] = {other}
    await get_store(hass, LEAF_IP).async_save({ABSENT: _stored(ABSENT, leaf_entry), other: record})
    try:
        await _poll(hass, leaf)
        await _setup_trackers(hass, leaf_entry)

        assert ABSENT in leaf.devices
        assert _tracker(hass, ABSENT)
        assert other not in leaf.devices
        if case == "held_by_other_node":
            assert main.devices[other][ATTR_TRACKER_ENTRY_ID] == main_entry.entry_id
        else:
            assert _tracker(hass, other) is None
    finally:
        await _stop(leaf, main)


@pytest.mark.parametrize("counted_by", ["node_new_status", "main_push"])
async def test_restored_clients_are_not_counted(hass, router, counted_by):
    """Neither the node's own count (#348) nor the main's recount includes them."""
    client, _ = router
    main_entry, main = _main(hass)
    leaf_entry, leaf = await _leaf(hass, client, iot_wifi=counted_by == "main_push")
    stored = ["02:00:00:00:00:44", "02:00:00:00:00:45", ABSENT]
    await get_store(hass, LEAF_IP).async_save({mac: _stored(mac, leaf_entry) for mac in stored})
    try:
        await _poll(hass, leaf)
        assert set(stored) <= set(leaf.devices)
        await _push(hass, main, PRESENT)
        await _poll(hass, leaf)

        assert leaf._has_dedicated_iot_wifi() is (counted_by == "main_push")
        # Only the client on the node's radio is online, whoever counts it.
        assert leaf.data[ATTR_SENSOR_DEVICES] == 1
        assert leaf.data[ATTR_SENSOR_DEVICES_2_4] == 1
    finally:
        await _stop(leaf, main)


async def test_force_load_main_restores_its_own_clients(hass, router):
    """A main that runs force load is a repeater too, in access point mode."""
    client, _ = router
    main_entry, main = _main(hass)
    main.is_force_load = True
    main._store = get_store(hass, MAIN_IP)
    leaf_entry, leaf = await _leaf(hass, client)
    own = "02:00:00:00:00:46"
    await get_store(hass, MAIN_IP).async_save(
        {own: _stored(own, main_entry), ABSENT: _stored(ABSENT, leaf_entry)}
    )
    await get_store(hass, LEAF_IP).async_save({ABSENT: _stored(ABSENT, leaf_entry)})
    try:
        await main._async_prepare_device_restore(main.data)
        assert main.is_repeater and main.is_force_load
        assert own in main.devices
        assert ABSENT not in main.devices

        await _poll(hass, leaf)
        assert ABSENT in leaf.devices
        assert ABSENT not in main.devices
    finally:
        await _stop(leaf, main)


def _router_mode(hass, main):
    """The main as a router with no force load: it restores every record it saved."""
    main.data[ATTR_SENSOR_MODE] = Mode.DEFAULT
    main._store = get_store(hass, MAIN_IP)
    assert not main.is_repeater


@pytest.mark.parametrize("first", ["node", "main"])
async def test_a_client_in_two_stores_is_restored_once(hass, router, first):
    """Each store names its own node for the client: the first entry keeps it."""
    client, _ = router
    main_entry, main = _main(hass)
    _router_mode(hass, main)
    leaf_entry, leaf = await _leaf(hass, client)
    await get_store(hass, MAIN_IP).async_save({ABSENT: _stored(ABSENT, main_entry)})
    await get_store(hass, LEAF_IP).async_save({ABSENT: _stored(ABSENT, leaf_entry)})
    try:
        if first == "node":
            await _poll(hass, leaf)
            await main._async_prepare_device_restore(main.data)
        else:
            await main._async_prepare_device_restore(main.data)
            await _poll(hass, leaf)

        holders = [name for name, node in (("main", main), ("node", leaf)) if ABSENT in node.devices]
        assert holders == [first]
    finally:
        await _stop(leaf, main)


async def test_main_does_not_restore_a_client_live_on_the_node(hass, router):
    """The node set up first and lists the client; the main's store still names the main."""
    client, _ = router
    main_entry, main = _main(hass)
    _router_mode(hass, main)
    leaf_entry, leaf = await _leaf(hass, client)
    await get_store(hass, MAIN_IP).async_save({PRESENT: _stored(PRESENT, main_entry)})
    try:
        await _poll(hass, leaf)
        await main._async_prepare_device_restore(main.data)

        assert PRESENT in leaf.devices
        assert PRESENT not in main.devices
    finally:
        await _stop(leaf, main)


async def test_main_record_still_lends_the_node_its_name_and_ip(hass, router):
    """A record naming a force-load node fills in what its radio list lacks."""
    client, _ = router
    main_entry, main = _main(hass)
    _router_mode(hass, main)
    leaf_entry, leaf = await _leaf(hass, client)
    record = _stored(PRESENT, leaf_entry) | {"name": "Client named", "ip": "192.0.2.77"}
    await get_store(hass, MAIN_IP).async_save({PRESENT: record})
    try:
        await _poll(hass, leaf)
        await main._async_prepare_device_restore(main.data)

        assert PRESENT not in main.devices
        assert leaf.devices[PRESENT]["name"] == "Client named"
        assert leaf.devices[PRESENT]["ip"] == "192.0.2.77"
    finally:
        await _stop(leaf, main)


PLAIN_IP, PLAIN_MAC = "192.0.2.3", "02:00:00:00:00:03"


def _plain_node(hass, main):
    """A mesh node without force load: its clients come only from the main's push."""
    main.data["topo_graph"]["graph"]["leafs"].append({"ip": PLAIN_IP, "mode": 3})
    entry = _entry(hass, PLAIN_IP)
    node = LuciUpdater(hass, PLAIN_IP, "test-password", entry_id=entry.entry_id)
    node.update_interval = None
    node.luci = Mock()
    node.data = {ATTR_STATE: True, ATTR_SENSOR_MODE: Mode.MESH_NODE, ATTR_DEVICE_MAC_ADDRESS: PLAIN_MAC}
    hass.data[DOMAIN][entry.entry_id] = {CONF_IP_ADDRESS: PLAIN_IP, UPDATER: node}
    return entry, node


@pytest.mark.parametrize("platform_first", ["force_load_node", "plain_node"])
async def test_client_that_moved_to_another_node_while_down_shows_home(
    hass, router, platform_first
):
    """On the force-load node at the stop, behind a plain node at the start."""
    client, _ = router
    main_entry, main = _main(hass)
    leaf_entry, leaf = await _leaf(hass, client)
    plain_entry, plain = _plain_node(hass, main)
    await get_store(hass, LEAF_IP).async_save({ABSENT: _stored(ABSENT, leaf_entry)})
    try:
        await _poll(hass, leaf)
        await _push(hass, main, ABSENT, parent=PLAIN_MAC)
        assert ABSENT in plain.devices
        assert ABSENT not in leaf.devices

        entries = [leaf_entry, plain_entry]
        if platform_first == "plain_node":
            entries.reverse()
        for entry in entries:
            await _setup_trackers(hass, entry)
        await _push(hass, main, ABSENT, parent=PLAIN_MAC)
        await _poll(hass, leaf)

        assert hass.states.get(_tracker(hass, ABSENT)).state == STATE_HOME
    finally:
        await _stop(leaf, main, plain)


async def test_main_drops_its_restored_copy_once_the_node_lists_the_client(hass, router):
    """The main set up first and restored a client the node's radio lists."""
    client, _ = router
    main_entry, main = _main(hass)
    _router_mode(hass, main)
    leaf_entry, leaf = await _leaf(hass, client)
    await get_store(hass, MAIN_IP).async_save({PRESENT: _stored(PRESENT, main_entry)})
    try:
        await main._async_prepare_device_restore(main.data)
        assert PRESENT in main.devices
        await _setup_trackers(hass, main_entry)
        await _poll(hass, leaf)

        assert PRESENT in leaf.devices
        assert PRESENT not in main.devices
        main.async_set_updated_data(main.data)
        await hass.async_block_till_done()
        assert hass.states.get(_tracker(hass, PRESENT)).state == STATE_HOME
    finally:
        await _stop(leaf, main)
