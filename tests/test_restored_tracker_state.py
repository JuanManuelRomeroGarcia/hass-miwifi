"""A restored client's tracker keeps its last state until the mesh reports it.

The restore step runs in a node's first refresh, before the tracker platform is
set up, so the platform adds the trackers from the node's records rather than
from the restore signal. A restored client shows what it showed when Home
Assistant stopped until a router reports it, or until every node has polled
once more: a presence automation would otherwise see an arrival, or a
departure, at every restart. With no state recorded it starts not_home.

Runs on a real Home Assistant core: a real LuciUpdater over a scripted router
API, its real device store, and the real device_tracker platform.
"""

from __future__ import annotations

from datetime import datetime, timedelta
import time
from types import SimpleNamespace
from unittest.mock import AsyncMock, Mock, patch

import pytest

from homeassistant.const import (
    CONF_IP_ADDRESS,
    EVENT_STATE_CHANGED,
    STATE_HOME,
    STATE_NOT_HOME,
    STATE_UNAVAILABLE,
)
from homeassistant.core import State, callback
from homeassistant.helpers import entity_registry as er, restore_state
from pytest_homeassistant_custom_component.common import (
    MockConfigEntry,
    MockEntityPlatform,
    mock_restore_cache,
)

from custom_components.miwifi import device_tracker
from custom_components.miwifi.const import (
    ATTR_DEVICE_MAC_ADDRESS,
    ATTR_SENSOR_MODE,
    ATTR_STATE,
    ATTR_TRACKER_ENTRY_ID,
    ATTR_TRACKER_IS_RESTORED,
    ATTR_TRACKER_UPDATER_ENTRY_ID,
    CONF_IS_TRACK_DEVICES,
    DEFAULT_SCAN_INTERVAL,
    DEFAULT_STAY_ONLINE,
    DEFAULT_TIMEOUT,
    DOMAIN,
    UPDATER,
)
from custom_components.miwifi.enum import Mode
from custom_components.miwifi.helper import get_store
from custom_components.miwifi.updater import LuciUpdater

NODE_IP, NODE_MAC = "192.0.2.2", "02:00:00:00:00:02"
CLIENT = "02:00:00:00:00:42"
ENTITY_ID = f"device_tracker.{DOMAIN}_{CLIENT.lower().replace(':', '_')}"
# Within this every node polls once more, one request timing out.
POLL_PERIOD = DEFAULT_SCAN_INTERVAL + DEFAULT_TIMEOUT


@pytest.fixture
def router():
    with (
        patch("custom_components.miwifi.updater.LuciClient"),
        patch("custom_components.miwifi.updater.get_async_client", return_value=Mock()),
        patch("custom_components.miwifi.updater.asyncio.sleep", AsyncMock()),
        patch(
            "custom_components.miwifi.update.MiWiFiNewDeviceNotifier.async_notify_new_device",
            new_callable=AsyncMock,
        ),
    ):
        yield


def _node(hass, kind):
    entry = MockConfigEntry(
        domain=DOMAIN, title=NODE_IP, data={CONF_IP_ADDRESS: NODE_IP},
        options={CONF_IS_TRACK_DEVICES: True},
    )
    entry.add_to_hass(hass)
    force_load = kind == "force_load_node"
    node = LuciUpdater(
        hass, NODE_IP, "test-password", is_force_load=force_load,
        store=get_store(hass, NODE_IP), entry_id=entry.entry_id,
    )
    node.update_interval = None
    node.data = {
        ATTR_STATE: True,
        ATTR_SENSOR_MODE: Mode.MESH_NODE if force_load else Mode.DEFAULT,
        ATTR_DEVICE_MAC_ADDRESS: NODE_MAC,
    }
    hass.data.setdefault(DOMAIN, {})[entry.entry_id] = {CONF_IP_ADDRESS: NODE_IP, UPDATER: node}
    return entry, node


def _stored(entry):
    seen = (datetime.now() - timedelta(days=2)).replace(microsecond=0).isoformat()
    return {
        ATTR_TRACKER_ENTRY_ID: entry.entry_id,
        ATTR_TRACKER_UPDATER_ENTRY_ID: entry.entry_id,
        "mac": CLIENT,
        "router_mac": NODE_MAC,
        "name": "Client 42",
        "ip": "192.0.2.66",
        "connection": 1,
        "online": "",
        "last_activity": seen,
        "first_seen": "2026-01-01T10:00:00",
    }


async def _setup_trackers(hass, entry):
    platform = MockEntityPlatform(hass, domain="device_tracker", platform_name=DOMAIN)
    platform.config_entry = entry
    platform.async_prepare()
    await device_tracker.async_setup_entry(hass, entry, platform._async_schedule_add_entities)
    await hass.async_block_till_done()
    return platform


async def _report_client(hass, node, kind):
    """The node's next poll lists the client, through the list its kind reads."""
    if kind == "force_load_node":
        node.luci.wifi_connect_devices = AsyncMock(
            return_value={"code": 0, "list": [{"mac": CLIENT, "wifiIndex": 1, "signal": 60}]}
        )
        node.luci.macfilter_info = AsyncMock(return_value={"flist": [], "list": []})
        await node._async_prepare_devices(node.data)
    else:
        node.luci.device_list = AsyncMock(return_value={"code": 0, "list": [{
            "mac": CLIENT, "isap": 0, "parent": "", "online": 1, "type": 1,
            "ip": [{"ip": "192.0.2.66", "active": 1}],
        }]})
        await node._async_prepare_device_list(node.data)
    node.async_set_updated_data(node.data)
    await hass.async_block_till_done()


async def _poll_without_client(hass, node, seconds):
    """A poll that does not list the client, this many seconds from now.

    Only the trackers' clock moves: the records keep the time the routers'
    lists gave them.
    """
    now = time.time() + seconds
    with patch.object(device_tracker, "time", SimpleNamespace(time=lambda: now)):
        node.async_set_updated_data(node.data)
        await hass.async_block_till_done()


def _states(hass):
    """Every state the client's tracker shows from now on, without repeats."""
    states: list[str] = []

    @callback
    def _changed(event):
        new = event.data["new_state"]
        if event.data["entity_id"] == ENTITY_ID and new and states[-1:] != [new.state]:
            states.append(new.state)

    hass.bus.async_listen(EVENT_STATE_CHANGED, _changed)
    return states


@pytest.mark.parametrize("kind", ["gateway", "force_load_node"])
@pytest.mark.parametrize(
    ("last_state", "shown"),
    [
        (STATE_HOME, [STATE_HOME, STATE_NOT_HOME]),
        (STATE_NOT_HOME, [STATE_NOT_HOME]),
        (STATE_UNAVAILABLE, [STATE_NOT_HOME]),
        (None, [STATE_NOT_HOME]),
    ],
    ids=["home", "not_home", "unavailable", "no_state"],
)
async def test_restored_tracker_keeps_its_state_until_every_node_has_polled(
    hass, router, kind, last_state, shown
):
    """A client nobody reports since the start, whatever it was at the stop.

    Home then, it may have left while Home Assistant was down: it stays home
    until every node has polled once more and the stay_online window has
    passed, then turns not_home once. Away or unavailable then, or with no
    state recorded - the first start with this version - it is not_home
    throughout.
    """
    entry, node = _node(hass, kind)
    if last_state is not None:
        mock_restore_cache(hass, [State(ENTITY_ID, last_state)])
    await get_store(hass, NODE_IP).async_save({CLIENT: _stored(entry)})
    states = _states(hass)
    try:
        await node._async_prepare_device_restore(node.data)
        await _setup_trackers(hass, entry)
        assert hass.states.get(ENTITY_ID).state == shown[0]

        for seconds in (1, POLL_PERIOD, POLL_PERIOD + DEFAULT_STAY_ONLINE - 5):
            await _poll_without_client(hass, node, seconds)
            assert hass.states.get(ENTITY_ID).state == shown[0]

        for seconds in (POLL_PERIOD + DEFAULT_STAY_ONLINE + 5, 10 * POLL_PERIOD):
            await _poll_without_client(hass, node, seconds)
            assert hass.states.get(ENTITY_ID).state == STATE_NOT_HOME

        assert states == shown
        assert node.devices[CLIENT][ATTR_TRACKER_IS_RESTORED]
    finally:
        await node.async_shutdown()


async def test_restored_tracker_waits_for_the_slowest_node(hass, router):
    """Another node polls every two minutes: it gets its poll too."""
    entry, node = _node(hass, "force_load_node")
    slow_scan = 4 * DEFAULT_SCAN_INTERVAL
    slow = LuciUpdater(hass, "192.0.2.3", "test-password", scan_interval=slow_scan)
    slow.update_interval = None
    hass.data[DOMAIN]["slow"] = {CONF_IP_ADDRESS: "192.0.2.3", UPDATER: slow}
    mock_restore_cache(hass, [State(ENTITY_ID, STATE_HOME)])
    await get_store(hass, NODE_IP).async_save({CLIENT: _stored(entry)})
    hold = slow_scan + DEFAULT_TIMEOUT + DEFAULT_STAY_ONLINE
    try:
        await node._async_prepare_device_restore(node.data)
        await _setup_trackers(hass, entry)

        for seconds in (POLL_PERIOD + DEFAULT_STAY_ONLINE + 5, hold - 5):
            await _poll_without_client(hass, node, seconds)
            assert hass.states.get(ENTITY_ID).state == STATE_HOME
        await _poll_without_client(hass, node, hold + 5)
        assert hass.states.get(ENTITY_ID).state == STATE_NOT_HOME
    finally:
        await node.async_shutdown()
        await slow.async_shutdown()


@pytest.mark.parametrize("kind", ["gateway", "force_load_node"])
@pytest.mark.parametrize(
    ("saved_before_the_last_save", "shown"),
    [
        (timedelta(minutes=10), [STATE_HOME, STATE_NOT_HOME]),
        (timedelta(days=3), [STATE_NOT_HOME]),
    ],
    ids=["shortly_before", "in_an_earlier_run"],
)
async def test_restored_tracker_holds_only_a_state_from_the_last_save(
    hass, router, kind, saved_before_the_last_save, shown
):
    """Home in a state saved before the last save.

    in_an_earlier_run: the node did not load in the last run, so no entry
    provided the tracker, and core kept the state saved in the run before, with
    the time of that save. The client may have left days ago: not held.
    shortly_before: the tracker was removed a few minutes before the last save.
    """
    entry, node = _node(hass, kind)
    mock_restore_cache(
        hass, [State(ENTITY_ID, STATE_HOME), State("sensor.live_at_the_last_save", "1")]
    )
    restore_state.async_get(hass).last_states[ENTITY_ID].last_seen -= saved_before_the_last_save
    await get_store(hass, NODE_IP).async_save({CLIENT: _stored(entry)})
    states = _states(hass)
    try:
        await node._async_prepare_device_restore(node.data)
        await _setup_trackers(hass, entry)
        for seconds in (1, POLL_PERIOD + DEFAULT_STAY_ONLINE + 5):
            await _poll_without_client(hass, node, seconds)

        assert states == shown
    finally:
        await node.async_shutdown()


@pytest.mark.parametrize(
    ("reported", "shown"),
    [(False, [STATE_UNAVAILABLE, STATE_NOT_HOME]), (True, [STATE_UNAVAILABLE, STATE_HOME])],
    ids=["not_reported", "reported"],
)
async def test_restored_tracker_of_an_unreachable_node_is_not_held(
    hass, router, reported, shown
):
    """The node cannot be reached when its trackers are added.

    A client that was home at the stop shows unavailable. Once the node is back,
    its list says where the client is: a hold from then on would only show one
    that left arriving.
    """
    entry, node = _node(hass, "force_load_node")
    mock_restore_cache(hass, [State(ENTITY_ID, STATE_HOME)])
    await get_store(hass, NODE_IP).async_save({CLIENT: _stored(entry)})
    states = _states(hass)
    try:
        await node._async_prepare_device_restore(node.data)
        node.data[ATTR_STATE] = False
        await _setup_trackers(hass, entry)
        assert hass.states.get(ENTITY_ID).state == STATE_UNAVAILABLE

        node.data[ATTR_STATE] = True
        if reported:
            await _report_client(hass, node, "force_load_node")
        else:
            await _poll_without_client(hass, node, 5)

        assert states == shown
    finally:
        await node.async_shutdown()


@pytest.mark.parametrize("kind", ["gateway", "force_load_node"])
async def test_client_reported_since_the_restart_ages_as_usual(hass, router, kind):
    """Once a router reports the client, its last activity counts again."""
    entry, node = _node(hass, kind)
    mock_restore_cache(hass, [State(ENTITY_ID, STATE_HOME)])
    await get_store(hass, NODE_IP).async_save({CLIENT: _stored(entry)})
    try:
        await node._async_prepare_device_restore(node.data)
        await _setup_trackers(hass, entry)
        assert hass.states.get(ENTITY_ID).state == STATE_HOME
        await _report_client(hass, node, kind)
        assert hass.states.get(ENTITY_ID).state == STATE_HOME

        # Not listed again: away once the stay_online window has passed, well
        # before every node has polled since the start.
        await _poll_without_client(hass, node, DEFAULT_STAY_ONLINE + 5)
        assert hass.states.get(ENTITY_ID).state == STATE_NOT_HOME
    finally:
        await node.async_shutdown()


@pytest.mark.parametrize("kind", ["gateway", "force_load_node"])
async def test_restored_tracker_starts_not_home_until_reported(hass, router, kind):
    """With no state recorded, as on the first start with this version."""
    entry, node = _node(hass, kind)
    await get_store(hass, NODE_IP).async_save({CLIENT: _stored(entry)})
    try:
        # Restart: the first refresh restores, then the platform is set up.
        await node._async_prepare_device_restore(node.data)
        with patch(
            "custom_components.miwifi.update.MiWiFiNewDeviceNotifier.async_notify_new_device",
            new_callable=AsyncMock,
        ) as notify:
            platform = await _setup_trackers(hass, entry)
        # A client the store knew is not a new device.
        notify.assert_not_awaited()

        entity_id = er.async_get(hass).async_get_entity_id(
            "device_tracker", DOMAIN, f"{DOMAIN}-{CLIENT.lower()}"
        )
        assert entity_id
        # Before any further poll.
        assert hass.states.get(entity_id).state == STATE_NOT_HOME

        await _report_client(hass, node, kind)
        assert hass.states.get(entity_id).state == STATE_HOME
        assert ATTR_TRACKER_IS_RESTORED not in node.devices[CLIENT]

        # Made again from the record - its platform reloading - the tracker of
        # a client reported since the restore starts home.
        await platform.async_reset()
        await hass.async_block_till_done()
        await _setup_trackers(hass, entry)
        assert hass.states.get(entity_id).state == STATE_HOME
    finally:
        await node.async_shutdown()
