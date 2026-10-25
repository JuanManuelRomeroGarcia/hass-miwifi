"""A client's last activity in the hour the clocks repeat when they go back.

The updater stores a client's last activity as Home Assistant's local time,
without an offset. On 25 October 2026 Rome's clocks go back from 03:00 CEST to
02:00 CET, and every time from 02:00 to 03:00 names two instants an hour
apart. It was read as the first: a client the routers had reported seconds
before, in the second, was an hour old, and every tracker of the mesh went
not_home at 02:00 CET and came back home at 03:00.

The time zone is Home Assistant's and the clock is frozen, so no case depends
on the time zone of the host that runs it.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
import time
from unittest.mock import AsyncMock, Mock, patch

import pytest

from homeassistant.const import CONF_IP_ADDRESS, STATE_HOME, STATE_NOT_HOME
from homeassistant.util import dt as dt_util
from pytest_homeassistant_custom_component.common import MockConfigEntry, MockEntityPlatform

from custom_components.miwifi import device_tracker
from custom_components.miwifi.const import (
    ATTR_DEVICE_MAC_ADDRESS,
    ATTR_SENSOR_MODE,
    ATTR_STATE,
    ATTR_TRACKER_LAST_ACTIVITY,
    CONF_IS_TRACK_DEVICES,
    DEFAULT_STAY_ONLINE,
    DOMAIN,
    UPDATER,
)
from custom_components.miwifi.enum import Mode
from custom_components.miwifi.helper import get_store, parse_last_activity
from custom_components.miwifi.updater import LuciUpdater

ROME = dt_util.get_time_zone("Europe/Rome")
NODE_IP, NODE_MAC = "192.0.2.1", "02:00:00:00:00:01"
CLIENT = "02:00:00:00:00:42"
ENTITY_ID = f"device_tracker.{DOMAIN}_{CLIENT.lower().replace(':', '_')}"


def _utc(hour, minute, second=0, *, month=10, day=25):
    return datetime(2026, month, day, hour, minute, second, tzinfo=UTC)


# In Rome on 25 October 2026, 00:00 to 01:00 UTC is 02:00 to 03:00 CEST, and
# 01:00 to 02:00 UTC is 02:00 to 03:00 CET: the first and second occurrence.


@pytest.fixture
def rome():
    """Home Assistant's time zone is Rome's, whatever the host's."""
    original = dt_util.get_default_time_zone()
    dt_util.set_default_time_zone(ROME)
    yield
    dt_util.set_default_time_zone(original)


@pytest.mark.parametrize(
    ("last_activity", "seen", "read_after"),
    [
        # Reported seconds ago, in the second occurrence: an hour old before.
        pytest.param("2026-10-25T02:30:00", _utc(1, 30), 20, id="second_occurrence"),
        pytest.param("2026-10-25T02:00:00", _utc(1, 0), 0, id="the_change_itself"),
        # Written at 02:30:00 CET, then the clock is set back half a minute.
        pytest.param("2026-10-25T02:30:00", _utc(1, 30), -30, id="clock_set_back"),
        pytest.param("2026-10-25T02:30:00", _utc(0, 30), 20, id="first_occurrence"),
        # Last seen at 02:59:30 CEST, read at 02:00:15 CET.
        pytest.param("2026-10-25T02:59:30", _utc(0, 59, 30), 45, id="across_the_change"),
        # Seen at 02:10 CEST, read at 02:05 CET: 02:10 CET is still to come.
        pytest.param(
            "2026-10-25T02:10:00", _utc(0, 10), 3300, id="first_occurrence_read_in_the_second"
        ),
        pytest.param(
            "2026-10-25T01:59:59", _utc(23, 59, 59, day=24), 20, id="before_the_repeated_hour"
        ),
        pytest.param("2026-10-25T03:00:00", _utc(2, 0), 20, id="after_the_repeated_hour"),
        pytest.param("2026-01-15T12:00:00", _utc(11, 0, month=1, day=15), 20, id="standard_time"),
        pytest.param("2026-07-01T12:00:00", _utc(10, 0, month=7, day=1), 20, id="summer_time"),
        pytest.param(
            "2026-03-29T03:30:00", _utc(1, 30, month=3, day=29), 20, id="clocks_gone_forward"
        ),
    ],
)
def test_last_activity_is_the_time_it_was_written(rome, freezer, last_activity, seen, read_after):
    """Read read_after seconds after the routers listed the client."""
    freezer.move_to(seen + timedelta(seconds=read_after))
    assert parse_last_activity(last_activity) == int(seen.timestamp())


@pytest.mark.parametrize(
    "last_activity",
    ["2025-10-26T02:30:00", "2025-10-26T02:00:00", "2022-04-25T22:28:39"],
    ids=["last_years_repeated_hour", "last_years_change", "years_ago"],
)
def test_old_last_activity_still_reads_as_old(rome, freezer, last_activity):
    """Read in this year's repeated hour, a year ago is still a year ago."""
    freezer.move_to(_utc(1, 30, 20))
    assert time.time() - parse_last_activity(last_activity) > 300 * 86400


@pytest.mark.parametrize(
    ("zone", "seen"),
    [("UTC", _utc(2, 30)), ("America/New_York", _utc(6, 30))],
)
def test_last_activity_is_in_home_assistants_time_zone(freezer, zone, seen):
    """Not the system's: the client sensors read it in this zone too."""
    original = dt_util.get_default_time_zone()
    dt_util.set_default_time_zone(dt_util.get_time_zone(zone))
    try:
        freezer.move_to(seen + timedelta(seconds=20))
        assert parse_last_activity("2026-10-25T02:30:00") == int(seen.timestamp())
    finally:
        dt_util.set_default_time_zone(original)


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


async def _gateway(hass):
    """A router that lists its clients, and its trackers."""
    await hass.config.async_set_time_zone("Europe/Rome")
    entry = MockConfigEntry(
        domain=DOMAIN, title=NODE_IP, data={CONF_IP_ADDRESS: NODE_IP},
        options={CONF_IS_TRACK_DEVICES: True},
    )
    entry.add_to_hass(hass)
    node = LuciUpdater(
        hass, NODE_IP, "test-password", store=get_store(hass, NODE_IP), entry_id=entry.entry_id,
    )
    node.update_interval = None
    node._is_first_update = False
    node.data = {
        ATTR_STATE: True, ATTR_SENSOR_MODE: Mode.DEFAULT, ATTR_DEVICE_MAC_ADDRESS: NODE_MAC,
    }
    hass.data.setdefault(DOMAIN, {})[entry.entry_id] = {CONF_IP_ADDRESS: NODE_IP, UPDATER: node}

    platform = MockEntityPlatform(hass, domain="device_tracker", platform_name=DOMAIN)
    platform.config_entry = entry
    platform.async_prepare()
    await device_tracker.async_setup_entry(hass, entry, platform._async_schedule_add_entities)
    await hass.async_block_till_done()
    return node


async def _poll(hass, node, *clients):
    """A poll of the router, which lists these clients as online."""
    node.luci.device_list = AsyncMock(return_value={"code": 0, "list": [{
        "mac": mac, "isap": 0, "parent": "", "online": 1, "type": 1,
        "ip": [{"ip": "192.0.2.66", "active": 1}],
    } for mac in clients]})
    await node._async_prepare_device_list(node.data)
    node.async_set_updated_data(node.data)
    await hass.async_block_till_done()


async def test_updater_writes_home_assistants_local_time(hass, router, freezer):
    """As the client sensors and the panel show it: 02:30 at 02:30 CEST and CET."""
    freezer.move_to(_utc(0, 30))
    node = await _gateway(hass)
    try:
        await _poll(hass, node, CLIENT)
        assert node.devices[CLIENT][ATTR_TRACKER_LAST_ACTIVITY] == "2026-10-25T02:30:00"

        freezer.move_to(_utc(1, 30))
        await _poll(hass, node, CLIENT)
        assert node.devices[CLIENT][ATTR_TRACKER_LAST_ACTIVITY] == "2026-10-25T02:30:00"
    finally:
        await node.async_shutdown()


@pytest.mark.parametrize(
    "seen",
    [_utc(1, 30), _utc(1, 0), _utc(0, 30), _utc(0, 59, 30), _utc(11, 0, month=1, day=15)],
    ids=[
        "second_occurrence", "the_change_itself", "first_occurrence", "across_the_change",
        "standard_time",
    ],
)
async def test_reported_client_is_home_for_the_stay_online_window(hass, router, freezer, seen):
    """Reported, then no longer listed: home for stay_online, then not_home.

    across_the_change: listed last at 02:59:30 CEST, still home at 02:00:15 CET.
    """
    freezer.move_to(seen)
    node = await _gateway(hass)
    try:
        await _poll(hass, node, CLIENT)
        assert hass.states.get(ENTITY_ID).state == STATE_HOME

        for after, state in (
            (45, STATE_HOME),
            (DEFAULT_STAY_ONLINE - 5, STATE_HOME),
            (DEFAULT_STAY_ONLINE + 5, STATE_NOT_HOME),
            (1800, STATE_NOT_HOME),
        ):
            freezer.move_to(seen + timedelta(seconds=after))
            await _poll(hass, node)
            assert hass.states.get(ENTITY_ID).state == state, after
    finally:
        await node.async_shutdown()


async def test_client_listed_through_the_change_stays_home(hass, router, freezer):
    """Listed every 30 seconds from 02:58 CEST to 02:02 CET: home throughout."""
    freezer.move_to(_utc(0, 58))
    node = await _gateway(hass)
    try:
        for poll in range(9):
            freezer.move_to(_utc(0, 58) + timedelta(seconds=30 * poll))
            await _poll(hass, node, CLIENT)
            assert hass.states.get(ENTITY_ID).state == STATE_HOME, dt_util.now()
    finally:
        await node.async_shutdown()
