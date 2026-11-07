"""A client's last activity: when the routers last listed it.

The updater stores it as Home Assistant's local time, without an offset, and
the trackers and the client sensors read it back in that zone, whatever the
system's. Earlier versions wrote the system's.

On 25 October 2026 Rome's clocks go back from 03:00 CEST to 02:00 CET, and
every time from 02:00 to 03:00 names two instants an hour apart. It was read as
the first: a client the routers had reported seconds before, in the second,
was an hour old, and every tracker of the mesh went not_home at 02:00 CET and
came back home at 03:00.

The time zone is Home Assistant's, the system's is UTC where a case needs it,
and the clock is frozen, so no case depends on the time zone of the host that
runs it.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
import logging
import time
from unittest.mock import AsyncMock, Mock, patch

import pytest

from homeassistant.const import CONF_IP_ADDRESS, STATE_HOME, STATE_NOT_HOME
from homeassistant.core import State
from homeassistant.helpers.update_coordinator import DataUpdateCoordinator
from homeassistant.util import dt as dt_util
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
    ATTR_TRACKER_FIRST_SEEN,
    ATTR_TRACKER_LAST_ACTIVITY,
    ATTR_TRACKER_UPDATER_ENTRY_ID,
    CONF_IS_TRACK_DEVICES,
    DEFAULT_STAY_ONLINE,
    DOMAIN,
    UPDATER,
)
from custom_components.miwifi.enum import Mode
from custom_components.miwifi.helper import get_store, parse_last_activity
from custom_components.miwifi.sensor import MIWIFI_DEVICE_SENSORS, MiWifiDeviceAttributeSensor
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
        # Read at 02:08:59 CET: 02:10 CET is 61 seconds to come, beyond the slack.
        pytest.param(
            "2026-10-25T02:10:00", _utc(0, 10), 3539, id="first_occurrence_a_minute_before_it"
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


@pytest.fixture
def ha_zone():
    """Sets Home Assistant's time zone, whatever the host's."""
    original = dt_util.get_default_time_zone()
    yield lambda zone: dt_util.set_default_time_zone(dt_util.get_time_zone(zone))
    dt_util.set_default_time_zone(original)


@pytest.fixture
def system_in_utc():
    """The system's time zone is UTC, as in a container started without TZ."""
    with patch(
        "custom_components.miwifi.helper._system_timestamp",
        lambda wall: int(wall.replace(tzinfo=UTC).timestamp()),
    ):
        yield


@pytest.mark.parametrize(
    ("zone", "seen"),
    [("UTC", _utc(2, 30)), ("America/New_York", _utc(6, 30))],
)
def test_last_activity_is_in_home_assistants_time_zone(ha_zone, freezer, zone, seen):
    """Not the system's: the client sensors read it in this zone too."""
    ha_zone(zone)
    freezer.move_to(seen + timedelta(seconds=20))
    assert parse_last_activity("2026-10-25T02:30:00") == int(seen.timestamp())


@pytest.mark.parametrize(
    ("zone", "read_as"),
    [
        # Home Assistant's zone is 7 hours behind: still to come in it.
        pytest.param("America/Los_Angeles", _utc(3, 0, day=24), id="west_of_utc"),
        # 2 hours ahead: 2 hours older in it.
        pytest.param("Europe/Rome", _utc(1, 0, day=24), id="east_of_utc"),
    ],
)
def test_last_activity_of_an_earlier_version(system_in_utc, ha_zone, freezer, zone, read_as):
    """The system's time, UTC, an hour before the restart onto this version."""
    ha_zone(zone)
    freezer.move_to(_utc(4, 0, day=24))
    assert parse_last_activity("2026-10-24T03:00:00") == int(read_as.timestamp())


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


async def _gateway(hass, zone="Europe/Rome", stored=None):
    """A router that lists its clients, and its trackers.

    stored: the client's last activity in the store of the run before, which
    the router restores in its first refresh.
    """
    await hass.config.async_set_time_zone(zone)
    entry = MockConfigEntry(
        domain=DOMAIN, title=NODE_IP, data={CONF_IP_ADDRESS: NODE_IP},
        options={CONF_IS_TRACK_DEVICES: True},
    )
    entry.add_to_hass(hass)
    node = LuciUpdater(
        hass, NODE_IP, "test-password", store=get_store(hass, NODE_IP), entry_id=entry.entry_id,
    )
    node.update_interval = None
    node.data = {
        ATTR_STATE: True, ATTR_SENSOR_MODE: Mode.DEFAULT, ATTR_DEVICE_MAC_ADDRESS: NODE_MAC,
    }
    hass.data.setdefault(DOMAIN, {})[entry.entry_id] = {CONF_IP_ADDRESS: NODE_IP, UPDATER: node}
    if stored is not None:
        await get_store(hass, NODE_IP).async_save({CLIENT: {
            ATTR_TRACKER_ENTRY_ID: entry.entry_id,
            ATTR_TRACKER_UPDATER_ENTRY_ID: entry.entry_id,
            "mac": CLIENT,
            "router_mac": NODE_MAC,
            "name": "Client 42",
            "ip": "192.0.2.66",
            "connection": 1,
            "online": "",
            ATTR_TRACKER_LAST_ACTIVITY: stored,
            ATTR_TRACKER_FIRST_SEEN: "2026-01-01T10:00:00",
        }})
        await node._async_prepare_device_restore(node.data)
    node._is_first_update = False

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
        assert node.devices[CLIENT][ATTR_TRACKER_FIRST_SEEN] == "2026-10-25T02:30:00"

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


async def test_client_that_left_in_the_first_occurrence_stays_away(hass, router, freezer):
    """Listed at 02:30 CEST and not since: not_home at 02:30 CET too.

    From a minute before 02:30 CET its last activity also names a time that has
    come; the tracker keeps the reading it had when the routers listed it.
    """
    seen = _utc(0, 30)
    freezer.move_to(seen)
    node = await _gateway(hass)
    try:
        await _poll(hass, node, CLIENT)
        assert hass.states.get(ENTITY_ID).state == STATE_HOME

        for after in (
            DEFAULT_STAY_ONLINE + 5,
            3541,
            3600,
            3600 + DEFAULT_STAY_ONLINE - 5,
            3600 + DEFAULT_STAY_ONLINE + 5,
        ):
            freezer.move_to(seen + timedelta(seconds=after))
            await _poll(hass, node)
            assert hass.states.get(ENTITY_ID).state == STATE_NOT_HOME, after
    finally:
        await node.async_shutdown()


async def test_client_that_left_before_the_upgrade_stays_away(
    hass, router, freezer, system_in_utc
):
    """The system is in UTC, Home Assistant in Los Angeles, 7 hours behind.

    The client left at 20:00 PDT, an hour before the restart onto this version,
    and its record says 03:00, the time in UTC an earlier version wrote. Read as
    03:00 PDT, 6 hours to come, it would be home until then. At 03:00 PDT that
    reading is no longer to come: the tracker keeps the one it had.
    """
    restart = _utc(4, 0, day=24)
    freezer.move_to(restart)
    mock_restore_cache(hass, [State(ENTITY_ID, STATE_NOT_HOME)])
    node = await _gateway(hass, "America/Los_Angeles", stored="2026-10-24T03:00:00")
    try:
        assert hass.states.get(ENTITY_ID).state == STATE_NOT_HOME
        for after in (30, 3600, 6 * 3600):
            freezer.move_to(restart + timedelta(seconds=after))
            await _poll(hass, node)
            assert hass.states.get(ENTITY_ID).state == STATE_NOT_HOME, after
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


@pytest.mark.parametrize("key", [ATTR_TRACKER_LAST_ACTIVITY, ATTR_TRACKER_FIRST_SEEN])
async def test_client_sensor_shows_when_the_client_was_listed(hass, freezer, key):
    """The client's sensor reads the time as its tracker does.

    Listed at 02:30 CET, it shows 02:30 CET, not CEST. Listed at 02:30 CEST,
    it still shows 02:30 CEST at 02:35 CET.
    """
    await hass.config.async_set_time_zone("Europe/Rome")
    entry = MockConfigEntry(domain=DOMAIN)
    entry.add_to_hass(hass)
    updater = DataUpdateCoordinator(
        hass, logging.getLogger(__name__), name="client", config_entry=entry
    )
    updater.data = {}
    updater.devices = {CLIENT: {"mac": CLIENT, key: "2026-10-25T02:30:00"}}
    description = next(desc for desc in MIWIFI_DEVICE_SENSORS if desc.key == key)

    for seen, later in ((_utc(1, 30), _utc(1, 30, 20)), (_utc(0, 30), _utc(1, 35))):
        sensor = MiWifiDeviceAttributeSensor(updater, updater.devices[CLIENT], description)
        sensor.hass = hass
        freezer.move_to(seen)
        assert sensor.native_value == seen
        freezer.move_to(later)
        assert sensor.native_value == seen, later
