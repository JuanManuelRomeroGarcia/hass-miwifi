"""A restored client's tracker starts not_home, until the client is reported again.

The restore step runs in a node's first refresh, before the tracker platform is
set up, so the platform adds the trackers from the node's records rather than
from the restore signal. A restored client that is away must not show home
until the next poll: a presence automation would see an arrival at every
restart.

Runs on a real Home Assistant core: a real LuciUpdater over a scripted router
API, its real device store, and the real device_tracker platform.
"""

from __future__ import annotations

from datetime import datetime, timedelta
from unittest.mock import AsyncMock, Mock, patch

import pytest

from homeassistant.const import CONF_IP_ADDRESS, STATE_HOME, STATE_NOT_HOME
from homeassistant.helpers import entity_registry as er
from pytest_homeassistant_custom_component.common import MockConfigEntry, MockEntityPlatform

from custom_components.miwifi import device_tracker
from custom_components.miwifi.const import (
    ATTR_DEVICE_MAC_ADDRESS,
    ATTR_SENSOR_MODE,
    ATTR_STATE,
    ATTR_TRACKER_ENTRY_ID,
    ATTR_TRACKER_IS_RESTORED,
    ATTR_TRACKER_UPDATER_ENTRY_ID,
    CONF_IS_TRACK_DEVICES,
    DOMAIN,
    UPDATER,
)
from custom_components.miwifi.enum import Mode
from custom_components.miwifi.helper import get_store
from custom_components.miwifi.updater import LuciUpdater

NODE_IP, NODE_MAC = "192.0.2.2", "02:00:00:00:00:02"
CLIENT = "02:00:00:00:00:42"


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


@pytest.mark.parametrize("kind", ["gateway", "force_load_node"])
async def test_restored_tracker_starts_not_home_until_reported(hass, router, kind):
    entry, node = _node(hass, kind)
    await get_store(hass, NODE_IP).async_save({CLIENT: _stored(entry)})
    try:
        # Restart: the first refresh restores, then the platform is set up.
        await node._async_prepare_device_restore(node.data)
        platform = await _setup_trackers(hass, entry)

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
