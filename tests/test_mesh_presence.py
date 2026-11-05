"""Regression tests for live MiWiFi presence updates across mesh nodes."""

import time
from contextlib import asynccontextmanager
from datetime import datetime
from unittest.mock import AsyncMock, Mock, patch

from custom_components.miwifi.const import (
    ATTR_STATE,
    ATTR_TRACKER_ENTRY_ID,
    ATTR_TRACKER_IS_RESTORED,
    ATTR_TRACKER_LAST_ACTIVITY,
    ATTR_TRACKER_NAME,
    ATTR_TRACKER_UPDATER_ENTRY_ID,
    DOMAIN,
    UPDATER,
)
from custom_components.miwifi.device_tracker import MiWifiDeviceTracker
from custom_components.miwifi.enum import Mode
from custom_components.miwifi.updater import LuciUpdater

MAC = "02:00:00:00:00:20"
UID = f"{DOMAIN}-{MAC.lower()}"


@asynccontextmanager
async def mesh(hass):
    with patch("custom_components.miwifi.updater.LuciClient"):
        nodes = [
            LuciUpdater(
                hass, f"192.0.2.{index}", "test",
                entry_id=f"node-{index}", is_force_load=True,
            )
            for index in (1, 2)
        ]
    integrations = {}
    for index, node in enumerate(nodes, 1):
        node.update_interval = None
        node._is_first_update = False
        node.data = {
            "mode": Mode.MESH_NODE,
            "mac": f"02:00:00:00:01:0{index}",
            ATTR_STATE: True,
        }
        node.luci.wifi_connect_devices = AsyncMock(
            return_value={"code": 0, "list": [{"mac": MAC, "wifiIndex": 2, "signal": 64}]}
        )
        node.luci.macfilter_info = AsyncMock(return_value={})
        integrations[node.ip] = {UPDATER: node}
        hass.data.setdefault(DOMAIN, {})[node._entry_id] = {UPDATER: node}

    tracker = None
    with (
        patch(
            "custom_components.miwifi.updater.async_get_integrations",
            return_value=integrations,
        ),
        patch(
            "custom_components.miwifi.device_tracker.async_get_integrations",
            return_value=integrations,
        ),
        patch(
            "custom_components.miwifi.updater._known_mesh_nodes",
            return_value=(set(), {}),
        ),
        patch("custom_components.miwifi.device_tracker._reparent_client_device"),
    ):
        try:
            await nodes[0]._async_prepare_devices(nodes[0].data)
            tracker = MiWifiDeviceTracker(
                UID, "device_tracker.test_mesh_client",
                nodes[0].devices[MAC], nodes[0], stay_online=90,
            )
            tracker.hass = hass
            tracker.async_write_ha_state = Mock()
            hass.data[DOMAIN]["device_tracker_entities"] = {UID: tracker}
            # The subscription installed by CoordinatorEntity.async_added_to_hass.
            await tracker.async_added_to_hass()
            yield tracker, nodes[0], nodes[1]
        finally:
            if tracker is not None:
                await tracker.async_will_remove_from_hass()
                for remove in tracker._on_remove or ():
                    remove()
            for node in nodes:
                await node.async_shutdown()


def expire(hass, tracker, node):
    old = datetime.fromtimestamp(time.time() - 3600).replace(microsecond=0).isoformat()
    node.devices[MAC][ATTR_TRACKER_LAST_ACTIVITY] = old
    tracker._device[ATTR_TRACKER_LAST_ACTIVITY] = old
    hass.data[DOMAIN]["devices_cache"][MAC][ATTR_TRACKER_LAST_ACTIVITY] = old


async def roam(tracker, origin, destination):
    await destination._async_prepare_devices(destination.data)
    origin.async_set_updated_data(dict(origin.data))
    assert tracker.is_connected


async def test_fresh_other_node_observation_recovers_immediately(hass):
    async with mesh(hass) as (tracker, origin, destination):
        expire(hass, tracker, origin)
        origin.async_set_updated_data(dict(origin.data))
        assert not tracker.is_connected
        tracker.async_write_ha_state.reset_mock()

        await destination._async_prepare_devices(destination.data)

        assert tracker.is_connected, "Fresh mesh observation did not immediately restore home"
        assert tracker.available
        assert tracker.coordinator is destination
        tracker.async_write_ha_state.assert_called()


async def test_origin_failure_does_not_hide_healthy_serving_node(hass):
    async with mesh(hass) as (tracker, origin, destination):
        await roam(tracker, origin, destination)
        origin.last_update_success = False
        origin.data[ATTR_STATE] = False
        origin.async_update_listeners()

        assert tracker.is_connected
        assert tracker.available, "Original coordinator failure hid a healthy destination"


async def test_destination_callbacks_handle_expiry_failure_and_recovery(hass):
    async with mesh(hass) as (tracker, origin, destination):
        await roam(tracker, origin, destination)
        expire(hass, tracker, destination)
        destination.async_set_updated_data(dict(destination.data))
        assert not tracker.is_connected, "Departure did not expire on destination callbacks"
        assert tracker.available

        destination.last_update_success = False
        destination.data[ATTR_STATE] = False
        destination.async_update_listeners()
        assert not tracker.available

        destination.data[ATTR_STATE] = True
        await destination._async_prepare_devices(destination.data)
        assert not tracker.available
        destination.async_set_updated_data(dict(destination.data))
        assert tracker.available
        assert tracker.is_connected


async def test_roaming_updates_attributes_without_duplicate_listeners(hass):
    async with mesh(hass) as (tracker, origin, destination):
        for _ in range(3):
            await destination._async_prepare_devices(destination.data)
            assert tracker.coordinator is destination
            await origin._async_prepare_devices(origin.data)
            assert tracker.coordinator is origin
        assert len(origin._listeners) == 1
        assert len(destination._listeners) == 1

        origin.devices[MAC][ATTR_TRACKER_NAME] = "Renamed mesh client"
        tracker.async_write_ha_state.reset_mock()
        tracker.update_from_router(dict(origin.devices[MAC]))
        assert tracker.name == "Renamed mesh client"
        tracker.async_write_ha_state.assert_called()

    assert not origin._listeners
    assert not destination._listeners


async def test_stale_restored_snapshot_does_not_force_home(hass):
    async with mesh(hass) as (tracker, origin, destination):
        expire(hass, tracker, origin)
        origin.async_set_updated_data(dict(origin.data))
        assert not tracker.is_connected
        restored = dict(origin.devices[MAC])
        restored[ATTR_TRACKER_IS_RESTORED] = True
        restored[ATTR_TRACKER_ENTRY_ID] = destination._entry_id
        restored[ATTR_TRACKER_UPDATER_ENTRY_ID] = destination._entry_id
        destination.devices[MAC] = restored
        tracker.update_from_router(restored)
        assert not tracker.is_connected

        origin.devices.clear()
        destination.devices.clear()
        hass.data[DOMAIN]["devices_cache"].clear()
        tracker._handle_coordinator_update()
        assert not tracker.is_connected


async def test_manual_refresh_targets_current_serving_node(hass):
    async with mesh(hass) as (tracker, origin, destination):
        await roam(tracker, origin, destination)
        origin.async_request_refresh = AsyncMock()
        destination.async_request_refresh = AsyncMock()
        await tracker.async_update()
        destination.async_request_refresh.assert_awaited_once()
        origin.async_request_refresh.assert_not_awaited()

async def test_exact_absence_threshold_on_installed_code(hass):
    async with mesh(hass) as (tracker, origin, destination):
        await destination._async_prepare_devices(destination.data)
        now = int(time.time())
        with patch("custom_components.miwifi.device_tracker.time.time", return_value=now):
            for age, expected in ((0, True), (89, True), (90, True), (91, False)):
                seen = datetime.fromtimestamp(now - age).isoformat()
                destination.devices[MAC][ATTR_TRACKER_LAST_ACTIVITY] = seen
                tracker.update_from_router(dict(destination.devices[MAC]))
                assert tracker.is_connected is expected, (age, tracker.is_connected)
                assert tracker.available
            destination.async_set_updated_data(dict(destination.data))
            assert not tracker.is_connected
            assert tracker.coordinator is destination
            origin.last_update_success = False
            origin.data[ATTR_STATE] = False
            origin.async_update_listeners()
            assert tracker.available
