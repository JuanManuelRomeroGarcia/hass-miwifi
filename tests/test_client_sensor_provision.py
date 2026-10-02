"""Client sensors must be provided after startup, reload and reconnect, and only once (#330).

Runs on a real Home Assistant core (pytest-homeassistant-custom-component):
two MiWiFi config entries, two sensor platforms and the real entity registry.
"""

from __future__ import annotations

import logging
import asyncio
from contextlib import ExitStack
from unittest.mock import AsyncMock, patch

import pytest

from homeassistant.components.sensor import SensorEntity
from homeassistant.core import HomeAssistant
from homeassistant.helpers import device_registry as dr
from homeassistant.helpers import entity_registry as er
from homeassistant.helpers.dispatcher import async_dispatcher_send
from homeassistant.helpers.update_coordinator import DataUpdateCoordinator
from pytest_homeassistant_custom_component.common import MockConfigEntry, MockEntityPlatform

from custom_components.miwifi.const import (
    ATTR_TRACKER_IP,
    ATTR_TRACKER_MAC,
    ATTR_TRACKER_UPDATER_ENTRY_ID,
    CONF_ENABLE_DEVICE_SENSORS,
    DOMAIN,
    SIGNAL_NEW_DEVICE,
    UPDATER,
)
from custom_components.miwifi.device_tracker import _reparent_client_device
from custom_components.miwifi.sensor import (
    MIWIFI_DEVICE_SENSORS,
    _not_provided_elsewhere,
    _async_add_all_sensors_later,
    async_setup_entry,
)

UID = "miwifi-dev-02:00:00:00:00:01-ip"

MAC = "02:00:00:00:00:02"
CLIENT_UIDS = [f"miwifi-dev-{MAC.lower()}-{desc.key}" for desc in MIWIFI_DEVICE_SENSORS]
CLIENT_IP_UID = f"miwifi-dev-{MAC.lower()}-{ATTR_TRACKER_IP}"


@pytest.mark.parametrize("filter_live", [False, True])
async def test_offline_client_restored_by_two_nodes_has_one_live_sensor_set(hass: HomeAssistant, caplog, filter_live) -> None:
    """A disconnected client restored in two stores must not duplicate at startup."""
    main, node = _entries(hass)
    registry = er.async_get(hass)
    for uid in CLIENT_UIDS:
        registry.async_get_or_create("sensor", DOMAIN, uid, config_entry=main)

    updaters = []
    platforms = []
    for entry in (main, node):
        updater = DataUpdateCoordinator(hass, logging.getLogger(__name__), config_entry=entry, name=entry.entry_id)
        updater.data = {"topo_graph": {"graph": {"is_main": False}}}
        updater.devices = {MAC: {ATTR_TRACKER_MAC: MAC, ATTR_TRACKER_UPDATER_ENTRY_ID: entry.entry_id,
                                 ATTR_TRACKER_IP: "192.0.2.20", "is_restored": True, "online": ""}}
        updater.async_request_refresh = AsyncMock()
        hass.data.setdefault(DOMAIN, {})[entry.entry_id] = {UPDATER: updater}
        updaters.append(updater)
        platforms.append(_platform(hass, entry))

    caplog.set_level(logging.ERROR)
    with ExitStack() as stack:
        if not filter_live:
            # Control: reproduce the old startup path without the live-platform check.
            stack.enter_context(patch("custom_components.miwifi.sensor._not_provided_elsewhere",
                                      side_effect=lambda hass, sensors: sensors))
        # Router diagnostics are outside this regression; use separate unique IDs.
        stack.enter_context(patch("custom_components.miwifi.sensor.MIWIFI_SENSORS", []))
        stack.enter_context(patch("custom_components.miwifi.sensor._is_cb0401v2", return_value=False))
        for name in ("MiWifiTopologyGraphSensor", "MiWifiConfigSensor"):
            stack.enter_context(patch(f"custom_components.miwifi.sensor.{name}",
                side_effect=lambda updater, kind=name: ClientSensor("0", f"{kind}-{updater.name}")))
        await asyncio.gather(*[
            _async_add_all_sensors_later(hass, entry, platform._async_schedule_add_entities)
            for entry, platform in zip((main, node), platforms)
        ])
        await hass.async_block_till_done()

    assert ("does not generate unique IDs" in caplog.text) is (not filter_live)
    for uid in CLIENT_UIDS:
        entity_id = registry.async_get_entity_id("sensor", DOMAIN, uid)
        assert sum(entity_id in platform.entities for platform in platforms) == 1
    assert hass.states.get(registry.async_get_entity_id("sensor", DOMAIN, CLIENT_IP_UID)).state == "192.0.2.20"


class ClientSensor(SensorEntity):
    """Stands in for a client sensor: stable MAC-based unique id and a value."""

    _attr_should_poll = False

    def __init__(self, value: str, unique_id: str = UID) -> None:
        self._attr_unique_id = unique_id
        self._attr_name = "Client IP"
        self._attr_native_value = value


def _platform(hass: HomeAssistant, entry: MockConfigEntry) -> MockEntityPlatform:
    platform = MockEntityPlatform(hass, domain="sensor", platform_name=DOMAIN)
    platform.config_entry = entry
    platform.async_prepare()
    return platform


def _entries(hass: HomeAssistant) -> tuple[MockConfigEntry, MockConfigEntry]:
    main = MockConfigEntry(domain=DOMAIN, title="192.0.2.1")
    node = MockConfigEntry(
        domain=DOMAIN, title="192.0.2.2", options={CONF_ENABLE_DEVICE_SENSORS: True}
    )
    main.add_to_hass(hass)
    node.add_to_hass(hass)
    return main, node


async def test_registered_sensor_of_a_mesh_node_is_provided_after_startup(hass: HomeAssistant) -> None:
    main, node = _entries(hass)
    # As after a restart: the row exists and belongs to the node, nothing is live.
    er.async_get(hass).async_get_or_create("sensor", DOMAIN, UID, config_entry=node)
    _platform(hass, main)
    node_platform = _platform(hass, node)

    sensors = _not_provided_elsewhere(hass, [ClientSensor("192.0.2.10")])
    await node_platform.async_add_entities(sensors)

    entity_id = er.async_get(hass).async_get_entity_id("sensor", DOMAIN, UID)
    state = hass.states.get(entity_id)
    assert state is not None and state.state == "192.0.2.10"
    assert not state.attributes.get("restored")


async def test_sensor_live_on_another_entry_is_not_added_twice(hass: HomeAssistant, caplog) -> None:
    main, node = _entries(hass)
    main_platform = _platform(hass, main)
    node_platform = _platform(hass, node)
    await main_platform.async_add_entities([ClientSensor("192.0.2.10")])

    caplog.set_level(logging.ERROR)
    sensors = _not_provided_elsewhere(hass, [ClientSensor("192.0.2.10")])
    await node_platform.async_add_entities(sensors)

    assert sensors == []
    assert "does not generate unique IDs" not in caplog.text
    entity_id = er.async_get(hass).async_get_entity_id("sensor", DOMAIN, UID)
    assert hass.states.get(entity_id).state == "192.0.2.10"


async def test_sensor_is_provided_again_after_the_other_entry_reloads(hass: HomeAssistant) -> None:
    main, node = _entries(hass)
    main_platform = _platform(hass, main)
    node_platform = _platform(hass, node)
    await main_platform.async_add_entities([ClientSensor("192.0.2.10")])
    assert _not_provided_elsewhere(hass, [ClientSensor("192.0.2.10")]) == []

    # Unloading the entry resets its platform; nothing may keep blocking the add.
    await main_platform.async_reset()
    sensors = _not_provided_elsewhere(hass, [ClientSensor("192.0.2.11")])
    await node_platform.async_add_entities(sensors)

    entity_id = er.async_get(hass).async_get_entity_id("sensor", DOMAIN, UID)
    state = hass.states.get(entity_id)
    assert state is not None and state.state == "192.0.2.11"
    assert not state.attributes.get("restored")


async def _set_up_node_sensors(hass: HomeAssistant, node: MockConfigEntry) -> DataUpdateCoordinator:
    """Run the node's sensor setup; only the new-device path is exercised."""
    updater = DataUpdateCoordinator(
        hass, logging.getLogger(__name__), config_entry=node, name="node"
    )
    updater.data = {}
    updater.devices = {}
    hass.data.setdefault(DOMAIN, {})[node.entry_id] = {UPDATER: updater}
    platform = _platform(hass, node)

    def add_entities(entities, update_before_add=False):
        hass.async_create_task(platform.async_add_entities(entities))

    with patch("custom_components.miwifi.sensor._async_add_all_sensors_later", AsyncMock()):
        await async_setup_entry(hass, node, add_entities)
    return updater


def _client_comes_back(hass: HomeAssistant, updater: DataUpdateCoordinator, node: MockConfigEntry) -> None:
    device = {
        ATTR_TRACKER_MAC: MAC,
        ATTR_TRACKER_IP: "192.0.2.20",
        ATTR_TRACKER_UPDATER_ENTRY_ID: node.entry_id,
    }
    updater.devices[MAC] = device
    async_dispatcher_send(hass, SIGNAL_NEW_DEVICE, device)


async def test_client_back_after_restart_gets_its_registered_sensors(hass: HomeAssistant) -> None:
    _, node = _entries(hass)
    # The client was away at startup: its rows exist, enabled, and nothing provides them.
    registry = er.async_get(hass)
    for uid in CLIENT_UIDS:
        registry.async_get_or_create("sensor", DOMAIN, uid, config_entry=node)
    updater = await _set_up_node_sensors(hass, node)

    _client_comes_back(hass, updater, node)
    await hass.async_block_till_done()

    for uid in CLIENT_UIDS:
        assert hass.states.get(registry.async_get_entity_id("sensor", DOMAIN, uid)) is not None
    state = hass.states.get(registry.async_get_entity_id("sensor", DOMAIN, CLIENT_IP_UID))
    assert state.state == "192.0.2.20"
    assert not state.attributes.get("restored")


async def test_new_device_skips_a_sensor_live_on_another_entry(hass: HomeAssistant, caplog) -> None:
    main, node = _entries(hass)
    main_platform = _platform(hass, main)
    await main_platform.async_add_entities([ClientSensor("192.0.2.10", CLIENT_IP_UID)])
    updater = await _set_up_node_sensors(hass, node)

    caplog.set_level(logging.ERROR)
    _client_comes_back(hass, updater, node)
    await hass.async_block_till_done()

    assert "does not generate unique IDs" not in caplog.text
    registry = er.async_get(hass)
    entity_id = registry.async_get_entity_id("sensor", DOMAIN, CLIENT_IP_UID)
    assert entity_id in main_platform.entities
    assert hass.states.get(entity_id).state == "192.0.2.10"


async def test_client_back_on_another_node_ends_on_one_device_row(hass: HomeAssistant) -> None:
    main, node = _entries(hass)
    # Rows left by the node that served the client before the restart.
    devices = dr.async_get(hass)
    device = devices.async_get_or_create(
        config_entry_id=main.entry_id,
        identifiers={(DOMAIN, MAC.lower())},
        connections={(dr.CONNECTION_NETWORK_MAC, MAC.lower())},
    )
    registry = er.async_get(hass)
    for uid in CLIENT_UIDS:
        registry.async_get_or_create(
            "sensor", DOMAIN, uid, config_entry=main, device_id=device.id
        )
    updater = await _set_up_node_sensors(hass, node)

    _client_comes_back(hass, updater, node)
    await hass.async_block_till_done()
    entity_id = registry.async_get_entity_id("sensor", DOMAIN, CLIENT_IP_UID)
    assert hass.states.get(entity_id).state == "192.0.2.20"

    # From 2026.9 the node's add gives it a row of its own; the tracker hands the
    # client over when it is added and on every refresh, and that joins them.
    _reparent_client_device(hass, MAC.lower(), node.entry_id)
    await hass.async_block_till_done()

    rows = [
        row
        for entry in (main, node)
        for row in dr.async_entries_for_config_entry(devices, entry.entry_id)
        if (DOMAIN, MAC.lower()) in row.identifiers
    ]
    assert len(rows) == 1
    for uid in CLIENT_UIDS:
        sensor = registry.async_get(registry.async_get_entity_id("sensor", DOMAIN, uid))
        assert sensor.device_id == rows[0].id
    assert hass.states.get(entity_id).state == "192.0.2.20"
