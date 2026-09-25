"""Client sensors must be provided after startup and reload, and only once (#330).

Runs on a real Home Assistant core (pytest-homeassistant-custom-component):
two MiWiFi config entries, two sensor platforms and the real entity registry.
"""

from __future__ import annotations

import logging

from homeassistant.components.sensor import SensorEntity
from homeassistant.core import HomeAssistant
from homeassistant.helpers import entity_registry as er
from pytest_homeassistant_custom_component.common import MockConfigEntry, MockEntityPlatform

from custom_components.miwifi.const import DOMAIN
from custom_components.miwifi.sensor import _not_provided_elsewhere

UID = "miwifi-dev-02:00:00:00:00:01-ip"


class ClientSensor(SensorEntity):
    """Stands in for a client sensor: stable MAC-based unique id and a value."""

    _attr_should_poll = False

    def __init__(self, value: str) -> None:
        self._attr_unique_id = UID
        self._attr_name = "Client IP"
        self._attr_native_value = value


def _platform(hass: HomeAssistant, entry: MockConfigEntry) -> MockEntityPlatform:
    platform = MockEntityPlatform(hass, domain="sensor", platform_name=DOMAIN)
    platform.config_entry = entry
    platform.async_prepare()
    return platform


def _entries(hass: HomeAssistant) -> tuple[MockConfigEntry, MockConfigEntry]:
    main = MockConfigEntry(domain=DOMAIN, title="192.0.2.1")
    node = MockConfigEntry(domain=DOMAIN, title="192.0.2.2")
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
