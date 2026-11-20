"""Reproduce reported RC06 client-name loss before changing production code."""

import pytest

from custom_components.miwifi.const import ATTR_TRACKER_NAME
from tests.test_extended_client_metrics import MAC, ROW, make_updater
from custom_components.miwifi.const import UPDATER
from homeassistant.helpers import device_registry as dr


@pytest.mark.parametrize("alternative", ["oname", "originName"])
async def test_main_census_prefers_hostname_when_name_is_mac(hass, alternative):
    updater = make_updater(hass)
    row = {**ROW, "entry_id": updater._entry_id, "name": MAC, alternative: "name_16"}
    client = updater._build_device(row)
    assert client[ATTR_TRACKER_NAME] == "name_16"


async def test_three_node_censuses_keep_name_and_accept_router_rename(hass):
    nodes = [make_updater(hass) for _ in range(3)]
    for index, node in enumerate(nodes):
        node.ip = f"192.0.2.{index + 1}"
        node._entry_id = f"entry_{index}"
        del node._mass_update_device
    integrations = {node.ip: {UPDATER: node} for node in nodes}
    nodes[0].devices[MAC] = {ATTR_TRACKER_NAME: "name_16"}
    for node in nodes[1:]:
        node.devices[MAC] = {ATTR_TRACKER_NAME: "name_16"}
    for source in [nodes[1], nodes[0], nodes[2], nodes[0], nodes[1]]:
        row = {**ROW, "entry_id": source._entry_id, "name": MAC}
        if source is nodes[0]:
            row["oname"] = "name_16"
        source._mass_update_device(row, integrations)
        assert all(node.devices[MAC][ATTR_TRACKER_NAME] == "name_16" for node in nodes)
    row = {**ROW, "entry_id": nodes[0]._entry_id, "name": "Router custom", "oname": "name_16"}
    nodes[0]._mass_update_device(row, integrations)
    assert all(node.devices[MAC][ATTR_TRACKER_NAME] == "Router custom" for node in nodes[1:])


async def test_mac_only_observation_preserves_previously_known_name(hass):
    updater = make_updater(hass)
    updater.devices[MAC] = {ATTR_TRACKER_NAME: "name_16"}
    row = {**ROW, "entry_id": updater._entry_id, "name": MAC}
    client = updater._build_device(row)
    assert client[ATTR_TRACKER_NAME] == "name_16"


@pytest.mark.parametrize("name,alternative,expected", [
    ("Router custom", "Hostname", "Router custom"),
    ("", "Hostname", "Hostname"),
    ("02-00-00-00-00-41", "Hostname", "Hostname"),
    ("New name", "Previous", "New name"),
])
async def test_valid_router_name_precedence(hass, name, alternative, expected):
    updater = make_updater(hass)
    row = {**ROW, "entry_id": updater._entry_id, "name": name, "oname": alternative}
    assert updater._build_device(row)[ATTR_TRACKER_NAME] == expected


async def test_registry_events_for_repeated_observations(hass):
    updater = make_updater(hass)
    registry = dr.async_get(hass)
    identity = {("miwifi", MAC.lower())}
    device = registry.async_get_or_create(
        config_entry_id=updater._entry_id, identifiers=identity, name="name_16"
    )
    registry.async_update_device(device.id, name_by_user="Personal name")
    await hass.async_block_till_done()
    events = []
    unsubscribe = hass.bus.async_listen("device_registry_updated", events.append)
    updater.devices[MAC] = {ATTR_TRACKER_NAME: "name_16"}
    for row in [
        {"name": MAC, "oname": "name_16"},
        {"name": MAC},
        {"name": "", "originName": "name_16"},
        {"name": MAC},
    ]:
        built = updater._build_device({**ROW, **row, "entry_id": updater._entry_id})
        registry.async_get_or_create(config_entry_id=updater._entry_id, identifiers=identity,
                                     name=built[ATTR_TRACKER_NAME])
    await hass.async_block_till_done()
    unsubscribe()
    assert not [event for event in events if event.data.get("action") == "update"]
    assert registry.async_get(device.id).name_by_user == "Personal name"
    assert registry.async_get(device.id).name == "name_16"


async def test_restored_name_survives_partial_observation_without_cross_client_leak(hass):
    updater = make_updater(hass)
    updater.devices[MAC] = {ATTR_TRACKER_NAME: "Restored client"}
    row = {**ROW, "entry_id": updater._entry_id, "name": MAC}
    assert updater._build_device(row)[ATTR_TRACKER_NAME] == "Restored client"
    other_mac = "02:00:00:00:00:42"
    other = updater._build_device({**row, "mac": other_mac, "name": other_mac})
    assert other[ATTR_TRACKER_NAME] == other_mac
