"""Reproduce reported RC06 client-name loss before changing production code."""

import pytest

from custom_components.miwifi.const import ATTR_TRACKER_NAME
from tests.test_extended_client_metrics import MAC, ROW, make_updater
from custom_components.miwifi.const import UPDATER
from homeassistant.helpers import device_registry as dr
from homeassistant.helpers import entity_registry as er
from tests.test_tracker_recovery import _node, _client, _setup, MAC as TRACKER_MAC, UID


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


@pytest.mark.parametrize("target_name,expected", [(MAC, "Source hostname"), ("Target hostname", "Target hostname")])
async def test_mass_update_uses_known_origin_only_when_target_has_no_name(hass, target_name, expected):
    source = make_updater(hass, ip="192.0.2.1")
    target = make_updater(hass, ip="192.0.2.2")
    del source._mass_update_device
    source.devices[MAC] = {ATTR_TRACKER_NAME: "Source hostname"}
    target.devices[MAC] = {ATTR_TRACKER_NAME: target_name}
    row = {**ROW, "entry_id": source._entry_id, "name": MAC}
    assert source._mass_update_device(row, {target.ip: {UPDATER: target}})
    assert target.devices[MAC][ATTR_TRACKER_NAME] == expected


@pytest.mark.parametrize("order", [(0, 1, 2), (2, 1, 0)])
async def test_three_nodes_start_with_unequal_names_and_roam_in_both_orders(hass, order):
    nodes = [make_updater(hass, ip=f"192.0.2.{i + 1}") for i in range(3)]
    for node in nodes:
        del node._mass_update_device
        node.devices[MAC] = {ATTR_TRACKER_NAME: MAC}
    nodes[order[0]].devices[MAC][ATTR_TRACKER_NAME] = "Known hostname"
    integrations = {node.ip: {UPDATER: node} for node in nodes}
    for index in order:
        source = nodes[index]
        source._mass_update_device({**ROW, "entry_id": source._entry_id, "name": MAC}, integrations)
    assert all(node.devices[MAC][ATTR_TRACKER_NAME] == "Known hostname" for node in nodes)
    source = nodes[order[-1]]
    source._mass_update_device({**ROW, "entry_id": source._entry_id, "name": "New router name"}, integrations)
    assert all(node.devices[MAC][ATTR_TRACKER_NAME] == "New router name" for node in nodes if node is not source)


async def test_real_tracker_stable_observations_do_not_update_registry(hass):
    entry, updater, platform = _node(hass, "192.0.2.1")
    updater.devices[TRACKER_MAC] = _client(entry)
    await _setup(hass, entry, platform)
    entity_registry = er.async_get(hass)
    entity_id = entity_registry.async_get_entity_id("device_tracker", "miwifi", UID)
    assert entity_id
    device_id = entity_registry.async_get(entity_id).device_id
    observed = {"device_registry_updated": [], "entity_registry_updated": [], "state_changed": []}
    unsubscribers = [hass.bus.async_listen(key, observed[key].append) for key in observed]
    for _ in range(4):
        updater.async_set_updated_data(dict(updater.data))
        await hass.async_block_till_done()
    for unsubscribe in unsubscribers:
        unsubscribe()
    device_updates = [event for event in observed["device_registry_updated"]
                      if event.data.get("device_id") == device_id and event.data.get("action") == "update"]
    entity_updates = [event for event in observed["entity_registry_updated"]
                      if event.data.get("entity_id") == entity_id and event.data.get("action") == "update"]
    assert device_updates == []
    assert entity_updates == []
    assert entity_registry.async_get(entity_id).device_id == device_id
    assert hass.states.get(entity_id).state == "home"
