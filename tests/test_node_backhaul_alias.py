"""A node listed by its mesh under a second MAC is still found by that MAC.

On some leaves (an RA82, for one) the MAC the node reports for itself is not
the one its main writes in a client's `parent`. Clients were routed to the
right node, but nothing else could find the node by that MAC: "Connected via"
kept whatever it last pointed at, and the client attributes named a MAC that no
node device carries.
"""

# pylint: disable=protected-access

from types import SimpleNamespace
from unittest.mock import patch

import pytest
from homeassistant.helpers import device_registry as dr
from pytest_homeassistant_custom_component.common import MockConfigEntry

from custom_components.miwifi.const import (
    ATTR_DEVICE_MAC_ADDRESS,
    ATTR_DEVICE_NAME,
    ATTR_TRACKER_ENTRY_ID,
    ATTR_TRACKER_MAC,
    ATTR_TRACKER_ROUTER_MAC_ADDRESS,
    ATTR_TRACKER_UPDATER_ENTRY_ID,
    DOMAIN,
    UPDATER,
)
from custom_components.miwifi.device_tracker import (
    MiWifiDeviceTracker,
    _ensure_via_device_exists,
)
from custom_components.miwifi.helper import (
    async_get_serving_node,
    async_register_backhaul_alias,
)
from custom_components.miwifi.updater import LuciUpdater
from custom_components.miwifi.sensor import MiWifiDeviceAttributeSensor

NODE = "02:00:00:00:00:10"
BACKHAUL = "02:00:00:00:00:11"
CLIENT = "02:00:00:00:00:12"
NODE_IP = "192.0.2.103"


def _node(hass, backhaul: str | None = None, name: str | None = "MiWiFi-Node"):
    """A loaded node entry with its own device row."""

    entry = MockConfigEntry(domain=DOMAIN)
    entry.add_to_hass(hass)
    hass.data.setdefault(DOMAIN, {})[entry.entry_id] = {
        UPDATER: SimpleNamespace(
            data={ATTR_DEVICE_MAC_ADDRESS: NODE, ATTR_DEVICE_NAME: name},
            backhaul_mac=backhaul,
        )
    }
    row = dr.async_get(hass).async_get_or_create(
        config_entry_id=entry.entry_id,
        identifiers={(DOMAIN, NODE.lower())},
        connections={(dr.CONNECTION_NETWORK_MAC, NODE.lower())},
        name="ra82",
    )

    return entry, row


def test_the_alias_goes_on_the_nodes_own_row_and_resolves_to_it(hass):
    """`_ensure_via_device_exists` already resolved such a row; nothing made one."""

    entry, row = _node(hass)
    registry = dr.async_get(hass)

    assert async_register_backhaul_alias(hass, entry.entry_id, NODE, BACKHAUL) == "added"
    assert (dr.CONNECTION_NETWORK_MAC, BACKHAUL.lower()) in registry.async_get(
        row.id
    ).connections
    assert async_register_backhaul_alias(hass, entry.entry_id, NODE, BACKHAUL) == "present"

    before = len(registry.devices)
    assert _ensure_via_device_exists(hass, BACKHAUL).id == row.id
    assert len(registry.devices) == before


def test_nothing_is_recorded_on_a_row_the_node_does_not_own(hass):
    """The node's MAC under another entry is not the node's row."""

    _, row = _node(hass)
    other = MockConfigEntry(domain=DOMAIN)
    other.add_to_hass(hass)

    assert async_register_backhaul_alias(hass, other.entry_id, NODE, BACKHAUL) == "missing"
    assert async_register_backhaul_alias(hass, "", NODE, NODE) == "missing"
    assert (dr.CONNECTION_NETWORK_MAC, BACKHAUL.lower()) not in dr.async_get(
        hass
    ).async_get(row.id).connections


def test_a_mac_another_row_already_has_is_left_where_it_is(hass):
    """The registry refuses the duplicate; neither row is merged or dropped."""

    entry, row = _node(hass)
    registry = dr.async_get(hass)
    stale = registry.async_get_or_create(
        config_entry_id=entry.entry_id,
        identifiers={(DOMAIN, BACKHAUL.lower())},
        connections={(dr.CONNECTION_NETWORK_MAC, BACKHAUL.lower())},
    )

    assert async_register_backhaul_alias(hass, entry.entry_id, NODE, BACKHAUL) == "taken"
    assert registry.async_get(row.id).connections == {
        (dr.CONNECTION_NETWORK_MAC, NODE.lower())
    }
    assert registry.async_get(stale.id) is not None


def test_a_known_backhaul_is_the_node_even_with_a_client_row_under_that_mac(hass):
    """A node once tracked as a client leaves a client row under its listed MAC."""

    _, row = _node(hass, backhaul=BACKHAUL)
    main = MockConfigEntry(domain=DOMAIN)
    main.add_to_hass(hass)
    stale = dr.async_get(hass).async_get_or_create(
        config_entry_id=main.entry_id,
        identifiers={(DOMAIN, BACKHAUL.lower())},
        connections={(dr.CONNECTION_NETWORK_MAC, BACKHAUL.lower())},
    )

    resolved = _ensure_via_device_exists(hass, BACKHAUL)

    assert resolved.id == row.id
    assert resolved.id != stale.id


def test_the_serving_node_is_named_by_either_mac(hass):
    """Client attributes name the node, whichever MAC the main used."""

    _node(hass, backhaul=BACKHAUL)

    assert async_get_serving_node(hass, NODE.lower()) == (NODE, "MiWiFi-Node")
    assert async_get_serving_node(hass, BACKHAUL) == (NODE, "MiWiFi-Node")
    assert async_get_serving_node(hass, CLIENT) is None
    assert async_get_serving_node(hass, None) is None
    assert async_get_serving_node(None, NODE) is None


def test_the_name_given_in_home_assistant_comes_first(hass):
    """Then the router's own name, then the row's default name."""

    entry, row = _node(hass, name=None)
    registry = dr.async_get(hass)

    assert async_get_serving_node(hass, NODE) == (NODE, "ra82")

    registry.async_update_device(row.id, name_by_user="Box")
    assert async_get_serving_node(hass, NODE) == (NODE, "Box")

    hass.data[DOMAIN][entry.entry_id][UPDATER].data[ATTR_DEVICE_NAME] = "MiWiFi-Node"
    assert async_get_serving_node(hass, NODE) == (NODE, "Box")


def _updater(hass, mac: str) -> LuciUpdater:
    """A shell holding only what the alias step reads and writes."""

    updater = LuciUpdater.__new__(LuciUpdater)
    updater.hass = hass
    updater.data = {ATTR_DEVICE_MAC_ADDRESS: mac}
    updater.backhaul_mac = None
    updater._backhaul_alias_skipped = set()

    return updater


async def test_the_main_device_list_records_the_alias(hass):
    """The step runs on the device list that names the node."""

    entry, row = _node(hass)
    main = _updater(hass, "02:00:00:00:00:01")
    node = _updater(hass, NODE)
    integrations = {NODE_IP: {UPDATER: node, ATTR_TRACKER_ENTRY_ID: entry.entry_id}}

    await main._async_record_backhaul_aliases(
        integrations, {NODE_IP: BACKHAUL}, {NODE: NODE_IP, BACKHAUL: NODE_IP}
    )

    assert node.backhaul_mac == BACKHAUL
    assert (dr.CONNECTION_NETWORK_MAC, BACKHAUL.lower()) in dr.async_get(
        hass
    ).async_get(row.id).connections


async def test_a_listed_mac_that_is_the_nodes_own_or_another_nodes_is_ignored(hass):
    """Only a second MAC that routes to this very node is an alias."""

    entry, row = _node(hass)
    main = _updater(hass, "02:00:00:00:00:01")
    node = _updater(hass, NODE)
    integrations = {NODE_IP: {UPDATER: node, ATTR_TRACKER_ENTRY_ID: entry.entry_id}}

    await main._async_record_backhaul_aliases(
        integrations, {NODE_IP: NODE}, {NODE: NODE_IP}
    )
    await main._async_record_backhaul_aliases(
        integrations, {NODE_IP: BACKHAUL}, {NODE: NODE_IP, BACKHAUL: "192.0.2.104"}
    )

    assert node.backhaul_mac is None
    assert dr.async_get(hass).async_get(row.id).connections == {
        (dr.CONNECTION_NETWORK_MAC, NODE.lower())
    }


async def test_a_taken_mac_is_not_tried_again_every_cycle(hass):
    """The other row is not going anywhere; the node is still resolved."""

    entry, _ = _node(hass)
    main = _updater(hass, "02:00:00:00:00:01")
    node = _updater(hass, NODE)
    integrations = {NODE_IP: {UPDATER: node, ATTR_TRACKER_ENTRY_ID: entry.entry_id}}

    with patch(
        "custom_components.miwifi.helper.async_register_backhaul_alias",
        return_value="taken",
    ) as register:
        for _ in range(3):
            await main._async_record_backhaul_aliases(
                integrations, {NODE_IP: BACKHAUL}, {NODE: NODE_IP, BACKHAUL: NODE_IP}
            )

    assert register.call_count == 1
    assert node.backhaul_mac == BACKHAUL


@pytest.mark.parametrize("entity_type", [MiWifiDeviceTracker, MiWifiDeviceAttributeSensor])
def test_clients_publish_both_node_identities_without_changing_existing_attributes(
    hass, entity_type,
):
    """Dashboards can use the node's real MAC on trackers and client sensors."""
    entry, row = _node(hass, backhaul=BACKHAUL)
    dr.async_get(hass).async_update_device(row.id, name_by_user="Node in HA")
    device = {
        ATTR_TRACKER_MAC: CLIENT,
        ATTR_TRACKER_ROUTER_MAC_ADDRESS: BACKHAUL,
        ATTR_TRACKER_UPDATER_ENTRY_ID: entry.entry_id,
    }
    entity = entity_type.__new__(entity_type)
    entity.hass = hass
    if entity_type is MiWifiDeviceTracker:
        entity._device = device
        entity._is_connected = True
    else:
        entity._mac = CLIENT
        entity._updater = SimpleNamespace(devices={CLIENT: device})

    attributes = entity.extra_state_attributes

    assert attributes[ATTR_TRACKER_ROUTER_MAC_ADDRESS] == BACKHAUL
    assert attributes["connected_via_router_mac"] == BACKHAUL
    assert attributes["connected_via_entry_id"] == entry.entry_id
    assert attributes["connected_via_router_device_mac"] == NODE
    assert attributes["connected_via_router_name"] == "Node in HA"


async def test_alias_registration_retries_when_the_node_row_appears_later(hass):
    """The first census may run before the node's platforms create its row."""
    entry = MockConfigEntry(domain=DOMAIN)
    entry.add_to_hass(hass)
    main = _updater(hass, "02:00:00:00:00:01")
    node = _updater(hass, NODE)
    integrations = {NODE_IP: {UPDATER: node, ATTR_TRACKER_ENTRY_ID: entry.entry_id}}
    hass.data.setdefault(DOMAIN, {})[entry.entry_id] = integrations[NODE_IP]
    listed = {NODE_IP: BACKHAUL}
    routed = {NODE: NODE_IP, BACKHAUL: NODE_IP}

    await main._async_record_backhaul_aliases(integrations, listed, routed)
    assert node.backhaul_mac == BACKHAUL
    assert main._backhaul_alias_skipped == set()

    registry = dr.async_get(hass)
    row = registry.async_get_or_create(
        config_entry_id=entry.entry_id,
        identifiers={(DOMAIN, NODE.lower())},
        connections={(dr.CONNECTION_NETWORK_MAC, NODE.lower())},
    )
    await main._async_record_backhaul_aliases(integrations, listed, routed)

    assert (dr.CONNECTION_NETWORK_MAC, BACKHAUL.lower()) in registry.async_get(
        row.id
    ).connections
    assert _ensure_via_device_exists(hass, BACKHAUL).id == row.id
