"""A client must never be its own via-device, including restored aliases."""

import logging

import pytest

from homeassistant.helpers import device_registry as dr, entity_registry as er
from homeassistant.helpers.update_coordinator import DataUpdateCoordinator
from pytest_homeassistant_custom_component.common import MockConfigEntry, MockEntityPlatform

from custom_components.miwifi.const import (
    ATTR_STATE, ATTR_TRACKER_IS_RESTORED, ATTR_TRACKER_MAC,
    ATTR_TRACKER_OPTIONAL_MAC, ATTR_TRACKER_ROUTER_MAC_ADDRESS,
    ATTR_TRACKER_UPDATER_ENTRY_ID, DOMAIN,
)
from custom_components.miwifi.device_tracker import MiWifiDeviceTracker

MAC = "02:00:00:00:00:40"
ROUTER_MAC = "02:00:00:00:00:41"
UID = f"{DOMAIN}-{MAC.lower()}"


@pytest.mark.parametrize("restored", [False, True])
@pytest.mark.parametrize("identity", ["own_mac", "optional_mac", "merged_row", "normal_router"])
async def test_client_parent_never_resolves_to_itself(hass, caplog, restored, identity):
    entry = MockConfigEntry(domain=DOMAIN)
    entry.add_to_hass(hass)
    devices = dr.async_get(hass)
    node_mac = MAC if identity == "own_mac" else ROUTER_MAC
    identifiers = {(DOMAIN, node_mac.lower())}
    if identity == "merged_row":
        identifiers.add((DOMAIN, MAC.lower()))
    node = devices.async_get_or_create(
        config_entry_id=entry.entry_id, identifiers=identifiers,
        connections={(dr.CONNECTION_NETWORK_MAC, node_mac.lower())},
    )
    data = {
        ATTR_TRACKER_MAC: MAC,
        ATTR_TRACKER_ROUTER_MAC_ADDRESS: node_mac,
        ATTR_TRACKER_UPDATER_ENTRY_ID: entry.entry_id,
        ATTR_TRACKER_IS_RESTORED: restored,
    }
    if identity == "optional_mac":
        data[ATTR_TRACKER_OPTIONAL_MAC] = ROUTER_MAC
    updater = DataUpdateCoordinator(hass, logging.getLogger(__name__), config_entry=entry, name="test")
    updater.data = {ATTR_STATE: True}
    updater.devices = {MAC: data}
    tracker = MiWifiDeviceTracker(UID, "device_tracker.test_client", data, updater, 30)
    platform = MockEntityPlatform(hass, domain="device_tracker", platform_name=DOMAIN)
    platform.config_entry = entry
    platform.async_prepare()
    await platform.async_add_entities([tracker])
    await hass.async_block_till_done()

    entity_id = er.async_get(hass).async_get_entity_id("device_tracker", DOMAIN, UID)
    assert entity_id is not None
    state = hass.states.get(entity_id)
    assert state is not None
    assert state.state == ("not_home" if restored else "home")
    row = devices.async_get(er.async_get(hass).async_get(entity_id).device_id)
    if identity == "normal_router":
        assert row.id != node.id
        assert row.via_device_id == node.id
    else:
        assert row.id == node.id
        assert row.via_device_id is None
    assert "A device can not be its own via device" not in caplog.text
