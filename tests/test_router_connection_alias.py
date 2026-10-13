"""Only a loaded router's own row may supply a backhaul connection alias."""
from types import SimpleNamespace

import pytest
from homeassistant.helpers import device_registry as dr
from pytest_homeassistant_custom_component.common import MockConfigEntry

from custom_components.miwifi.const import ATTR_DEVICE_MAC_ADDRESS, DOMAIN, UPDATER
from custom_components.miwifi.device_tracker import _ensure_via_device_exists

PRIMARY = "02:00:00:00:00:10"
BACKHAUL = "02:00:00:00:00:11"
CLIENT = "02:00:00:00:00:12"


@pytest.mark.parametrize("identity", ["router", "other_entry", "client"])
def test_backhaul_alias_requires_loaded_router_identity_and_owner(hass, identity):
    entry = MockConfigEntry(domain=DOMAIN)
    entry.add_to_hass(hass)
    other = MockConfigEntry(domain=DOMAIN)
    other.add_to_hass(hass)
    hass.data[DOMAIN] = {
        entry.entry_id: {UPDATER: SimpleNamespace(data={ATTR_DEVICE_MAC_ADDRESS: PRIMARY})}
    }
    registry = dr.async_get(hass)
    row = registry.async_get_or_create(
        config_entry_id=other.entry_id if identity == "other_entry" else entry.entry_id,
        identifiers={(DOMAIN, CLIENT if identity == "client" else PRIMARY)},
        connections={(dr.CONNECTION_NETWORK_MAC, BACKHAUL)},
    )
    before = len(registry.devices)
    resolved = _ensure_via_device_exists(hass, BACKHAUL.upper())
    assert resolved == (row if identity == "router" else None)
    assert len(registry.devices) == before
