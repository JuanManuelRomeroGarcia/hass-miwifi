"""Channel icons remain visible while signal selectors reflect their option."""

import logging

from homeassistant.helpers.update_coordinator import DataUpdateCoordinator
from pytest_homeassistant_custom_component.common import MockConfigEntry

import pytest

from custom_components.miwifi.const import ATTR_DEVICE_MAC_ADDRESS, DOMAIN
from custom_components.miwifi.select import CHANNELS_MAP, MIWIFI_SELECTS, MiWifiSelect


@pytest.mark.parametrize("description", MIWIFI_SELECTS, ids=lambda item: item.key)
@pytest.mark.parametrize("option", ["min", "mid", "max", None])
async def test_select_icons(hass, description, option):
    entry = MockConfigEntry(domain=DOMAIN)
    entry.add_to_hass(hass)
    updater = DataUpdateCoordinator(
        hass, logging.getLogger(__name__), name=entry.entry_id, config_entry=entry
    )
    updater.data = {ATTR_DEVICE_MAC_ADDRESS: "00:11:22:33:44:55", description.key: option}
    updater.ip = "192.168.31.1"
    entity = MiWifiSelect("test_select", description, updater)

    if description.key in CHANNELS_MAP:
        assert entity.icon == "mdi:format-list-numbered"
    else:
        assert entity.icon == {
            "min": "mdi:wifi-strength-1",
            "mid": "mdi:wifi-strength-2",
            "max": "mdi:wifi-strength-4",
            None: "mdi:wifi-strength-4",
        }[option]

    await updater.async_shutdown()
