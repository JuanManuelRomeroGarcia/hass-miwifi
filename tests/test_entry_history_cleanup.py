"""Removing an unloaded config entry must also remove its router history."""

from unittest.mock import AsyncMock, Mock, patch

import pytest
from homeassistant.const import CONF_IP_ADDRESS
from pytest_homeassistant_custom_component.common import MockConfigEntry

from custom_components.miwifi import async_remove_entry
from custom_components.miwifi.const import DOMAIN, UPDATER


@pytest.mark.parametrize("has_runtime", [False, True], ids=["unloaded", "loaded"])
async def test_remove_entry_cleans_history(hass, has_runtime):
    entry = MockConfigEntry(domain=DOMAIN, data={CONF_IP_ADDRESS: "192.0.2.1"})
    entry.add_to_hass(hass)
    updater = Mock(async_stop=AsyncMock())
    hass.data[DOMAIN] = {entry.entry_id: {UPDATER: updater}} if has_runtime else {}
    store = Mock(async_remove=AsyncMock())

    with patch("custom_components.miwifi.get_store", return_value=store) as factory:
        await async_remove_entry(hass, entry)

    assert entry.entry_id not in hass.data[DOMAIN]
    if has_runtime:
        updater.async_stop.assert_awaited_once_with(clean_store=True)
        factory.assert_not_called()
    else:
        factory.assert_called_once_with(hass, "192.0.2.1")
        store.async_remove.assert_awaited_once_with()
