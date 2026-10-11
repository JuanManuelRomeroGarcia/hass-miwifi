"""The updater owns its real entry without relying on HA's ambient context."""

from unittest.mock import AsyncMock, patch

import pytest
from homeassistant.config_entries import ConfigEntryState, current_entry
from pytest_homeassistant_custom_component.common import MockConfigEntry

from custom_components.miwifi.const import DOMAIN
from custom_components.miwifi.updater import LuciUpdater


@pytest.mark.parametrize("ambient", [False, True])
async def test_explicit_entry_and_first_refresh(hass, ambient):
    entry = MockConfigEntry(domain=DOMAIN)
    entry.add_to_hass(hass)
    other = MockConfigEntry(domain=DOMAIN)
    other.add_to_hass(hass)
    token = current_entry.set(other if ambient else None)
    try:
        with patch("custom_components.miwifi.updater.LuciClient"):
            updater = LuciUpdater(
                hass, "192.0.2.1", "test", entry_id=entry.entry_id, config_entry=entry,
            )
    finally:
        current_entry.reset(token)
    assert updater.config_entry is entry
    updater.update_method = AsyncMock(return_value={"state": True})
    entry.mock_state(hass, ConfigEntryState.SETUP_IN_PROGRESS)
    try:
        await updater.async_config_entry_first_refresh()
        assert updater.last_update_success
        assert updater.data == {"state": True}
        updater.update_method.assert_awaited_once()
    finally:
        await updater.async_shutdown()
        entry.mock_state(hass, ConfigEntryState.NOT_LOADED)


async def test_login_updater_without_entry_still_refreshes(hass):
    token = current_entry.set(None)
    try:
        with patch("custom_components.miwifi.updater.LuciClient"):
            updater = LuciUpdater(hass, "192.0.2.1", "test", is_only_login=True)
    finally:
        current_entry.reset(token)
    assert updater.config_entry is None
    updater.update_method = AsyncMock(return_value={"state": True})
    try:
        await updater.async_request_refresh()
        assert updater.last_update_success
        updater.update_method.assert_awaited_once()
    finally:
        await updater.async_shutdown()
