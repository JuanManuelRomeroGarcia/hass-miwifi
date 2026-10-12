"""Optional endpoint failures must not prevent later client preparation."""

from unittest.mock import AsyncMock, Mock, patch

import pytest
from homeassistant.config_entries import ConfigEntryState
from pytest_homeassistant_custom_component.common import MockConfigEntry

from custom_components.miwifi.const import (
    ATTR_SENSOR_MODE, ATTR_STATE, ATTR_WIFI_ADAPTER_LENGTH, DOMAIN,
)
from custom_components.miwifi.enum import Mode
from custom_components.miwifi.exceptions import LuciRequestError
from custom_components.miwifi.updater import LuciUpdater


@pytest.mark.parametrize("step, endpoint", [
    ("wan", "wan_info"),
    ("channels", "avaliable_channels"),
    ("device_list", "device_list"),
    ("ap", "wifi_ap_signal"),
    ("new_status", "new_status"),
])
async def test_failed_endpoint_does_not_skip_later_client_restore(hass, step, endpoint):
    entry = MockConfigEntry(domain=DOMAIN)
    entry.add_to_hass(hass)
    with patch("custom_components.miwifi.updater.LuciClient"):
        updater = LuciUpdater(
            hass, "192.0.2.1", "test", entry_id=entry.entry_id,
            config_entry=entry, is_force_load=True,
        )
    updater.data = {ATTR_SENSOR_MODE: Mode.REPEATER, ATTR_WIFI_ADAPTER_LENGTH: 2}
    updater.luci.login = AsyncMock()
    updater.luci.logout = AsyncMock()
    failing = AsyncMock(side_effect=LuciRequestError("unsupported endpoint"))
    setattr(updater.luci, endpoint, failing)
    updater._async_prepare_device_restore = AsyncMock()
    updater._clean_devices = Mock()
    updater._async_prepare_topo = AsyncMock()
    updater._async_apply_leaf_client_count = AsyncMock()
    updater._async_prepare_compatibility = AsyncMock()
    if step != "new_status":
        updater._async_prepare_new_status = AsyncMock()
    try:
        with patch("custom_components.miwifi.updater.PREPARE_METHODS", (step, "device_restore")), \
             patch("custom_components.miwifi.updater.get_combined_unsupported", new=AsyncMock(return_value={})), \
             patch("custom_components.miwifi.updater.asyncio.sleep", new=AsyncMock()):
            result = await updater.update()
        assert failing.await_count >= 1
        updater._async_prepare_device_restore.assert_awaited_once()
        assert result[ATTR_STATE] is True
        assert not updater._is_reauthorization
    finally:
        await updater.async_shutdown()


@pytest.mark.parametrize("logout_fails", [False, True])
async def test_stop_cancels_real_refresh_timer_even_when_logout_fails(hass, logout_fails):
    entry = MockConfigEntry(domain=DOMAIN)
    entry.add_to_hass(hass)
    with patch("custom_components.miwifi.updater.LuciClient"):
        updater = LuciUpdater(
            hass, "192.0.2.1", "test", entry_id=entry.entry_id, config_entry=entry,
        )
    updater.update_method = AsyncMock(return_value={ATTR_STATE: True})
    updater.luci.logout = AsyncMock(
        side_effect=LuciRequestError("logout unavailable") if logout_fails else None,
    )
    entry.mock_state(hass, ConfigEntryState.SETUP_IN_PROGRESS)
    unsubscribe = updater.async_add_listener(lambda: None)
    try:
        await updater.async_config_entry_first_refresh()
        assert updater._unsub_refresh is not None
        await updater.async_stop()
        assert updater._unsub_refresh is None
        updater.luci.logout.assert_awaited_once()
    finally:
        unsubscribe()
        await updater.async_shutdown()
        entry.mock_state(hass, ConfigEntryState.NOT_LOADED)
