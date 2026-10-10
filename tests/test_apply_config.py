"""Validate panel settings through the real Home Assistant service registry (#337)."""

from unittest.mock import AsyncMock, patch

import pytest
import voluptuous as vol

from homeassistant.core import Context
from homeassistant.exceptions import Unauthorized
from pytest_homeassistant_custom_component.common import MockConfigEntry

from custom_components.miwifi import async_setup
from custom_components.miwifi.const import (
    CONF_ENABLE_PANEL,
    CONF_LOG_LEVEL,
    CONF_WAN_SPEED_UNIT,
    DOMAIN,
)


@pytest.fixture
async def settings_service(hass):
    """Register the actual admin service, isolating unrelated startup work."""
    entries = [
        MockConfigEntry(domain=DOMAIN, options={"keep": index})
        for index in range(2)
    ]
    for entry in entries:
        entry.add_to_hass(hass)
    with (
        patch("custom_components.miwifi.logger.async_init_log_handlers", new_callable=AsyncMock),
        patch("custom_components.miwifi.async_register_http_views", new_callable=AsyncMock),
        patch("custom_components.miwifi.websocket_api.async_register_command"),
        patch("custom_components.miwifi.set_global_log_level", new_callable=AsyncMock) as log,
        patch("custom_components.miwifi.set_global_panel_state", new_callable=AsyncMock) as panel,
        patch.object(hass.config_entries, "async_reload", new_callable=AsyncMock) as reload,
    ):
        assert await async_setup(hass, {})
        yield entries, log, panel, reload
    await hass.async_block_till_done()


async def test_panel_payload_updates_all_entries(hass, hass_admin_user, settings_service):
    """The exact frontend payload must pass validation, including false."""
    entries, log, panel, reload = settings_service
    await hass.services.async_call(
        DOMAIN, "apply_config",
        {"panel_active": False, "speed_unit": "Mbps", "log_level": "debug"},
        blocking=True, context=Context(user_id=hass_admin_user.id),
    )
    log.assert_awaited_once_with(hass, "debug")
    panel.assert_awaited_once_with(hass, False)
    for index, entry in enumerate(entries):
        assert entry.options == {
            "keep": index, CONF_ENABLE_PANEL: False,
            CONF_WAN_SPEED_UNIT: "Mbps", CONF_LOG_LEVEL: "debug",
        }
        reload.assert_any_await(entry.entry_id)
    assert reload.await_count == 2


@pytest.mark.parametrize("data", [{}, {"speed_unit": "B/s"}, {"log_level": "warning"}, {"log_level": "info"}, {"panel_active": True}])
async def test_partial_settings(hass, hass_admin_user, settings_service, data):
    entries, log, panel, reload = settings_service
    await hass.services.async_call(
        DOMAIN, "apply_config", data, blocking=True,
        context=Context(user_id=hass_admin_user.id),
    )
    for index, entry in enumerate(entries):
        expected = {"keep": index}
        for field, option in (("speed_unit", CONF_WAN_SPEED_UNIT), ("log_level", CONF_LOG_LEVEL), ("panel_active", CONF_ENABLE_PANEL)):
            if field in data:
                expected[option] = data[field]
        assert entry.options == expected


@pytest.mark.parametrize("data", [
    {"log_level": "error"}, {"speed_unit": "Gbps"},
    {"panel_active": "invalid"}, {"unknown": True},
])
async def test_invalid_settings_do_not_change_entries(hass, hass_admin_user, settings_service, data):
    entries, log, panel, reload = settings_service
    with pytest.raises(vol.Invalid):
        await hass.services.async_call(
            DOMAIN, "apply_config", data, blocking=True,
            context=Context(user_id=hass_admin_user.id),
        )
    assert [dict(entry.options) for entry in entries] == [{"keep": 0}, {"keep": 1}]
    log.assert_not_awaited()
    panel.assert_not_awaited()
    reload.assert_not_awaited()


async def test_settings_still_require_admin(hass, hass_read_only_user, settings_service):
    entries, log, panel, reload = settings_service
    with pytest.raises(Unauthorized):
        await hass.services.async_call(
            DOMAIN, "apply_config", {"log_level": "debug"}, blocking=True,
            context=Context(user_id=hass_read_only_user.id),
        )
    assert [dict(entry.options) for entry in entries] == [{"keep": 0}, {"keep": 1}]
    log.assert_not_awaited()
    panel.assert_not_awaited()
    reload.assert_not_awaited()
