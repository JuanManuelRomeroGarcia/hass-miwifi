"""Tests for the miwifi component."""

# pylint: disable=no-member,too-many-statements,protected-access,too-many-lines


from __future__ import annotations

from tests.setup import async_advance_time

import json
import logging
from datetime import timedelta
from unittest.mock import AsyncMock, patch

import pytest
from homeassistant.components.light import DOMAIN as LIGHT_DOMAIN
from homeassistant.components.light import ENTITY_ID_FORMAT as LIGHT_ENTITY_ID_FORMAT
from homeassistant.components.light import SERVICE_TURN_OFF, SERVICE_TURN_ON
from homeassistant.const import ATTR_ENTITY_ID, STATE_OFF, STATE_ON, STATE_UNAVAILABLE
from homeassistant.core import HomeAssistant, State
from homeassistant.helpers import entity_registry as er
from homeassistant.helpers.entity import EntityCategory
from homeassistant.util.dt import utcnow
from pytest_homeassistant_custom_component.common import (
    MockConfigEntry,
    async_fire_time_changed,
    load_fixture,
)

from custom_components.miwifi.const import (
    ATTR_DEVICE_MAC_ADDRESS,
    ATTR_LIGHT_LED_NAME,
    ATTRIBUTION,
    DEFAULT_SCAN_INTERVAL,
    DOMAIN,
    UPDATER,
)
from custom_components.miwifi.exceptions import LuciRequestError
from custom_components.miwifi.helper import generate_entity_id
from custom_components.miwifi.updater import LuciUpdater
from tests.setup import MultipleSideEffect, async_mock_luci_client, async_setup

_LOGGER = logging.getLogger(__name__)


@pytest.fixture(autouse=True)
def auto_enable_custom_integrations(enable_custom_integrations):
    """Enable custom integrations"""

    yield


@pytest.mark.asyncio
async def test_init(hass: HomeAssistant, legacy_clock) -> None:
    """Test init.

    :param hass: HomeAssistant
    """

    with patch(
        "custom_components.miwifi.updater.LuciClient"
    ) as mock_luci_client, patch(
        "custom_components.miwifi.updater.async_dispatcher_send"
    ), patch(
        "custom_components.miwifi.async_start_discovery", return_value=None
    ), patch(
        "custom_components.miwifi.updater.asyncio.sleep", return_value=None
    ):


        await async_mock_luci_client(mock_luci_client)

        setup_data: list = await async_setup(hass)

        config_entry: MockConfigEntry = setup_data[1]

        assert await hass.config_entries.async_setup(config_entry.entry_id)
        await hass.async_block_till_done(wait_background_tasks=True)

        updater: LuciUpdater = hass.data[DOMAIN][config_entry.entry_id][UPDATER]
        registry = er.async_get(hass)

        assert updater.last_update_success

        unique_id: str = _generate_id(ATTR_LIGHT_LED_NAME, updater)

        entry: er.RegistryEntry | None = registry.async_get(unique_id)
        state: State = hass.states.get(unique_id)
        assert state.state == STATE_ON
        assert state.name == f"{updater.data['model']} {ATTR_LIGHT_LED_NAME}"
        assert state.attributes["icon"] == "mdi:led-on"
        assert state.attributes["attribution"] == ATTRIBUTION
        assert entry is not None
        assert entry.entity_category == EntityCategory.CONFIG


@pytest.mark.asyncio
async def test_update_led(hass: HomeAssistant, legacy_clock) -> None:
    """Test update led.

    :param hass: HomeAssistant
    """

    with patch(
        "custom_components.miwifi.updater.LuciClient"
    ) as mock_luci_client, patch(
        "custom_components.miwifi.async_start_discovery", return_value=None
    ), patch(
        "custom_components.miwifi.updater.asyncio.sleep", return_value=None
    ):
        await async_mock_luci_client(mock_luci_client)


        def success() -> dict:
            return json.loads(load_fixture("device_list_data.json"))

        def error() -> None:
            raise LuciRequestError

        mock_luci_client.return_value.device_list = AsyncMock(
            side_effect=MultipleSideEffect(success, error, error)
        )

        def success_led(state: int | None = None) -> dict:
            return json.loads(load_fixture("led_data.json"))

        def error_led(state: int | None = None) -> None:
            raise LuciRequestError

        mock_luci_client.return_value.led = AsyncMock(
            side_effect=success_led
        )

        setup_data: list = await async_setup(hass)

        config_entry: MockConfigEntry = setup_data[1]

        assert await hass.config_entries.async_setup(config_entry.entry_id)
        await hass.async_block_till_done(wait_background_tasks=True)

        updater: LuciUpdater = hass.data[DOMAIN][config_entry.entry_id][UPDATER]

        assert updater.last_update_success

        unique_id: str = _generate_id(ATTR_LIGHT_LED_NAME, updater)

        async_advance_time(hass, legacy_clock, utcnow() + timedelta(seconds=DEFAULT_SCAN_INTERVAL + 1)
        )
        await hass.async_block_till_done(wait_background_tasks=True)

        _prev_calls: int = mock_luci_client.return_value.led.await_count

        await hass.services.async_call(
            LIGHT_DOMAIN,
            SERVICE_TURN_ON,
            {ATTR_ENTITY_ID: [unique_id]},
            blocking=True,
        )

        state = hass.states.get(unique_id)
        assert state.state == STATE_ON
        assert state.attributes["icon"] == "mdi:led-on"
        assert mock_luci_client.return_value.led.await_count == _prev_calls + 1
        mock_luci_client.return_value.led.assert_awaited_with(1)

        await hass.services.async_call(
            LIGHT_DOMAIN,
            SERVICE_TURN_OFF,
            {ATTR_ENTITY_ID: [unique_id]},
            blocking=True,
        )

        state = hass.states.get(unique_id)
        assert state.state == STATE_OFF
        assert state.attributes["icon"] == "mdi:led-off"
        assert mock_luci_client.return_value.led.await_count == _prev_calls + 2
        mock_luci_client.return_value.led.assert_awaited_with(0)

        # A rejected command preserves the last confirmed state.
        mock_luci_client.return_value.led.side_effect = error_led

        await hass.services.async_call(
            LIGHT_DOMAIN,
            SERVICE_TURN_ON,
            {ATTR_ENTITY_ID: [unique_id]},
            blocking=True,
        )

        state = hass.states.get(unique_id)
        assert state.state == STATE_OFF
        assert state.attributes["icon"] == "mdi:led-off"
        assert mock_luci_client.return_value.led.await_count == _prev_calls + 3

        await hass.services.async_call(
            LIGHT_DOMAIN,
            SERVICE_TURN_OFF,
            {ATTR_ENTITY_ID: [unique_id]},
            blocking=True,
        )

        state = hass.states.get(unique_id)
        assert state.state == STATE_OFF
        assert state.attributes["icon"] == "mdi:led-off"
        assert mock_luci_client.return_value.led.await_count == _prev_calls + 4

        mock_luci_client.return_value.led.side_effect = success_led
        await hass.services.async_call(
            LIGHT_DOMAIN,
            SERVICE_TURN_ON,
            {ATTR_ENTITY_ID: [unique_id]},
            blocking=True,
        )
        assert hass.states.get(unique_id).state == STATE_ON
        assert mock_luci_client.return_value.led.await_count == _prev_calls + 5

        # Optional client-list errors leave the router healthy. A later
        # critical status failure still exercises reauthorization and
        # eventual entity unavailability on the repeated failed refresh.
        assert updater.data["state"] is True
        assert not updater._is_reauthorization
        mock_luci_client.return_value.status.side_effect = LuciRequestError
        async_advance_time(
            hass, legacy_clock, utcnow() + timedelta(seconds=DEFAULT_SCAN_INTERVAL + 1)
        )
        await hass.async_block_till_done(wait_background_tasks=True)
        assert updater._is_reauthorization

        async_advance_time(hass, legacy_clock, utcnow() + timedelta(seconds=DEFAULT_SCAN_INTERVAL + 1)
        )
        await hass.async_block_till_done(wait_background_tasks=True)

        state = hass.states.get(unique_id)
        assert state.state == STATE_UNAVAILABLE


def _generate_id(code: str, updater: LuciUpdater) -> str:
    """Generate unique id

    :param code: str
    :param updater: LuciUpdater
    :return str
    """

    return generate_entity_id(
        LIGHT_ENTITY_ID_FORMAT,
        updater.data.get(ATTR_DEVICE_MAC_ADDRESS, updater.ip),
        code,
    )
