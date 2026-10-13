"""Tests for the miwifi component."""

# pylint: disable=no-member,too-many-statements,protected-access,too-many-lines


from __future__ import annotations

from tests.setup import async_advance_time

import json
import asyncio
import logging
from types import SimpleNamespace
from datetime import timedelta
from unittest.mock import AsyncMock, Mock, patch

import pytest
from homeassistant.components.device_tracker import (
    ENTITY_ID_FORMAT as DEVICE_TRACKER_ENTITY_ID_FORMAT,
)
from homeassistant.components.device_tracker import SourceType
from homeassistant.const import (
    CONF_IP_ADDRESS,
    STATE_HOME,
    STATE_NOT_HOME,
    STATE_UNAVAILABLE,
)
from homeassistant.core import HomeAssistant, State
from homeassistant.helpers import device_registry as dr
from homeassistant.helpers import entity_registry as er
from homeassistant.util.dt import utcnow
from pytest_homeassistant_custom_component.common import (
    MockConfigEntry,
    async_fire_time_changed,
    load_fixture,
)

from custom_components.miwifi.const import (
    ATTRIBUTION,
    DEFAULT_SCAN_INTERVAL,
    DOMAIN,
    MANUFACTURERS,
    UPDATER,
)
from custom_components.miwifi.enum import Connection
from custom_components.miwifi.helper import generate_entity_id
from custom_components.miwifi.updater import LuciUpdater
from tests.setup import MultipleSideEffect, async_mock_luci_client, async_setup, load_leaf_status

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
        "custom_components.miwifi.async_start_discovery", return_value=None
    ):


        await async_mock_luci_client(mock_luci_client)

        setup_data: list = await async_setup(hass)

        config_entry: MockConfigEntry = setup_data[1]

        assert await hass.config_entries.async_setup(config_entry.entry_id)
        await hass.async_block_till_done(wait_background_tasks=True)
        async_advance_time(hass, legacy_clock, utcnow() + timedelta(seconds=DEFAULT_SCAN_INTERVAL + 1)
        )
        await hass.async_block_till_done(wait_background_tasks=True)

        updater: LuciUpdater = hass.data[DOMAIN][config_entry.entry_id][UPDATER]

        assert updater.last_update_success

        state: State = hass.states.get(_generate_id("00:00:00:00:00:01"))
        assert state.state == STATE_HOME
        assert state.name == "Device 1"
        assert state.attributes["icon"] == "mdi:lan-connect"
        assert state.attributes["attribution"] == ATTRIBUTION
        assert state.attributes["source_type"] == SourceType.ROUTER
        assert state.attributes["ip"] == "192.168.31.2"
        assert state.attributes["mac"] == "00:00:00:00:00:01"
        assert state.attributes["scanner"] == DOMAIN
        assert state.attributes["online"] == "8:05:01"
        assert state.attributes["connection"] == Connection.WIFI_2_4.phrase  # type: ignore
        assert state.attributes["router_mac"] == "00:00:00:00:00:00"
        assert state.attributes["signal"] == 100
        assert state.attributes["down_speed"] == "0 B/s"
        assert state.attributes["up_speed"] == "0 B/s"
        assert state.attributes["attribution"] == ATTRIBUTION

        state = hass.states.get(_generate_id("00:00:00:00:00:02"))
        assert state.state == STATE_HOME
        assert state.name == "Device 2"
        assert state.attributes["icon"] == "mdi:lan-connect"
        assert state.attributes["attribution"] == ATTRIBUTION
        assert state.attributes["source_type"] == SourceType.ROUTER
        assert state.attributes["ip"] == "192.168.31.3"
        assert state.attributes["mac"] == "00:00:00:00:00:02"
        assert state.attributes["scanner"] == DOMAIN
        assert state.attributes["online"] == "8:05:01"
        assert state.attributes["connection"] == Connection.WIFI_5_0.phrase  # type: ignore
        assert state.attributes["router_mac"] == "00:00:00:00:00:00"
        assert state.attributes["signal"] == 100
        assert state.attributes["down_speed"] == "0 B/s"
        assert state.attributes["up_speed"] == "0 B/s"
        assert state.attributes["attribution"] == ATTRIBUTION

        state = hass.states.get(_generate_id("00:00:00:00:00:03"))
        assert state.state == STATE_HOME
        assert state.name == "Device 3"
        assert state.attributes["icon"] == "mdi:lan-connect"
        assert state.attributes["attribution"] == ATTRIBUTION
        assert state.attributes["source_type"] == SourceType.ROUTER
        assert state.attributes["ip"] == "192.168.31.4"
        assert state.attributes["mac"] == "00:00:00:00:00:03"
        assert state.attributes["scanner"] == DOMAIN
        assert state.attributes["online"] == "8:05:01"
        assert state.attributes["connection"] == Connection.LAN.phrase  # type: ignore
        assert state.attributes["router_mac"] == "00:00:00:00:00:00"
        assert len(state.attributes["signal"]) == 0
        assert state.attributes["down_speed"] == "0 B/s"
        assert state.attributes["up_speed"] == "0 B/s"
        assert state.attributes["attribution"] == ATTRIBUTION


@pytest.mark.asyncio
async def test_init_with_restore(hass: HomeAssistant, legacy_clock) -> None:
    """Test init.

    :param hass: HomeAssistant
    """

    with patch(
        "custom_components.miwifi.updater.LuciClient"
    ) as mock_luci_client, patch(
        "custom_components.miwifi.async_start_discovery", return_value=None
    ), patch(
        "custom_components.miwifi.helper.Store"
    ) as mock_store:


        await async_mock_luci_client(mock_luci_client)

        mock_store.return_value.async_load = AsyncMock(
            return_value=json.loads(load_fixture("store_data.json"))
        )
        mock_store.return_value.async_save = AsyncMock(return_value=None)

        setup_data: list = await async_setup(hass)

        config_entry: MockConfigEntry = setup_data[1]

        assert await hass.config_entries.async_setup(config_entry.entry_id)
        await hass.async_block_till_done(wait_background_tasks=True)
        async_advance_time(hass, legacy_clock, utcnow() + timedelta(seconds=DEFAULT_SCAN_INTERVAL + 1)
        )
        await hass.async_block_till_done(wait_background_tasks=True)

        updater: LuciUpdater = hass.data[DOMAIN][config_entry.entry_id][UPDATER]

        assert updater.last_update_success

        state: State = hass.states.get(_generate_id("00:00:00:00:00:01"))
        assert state.state == STATE_HOME
        assert state.name == "Device 1"
        assert state.attributes["icon"] == "mdi:lan-connect"
        assert state.attributes["attribution"] == ATTRIBUTION
        assert state.attributes["source_type"] == SourceType.ROUTER
        assert state.attributes["ip"] == "192.168.31.2"
        assert state.attributes["mac"] == "00:00:00:00:00:01"
        assert state.attributes["scanner"] == DOMAIN
        assert state.attributes["online"] == "8:05:01"
        assert state.attributes["connection"] == Connection.WIFI_2_4.phrase  # type: ignore
        assert state.attributes["router_mac"] == "00:00:00:00:00:00"
        assert state.attributes["signal"] == 100
        assert state.attributes["down_speed"] == "0 B/s"
        assert state.attributes["up_speed"] == "0 B/s"
        assert state.attributes["attribution"] == ATTRIBUTION

        state = hass.states.get(_generate_id("00:00:00:00:00:02"))
        assert state.state == STATE_HOME
        assert state.name == "Device 2"
        assert state.attributes["icon"] == "mdi:lan-connect"
        assert state.attributes["attribution"] == ATTRIBUTION
        assert state.attributes["source_type"] == SourceType.ROUTER
        assert state.attributes["ip"] == "192.168.31.3"
        assert state.attributes["mac"] == "00:00:00:00:00:02"
        assert state.attributes["scanner"] == DOMAIN
        assert state.attributes["online"] == "8:05:01"
        assert state.attributes["connection"] == Connection.WIFI_5_0.phrase  # type: ignore
        assert state.attributes["router_mac"] == "00:00:00:00:00:00"
        assert state.attributes["signal"] == 100
        assert state.attributes["down_speed"] == "0 B/s"
        assert state.attributes["up_speed"] == "0 B/s"
        assert state.attributes["attribution"] == ATTRIBUTION

        state = hass.states.get(_generate_id("00:00:00:00:00:03"))
        assert state.state == STATE_HOME
        assert state.name == "Device 3"
        assert state.attributes["icon"] == "mdi:lan-connect"
        assert state.attributes["attribution"] == ATTRIBUTION
        assert state.attributes["source_type"] == SourceType.ROUTER
        assert state.attributes["ip"] == "192.168.31.4"
        assert state.attributes["mac"] == "00:00:00:00:00:03"
        assert state.attributes["scanner"] == DOMAIN
        assert state.attributes["online"] == "8:05:01"
        assert state.attributes["connection"] == Connection.LAN.phrase  # type: ignore
        assert state.attributes["router_mac"] == "00:00:00:00:00:00"
        assert len(state.attributes["signal"]) == 0
        assert state.attributes["down_speed"] == "0 B/s"
        assert state.attributes["up_speed"] == "0 B/s"
        assert state.attributes["attribution"] == ATTRIBUTION

        state = hass.states.get(_generate_id("00:00:00:00:00:05"))
        assert state.state == STATE_NOT_HOME
        assert state.name == "Device 5"
        assert state.attributes["icon"] == "mdi:lan-disconnect"
        assert state.attributes["attribution"] == ATTRIBUTION
        assert state.attributes["source_type"] == SourceType.ROUTER
        assert state.attributes["ip"] == "192.168.31.55"
        assert state.attributes["mac"] == "00:00:00:00:00:05"
        assert state.attributes["scanner"] == DOMAIN
        assert len(state.attributes["online"]) == 0
        assert state.attributes["connection"] == Connection.LAN.phrase  # type: ignore
        assert state.attributes["router_mac"] == "00:00:00:00:00:00"
        assert len(state.attributes["signal"]) == 0
        assert len(state.attributes["down_speed"]) == 0
        assert len(state.attributes["up_speed"]) == 0
        assert state.attributes["attribution"] == ATTRIBUTION


@pytest.mark.asyncio
async def test_init_with_parent(hass: HomeAssistant, legacy_clock) -> None:
    """Test init.

    :param hass: HomeAssistant
    """

    with patch(
        "custom_components.miwifi.updater.LuciClient"
    ) as mock_luci_client_first, patch(
        "custom_components.miwifi.async_start_discovery", return_value=None
    ):


        await async_mock_luci_client(mock_luci_client_first)

        mock_luci_client_first.return_value.device_list = AsyncMock(
            return_value=json.loads(load_fixture("device_list_parent_data.json"))
        )

        setup_data: list = await async_setup(hass)

        config_entry: MockConfigEntry = setup_data[1]

        assert await hass.config_entries.async_setup(config_entry.entry_id)
        await hass.async_block_till_done(wait_background_tasks=True)
        async_advance_time(hass, legacy_clock, utcnow() + timedelta(seconds=DEFAULT_SCAN_INTERVAL + 1)
        )
        await hass.async_block_till_done(wait_background_tasks=True)

        updater_first: LuciUpdater = hass.data[DOMAIN][config_entry.entry_id][UPDATER]

    assert updater_first.last_update_success

    state: State = hass.states.get(_generate_id("00:00:00:00:00:01"))
    assert state.state == STATE_HOME
    assert state.name == "Device 1"
    assert state.attributes["icon"] == "mdi:lan-connect"
    assert state.attributes["attribution"] == ATTRIBUTION
    assert state.attributes["source_type"] == SourceType.ROUTER
    assert state.attributes["ip"] == "192.168.31.2"
    assert state.attributes["mac"] == "00:00:00:00:00:01"
    assert state.attributes["scanner"] == DOMAIN
    assert state.attributes["online"] == "8:05:01"
    assert state.attributes["connection"] == Connection.WIFI_2_4.phrase  # type: ignore
    assert state.attributes["router_mac"] == "00:00:00:00:00:04"
    assert state.attributes["signal"] == 100
    assert state.attributes["down_speed"] == "0 B/s"
    assert state.attributes["up_speed"] == "0 B/s"
    assert state.attributes["attribution"] == ATTRIBUTION

    state = hass.states.get(_generate_id("00:00:00:00:00:02"))
    assert state.state == STATE_HOME
    assert state.name == "Device 2"
    assert state.attributes["icon"] == "mdi:lan-connect"
    assert state.attributes["attribution"] == ATTRIBUTION
    assert state.attributes["source_type"] == SourceType.ROUTER
    assert state.attributes["ip"] == "192.168.31.3"
    assert state.attributes["mac"] == "00:00:00:00:00:02"
    assert state.attributes["scanner"] == DOMAIN
    assert state.attributes["online"] == "8:05:01"
    assert state.attributes["connection"] == Connection.WIFI_5_0.phrase  # type: ignore
    assert state.attributes["router_mac"] == "00:00:00:00:00:00"
    assert state.attributes["signal"] == 100
    assert state.attributes["down_speed"] == "0 B/s"
    assert state.attributes["up_speed"] == "0 B/s"
    assert state.attributes["attribution"] == ATTRIBUTION

    state = hass.states.get(_generate_id("00:00:00:00:00:03"))
    assert state.state == STATE_HOME
    assert state.name == "Device 3"
    assert state.attributes["icon"] == "mdi:lan-connect"
    assert state.attributes["attribution"] == ATTRIBUTION
    assert state.attributes["source_type"] == SourceType.ROUTER
    assert state.attributes["ip"] == "192.168.31.4"
    assert state.attributes["mac"] == "00:00:00:00:00:03"
    assert state.attributes["scanner"] == DOMAIN
    assert state.attributes["online"] == "8:05:01"
    assert state.attributes["connection"] == Connection.LAN.phrase  # type: ignore
    assert state.attributes["router_mac"] == "00:00:00:00:00:00"
    assert len(state.attributes["signal"]) == 0
    assert state.attributes["down_speed"] == "0 B/s"
    assert state.attributes["up_speed"] == "0 B/s"
    assert state.attributes["attribution"] == ATTRIBUTION

    state = hass.states.get(_generate_id("00:00:00:00:00:04"))
    assert state.state == STATE_HOME
    assert state.name == "Device 4 (Repeater)"
    assert state.attributes["icon"] == "mdi:lan-connect"
    assert state.attributes["attribution"] == ATTRIBUTION
    assert state.attributes["source_type"] == SourceType.ROUTER
    assert state.attributes["ip"] == "192.168.31.100"
    assert state.attributes["mac"] == "00:00:00:00:00:04"
    assert state.attributes["scanner"] == DOMAIN
    assert state.attributes["online"] == "8:05:01"
    assert state.attributes["connection"] == Connection.LAN.phrase  # type: ignore
    assert state.attributes["router_mac"] == "00:00:00:00:00:00"
    assert len(state.attributes["signal"]) == 0
    assert state.attributes["down_speed"] == "0 B/s"
    assert state.attributes["up_speed"] == "0 B/s"
    assert state.attributes["attribution"] == ATTRIBUTION

    with patch(
        "custom_components.miwifi.updater.LuciClient"
    ) as mock_luci_client_second, patch(
        "custom_components.miwifi.async_start_discovery", return_value=None
    ):


        await async_mock_luci_client(mock_luci_client_second)

        mock_luci_client_second.return_value.mode = AsyncMock(
            return_value=json.loads(load_fixture("mode_repeater_data.json"))
        )
        mock_luci_client_second.return_value.wifi_connect_devices = AsyncMock(
            return_value=json.loads(
                load_fixture("wifi_connect_devices_parent_data.json")
            )
        )
        mock_luci_client_second.return_value.status = AsyncMock(
            return_value=load_leaf_status()
        )
        mock_luci_client_second.return_value.device_list = AsyncMock(return_value={"code": 0, "list": []})

        setup_data = await async_setup(hass, "192.168.31.100")

        config_entry = setup_data[1]

        assert await hass.config_entries.async_setup(config_entry.entry_id)
        await hass.async_block_till_done(wait_background_tasks=True)
        async_advance_time(hass, legacy_clock, utcnow() + timedelta(seconds=DEFAULT_SCAN_INTERVAL + 1)
        )
        await hass.async_block_till_done(wait_background_tasks=True)
        async_advance_time(hass, legacy_clock, utcnow() + timedelta(seconds=DEFAULT_SCAN_INTERVAL + 1)
        )
        await hass.async_block_till_done(wait_background_tasks=True)

        updater_second: LuciUpdater = hass.data[DOMAIN][config_entry.entry_id][UPDATER]

    assert updater_second.last_update_success

    state = hass.states.get(_generate_id("00:00:00:00:00:01"))
    assert state.state == STATE_HOME
    assert state.name == "Device 1"
    assert state.attributes["icon"] == "mdi:lan-connect"
    assert state.attributes["attribution"] == ATTRIBUTION
    assert state.attributes["source_type"] == SourceType.ROUTER
    assert state.attributes["ip"] == "192.168.31.2"
    assert state.attributes["mac"] == "00:00:00:00:00:01"
    assert state.attributes["scanner"] == DOMAIN
    assert state.attributes["online"] == "8:05:01"
    assert state.attributes["connection"] == Connection.WIFI_2_4.phrase  # type: ignore
    assert state.attributes["router_mac"] == "00:00:00:00:00:04"
    assert state.attributes["signal"] == 10
    assert state.attributes["down_speed"] == "0 B/s"
    assert state.attributes["up_speed"] == "0 B/s"
    assert state.attributes["attribution"] == ATTRIBUTION

    state = hass.states.get(_generate_id("00:00:00:00:00:02"))
    assert state.state == STATE_HOME
    assert state.name == "Device 2"
    assert state.attributes["icon"] == "mdi:lan-connect"
    assert state.attributes["attribution"] == ATTRIBUTION
    assert state.attributes["source_type"] == SourceType.ROUTER
    assert state.attributes["ip"] == "192.168.31.3"
    assert state.attributes["mac"] == "00:00:00:00:00:02"
    assert state.attributes["scanner"] == DOMAIN
    assert state.attributes["online"] == "8:05:01"
    assert state.attributes["connection"] == Connection.WIFI_5_0.phrase  # type: ignore
    assert state.attributes["router_mac"] == "00:00:00:00:00:00"
    assert state.attributes["signal"] == 100
    assert state.attributes["down_speed"] == "0 B/s"
    assert state.attributes["up_speed"] == "0 B/s"
    assert state.attributes["attribution"] == ATTRIBUTION

    state = hass.states.get(_generate_id("00:00:00:00:00:03"))
    assert state.state == STATE_HOME
    assert state.name == "Device 3"
    assert state.attributes["icon"] == "mdi:lan-connect"
    assert state.attributes["attribution"] == ATTRIBUTION
    assert state.attributes["source_type"] == SourceType.ROUTER
    assert state.attributes["ip"] == "192.168.31.4"
    assert state.attributes["mac"] == "00:00:00:00:00:03"
    assert state.attributes["scanner"] == DOMAIN
    assert state.attributes["online"] == "8:05:01"
    assert state.attributes["connection"] == Connection.LAN.phrase  # type: ignore
    assert state.attributes["router_mac"] == "00:00:00:00:00:00"
    assert len(state.attributes["signal"]) == 0
    assert state.attributes["down_speed"] == "0 B/s"
    assert state.attributes["up_speed"] == "0 B/s"
    assert state.attributes["attribution"] == ATTRIBUTION

    state = hass.states.get(_generate_id("00:00:00:00:00:04"))
    assert state.state == STATE_HOME
    assert state.name == "Device 4 (Repeater)"
    assert state.attributes["icon"] == "mdi:lan-connect"
    assert state.attributes["attribution"] == ATTRIBUTION
    assert state.attributes["source_type"] == SourceType.ROUTER
    assert state.attributes["ip"] == "192.168.31.100"
    assert state.attributes["mac"] == "00:00:00:00:00:04"
    assert state.attributes["scanner"] == DOMAIN
    assert state.attributes["online"] == "8:05:01"
    assert state.attributes["connection"] == Connection.LAN.phrase  # type: ignore
    assert state.attributes["router_mac"] == "00:00:00:00:00:00"
    assert len(state.attributes["signal"]) == 0
    assert state.attributes["down_speed"] == "0 B/s"
    assert state.attributes["up_speed"] == "0 B/s"
    assert state.attributes["attribution"] == ATTRIBUTION


@pytest.mark.asyncio
async def test_init_with_parent_revert(hass: HomeAssistant, legacy_clock) -> None:
    """Test init.

    :param hass: HomeAssistant
    """

    with patch(
        "custom_components.miwifi.updater.LuciClient"
    ) as mock_luci_client_first, patch(
        "custom_components.miwifi.async_start_discovery", return_value=None
    ):


        await async_mock_luci_client(mock_luci_client_first)

        def parent() -> dict:
            return json.loads(load_fixture("device_list_parent_data.json"))

        def revert() -> dict:
            return json.loads(load_fixture("device_list_revert_parent_data.json"))

        mock_luci_client_first.return_value.device_list = AsyncMock(
            side_effect=MultipleSideEffect(
                parent, parent, parent, parent, revert, revert
            )
        )

        setup_data: list = await async_setup(hass)

        config_entry: MockConfigEntry = setup_data[1]

        assert await hass.config_entries.async_setup(config_entry.entry_id)
        await hass.async_block_till_done(wait_background_tasks=True)
        async_advance_time(hass, legacy_clock, utcnow() + timedelta(seconds=DEFAULT_SCAN_INTERVAL + 1)
        )
        await hass.async_block_till_done(wait_background_tasks=True)

        updater_first: LuciUpdater = hass.data[DOMAIN][config_entry.entry_id][UPDATER]

    assert updater_first.last_update_success

    state: State = hass.states.get(_generate_id("00:00:00:00:00:01"))
    assert state.state == STATE_HOME
    assert state.name == "Device 1"
    assert state.attributes["icon"] == "mdi:lan-connect"
    assert state.attributes["attribution"] == ATTRIBUTION
    assert state.attributes["source_type"] == SourceType.ROUTER
    assert state.attributes["ip"] == "192.168.31.2"
    assert state.attributes["mac"] == "00:00:00:00:00:01"
    assert state.attributes["scanner"] == DOMAIN
    assert state.attributes["online"] == "8:05:01"
    assert state.attributes["connection"] == Connection.WIFI_2_4.phrase  # type: ignore
    assert state.attributes["router_mac"] == "00:00:00:00:00:04"
    assert state.attributes["signal"] == 100
    assert state.attributes["down_speed"] == "0 B/s"
    assert state.attributes["up_speed"] == "0 B/s"
    assert state.attributes["attribution"] == ATTRIBUTION

    state = hass.states.get(_generate_id("00:00:00:00:00:02"))
    assert state.state == STATE_HOME
    assert state.name == "Device 2"
    assert state.attributes["icon"] == "mdi:lan-connect"
    assert state.attributes["attribution"] == ATTRIBUTION
    assert state.attributes["source_type"] == SourceType.ROUTER
    assert state.attributes["ip"] == "192.168.31.3"
    assert state.attributes["mac"] == "00:00:00:00:00:02"
    assert state.attributes["scanner"] == DOMAIN
    assert state.attributes["online"] == "8:05:01"
    assert state.attributes["connection"] == Connection.WIFI_5_0.phrase  # type: ignore
    assert state.attributes["router_mac"] == "00:00:00:00:00:00"
    assert state.attributes["signal"] == 100
    assert state.attributes["down_speed"] == "0 B/s"
    assert state.attributes["up_speed"] == "0 B/s"
    assert state.attributes["attribution"] == ATTRIBUTION

    state = hass.states.get(_generate_id("00:00:00:00:00:03"))
    assert state.state == STATE_HOME
    assert state.name == "Device 3"
    assert state.attributes["icon"] == "mdi:lan-connect"
    assert state.attributes["attribution"] == ATTRIBUTION
    assert state.attributes["source_type"] == SourceType.ROUTER
    assert state.attributes["ip"] == "192.168.31.4"
    assert state.attributes["mac"] == "00:00:00:00:00:03"
    assert state.attributes["scanner"] == DOMAIN
    assert state.attributes["online"] == "8:05:01"
    assert state.attributes["connection"] == Connection.LAN.phrase  # type: ignore
    assert state.attributes["router_mac"] == "00:00:00:00:00:00"
    assert len(state.attributes["signal"]) == 0
    assert state.attributes["down_speed"] == "0 B/s"
    assert state.attributes["up_speed"] == "0 B/s"
    assert state.attributes["attribution"] == ATTRIBUTION

    state = hass.states.get(_generate_id("00:00:00:00:00:04"))
    assert state.state == STATE_HOME
    assert state.name == "Device 4 (Repeater)"
    assert state.attributes["icon"] == "mdi:lan-connect"
    assert state.attributes["attribution"] == ATTRIBUTION
    assert state.attributes["source_type"] == SourceType.ROUTER
    assert state.attributes["ip"] == "192.168.31.100"
    assert state.attributes["mac"] == "00:00:00:00:00:04"
    assert state.attributes["scanner"] == DOMAIN
    assert state.attributes["online"] == "8:05:01"
    assert state.attributes["connection"] == Connection.LAN.phrase  # type: ignore
    assert state.attributes["router_mac"] == "00:00:00:00:00:00"
    assert len(state.attributes["signal"]) == 0
    assert state.attributes["down_speed"] == "0 B/s"
    assert state.attributes["up_speed"] == "0 B/s"
    assert state.attributes["attribution"] == ATTRIBUTION

    with patch(
        "custom_components.miwifi.updater.LuciClient"
    ) as mock_luci_client_second, patch(
        "custom_components.miwifi.async_start_discovery", return_value=None
    ):


        await async_mock_luci_client(mock_luci_client_second)

        mock_luci_client_second.return_value.mode = AsyncMock(
            return_value=json.loads(load_fixture("mode_repeater_data.json"))
        )
        mock_luci_client_second.return_value.wifi_connect_devices = AsyncMock(
            return_value=json.loads(
                load_fixture("wifi_connect_devices_parent_data.json")
            )
        )
        mock_luci_client_second.return_value.status = AsyncMock(
            return_value=load_leaf_status()
        )
        mock_luci_client_second.return_value.device_list = AsyncMock(return_value={"code": 0, "list": []})

        setup_data = await async_setup(hass, "192.168.31.100")

        config_entry = setup_data[1]

        assert await hass.config_entries.async_setup(config_entry.entry_id)
        await hass.async_block_till_done(wait_background_tasks=True)
        async_advance_time(hass, legacy_clock, utcnow() + timedelta(seconds=DEFAULT_SCAN_INTERVAL + 1)
        )
        await hass.async_block_till_done(wait_background_tasks=True)
        async_advance_time(hass, legacy_clock, utcnow() + timedelta(seconds=DEFAULT_SCAN_INTERVAL + 1)
        )
        await hass.async_block_till_done(wait_background_tasks=True)

        updater_second: LuciUpdater = hass.data[DOMAIN][config_entry.entry_id][UPDATER]

    assert updater_second.last_update_success

    state = hass.states.get(_generate_id("00:00:00:00:00:01"))
    assert state.state == STATE_HOME
    assert state.name == "Device 1"
    assert state.attributes["icon"] == "mdi:lan-connect"
    assert state.attributes["attribution"] == ATTRIBUTION
    assert state.attributes["source_type"] == SourceType.ROUTER
    assert state.attributes["ip"] == "192.168.31.2"
    assert state.attributes["mac"] == "00:00:00:00:00:01"
    assert state.attributes["scanner"] == DOMAIN
    assert state.attributes["online"] == "8:05:01"
    assert state.attributes["connection"] == Connection.WIFI_2_4.phrase  # type: ignore
    assert state.attributes["router_mac"] == "00:00:00:00:00:04"
    assert state.attributes["signal"] == 10
    assert state.attributes["down_speed"] == "0 B/s"
    assert state.attributes["up_speed"] == "0 B/s"
    assert state.attributes["attribution"] == ATTRIBUTION

    state = hass.states.get(_generate_id("00:00:00:00:00:02"))
    assert state.state == STATE_HOME
    assert state.name == "Device 2"
    assert state.attributes["icon"] == "mdi:lan-connect"
    assert state.attributes["attribution"] == ATTRIBUTION
    assert state.attributes["source_type"] == SourceType.ROUTER
    assert state.attributes["ip"] == "192.168.31.3"
    assert state.attributes["mac"] == "00:00:00:00:00:02"
    assert state.attributes["scanner"] == DOMAIN
    assert state.attributes["online"] == "8:05:01"
    assert state.attributes["connection"] == Connection.WIFI_5_0.phrase  # type: ignore
    assert state.attributes["router_mac"] == "00:00:00:00:00:00"
    assert state.attributes["signal"] == 100
    assert state.attributes["down_speed"] == "0 B/s"
    assert state.attributes["up_speed"] == "0 B/s"
    assert state.attributes["attribution"] == ATTRIBUTION

    state = hass.states.get(_generate_id("00:00:00:00:00:03"))
    assert state.state == STATE_HOME
    assert state.name == "Device 3"
    assert state.attributes["icon"] == "mdi:lan-connect"
    assert state.attributes["attribution"] == ATTRIBUTION
    assert state.attributes["source_type"] == SourceType.ROUTER
    assert state.attributes["ip"] == "192.168.31.4"
    assert state.attributes["mac"] == "00:00:00:00:00:03"
    assert state.attributes["scanner"] == DOMAIN
    assert state.attributes["online"] == "8:05:01"
    assert state.attributes["connection"] == Connection.LAN.phrase  # type: ignore
    assert state.attributes["router_mac"] == "00:00:00:00:00:00"
    assert len(state.attributes["signal"]) == 0
    assert state.attributes["down_speed"] == "0 B/s"
    assert state.attributes["up_speed"] == "0 B/s"
    assert state.attributes["attribution"] == ATTRIBUTION

    state = hass.states.get(_generate_id("00:00:00:00:00:04"))
    assert state.state == STATE_HOME
    assert state.name == "Device 4 (Repeater)"
    assert state.attributes["icon"] == "mdi:lan-connect"
    assert state.attributes["attribution"] == ATTRIBUTION
    assert state.attributes["source_type"] == SourceType.ROUTER
    assert state.attributes["ip"] == "192.168.31.100"
    assert state.attributes["mac"] == "00:00:00:00:00:04"
    assert state.attributes["scanner"] == DOMAIN
    assert state.attributes["online"] == "8:05:01"
    assert state.attributes["connection"] == Connection.LAN.phrase  # type: ignore
    assert state.attributes["router_mac"] == "00:00:00:00:00:00"
    assert len(state.attributes["signal"]) == 0
    assert state.attributes["down_speed"] == "0 B/s"
    assert state.attributes["up_speed"] == "0 B/s"
    assert state.attributes["attribution"] == ATTRIBUTION

    async_advance_time(hass, legacy_clock, utcnow() + timedelta(seconds=DEFAULT_SCAN_INTERVAL + 1)
    )
    await hass.async_block_till_done(wait_background_tasks=True)

    state = hass.states.get(_generate_id("00:00:00:00:00:01"))
    assert state.state == STATE_HOME
    assert state.name == "Device 1"
    assert state.attributes["icon"] == "mdi:lan-connect"
    assert state.attributes["attribution"] == ATTRIBUTION
    assert state.attributes["source_type"] == SourceType.ROUTER
    assert state.attributes["ip"] == "192.168.31.2"
    assert state.attributes["mac"] == "00:00:00:00:00:01"
    assert state.attributes["scanner"] == DOMAIN
    assert state.attributes["online"] == "8:05:01"
    assert state.attributes["connection"] == Connection.WIFI_2_4.phrase  # type: ignore
    assert state.attributes["router_mac"] == "00:00:00:00:00:00"
    assert state.attributes["signal"] == 100
    assert state.attributes["down_speed"] == "0 B/s"
    assert state.attributes["up_speed"] == "0 B/s"
    assert state.attributes["attribution"] == ATTRIBUTION

    state = hass.states.get(_generate_id("00:00:00:00:00:02"))
    assert state.state == STATE_HOME
    assert state.name == "Device 2"
    assert state.attributes["icon"] == "mdi:lan-connect"
    assert state.attributes["attribution"] == ATTRIBUTION
    assert state.attributes["source_type"] == SourceType.ROUTER
    assert state.attributes["ip"] == "192.168.31.3"
    assert state.attributes["mac"] == "00:00:00:00:00:02"
    assert state.attributes["scanner"] == DOMAIN
    assert state.attributes["online"] == "8:05:01"
    assert state.attributes["connection"] == Connection.WIFI_5_0.phrase  # type: ignore
    assert state.attributes["router_mac"] == "00:00:00:00:00:00"
    assert state.attributes["signal"] == 100
    assert state.attributes["down_speed"] == "0 B/s"
    assert state.attributes["up_speed"] == "0 B/s"
    assert state.attributes["attribution"] == ATTRIBUTION

    state = hass.states.get(_generate_id("00:00:00:00:00:03"))
    assert state.state == STATE_HOME
    assert state.name == "Device 3"
    assert state.attributes["icon"] == "mdi:lan-connect"
    assert state.attributes["attribution"] == ATTRIBUTION
    assert state.attributes["source_type"] == SourceType.ROUTER
    assert state.attributes["ip"] == "192.168.31.4"
    assert state.attributes["mac"] == "00:00:00:00:00:03"
    assert state.attributes["scanner"] == DOMAIN
    assert state.attributes["online"] == "8:05:01"
    assert state.attributes["connection"] == Connection.LAN.phrase  # type: ignore
    assert state.attributes["router_mac"] == "00:00:00:00:00:00"
    assert len(state.attributes["signal"]) == 0
    assert state.attributes["down_speed"] == "0 B/s"
    assert state.attributes["up_speed"] == "0 B/s"
    assert state.attributes["attribution"] == ATTRIBUTION

    state = hass.states.get(_generate_id("00:00:00:00:00:04"))
    assert state.state == STATE_HOME
    assert state.name == "Device 4 (Repeater)"
    assert state.attributes["icon"] == "mdi:lan-connect"
    assert state.attributes["attribution"] == ATTRIBUTION
    assert state.attributes["source_type"] == SourceType.ROUTER
    assert state.attributes["ip"] == "192.168.31.100"
    assert state.attributes["mac"] == "00:00:00:00:00:04"
    assert state.attributes["scanner"] == DOMAIN
    assert state.attributes["online"] == "8:05:01"
    assert state.attributes["connection"] == Connection.LAN.phrase  # type: ignore
    assert state.attributes["router_mac"] == "00:00:00:00:00:00"
    assert len(state.attributes["signal"]) == 0
    assert state.attributes["down_speed"] == "0 B/s"
    assert state.attributes["up_speed"] == "0 B/s"
    assert state.attributes["attribution"] == ATTRIBUTION


@pytest.mark.asyncio
async def test_init_in_force_mode(hass: HomeAssistant, legacy_clock) -> None:
    """Test init.

    :param hass: HomeAssistant
    """

    with patch(
        "custom_components.miwifi.updater.LuciClient"
    ) as mock_luci_client, patch(
        "custom_components.miwifi.async_start_discovery", return_value=None
    ):


        await async_mock_luci_client(mock_luci_client)

        mock_luci_client.return_value.mode = AsyncMock(
            return_value=json.loads(load_fixture("mode_repeater_data.json"))
        )

        setup_data: list = await async_setup(hass, is_force=True)

        config_entry: MockConfigEntry = setup_data[1]

        assert await hass.config_entries.async_setup(config_entry.entry_id)
        await hass.async_block_till_done(wait_background_tasks=True)
        async_advance_time(hass, legacy_clock, utcnow() + timedelta(seconds=DEFAULT_SCAN_INTERVAL + 1)
        )
        await hass.async_block_till_done(wait_background_tasks=True)

        updater: LuciUpdater = hass.data[DOMAIN][config_entry.entry_id][UPDATER]

        assert updater.last_update_success

        state: State = hass.states.get(_generate_id("00:00:00:00:00:01"))
        assert state.state == STATE_HOME
        assert state.name == "00:00:00:00:00:01"
        assert state.attributes["icon"] == "mdi:lan-connect"
        assert state.attributes["attribution"] == ATTRIBUTION
        assert state.attributes["source_type"] == SourceType.ROUTER
        assert state.attributes["ip"] is None
        assert state.attributes["mac"] == "00:00:00:00:00:01"
        assert state.attributes["scanner"] == DOMAIN
        assert state.attributes["online"] == ""
        assert state.attributes["connection"] == Connection.WIFI_2_4.phrase  # type: ignore
        assert state.attributes["router_mac"] == "00:00:00:00:00:00"
        assert state.attributes["signal"] == 100
        assert state.attributes["down_speed"] == ""
        assert state.attributes["up_speed"] == ""
        assert state.attributes["attribution"] == ATTRIBUTION

        state = hass.states.get(_generate_id("00:00:00:00:00:02"))
        assert state.state == STATE_HOME
        assert state.name == "00:00:00:00:00:02"
        assert state.attributes["icon"] == "mdi:lan-connect"
        assert state.attributes["attribution"] == ATTRIBUTION
        assert state.attributes["source_type"] == SourceType.ROUTER
        assert state.attributes["ip"] is None
        assert state.attributes["mac"] == "00:00:00:00:00:02"
        assert state.attributes["scanner"] == DOMAIN
        assert state.attributes["online"] == ""
        assert state.attributes["connection"] == Connection.WIFI_5_0.phrase  # type: ignore
        assert state.attributes["router_mac"] == "00:00:00:00:00:00"
        assert state.attributes["signal"] == 100
        assert state.attributes["down_speed"] == ""
        assert state.attributes["up_speed"] == ""
        assert state.attributes["attribution"] == ATTRIBUTION

        state = hass.states.get(_generate_id("00:00:00:00:00:03"))
        assert state is None


@pytest.mark.asyncio
async def test_init_with_force_and_parent(hass: HomeAssistant, legacy_clock) -> None:
    """Test init.

    :param hass: HomeAssistant
    """

    with patch(
        "custom_components.miwifi.updater.LuciClient"
    ) as mock_luci_client_first, patch(
        "custom_components.miwifi.async_start_discovery", return_value=None
    ):


        await async_mock_luci_client(mock_luci_client_first)

        mock_luci_client_first.return_value.device_list = AsyncMock(
            return_value=json.loads(load_fixture("device_list_parent_data.json"))
        )

        setup_data: list = await async_setup(hass)

        config_entry: MockConfigEntry = setup_data[1]

        assert await hass.config_entries.async_setup(config_entry.entry_id)
        await hass.async_block_till_done(wait_background_tasks=True)
        async_advance_time(hass, legacy_clock, utcnow() + timedelta(seconds=DEFAULT_SCAN_INTERVAL + 1)
        )
        await hass.async_block_till_done(wait_background_tasks=True)

        updater_first: LuciUpdater = hass.data[DOMAIN][config_entry.entry_id][UPDATER]

    assert updater_first.last_update_success

    state: State = hass.states.get(_generate_id("00:00:00:00:00:01"))
    assert state.state == STATE_HOME
    assert state.name == "Device 1"
    assert state.attributes["icon"] == "mdi:lan-connect"
    assert state.attributes["attribution"] == ATTRIBUTION
    assert state.attributes["source_type"] == SourceType.ROUTER
    assert state.attributes["ip"] == "192.168.31.2"
    assert state.attributes["mac"] == "00:00:00:00:00:01"
    assert state.attributes["scanner"] == DOMAIN
    assert state.attributes["online"] == "8:05:01"
    assert state.attributes["connection"] == Connection.WIFI_2_4.phrase  # type: ignore
    assert state.attributes["router_mac"] == "00:00:00:00:00:04"
    assert state.attributes["signal"] == 100
    assert state.attributes["down_speed"] == "0 B/s"
    assert state.attributes["up_speed"] == "0 B/s"
    assert state.attributes["attribution"] == ATTRIBUTION

    state = hass.states.get(_generate_id("00:00:00:00:00:02"))
    assert state.state == STATE_HOME
    assert state.name == "Device 2"
    assert state.attributes["icon"] == "mdi:lan-connect"
    assert state.attributes["attribution"] == ATTRIBUTION
    assert state.attributes["source_type"] == SourceType.ROUTER
    assert state.attributes["ip"] == "192.168.31.3"
    assert state.attributes["mac"] == "00:00:00:00:00:02"
    assert state.attributes["scanner"] == DOMAIN
    assert state.attributes["online"] == "8:05:01"
    assert state.attributes["connection"] == Connection.WIFI_5_0.phrase  # type: ignore
    assert state.attributes["router_mac"] == "00:00:00:00:00:00"
    assert state.attributes["signal"] == 100
    assert state.attributes["down_speed"] == "0 B/s"
    assert state.attributes["up_speed"] == "0 B/s"
    assert state.attributes["attribution"] == ATTRIBUTION

    state = hass.states.get(_generate_id("00:00:00:00:00:03"))
    assert state.state == STATE_HOME
    assert state.name == "Device 3"
    assert state.attributes["icon"] == "mdi:lan-connect"
    assert state.attributes["attribution"] == ATTRIBUTION
    assert state.attributes["source_type"] == SourceType.ROUTER
    assert state.attributes["ip"] == "192.168.31.4"
    assert state.attributes["mac"] == "00:00:00:00:00:03"
    assert state.attributes["scanner"] == DOMAIN
    assert state.attributes["online"] == "8:05:01"
    assert state.attributes["connection"] == Connection.LAN.phrase  # type: ignore
    assert state.attributes["router_mac"] == "00:00:00:00:00:00"
    assert len(state.attributes["signal"]) == 0
    assert state.attributes["down_speed"] == "0 B/s"
    assert state.attributes["up_speed"] == "0 B/s"
    assert state.attributes["attribution"] == ATTRIBUTION

    state = hass.states.get(_generate_id("00:00:00:00:00:04"))
    assert state.state == STATE_HOME
    assert state.name == "Device 4 (Repeater)"
    assert state.attributes["icon"] == "mdi:lan-connect"
    assert state.attributes["attribution"] == ATTRIBUTION
    assert state.attributes["source_type"] == SourceType.ROUTER
    assert state.attributes["ip"] == "192.168.31.100"
    assert state.attributes["mac"] == "00:00:00:00:00:04"
    assert state.attributes["scanner"] == DOMAIN
    assert state.attributes["online"] == "8:05:01"
    assert state.attributes["connection"] == Connection.LAN.phrase  # type: ignore
    assert state.attributes["router_mac"] == "00:00:00:00:00:00"
    assert len(state.attributes["signal"]) == 0
    assert state.attributes["down_speed"] == "0 B/s"
    assert state.attributes["up_speed"] == "0 B/s"
    assert state.attributes["attribution"] == ATTRIBUTION

    with patch(
        "custom_components.miwifi.updater.LuciClient"
    ) as mock_luci_client_second, patch(
        "custom_components.miwifi.async_start_discovery", return_value=None
    ):


        await async_mock_luci_client(mock_luci_client_second)

        mock_luci_client_second.return_value.mode = AsyncMock(
            return_value=json.loads(load_fixture("mode_repeater_data.json"))
        )
        mock_luci_client_second.return_value.wifi_connect_devices = AsyncMock(
            return_value=json.loads(
                load_fixture("wifi_connect_devices_parent_data.json")
            )
        )
        mock_luci_client_second.return_value.status = AsyncMock(
            return_value=load_leaf_status()
        )
        mock_luci_client_second.return_value.device_list = AsyncMock(return_value={"code": 0, "list": []})

        setup_data = await async_setup(hass, "192.168.31.100", is_force=True)

        config_entry = setup_data[1]

        assert await hass.config_entries.async_setup(config_entry.entry_id)
        await hass.async_block_till_done(wait_background_tasks=True)
        async_advance_time(hass, legacy_clock, utcnow() + timedelta(seconds=DEFAULT_SCAN_INTERVAL + 1)
        )
        await hass.async_block_till_done(wait_background_tasks=True)
        async_advance_time(hass, legacy_clock, utcnow() + timedelta(seconds=DEFAULT_SCAN_INTERVAL + 1)
        )
        await hass.async_block_till_done(wait_background_tasks=True)

        updater_second: LuciUpdater = hass.data[DOMAIN][config_entry.entry_id][UPDATER]

    assert updater_second.last_update_success

    state = hass.states.get(_generate_id("00:00:00:00:00:01"))
    assert state.state == STATE_HOME
    assert state.name == "Device 1"
    assert state.attributes["icon"] == "mdi:lan-connect"
    assert state.attributes["attribution"] == ATTRIBUTION
    assert state.attributes["source_type"] == SourceType.ROUTER
    assert state.attributes["ip"] == "192.168.31.2"
    assert state.attributes["mac"] == "00:00:00:00:00:01"
    assert state.attributes["scanner"] == DOMAIN
    assert state.attributes["online"] == "8:05:01"
    assert state.attributes["connection"] == Connection.WIFI_2_4.phrase  # type: ignore
    assert state.attributes["router_mac"] == "00:00:00:00:00:04"
    assert state.attributes["signal"] == 10
    assert state.attributes["down_speed"] == "0 B/s"
    assert state.attributes["up_speed"] == "0 B/s"
    assert state.attributes["attribution"] == ATTRIBUTION

    state = hass.states.get(_generate_id("00:00:00:00:00:02"))
    assert state.state == STATE_HOME
    assert state.name == "Device 2"
    assert state.attributes["icon"] == "mdi:lan-connect"
    assert state.attributes["attribution"] == ATTRIBUTION
    assert state.attributes["source_type"] == SourceType.ROUTER
    assert state.attributes["ip"] == "192.168.31.3"
    assert state.attributes["mac"] == "00:00:00:00:00:02"
    assert state.attributes["scanner"] == DOMAIN
    assert state.attributes["online"] == "8:05:01"
    assert state.attributes["connection"] == Connection.WIFI_5_0.phrase  # type: ignore
    assert state.attributes["router_mac"] == "00:00:00:00:00:00"
    assert state.attributes["signal"] == 100
    assert state.attributes["down_speed"] == "0 B/s"
    assert state.attributes["up_speed"] == "0 B/s"
    assert state.attributes["attribution"] == ATTRIBUTION

    state = hass.states.get(_generate_id("00:00:00:00:00:03"))
    assert state.state == STATE_HOME
    assert state.name == "Device 3"
    assert state.attributes["icon"] == "mdi:lan-connect"
    assert state.attributes["attribution"] == ATTRIBUTION
    assert state.attributes["source_type"] == SourceType.ROUTER
    assert state.attributes["ip"] == "192.168.31.4"
    assert state.attributes["mac"] == "00:00:00:00:00:03"
    assert state.attributes["scanner"] == DOMAIN
    assert state.attributes["online"] == "8:05:01"
    assert state.attributes["connection"] == Connection.LAN.phrase  # type: ignore
    assert state.attributes["router_mac"] == "00:00:00:00:00:00"
    assert len(state.attributes["signal"]) == 0
    assert state.attributes["down_speed"] == "0 B/s"
    assert state.attributes["up_speed"] == "0 B/s"
    assert state.attributes["attribution"] == ATTRIBUTION

    state = hass.states.get(_generate_id("00:00:00:00:00:04"))
    assert state.state == STATE_HOME
    assert state.name == "Device 4 (Repeater)"
    assert state.attributes["icon"] == "mdi:lan-connect"
    assert state.attributes["attribution"] == ATTRIBUTION
    assert state.attributes["source_type"] == SourceType.ROUTER
    assert state.attributes["ip"] == "192.168.31.100"
    assert state.attributes["mac"] == "00:00:00:00:00:04"
    assert state.attributes["scanner"] == DOMAIN
    assert state.attributes["online"] == "8:05:01"
    assert state.attributes["connection"] == Connection.LAN.phrase  # type: ignore
    assert state.attributes["router_mac"] == "00:00:00:00:00:00"
    assert len(state.attributes["signal"]) == 0
    assert state.attributes["down_speed"] == "0 B/s"
    assert state.attributes["up_speed"] == "0 B/s"
    assert state.attributes["attribution"] == ATTRIBUTION


@pytest.mark.asyncio
async def test_init_with_restore_without_connection(hass: HomeAssistant, legacy_clock) -> None:
    """Test init.

    :param hass: HomeAssistant
    """

    with patch(
        "custom_components.miwifi.updater.LuciClient"
    ) as mock_luci_client, patch(
        "custom_components.miwifi.async_start_discovery", return_value=None
    ), patch(
        "custom_components.miwifi.helper.Store"
    ) as mock_store:


        await async_mock_luci_client(mock_luci_client)

        mock_store.return_value.async_load = AsyncMock(
            return_value=json.loads(
                load_fixture("store_incorrect_connection_data.json")
            )
        )
        mock_store.return_value.async_save = AsyncMock(return_value=None)

        setup_data: list = await async_setup(hass)

        config_entry: MockConfigEntry = setup_data[1]

        assert await hass.config_entries.async_setup(config_entry.entry_id)
        await hass.async_block_till_done(wait_background_tasks=True)
        async_advance_time(hass, legacy_clock, utcnow() + timedelta(seconds=DEFAULT_SCAN_INTERVAL + 1)
        )
        await hass.async_block_till_done(wait_background_tasks=True)

        updater: LuciUpdater = hass.data[DOMAIN][config_entry.entry_id][UPDATER]

        assert updater.last_update_success

        state: State = hass.states.get(_generate_id("00:00:00:00:00:01"))
        assert state.state == STATE_HOME
        assert state.name == "Device 1"
        assert state.attributes["icon"] == "mdi:lan-connect"
        assert state.attributes["attribution"] == ATTRIBUTION
        assert state.attributes["source_type"] == SourceType.ROUTER
        assert state.attributes["ip"] == "192.168.31.2"
        assert state.attributes["mac"] == "00:00:00:00:00:01"
        assert state.attributes["scanner"] == DOMAIN
        assert state.attributes["online"] == "8:05:01"
        assert state.attributes["connection"] == Connection.WIFI_2_4.phrase  # type: ignore
        assert state.attributes["router_mac"] == "00:00:00:00:00:00"
        assert state.attributes["signal"] == 100
        assert state.attributes["down_speed"] == "0 B/s"
        assert state.attributes["up_speed"] == "0 B/s"
        assert state.attributes["attribution"] == ATTRIBUTION

        state = hass.states.get(_generate_id("00:00:00:00:00:02"))
        assert state.state == STATE_HOME
        assert state.name == "Device 2"
        assert state.attributes["icon"] == "mdi:lan-connect"
        assert state.attributes["attribution"] == ATTRIBUTION
        assert state.attributes["source_type"] == SourceType.ROUTER
        assert state.attributes["ip"] == "192.168.31.3"
        assert state.attributes["mac"] == "00:00:00:00:00:02"
        assert state.attributes["scanner"] == DOMAIN
        assert state.attributes["online"] == "8:05:01"
        assert state.attributes["connection"] == Connection.WIFI_5_0.phrase  # type: ignore
        assert state.attributes["router_mac"] == "00:00:00:00:00:00"
        assert state.attributes["signal"] == 100
        assert state.attributes["down_speed"] == "0 B/s"
        assert state.attributes["up_speed"] == "0 B/s"
        assert state.attributes["attribution"] == ATTRIBUTION

        state = hass.states.get(_generate_id("00:00:00:00:00:03"))
        assert state.state == STATE_HOME
        assert state.name == "Device 3"
        assert state.attributes["icon"] == "mdi:lan-connect"
        assert state.attributes["attribution"] == ATTRIBUTION
        assert state.attributes["source_type"] == SourceType.ROUTER
        assert state.attributes["ip"] == "192.168.31.4"
        assert state.attributes["mac"] == "00:00:00:00:00:03"
        assert state.attributes["scanner"] == DOMAIN
        assert state.attributes["online"] == "8:05:01"
        assert state.attributes["connection"] == Connection.LAN.phrase  # type: ignore
        assert state.attributes["router_mac"] == "00:00:00:00:00:00"
        assert len(state.attributes["signal"]) == 0
        assert state.attributes["down_speed"] == "0 B/s"
        assert state.attributes["up_speed"] == "0 B/s"
        assert state.attributes["attribution"] == ATTRIBUTION

        state = hass.states.get(_generate_id("00:00:00:00:00:05"))
        assert state.state == STATE_NOT_HOME
        assert state.name == "Device 5"
        assert state.attributes["icon"] == "mdi:lan-disconnect"
        assert state.attributes["attribution"] == ATTRIBUTION
        assert state.attributes["source_type"] == SourceType.ROUTER
        assert state.attributes["ip"] == "192.168.31.55"
        assert state.attributes["mac"] == "00:00:00:00:00:05"
        assert state.attributes["scanner"] == DOMAIN
        assert len(state.attributes["online"]) == 0
        assert state.attributes["connection"] is None
        assert state.attributes["router_mac"] == "00:00:00:00:00:00"
        assert len(state.attributes["signal"]) == 0
        assert len(state.attributes["down_speed"]) == 0
        assert len(state.attributes["up_speed"]) == 0
        assert state.attributes["attribution"] == ATTRIBUTION


@pytest.mark.asyncio
async def test_init_with_optional_parent(hass: HomeAssistant, legacy_clock) -> None:
    """Route through a node's known hardware/backhaul aliases without a node tracker."""
    with patch("custom_components.miwifi.updater.LuciClient") as leaf_client, patch(
        "custom_components.miwifi.async_start_discovery", return_value=None
    ):
        await async_mock_luci_client(leaf_client)
        leaf_client.return_value.mode = AsyncMock(
            return_value=json.loads(load_fixture("mode_repeater_data.json"))
        )
        leaf_client.return_value.status = AsyncMock(
            return_value=json.loads(load_fixture("status_parent_data.json"))
        )
        leaf_client.return_value.device_list = AsyncMock(return_value={"code": 0, "list": []})
        leaf_client.return_value.wifi_connect_devices = AsyncMock(
            return_value=json.loads(load_fixture("wifi_connect_devices_parent_data.json"))
        )
        _, leaf_entry = await async_setup(hass, "192.168.31.100")
        assert await hass.config_entries.async_setup(leaf_entry.entry_id)
        await hass.async_block_till_done(wait_background_tasks=True)

    devices = dr.async_get(hass)
    node = devices.async_get_device_by_connection(
        (dr.CONNECTION_NETWORK_MAC, "01:00:00:00:00:00"), leaf_entry.entry_id
    )
    assert node is not None
    # This node is already known under both MACs. The main census identifies
    # its backhaul by isap, while its own status reports the hardware MAC.
    devices.async_update_device(
        node.id, connections=node.connections | {(dr.CONNECTION_NETWORK_MAC, "00:00:00:00:00:04")}
    )

    def parent_census():
        response = json.loads(load_fixture("device_list_parent_data.json"))
        for row in response["list"]:
            if row["mac"] == "00:00:00:00:00:04":
                row["isap"] = 8
        return response

    with patch("custom_components.miwifi.updater.LuciClient") as main_client, patch(
        "custom_components.miwifi.async_start_discovery", return_value=None
    ):
        await async_mock_luci_client(main_client)
        main_client.return_value.device_list = AsyncMock(side_effect=parent_census)
        _, main_entry = await async_setup(hass)
        assert await hass.config_entries.async_setup(main_entry.entry_id)
        await hass.async_block_till_done(wait_background_tasks=True)
        async_advance_time(hass, legacy_clock, utcnow() + timedelta(seconds=DEFAULT_SCAN_INTERVAL + 1))
        await hass.async_block_till_done(wait_background_tasks=True)

    client_id = _generate_id("00:00:00:00:00:01")
    client = hass.states.get(client_id)
    assert client.state == STATE_HOME
    assert client.attributes["router_mac"] == "00:00:00:00:00:04"
    assert client.attributes["ip"] == "192.168.31.2"
    registry = er.async_get(hass)
    row = registry.async_get(client_id)
    assert row.config_entry_id == leaf_entry.entry_id
    assert devices.async_get(row.device_id).via_device_id == node.id
    assert hass.states.get(_generate_id("00:00:00:00:00:04")) is None

    for mac in ("00:00:00:00:00:02", "00:00:00:00:00:03"):
        state = hass.states.get(_generate_id(mac))
        assert state.state == STATE_HOME
        assert state.attributes["router_mac"] == "00:00:00:00:00:00"
        assert registry.async_get(_generate_id(mac)).config_entry_id == main_entry.entry_id

    node = devices.async_get(node.id)
    assert (dr.CONNECTION_NETWORK_MAC, "00:00:00:00:00:04") in node.connections
    assert (dr.CONNECTION_NETWORK_MAC, "01:00:00:00:00:00") in node.connections


@pytest.mark.asyncio
async def test_init_with_restore_and_remove(hass: HomeAssistant, legacy_clock) -> None:
    """Test init.

    :param hass: HomeAssistant
    """

    with patch(
        "custom_components.miwifi.updater.LuciClient"
    ) as mock_luci_client, patch(
        "custom_components.miwifi.async_start_discovery", return_value=None
    ), patch(
        "custom_components.miwifi.helper.Store"
    ) as mock_store:


        await async_mock_luci_client(mock_luci_client)

        mock_store.return_value.async_load = AsyncMock(
            return_value=json.loads(load_fixture("store_data.json"))
        )
        mock_store.return_value.async_save = AsyncMock(return_value=None)

        setup_data: list = await async_setup(hass)

        config_entry: MockConfigEntry = setup_data[1]

        assert await hass.config_entries.async_setup(config_entry.entry_id)
        await hass.async_block_till_done(wait_background_tasks=True)
        async_advance_time(hass, legacy_clock, utcnow() + timedelta(seconds=DEFAULT_SCAN_INTERVAL + 1)
        )
        await hass.async_block_till_done(wait_background_tasks=True)

        updater: LuciUpdater = hass.data[DOMAIN][config_entry.entry_id][UPDATER]
        updater._activity_days = 1

        async_advance_time(hass, legacy_clock, utcnow() + timedelta(seconds=DEFAULT_SCAN_INTERVAL + 1)
        )
        await hass.async_block_till_done(wait_background_tasks=True)

        assert updater.last_update_success

        state: State = hass.states.get(_generate_id("00:00:00:00:00:01"))
        assert state.state == STATE_HOME
        assert state.name == "Device 1"
        assert state.attributes["icon"] == "mdi:lan-connect"
        assert state.attributes["attribution"] == ATTRIBUTION
        assert state.attributes["source_type"] == SourceType.ROUTER
        assert state.attributes["ip"] == "192.168.31.2"
        assert state.attributes["mac"] == "00:00:00:00:00:01"
        assert state.attributes["scanner"] == DOMAIN
        assert state.attributes["online"] == "8:05:01"
        assert state.attributes["connection"] == Connection.WIFI_2_4.phrase  # type: ignore
        assert state.attributes["router_mac"] == "00:00:00:00:00:00"
        assert state.attributes["signal"] == 100
        assert state.attributes["down_speed"] == "0 B/s"
        assert state.attributes["up_speed"] == "0 B/s"
        assert state.attributes["attribution"] == ATTRIBUTION

        state = hass.states.get(_generate_id("00:00:00:00:00:02"))
        assert state.state == STATE_HOME
        assert state.name == "Device 2"
        assert state.attributes["icon"] == "mdi:lan-connect"
        assert state.attributes["attribution"] == ATTRIBUTION
        assert state.attributes["source_type"] == SourceType.ROUTER
        assert state.attributes["ip"] == "192.168.31.3"
        assert state.attributes["mac"] == "00:00:00:00:00:02"
        assert state.attributes["scanner"] == DOMAIN
        assert state.attributes["online"] == "8:05:01"
        assert state.attributes["connection"] == Connection.WIFI_5_0.phrase  # type: ignore
        assert state.attributes["router_mac"] == "00:00:00:00:00:00"
        assert state.attributes["signal"] == 100
        assert state.attributes["down_speed"] == "0 B/s"
        assert state.attributes["up_speed"] == "0 B/s"
        assert state.attributes["attribution"] == ATTRIBUTION

        state = hass.states.get(_generate_id("00:00:00:00:00:03"))
        assert state.state == STATE_HOME
        assert state.name == "Device 3"
        assert state.attributes["icon"] == "mdi:lan-connect"
        assert state.attributes["attribution"] == ATTRIBUTION
        assert state.attributes["source_type"] == SourceType.ROUTER
        assert state.attributes["ip"] == "192.168.31.4"
        assert state.attributes["mac"] == "00:00:00:00:00:03"
        assert state.attributes["scanner"] == DOMAIN
        assert state.attributes["online"] == "8:05:01"
        assert state.attributes["connection"] == Connection.LAN.phrase  # type: ignore
        assert state.attributes["router_mac"] == "00:00:00:00:00:00"
        assert len(state.attributes["signal"]) == 0
        assert state.attributes["down_speed"] == "0 B/s"
        assert state.attributes["up_speed"] == "0 B/s"
        assert state.attributes["attribution"] == ATTRIBUTION

        state = hass.states.get(_generate_id("00:00:00:00:00:05"))
        assert state is None
        assert er.async_get(hass).async_get(_generate_id("00:00:00:00:00:05")) is None
        assert "00:00:00:00:00:05" not in updater.devices


@pytest.mark.asyncio
async def test_init_detect_manufacturer(hass: HomeAssistant, legacy_clock) -> None:
    """Test init.

    :param hass: HomeAssistant
    """

    with patch(
        "custom_components.miwifi.updater.LuciClient"
    ) as mock_luci_client, patch(
        "custom_components.miwifi.async_start_discovery", return_value=None
    ):


        await async_mock_luci_client(mock_luci_client)

        mock_luci_client.return_value.device_list = AsyncMock(
            return_value=json.loads(
                load_fixture("device_list_detect_manufacturer_data.json")
            )
        )

        setup_data: list = await async_setup(hass)

        config_entry: MockConfigEntry = setup_data[1]

        assert await hass.config_entries.async_setup(config_entry.entry_id)
        await hass.async_block_till_done(wait_background_tasks=True)
        async_advance_time(hass, legacy_clock, utcnow() + timedelta(seconds=DEFAULT_SCAN_INTERVAL + 1)
        )
        await hass.async_block_till_done(wait_background_tasks=True)

        updater: LuciUpdater = hass.data[DOMAIN][config_entry.entry_id][UPDATER]

        assert updater.last_update_success

        device_registry = dr.async_get(hass)
        device = device_registry.async_get_device_by_connection((dr.CONNECTION_NETWORK_MAC, "CC:50:E3:96:29:78"), config_entry.entry_id)

        device_registry.async_update_device(device.id, manufacturer=None)

        async_advance_time(hass, legacy_clock, utcnow() + timedelta(seconds=DEFAULT_SCAN_INTERVAL + 1)
        )
        await hass.async_block_till_done(wait_background_tasks=True)

        state: State = hass.states.get(_generate_id("CC:50:E3:96:29:78"))
        assert state.state == STATE_HOME
        assert state.name == "Device 1"
        assert state.attributes["icon"] == "mdi:lan-connect"
        assert state.attributes["attribution"] == ATTRIBUTION
        assert state.attributes["source_type"] == SourceType.ROUTER
        assert state.attributes["ip"] == "192.168.31.2"
        assert state.attributes["mac"] == "cc:50:e3:96:29:78"
        assert state.attributes["scanner"] == DOMAIN
        assert state.attributes["online"] == "8:05:01"
        assert state.attributes["connection"] == Connection.WIFI_2_4.phrase  # type: ignore
        assert state.attributes["router_mac"] == "00:00:00:00:00:00"
        assert state.attributes["signal"] is None
        assert state.attributes["down_speed"] == "9.54 MB/s"
        assert state.attributes["up_speed"] == "0 B/s"
        assert state.attributes["attribution"] == ATTRIBUTION

        device = device_registry.async_get_device_by_connection((dr.CONNECTION_NETWORK_MAC, "CC:50:E3:96:29:78"), config_entry.entry_id)

        assert device.manufacturer == MANUFACTURERS["CC50E3"]


@pytest.mark.asyncio
@pytest.mark.parametrize("enable_port_probe", [False, True])
async def test_init_detect_url(hass: HomeAssistant, legacy_clock, enable_port_probe) -> None:
    """Test init.

    :param hass: HomeAssistant
    """

    writer = Mock()
    writer.wait_closed = AsyncMock()
    connect = AsyncMock(return_value=(Mock(), writer))
    probe_asyncio = SimpleNamespace(**(vars(asyncio) | {"open_connection": connect}))

    with patch(
        "custom_components.miwifi.updater.LuciClient"
    ) as mock_luci_client, patch(
        "custom_components.miwifi.async_start_discovery", return_value=None
    ), patch("custom_components.miwifi.device_tracker.asyncio", probe_asyncio):

        await async_mock_luci_client(mock_luci_client)

        mock_luci_client.return_value.device_list = AsyncMock(
            return_value=json.loads(
                load_fixture("device_list_detect_manufacturer_data.json")
            )
        )

        setup_data: list = await async_setup(hass, enable_port_probe=enable_port_probe)

        config_entry: MockConfigEntry = setup_data[1]

        assert await hass.config_entries.async_setup(config_entry.entry_id)
        await hass.async_block_till_done(wait_background_tasks=True)
        async_advance_time(hass, legacy_clock, utcnow() + timedelta(seconds=DEFAULT_SCAN_INTERVAL + 1)
        )
        await hass.async_block_till_done(wait_background_tasks=True)

        # Probing is asynchronous. The next census applies the discovered URL
        # to the registry after the port connection has completed.
        async_advance_time(hass, legacy_clock, utcnow() + timedelta(seconds=DEFAULT_SCAN_INTERVAL + 1))
        await hass.async_block_till_done(wait_background_tasks=True)

        updater: LuciUpdater = hass.data[DOMAIN][config_entry.entry_id][UPDATER]

        assert updater.last_update_success

        device_registry = dr.async_get(hass)

        state: State = hass.states.get(_generate_id("CC:50:E3:96:29:78"))
        assert state.state == STATE_HOME
        assert state.name == "Device 1"
        assert state.attributes["icon"] == "mdi:lan-connect"
        assert state.attributes["attribution"] == ATTRIBUTION
        assert state.attributes["source_type"] == SourceType.ROUTER
        assert state.attributes["ip"] == "192.168.31.2"
        assert state.attributes["mac"] == "cc:50:e3:96:29:78"
        assert state.attributes["scanner"] == DOMAIN
        assert state.attributes["online"] == "8:05:01"
        assert state.attributes["connection"] == Connection.WIFI_2_4.phrase  # type: ignore
        assert state.attributes["router_mac"] == "00:00:00:00:00:00"
        assert state.attributes["signal"] is None
        assert state.attributes["down_speed"] == "9.54 MB/s"
        assert state.attributes["up_speed"] == "0 B/s"
        assert state.attributes["attribution"] == ATTRIBUTION

        device = device_registry.async_get_device_by_connection((dr.CONNECTION_NETWORK_MAC, "CC:50:E3:96:29:78"), config_entry.entry_id)

        if enable_port_probe:
            assert device.configuration_url == "http://192.168.31.2"
            connect.assert_awaited_once_with("192.168.31.2", 80)
            writer.close.assert_called_once()
            writer.wait_closed.assert_awaited_once()
        else:
            assert device.configuration_url is None
            connect.assert_not_awaited()


def _generate_id(mac: str) -> str:
    """Generate unique id

    :param mac: str
    :return str
    """

    return generate_entity_id(DEVICE_TRACKER_ENTITY_ID_FORMAT, mac)
