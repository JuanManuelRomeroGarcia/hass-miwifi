"""Tests for the miwifi component."""

# pylint: disable=no-member,too-many-statements,protected-access,too-many-lines,line-too-long

from __future__ import annotations

import logging

import pytest
from homeassistant.const import CONF_DEVICE_ID, CONF_DOMAIN, CONF_PLATFORM, CONF_TYPE
from homeassistant.core import HomeAssistant
from homeassistant.components.device_automation import (
    DeviceAutomationType, async_get_device_automations,
)
from homeassistant.helpers import device_registry as dr
from pytest_homeassistant_custom_component.common import MockConfigEntry

from custom_components.miwifi.const import DOMAIN, EVENT_LUCI, EVENT_TYPE_RESPONSE
from custom_components.miwifi.device_trigger import DEVICE, async_attach_trigger, async_get_triggers

_LOGGER = logging.getLogger(__name__)


@pytest.fixture(autouse=True)
def auto_enable_custom_integrations(enable_custom_integrations):
    """Enable custom integrations"""

    yield


@pytest.mark.asyncio
async def test_get_triggers(hass: HomeAssistant) -> None:
    """Get triggers test.

    :param hass: HomeAssistant
    """

    assert await async_get_triggers(hass, "test") == [
        {
            CONF_PLATFORM: DEVICE,
            CONF_DEVICE_ID: "test",
            CONF_DOMAIN: DOMAIN,
            CONF_TYPE: EVENT_TYPE_RESPONSE,
        }
    ]


@pytest.mark.asyncio
async def test_trigger_filters_events_and_can_be_removed(hass: HomeAssistant) -> None:
    """Run the real HA event listener, including filtering and unsubscribe."""
    calls = []

    async def action(variables, context):
        calls.append(variables)

    config = (await async_get_triggers(hass, "test"))[0]
    remove = await async_attach_trigger(
        hass, config, action,
        {"trigger_data": {"id": "0", "idx": "0", "alias": None}, "variables": {}},
    )

    for event_type, device_id, response_type in (
        (EVENT_LUCI, "other", EVENT_TYPE_RESPONSE),
        (EVENT_LUCI, "test", "other"),
        ("other_event", "test", EVENT_TYPE_RESPONSE),
    ):
        hass.bus.async_fire(event_type, {CONF_DEVICE_ID: device_id, CONF_TYPE: response_type})
    await hass.async_block_till_done()
    assert not calls

    event_data = {CONF_DEVICE_ID: "test", CONF_TYPE: EVENT_TYPE_RESPONSE, "result": "ok"}
    hass.bus.async_fire(EVENT_LUCI, event_data)
    await hass.async_block_till_done()
    assert len(calls) == 1
    assert calls[0]["trigger"]["platform"] == DEVICE
    assert calls[0]["trigger"]["event"].data == event_data

    remove()
    hass.bus.async_fire(EVENT_LUCI, event_data)
    await hass.async_block_till_done()
    assert len(calls) == 1


@pytest.mark.asyncio
async def test_trigger_is_discovered_for_router_device(hass: HomeAssistant) -> None:
    """Use the discovery path used by the automation editor."""
    entry = MockConfigEntry(domain=DOMAIN)
    entry.add_to_hass(hass)
    device = dr.async_get(hass).async_get_or_create(
        config_entry_id=entry.entry_id,
        identifiers={(DOMAIN, "02:00:00:00:00:01")},
        name="Test router",
    )
    triggers = await async_get_device_automations(
        hass, DeviceAutomationType.TRIGGER, [device.id],
    )
    assert any(
        trigger[CONF_DOMAIN] == DOMAIN
        and trigger[CONF_TYPE] == EVENT_TYPE_RESPONSE
        for trigger in triggers[device.id]
    )
