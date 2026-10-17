"""The access point option and the node's WAN entities, on a real entry setup.

With the option on, wan_info is never asked. The WAN speed sensors read
misystem/status, which the node still answers, so they are created and show the
same values as with the option off. The WAN state and link, which only wan_info
can tell, read unknown rather than a WAN that is down.
"""

from __future__ import annotations

from unittest.mock import patch

import pytest
from homeassistant.const import STATE_ON, STATE_UNKNOWN
from homeassistant.core import HomeAssistant
from homeassistant.helpers import entity_registry as er

from custom_components.miwifi.const import (
    ATTR_BINARY_SENSOR_WAN_LINK,
    ATTR_BINARY_SENSOR_WAN_STATE,
    ATTR_SENSOR_WAN_DOWNLOAD_SPEED,
    ATTR_SENSOR_WAN_UPLOAD_SPEED,
    CONF_IS_AP_MODE,
    DOMAIN,
)
from tests.setup import async_mock_luci_client, async_setup


@pytest.mark.parametrize(
    ("is_ap_mode", "wan_state"),
    [
        pytest.param(False, STATE_ON, id="option-off"),
        pytest.param(True, STATE_UNKNOWN, id="option-on"),
    ],
)
async def test_wan_entities_with_and_without_the_option(
    hass: HomeAssistant, is_ap_mode: bool, wan_state: str
) -> None:
    """The speed sensors exist either way; only the WAN state needs wan_info."""

    with patch("custom_components.miwifi.updater.LuciClient") as client, patch(
        "custom_components.miwifi.updater.async_dispatcher_send"
    ), patch(
        "custom_components.miwifi.async_start_discovery", return_value=None
    ), patch(
        "custom_components.miwifi.updater.asyncio.sleep", return_value=None
    ):
        await async_mock_luci_client(client)

        _, entry = await async_setup(hass)
        hass.config_entries.async_update_entry(
            entry, data=entry.data | {CONF_IS_AP_MODE: is_ap_mode}
        )

        assert await hass.config_entries.async_setup(entry.entry_id)
        await hass.async_block_till_done(wait_background_tasks=True)

        registry = er.async_get(hass)

        def state(domain: str, key: str) -> str | None:
            entity_id = registry.async_get_entity_id(
                domain, DOMAIN, f"{entry.entry_id}-{key}"
            )
            return None if entity_id is None else hass.states.get(entity_id).state

        # status_data.json reports 225064 B/s down and 19276 B/s up, in Mbps here.
        assert state("sensor", ATTR_SENSOR_WAN_DOWNLOAD_SPEED) == "1.8"
        assert state("sensor", ATTR_SENSOR_WAN_UPLOAD_SPEED) == "0.15"
        assert state("binary_sensor", ATTR_BINARY_SENSOR_WAN_STATE) == wan_state
        assert state("binary_sensor", ATTR_BINARY_SENSOR_WAN_LINK) == wan_state

        if is_ap_mode:
            client.return_value.wan_info.assert_not_awaited()
        else:
            client.return_value.wan_info.assert_awaited()

        assert await hass.config_entries.async_unload(entry.entry_id)
