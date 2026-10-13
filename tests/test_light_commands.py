"""Failed LED commands preserve the last confirmed state and can recover."""
from types import SimpleNamespace
from unittest.mock import AsyncMock, Mock, call

import pytest

from custom_components.miwifi.const import ATTR_LIGHT_LED
from custom_components.miwifi.exceptions import LuciConnectionError, LuciRequestError
from custom_components.miwifi.light import MiWifiLight


@pytest.mark.parametrize("error", [LuciConnectionError, LuciRequestError])
async def test_led_rejected_command_preserves_state_then_recovers(error):
    light = object.__new__(MiWifiLight)
    led = AsyncMock(return_value={"code": 0})
    light._updater = SimpleNamespace(luci=SimpleNamespace(led=led), data={ATTR_LIGHT_LED: False})
    light.entity_description = SimpleNamespace(key=ATTR_LIGHT_LED)
    light.async_write_ha_state = Mock()
    light._attr_is_on = False

    await light.async_turn_on()
    assert light.is_on is True
    assert light._updater.data[ATTR_LIGHT_LED] is True
    light.async_write_ha_state.assert_called_once()

    led.side_effect = error
    await light.async_turn_off()
    await light.async_turn_on()
    assert light.is_on is True
    assert light._updater.data[ATTR_LIGHT_LED] is True
    light.async_write_ha_state.assert_called_once()

    led.side_effect = None
    await light.async_turn_off()
    assert light.is_on is False
    assert light._updater.data[ATTR_LIGHT_LED] is False
    assert light.async_write_ha_state.call_count == 2
    assert led.await_args_list == [call(1), call(0), call(1), call(0)]
