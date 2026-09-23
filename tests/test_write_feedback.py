"""A refused write must not look like an accepted one, and an overridden one must say so.

`_async_update_wifi_adapter` logged a `LuciError` at debug and returned, while
`async_select_option` went on to write the requested value into the entity. A
router that refused the change was therefore indistinguishable from one that took
it - and a mesh controller that answers `code: 0` and puts its own value back
later was indistinguishable from both.

3.6.12 watched for the second case with a counter that disarmed on the first
refresh that agreed, so it only ever caught an immediate revert. On a real mesh
the RA82 leaves undo a change on their own within minutes, and the RD28 leaf kept
one for hours and lost it the moment the main's profile was touched and pushed to
every node. Both went unreported. The request is now remembered for the life of
the entity, and every departure from it is reported once.
"""

# pylint: disable=no-member,protected-access

from __future__ import annotations

import logging
from unittest.mock import AsyncMock, MagicMock

import pytest
from homeassistant.exceptions import HomeAssistantError

from custom_components.miwifi.const import (
    ATTR_SELECT_REQUESTED_OPTION,
    ATTR_SELECT_WIFI_2_4_CHANNEL,
    ATTR_STATE,
    ATTR_WIFI_2_4_DATA,
)
from custom_components.miwifi.exceptions import LuciConnectionError, LuciRequestError
from custom_components.miwifi.select import MIWIFI_SELECTS, MiWifiSelect
from custom_components.miwifi.switch import MIWIFI_SWITCHES, MiWifiSwitch

OVERRIDDEN = "replaced wifi_2_4_channel with"


def _select(key: str = ATTR_SELECT_WIFI_2_4_CHANNEL) -> MiWifiSelect:
    """Build a select shell with only the attributes these paths touch."""

    select = MiWifiSelect.__new__(MiWifiSelect)
    select.entity_description = next(d for d in MIWIFI_SELECTS if d.key == key)
    select._base_options = ["1", "6", "11"]
    select._attr_options = list(select._base_options)
    select._attr_current_option = "1"
    select._attr_available = True
    select._wifi_data = {"ssid": "net", "channel": "1"}
    select._requested_option = None
    select._requested_confirmed = False
    select._requested_mismatches = 0
    select._override_reported = None

    updater = MagicMock()
    updater.ip = "192.0.2.104"
    updater.data = {
        ATTR_STATE: True,
        key: "1",
        ATTR_WIFI_2_4_DATA: {"ssid": "net", "channel": "1"},
    }
    updater.luci.set_wifi = AsyncMock()
    select._updater = updater
    select.async_write_ha_state = MagicMock()

    return select


def _report(select: MiWifiSelect, channel) -> None:
    """Let a refresh land carrying what the router says now."""

    key = select.entity_description.key
    select._updater.data[key] = channel
    select._updater.data[ATTR_WIFI_2_4_DATA] = {"ssid": "net", "channel": channel}
    select._handle_coordinator_update()


@pytest.mark.asyncio
async def test_a_refused_write_surfaces_and_does_not_move_the_entity() -> None:
    """It used to log at debug and show the value anyway."""

    select = _select()
    select._updater.luci.set_wifi = AsyncMock(
        side_effect=LuciRequestError("Invalid value")
    )

    with pytest.raises(HomeAssistantError, match="refused the change"):
        await select.async_select_option("6")

    assert select._attr_current_option == "1"
    assert select._requested_option is None
    select.async_write_ha_state.assert_not_called()


@pytest.mark.asyncio
async def test_an_accepted_write_is_shown_and_then_confirmed(caplog) -> None:
    """The happy path stays exactly as it was."""

    select = _select()

    with caplog.at_level(logging.WARNING):
        await select.async_select_option("6")

        assert select._attr_current_option == "6"
        assert select._requested_option == "6"

        _report(select, "6")

    assert select._requested_confirmed is True
    assert OVERRIDDEN not in caplog.text
    assert select.extra_state_attributes is None


@pytest.mark.asyncio
async def test_an_override_that_arrives_after_a_confirmation_is_reported(
    caplog,
) -> None:
    """The 3.6.12 gap: the counter had disarmed on the refresh that agreed."""

    select = _select()

    await select.async_select_option("6")

    # The router keeps it for a while. This is what used to end the watch.
    _report(select, "6")
    _report(select, "6")

    with caplog.at_level(logging.WARNING):
        # Then the main's profile is pushed onto the node.
        _report(select, "11")

    assert "replaced wifi_2_4_channel with 11 after accepting 6" in caplog.text


@pytest.mark.asyncio
async def test_an_immediate_revert_still_needs_two_disagreeing_refreshes(
    caplog,
) -> None:
    """A poll in flight when the write landed reports the old value once."""

    select = _select()

    await select.async_select_option("6")

    with caplog.at_level(logging.WARNING):
        _report(select, "1")
        assert OVERRIDDEN not in caplog.text

        _report(select, "1")

    assert "replaced wifi_2_4_channel with 1 after accepting 6" in caplog.text


@pytest.mark.asyncio
async def test_the_same_override_is_not_repeated_every_refresh(caplog) -> None:
    """Thirty seconds a cycle, for ever, for a value the router will not give back."""

    select = _select()

    await select.async_select_option("6")
    _report(select, "6")

    with caplog.at_level(logging.WARNING):
        for _ in range(5):
            _report(select, "11")

    assert caplog.text.count(OVERRIDDEN) == 1


@pytest.mark.asyncio
async def test_being_overridden_again_after_a_recovery_is_a_new_event(caplog) -> None:
    """The value came back, then went away again: that is worth saying twice."""

    select = _select()

    await select.async_select_option("6")
    _report(select, "6")

    with caplog.at_level(logging.WARNING):
        _report(select, "11")
        _report(select, "6")
        _report(select, "11")

    assert caplog.text.count(OVERRIDDEN) == 2


@pytest.mark.asyncio
async def test_nothing_is_reported_when_nothing_was_asked(caplog) -> None:
    """A value changing on its own is the router's business, not an override."""

    select = _select()

    with caplog.at_level(logging.WARNING):
        _report(select, "11")
        _report(select, "1")

    assert OVERRIDDEN not in caplog.text


@pytest.mark.asyncio
async def test_a_band_that_stops_being_reported_is_not_an_override(caplog) -> None:
    """An absent key arrives as the False `data.get` was given as a default."""

    select = _select()

    await select.async_select_option("6")
    _report(select, "6")

    with caplog.at_level(logging.WARNING):
        _report(select, False)
        _report(select, False)

    assert OVERRIDDEN not in caplog.text


@pytest.mark.asyncio
async def test_the_value_you_asked_for_is_published_while_it_is_ignored() -> None:
    """The warning goes to a log nobody reads; this sits next to the state."""

    select = _select()

    await select.async_select_option("6")
    _report(select, "6")

    assert select.extra_state_attributes is None

    _report(select, "11")

    assert select.extra_state_attributes == {ATTR_SELECT_REQUESTED_OPTION: "6"}


@pytest.mark.asyncio
async def test_an_unanswered_write_is_not_called_a_refusal(caplog) -> None:
    """set_wifi restarts the radios; the reply can be lost with them."""

    select = _select()
    select._updater.luci.set_wifi = AsyncMock(
        side_effect=LuciConnectionError("Connection error")
    )

    with caplog.at_level(logging.WARNING):
        await select.async_select_option("6")

    assert "did not answer the change" in caplog.text
    assert select._attr_current_option == "6"
    assert select._requested_option == "6"


@pytest.mark.asyncio
async def test_an_unanswered_write_that_did_not_stick_is_reported(caplog) -> None:
    """The request is kept, so the next refreshes check it like any other."""

    select = _select()
    select._updater.luci.set_wifi = AsyncMock(
        side_effect=LuciConnectionError("Connection error")
    )

    await select.async_select_option("6")

    with caplog.at_level(logging.WARNING):
        _report(select, "1")
        _report(select, "1")

    assert OVERRIDDEN in caplog.text
    assert select.extra_state_attributes == {ATTR_SELECT_REQUESTED_OPTION: "6"}


def _switch(key: str = "wifi_2_4") -> MiWifiSwitch:
    """Build a switch shell with only the attributes the write path touches."""

    switch = MiWifiSwitch.__new__(MiWifiSwitch)
    switch.entity_description = next(d for d in MIWIFI_SWITCHES if d.key == key)
    switch._attr_is_on = True
    switch._wifi_data = {"ssid": "net", "on": 1}

    updater = MagicMock()
    updater.ip = "192.0.2.104"
    updater.data = {key: True}
    updater.luci.set_wifi = AsyncMock()
    switch._updater = updater
    switch.async_write_ha_state = MagicMock()

    hass = MagicMock()

    async def _run(func, *args):
        return func(*args)

    hass.async_add_executor_job = _run
    switch.hass = hass

    return switch


@pytest.mark.asyncio
async def test_a_refused_switch_write_surfaces_and_does_not_move_the_switch() -> None:
    """The router answered with an error code: that is a refusal."""

    switch = _switch()
    switch._updater.luci.set_wifi = AsyncMock(side_effect=LuciRequestError("Invalid"))

    with pytest.raises(HomeAssistantError, match="refused the change"):
        await switch.async_turn_off()

    assert switch._attr_is_on is True
    switch.async_write_ha_state.assert_not_called()


@pytest.mark.asyncio
async def test_an_unanswered_switch_write_is_not_called_a_refusal(caplog) -> None:
    """No reply is an unknown outcome; the next refresh settles it."""

    switch = _switch()
    switch._updater.luci.set_wifi = AsyncMock(
        side_effect=LuciConnectionError("Connection error")
    )

    with caplog.at_level(logging.WARNING):
        await switch.async_turn_off()

    assert "did not answer the change" in caplog.text
    assert switch._attr_is_on is False
