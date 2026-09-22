"""A channel the router reports must stay selectable, whatever its list said.

The options come from `avaliable_channels`, asked once on the first update. On a
mesh the answer goes stale immediately: the RA82 leaves offer 36-48 and are then
parked on the main's channel by the controller. Home Assistant renders a select
whose current option is not among its options as `unknown`, so the picker went
blank exactly when the channel was worth seeing, and stayed blank because the
list is never asked for again.
"""

# pylint: disable=no-member,protected-access

from __future__ import annotations

from unittest.mock import MagicMock

import pytest

from custom_components.miwifi.const import (
    ATTR_SELECT_SIGNAL_STRENGTH_OPTIONS,
    ATTR_SELECT_WIFI_2_4_CHANNEL,
    ATTR_SELECT_WIFI_2_4_SIGNAL_STRENGTH,
    ATTR_SELECT_WIFI_5_0_CHANNEL,
    ATTR_SELECT_WIFI_5_0_GAME_CHANNEL,
    ATTR_SELECT_WIFI_5_0_GAME_SIGNAL_STRENGTH,
    ATTR_SELECT_WIFI_5_0_SIGNAL_STRENGTH,
    ATTR_STATE,
    ATTR_WIFI_2_4_DATA,
    ATTR_WIFI_5_0_DATA,
    ATTR_WIFI_5_0_GAME_DATA,
)
from custom_components.miwifi.select import DATA_MAP, MIWIFI_SELECTS, MiWifiSelect

CHANNEL_CONTROLS = (
    ATTR_SELECT_WIFI_2_4_CHANNEL,
    ATTR_SELECT_WIFI_5_0_CHANNEL,
    ATTR_SELECT_WIFI_5_0_GAME_CHANNEL,
)

SIGNAL_CONTROLS = (
    ATTR_SELECT_WIFI_2_4_SIGNAL_STRENGTH,
    ATTR_SELECT_WIFI_5_0_SIGNAL_STRENGTH,
    ATTR_SELECT_WIFI_5_0_GAME_SIGNAL_STRENGTH,
)

# What an RA82 leaf answers `avaliable_channels` with: the non-DFS 80 MHz block
# alone, while the controller has it sitting on the main's 100.
RA82_5G_OPTIONS = ["36", "40", "44", "48"]


def _select(key: str, base: list, **data) -> MiWifiSelect:
    """Build a select shell whose option list is `base`."""

    select = MiWifiSelect.__new__(MiWifiSelect)
    select.entity_description = next(d for d in MIWIFI_SELECTS if d.key == key)
    select._base_options = list(base)
    select._attr_options = list(base)
    select._attr_current_option = None
    select._wifi_data = {}
    select._requested_option = None
    select._requested_confirmed = False
    select._requested_mismatches = 0
    select._override_reported = None

    updater = MagicMock()
    updater.data = {
        ATTR_STATE: True,
        ATTR_WIFI_2_4_DATA: {"channel": "1"},
        ATTR_WIFI_5_0_DATA: {"channel": "100"},
        ATTR_WIFI_5_0_GAME_DATA: {"channel": "149"},
        **data,
    }
    select._updater = updater
    select.async_write_ha_state = MagicMock()

    return select


def test_a_channel_outside_the_routers_list_is_still_offered() -> None:
    """The RA82 case, which read `unknown` in 3.6.12."""

    key = ATTR_SELECT_WIFI_5_0_CHANNEL
    select = _select(key, RA82_5G_OPTIONS, **{key: "100"})

    select._handle_coordinator_update()

    assert select._attr_current_option == "100"
    assert "100" in select._attr_options, "the picker would render as unknown"
    assert select._attr_available is True


def test_it_lands_in_numeric_place() -> None:
    """String order would put 100 between 1 and 11."""

    key = ATTR_SELECT_WIFI_2_4_CHANNEL
    select = _select(key, ["1", "6", "11"], **{key: "9"})

    assert select._options_with_current("9") == ["1", "6", "9", "11"]


@pytest.mark.parametrize("key", CHANNEL_CONTROLS)
def test_a_channel_already_on_the_list_changes_nothing(key: str) -> None:
    """No duplicate, no reordering, nothing to write to the state machine."""

    select = _select(key, ["1", "6", "11"], **{key: "6"})

    assert select._options_with_current("6") == ["1", "6", "11"]


@pytest.mark.parametrize("reported", (None, "", "0", 0, False))
def test_an_unstated_channel_is_not_an_option(reported) -> None:
    """"0" is how a firmware says unset, and False is `data.get`'s default."""

    key = ATTR_SELECT_WIFI_2_4_CHANNEL
    select = _select(key, ["1", "6", "11"], **{key: reported})

    assert select._options_with_current(reported) == ["1", "6", "11"]


@pytest.mark.parametrize("key", SIGNAL_CONTROLS)
def test_signal_strength_is_never_widened(key: str) -> None:
    """min/mid/max is the whole vocabulary; a fourth value is a bug."""

    select = _select(key, list(ATTR_SELECT_SIGNAL_STRENGTH_OPTIONS), **{key: "high"})

    select._handle_coordinator_update()

    assert select._attr_options == ATTR_SELECT_SIGNAL_STRENGTH_OPTIONS


def test_the_list_follows_the_router_from_cycle_to_cycle() -> None:
    """Frozen at the first update was the whole defect: it has to be recomputed."""

    key = ATTR_SELECT_WIFI_5_0_CHANNEL
    select = _select(key, RA82_5G_OPTIONS, **{key: "36"})

    select._handle_coordinator_update()
    assert select._attr_options == RA82_5G_OPTIONS

    # The controller parks the leaf on the main's channel.
    select._updater.data[key] = "100"
    select._updater.data[DATA_MAP[key]] = {"channel": "100"}
    select._handle_coordinator_update()

    assert select._attr_options == RA82_5G_OPTIONS + ["100"]

    # And back, once the main is moved somewhere the leaf can follow.
    select._updater.data[key] = "44"
    select._updater.data[DATA_MAP[key]] = {"channel": "44"}
    select._handle_coordinator_update()

    assert select._attr_options == RA82_5G_OPTIONS
