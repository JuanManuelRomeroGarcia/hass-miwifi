"""A channel picker stays available whether or not the router states its channel.

Some nodes answer wifi_detail_all with an adapter that carries power and status
but no channel. Hiding the picker there was considered and rejected: across
router models and firmwares a missing channel in the read path says nothing
about whether set_wifi accepts one, so taking the control away could remove a
working setting. The picker keeps the availability it always had, the updater
recovers the channel from the diagnostics endpoint where it can, and where it
cannot the state simply reads `unknown`.
"""

# pylint: disable=no-member,protected-access

from __future__ import annotations

from unittest.mock import MagicMock

import pytest

from custom_components.miwifi.const import (
    ATTR_BINARY_SENSOR_DUAL_BAND,
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
from custom_components.miwifi.select import MIWIFI_SELECTS, MiWifiSelect

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


def _select(key: str, dual_band: bool = True, **data) -> MiWifiSelect:
    """Build a select shell holding a node with the given reported values."""

    select = MiWifiSelect.__new__(MiWifiSelect)
    select.entity_description = next(d for d in MIWIFI_SELECTS if d.key == key)
    select._attr_entity_registry_enabled_default = (
        select.entity_description.entity_registry_enabled_default
    )
    select._base_options = ["1", "6", "11", "36", "100", "mid"]
    select._attr_options = list(select._base_options)
    select._attr_current_option = None
    select._wifi_data = {}
    select._requested_option = None
    select._requested_confirmed = False
    select._requested_mismatches = 0
    select._override_reported = None

    updater = MagicMock()
    updater.data = {
        ATTR_STATE: True,
        ATTR_BINARY_SENSOR_DUAL_BAND: dual_band,
        ATTR_WIFI_2_4_DATA: {"channel": "1"},
        ATTR_WIFI_5_0_DATA: {"channel": "100"},
        ATTR_WIFI_5_0_GAME_DATA: {"channel": "149"},
        **data,
    }
    select._updater = updater
    select.async_write_ha_state = MagicMock()

    return select


@pytest.mark.parametrize("key", CHANNEL_CONTROLS)
def test_a_reported_channel_keeps_its_picker(key: str) -> None:
    """Merged bands, and a real channel to show and set."""

    select = _select(key, **{key: "100"})

    select._handle_coordinator_update()

    assert select._attr_available is True
    assert select._attr_current_option == "100"


@pytest.mark.parametrize("key", CHANNEL_CONTROLS)
@pytest.mark.parametrize("reported", (None, "", "0", 0))
def test_an_unstated_channel_does_not_take_the_picker_away(key: str, reported) -> None:
    """The read path saying nothing is no proof that the write path is broken."""

    select = _select(key, **{key: reported})

    select._handle_coordinator_update()

    assert select._attr_available is True


@pytest.mark.parametrize("key", SIGNAL_CONTROLS)
def test_signal_strength_is_available(key: str) -> None:
    """It is reported on both bands, merged or not."""

    select = _select(key)

    select._handle_coordinator_update()

    assert select._attr_available is True


@pytest.mark.parametrize("key", CHANNEL_CONTROLS)
def test_band_steering_alone_decides_nothing(key: str) -> None:
    """The merge is not the test."""

    merged = _select(key, dual_band=True, **{key: "36"})
    split = _select(key, dual_band=False, **{key: "36"})

    merged._handle_coordinator_update()
    split._handle_coordinator_update()

    assert merged._attr_available is split._attr_available is True


def test_registration_does_not_depend_on_reported_values() -> None:
    """The 3.6.7 lesson: a registry default may not be taken from live data."""

    for key in CHANNEL_CONTROLS + SIGNAL_CONTROLS:
        for reported in ("36", None):
            select = _select(key, **{key: reported})
            select._handle_coordinator_update()

            assert (
                select._attr_entity_registry_enabled_default
                is select.entity_description.entity_registry_enabled_default
            ), f"{key} reporting {reported!r} changed its registry default"
