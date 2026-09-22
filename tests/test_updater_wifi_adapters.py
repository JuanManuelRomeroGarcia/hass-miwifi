"""Visibility of the wifi adapters a node reports.

Only wl0/wl1/wl2/wl14 are mapped to an IfName. Anything else was dropped with no
trace, taking the switch, the channel and the signal of a radio the node has -
which is exactly the shape of "this node shows no 5G switch and the others do".
"""

# pylint: disable=no-member,protected-access

from __future__ import annotations

import logging
from unittest.mock import AsyncMock, MagicMock

import pytest

from custom_components.miwifi.const import ATTR_WIFI_ADAPTER_LENGTH
from custom_components.miwifi.exceptions import LuciError
from custom_components.miwifi.updater import LuciUpdater

MOCK_IP: str = "192.0.2.102"


def _updater() -> LuciUpdater:
    """Build an updater shell with only the attributes this path touches."""

    updater = LuciUpdater.__new__(LuciUpdater)
    updater.ip = MOCK_IP
    updater.data = {}
    updater.luci = MagicMock()
    updater.supports_guest = False
    updater._wifi_adapters_logged = None
    updater._wifi_diag_fills_channels = None

    hass = MagicMock()

    async def _run(func, *args):
        return func(*args)

    hass.async_add_executor_job = _run
    updater.hass = hass

    return updater


def _adapter(ifname: str) -> dict:
    return {"ifname": ifname, "status": "1", "channelInfo": {"channel": 1}}


@pytest.mark.asyncio
async def test_mapped_and_skipped_adapters_are_reported(caplog) -> None:
    """The unknown ifname is named, not swallowed."""

    updater = _updater()
    updater.luci.wifi_detail_all = AsyncMock(
        return_value={"bsd": 1, "info": [_adapter("wl1"), _adapter("wl9")]}
    )
    data: dict = {}

    with caplog.at_level(logging.DEBUG):
        await updater._async_prepare_wifi(data)

    reported = [rec.getMessage() for rec in caplog.records if "wifi adapters" in rec.getMessage()]

    assert len(reported) == 1
    assert "wl1" in reported[0]
    assert "wl9" in reported[0]
    # The unknown radio is still not counted as an adapter.
    assert data[ATTR_WIFI_ADAPTER_LENGTH] == 1


@pytest.mark.asyncio
async def test_the_picture_is_reported_once_while_it_holds(caplog) -> None:
    """Per-cycle repetition would be noise; a change is worth a line."""

    updater = _updater()
    updater.luci.wifi_detail_all = AsyncMock(
        return_value={"bsd": 1, "info": [_adapter("wl1")]}
    )

    with caplog.at_level(logging.DEBUG):
        await updater._async_prepare_wifi({})
        await updater._async_prepare_wifi({})

        updater.luci.wifi_detail_all = AsyncMock(
            return_value={"bsd": 1, "info": [_adapter("wl1"), _adapter("wl0")]}
        )
        await updater._async_prepare_wifi({})

    reported = [rec.getMessage() for rec in caplog.records if "wifi adapters" in rec.getMessage()]

    assert len(reported) == 2
    assert "wl0" in reported[1]


# --------------------------------------------------------------------------
# Channels the detail endpoint omits
# --------------------------------------------------------------------------


def _adapter_without_channel(ifname: str) -> dict:
    """What the RA82 leaves answer for 5 GHz: power and status, no channel."""

    return {"ifname": ifname, "status": "1", "txpwr": "mid"}


@pytest.mark.asyncio
async def test_a_missing_channel_is_filled_from_the_diagnostics_endpoint() -> None:
    """The two endpoints are complementary; only one was ever read."""

    updater = _updater()
    updater.luci.wifi_detail_all = AsyncMock(
        return_value={
            "bsd": 1,
            "info": [_adapter("wl1"), _adapter_without_channel("wl0")],
        }
    )
    updater.luci.wifi_diag_detail_all = AsyncMock(
        return_value={"info": [{"ifname": "wl0", "channelInfo": {"channel": 36}}]}
    )
    data: dict = {}

    await updater._async_prepare_wifi(data)

    updater.luci.wifi_diag_detail_all.assert_awaited_once()
    assert data["wifi_5_0_channel"] == "36"
    # The picker reads its availability from the data dict, not from the key.
    assert data["wifi_5_0_data"]["channel"] == "36"


@pytest.mark.asyncio
async def test_the_detail_endpoint_is_enough_on_its_own() -> None:
    """No gap, no second request."""

    updater = _updater()
    updater.luci.wifi_detail_all = AsyncMock(
        return_value={"bsd": 1, "info": [_adapter("wl1"), _adapter("wl0")]}
    )
    updater.luci.wifi_diag_detail_all = AsyncMock()

    await updater._async_prepare_wifi({})

    updater.luci.wifi_diag_detail_all.assert_not_awaited()


@pytest.mark.asyncio
async def test_a_node_that_never_states_its_channel_is_asked_once() -> None:
    """Otherwise it costs an extra request every cycle, for ever."""

    updater = _updater()
    updater.luci.wifi_detail_all = AsyncMock(
        return_value={
            "bsd": 1,
            "info": [_adapter("wl1"), _adapter_without_channel("wl0")],
        }
    )
    updater.luci.wifi_diag_detail_all = AsyncMock(
        return_value={"info": [_adapter_without_channel("wl0")]}
    )

    for _ in range(3):
        await updater._async_prepare_wifi({})

    assert updater.luci.wifi_diag_detail_all.await_count == 1
    assert updater._wifi_diag_fills_channels is False


@pytest.mark.asyncio
async def test_a_diagnostics_failure_does_not_break_the_step() -> None:
    """LuciError derives from BaseException and would abort the cycle."""

    updater = _updater()
    updater.luci.wifi_detail_all = AsyncMock(
        return_value={
            "bsd": 1,
            "info": [_adapter("wl1"), _adapter_without_channel("wl0")],
        }
    )
    updater.luci.wifi_diag_detail_all = AsyncMock(side_effect=LuciError("404"))
    data: dict = {}

    await updater._async_prepare_wifi(data)

    assert "wifi_5_0_channel" not in data
    assert updater._wifi_diag_fills_channels is False


@pytest.mark.asyncio
async def test_a_channel_of_zero_is_not_a_channel() -> None:
    """It is how a firmware says "unset" where it says anything at all."""

    updater = _updater()
    updater.luci.wifi_detail_all = AsyncMock(
        return_value={
            "bsd": 1,
            "info": [_adapter("wl1"), {"ifname": "wl0", "channel": "0"}],
        }
    )
    updater.luci.wifi_diag_detail_all = AsyncMock(
        return_value={"info": [{"ifname": "wl0", "channelInfo": {"channel": "0"}}]}
    )
    data: dict = {}

    await updater._async_prepare_wifi(data)

    assert "wifi_5_0_channel" not in data
