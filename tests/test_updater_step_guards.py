"""Per-step LuciError guards in the prepare loop.

LuciError derives from BaseException, so an unhandled one escapes the prepare
loop and takes every later step of the cycle with it - a failing wan call, for
one, aborted everything from led to new_status.
"""


# pylint: disable=no-member,protected-access

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock

import pytest

from custom_components.miwifi.const import (
    ATTR_BINARY_SENSOR_WAN_STATE,
    ATTR_SENSOR_AP_SIGNAL,
    ATTR_SENSOR_MODE,
    ATTR_WIFI_ADAPTER_LENGTH,
)
from custom_components.miwifi.enum import Mode
from custom_components.miwifi.exceptions import LuciConnectionError, LuciRequestError
from custom_components.miwifi.updater import LuciUpdater

MOCK_IP: str = "192.0.2.104"


def _updater(mode: Mode = Mode.ACCESS_POINT, is_force_load: bool = False) -> LuciUpdater:
    """Build an updater shell with only the attributes these paths touch."""

    updater = LuciUpdater.__new__(LuciUpdater)
    updater.ip = MOCK_IP
    updater.is_force_load = is_force_load
    updater.data = {ATTR_SENSOR_MODE: mode}
    updater.devices = {}
    updater.luci = MagicMock()
    updater.new_device_callback = None
    updater._is_first_update = True
    updater._moved_devices = []
    updater._signals = {}
    updater._store = None
    updater._build_device = lambda device, integrations=None: dict(device)
    updater._is_cb0401v2 = False

    hass = MagicMock()

    async def _run(func, *args):
        return func(*args)

    hass.async_add_executor_job = _run
    updater.hass = hass

    return updater


@pytest.mark.asyncio
async def test_wan_failure_does_not_abort_the_cycle() -> None:
    """The handler caught Exception only, and LuciError is not one."""

    updater = _updater(mode=Mode.DEFAULT)
    updater.luci.wan_info = AsyncMock(side_effect=LuciConnectionError("Connection error"))
    data: dict = {}

    await updater._async_prepare_wan(data)

    assert data[ATTR_BINARY_SENSOR_WAN_STATE] is False


@pytest.mark.asyncio
async def test_channels_failure_does_not_abort_the_cycle() -> None:
    """channels runs before devices, device_list, ap and new_status."""

    updater = _updater(mode=Mode.DEFAULT)
    updater.luci.avaliable_channels = AsyncMock(side_effect=LuciRequestError("404"))
    data: dict = {ATTR_WIFI_ADAPTER_LENGTH: 2}

    await updater._async_prepare_channels(data)

    assert updater.luci.avaliable_channels.await_count == 2
    assert "2_4_channels" not in data


@pytest.mark.asyncio
async def test_device_list_failure_does_not_abort_the_cycle() -> None:
    """A node that is really gone has already failed at status."""

    updater = _updater(mode=Mode.DEFAULT)
    updater.luci.device_list = AsyncMock(side_effect=LuciConnectionError("Connection error"))

    await updater._async_prepare_device_list({})

    assert updater.devices == {}


@pytest.mark.asyncio
async def test_ap_signal_failure_does_not_abort_the_cycle() -> None:
    """wifi_ap_signal is answered by repeaters only, and not always."""

    updater = _updater(mode=Mode.REPEATER)
    updater.luci.wifi_ap_signal = AsyncMock(side_effect=LuciRequestError("404"))
    data: dict = {}

    await updater._async_prepare_ap(data)

    assert ATTR_SENSOR_AP_SIGNAL not in data


@pytest.mark.asyncio
async def test_new_status_failure_does_not_abort_the_cycle() -> None:
    """new_status is the last step, but it still marks the cycle failed."""

    updater = _updater(mode=Mode.DEFAULT, is_force_load=True)
    updater.luci.new_status = AsyncMock(side_effect=LuciRequestError("404"))
    data: dict = {}

    await updater._async_prepare_new_status(data)

    assert data == {}
