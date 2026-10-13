"""Legacy time travel advances coordinator timer deadlines too."""
import asyncio
from datetime import timedelta
from unittest.mock import patch

from homeassistant.util.dt import utcnow

from tests.setup import async_advance_time


async def test_skipping_router_delay_keeps_ha_event_loop_yield(hass):
    real_sleep = asyncio.sleep
    with patch("custom_components.miwifi.updater.asyncio.sleep", return_value=None):
        assert asyncio.sleep is real_sleep
        callbacks = []
        asyncio.get_running_loop().call_soon(callbacks.append, "yielded")
        await asyncio.sleep(0)
        assert callbacks == ["yielded"]


async def test_time_travel_runs_due_timer_and_advances_its_deadline(hass, legacy_clock):
    loop = asyncio.get_running_loop()
    started = loop.time()
    callbacks = []
    handle = loop.call_later(60, callbacks.append, "due")
    try:
        async_advance_time(hass, legacy_clock, utcnow() + timedelta(seconds=61))
        await hass.async_block_till_done()
        assert callbacks == ["due"]
        assert loop.time() - started >= 61
        await hass.async_block_till_done()
        assert callbacks == ["due"]
    finally:
        handle.cancel()


async def test_time_travel_rearms_poll_for_next_interval(hass, legacy_clock):
    """A polling callback must not immediately run its newly scheduled timer."""
    loop = asyncio.get_running_loop()
    callbacks = []
    handles = []

    def poll():
        callbacks.append(loop.time())
        handles.append(loop.call_later(60, poll))

    handles.append(loop.call_later(60, poll))
    try:
        for expected in range(1, 4):
            async_advance_time(hass, legacy_clock, utcnow() + timedelta(seconds=61))
            await hass.async_block_till_done()
            assert len(callbacks) == expected
    finally:
        for handle in handles:
            handle.cancel()
