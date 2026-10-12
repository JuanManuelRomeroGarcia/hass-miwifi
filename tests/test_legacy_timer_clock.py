"""Legacy time travel advances coordinator timer deadlines too."""
import asyncio
from datetime import timedelta

from homeassistant.util.dt import utcnow

from tests.setup import async_advance_time


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
