"""The scheduled purge: conservative parameters, and an off switch that works.

Two defects, both measured on a live instance:

- the job ran with `only_randomized: False` and
  `include_orphans_without_age: True` under `apply: True`. Unattended, with no
  preview anyone reads, that deleted seven trackers - two of them clients
  associated to a router's radios at that moment.
- `every_days = 0` was documented in the UI as "disabled" and implemented as
  `int(s.get("every_days") or DEFAULT)`, which read zero as missing and handed
  back the default of 1. Asking for "never" got "every day".
"""

# pylint: disable=protected-access

from __future__ import annotations

import asyncio
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from custom_components.miwifi import auto_purge
from custom_components.miwifi.auto_purge import (
    AUTO_PURGE_FIRST,
    AUTO_PURGE_UNSUB,
    DOMAIN,
    schedule_auto_purge,
)


def _hass_with_tasks() -> MagicMock:
    """A hass whose async_create_task actually awaits, so _prime runs."""

    hass = MagicMock()
    hass.data = {}

    tasks: list = []
    hass.async_create_task.side_effect = tasks.append
    hass.pending = tasks
    return hass


async def _schedule(store: dict) -> tuple[MagicMock, list, list]:
    hass = _hass_with_tasks()
    entry = SimpleNamespace(entry_id="entry-1")

    scheduled: list = []
    later: list = []

    with patch.object(auto_purge, "_load", AsyncMock(return_value=dict(store))), patch.object(
        auto_purge, "_save", AsyncMock()
    ), patch.object(
        auto_purge,
        "async_track_point_in_time",
        lambda _h, _cb, when: scheduled.append(when) or (lambda: None),
    ), patch.object(
        auto_purge,
        "async_call_later",
        lambda _h, delay, _cb: later.append(delay) or (lambda: None),
    ):
        schedule_auto_purge(hass, entry, kickoff=True)
        for coro in hass.pending:
            await coro

    return hass, scheduled, later


@pytest.mark.asyncio
async def test_zero_disables_the_scheduled_purge() -> None:
    """every_days=0 schedules nothing and kicks nothing off."""

    hass, scheduled, later = await _schedule({"every_days": 0, "at": "00:00"})

    assert scheduled == []
    assert later == []
    assert AUTO_PURGE_UNSUB not in hass.data.get(DOMAIN, {})
    assert AUTO_PURGE_FIRST not in hass.data.get(DOMAIN, {})


@pytest.mark.asyncio
async def test_a_missing_value_still_takes_the_default() -> None:
    """Absent is not zero: the default frequency still applies."""

    _hass, scheduled, _later = await _schedule({"at": "00:00"})

    assert len(scheduled) == 1


@pytest.mark.asyncio
async def test_a_positive_value_schedules_normally() -> None:
    """The ordinary path is untouched."""

    _hass, scheduled, _later = await _schedule({"every_days": 7, "at": "00:00"})

    assert len(scheduled) == 1


def test_scheduled_parameters_are_the_conservative_ones() -> None:
    """The unattended job must not delete stable MACs or undatable rows.

    Read off the source rather than executed: the params live inside a closure
    that a fired timer builds, and what matters is the literal.
    """

    source = (auto_purge.__file__).replace(".pyc", ".py")
    with open(source, "r", encoding="utf-8") as handle:
        body = handle.read()

    params = body.split('params = {', 1)[1].split('}', 1)[0]

    assert '"only_randomized": True' in params
    assert '"include_orphans_without_age": False' in params
    assert '"apply": True' in params
