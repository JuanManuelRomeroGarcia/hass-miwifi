"""The scheduled purge: conservative parameters, and an off switch that works.

Two defects, both measured on a live instance:

- the job ran with `only_randomized: False` and
  `include_orphans_without_age: True` under `apply: True`. Unattended, with no
  preview anyone reads, that deleted seven trackers - two of them clients
  associated to a router's radios at that moment.
- `every_days = 0` was documented in the UI as "disabled" and implemented as
  `int(s.get("every_days") or DEFAULT)`, which read zero as missing and handed
  back the default of 1. Asking for "never" got "every day".

A third one, also live: every setup recomputed the deadline from now, so an
instance restarting more often than `every_days` pushed it forward forever
and the purge stopped running (last run in August, next_due always a week
away).
"""

# pylint: disable=protected-access

from __future__ import annotations

import asyncio
import copy
from contextlib import contextmanager
from datetime import datetime
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from homeassistant.util import dt as dt_util

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


@pytest.mark.parametrize("disable_before_kickoff", [False, True])
async def test_kickoff_cancels_previous_deadline_and_shutdown_cancels_replacement(
    disable_before_kickoff,
):
    hass = _hass_with_tasks()
    hass.services.async_call = AsyncMock()
    store = {"every_days": 7, "at": "00:00"}
    deadlines = []
    kickoff = []

    def schedule(_hass, callback, when):
        cancel = MagicMock()
        deadlines.append((callback, cancel))
        return cancel

    def schedule_kickoff(_hass, delay, callback):
        cancel = MagicMock()
        kickoff.append((callback, cancel))
        return cancel

    with patch.object(auto_purge, "_load", AsyncMock(side_effect=lambda _h: dict(store))), patch.object(
        auto_purge, "_save", AsyncMock()
    ), patch.object(auto_purge, "async_track_point_in_time", schedule), patch.object(
        auto_purge, "async_call_later", schedule_kickoff
    ):
        schedule_auto_purge(hass, SimpleNamespace(entry_id="entry-1"))
        for coro in hass.pending:
            await coro
        assert len(deadlines) == len(kickoff) == 1
        if disable_before_kickoff:
            store["every_days"] = 0
        await kickoff[0][0]()
        deadlines[0][1].assert_called_once()
        kickoff[0][1].assert_called_once()
        if disable_before_kickoff:
            assert len(deadlines) == 1
            hass.services.async_call.assert_not_awaited()
        else:
            assert len(deadlines) == 2
            hass.services.async_call.assert_awaited_once()
            auto_purge.cancel_auto_purge(hass)
            deadlines[1][1].assert_called_once()


ROME = dt_util.get_time_zone("Europe/Rome")


def _rome(day: int, hour: int, minute: int = 0) -> datetime:
    return datetime(2026, 10, day, hour, minute, tzinfo=ROME)


@pytest.fixture
def rome_time_zone():
    """A zone with an offset and a DST change (25 Oct 2026) inside the window."""

    original = dt_util.DEFAULT_TIME_ZONE
    dt_util.set_default_time_zone(ROME)
    yield
    dt_util.set_default_time_zone(original)


@contextmanager
def _persistent_store(store: dict):
    """Setups against a store that keeps what the scheduler saves.

    `setup(now)` runs schedule_auto_purge as an HA start or entry reload would
    (`kickoff=False` as async_unload_entry does for a remaining entry);
    `armed` collects every deadline handed to the timer, `kicks` every startup
    kickoff as (delay, callback).
    """

    env = SimpleNamespace(armed=[], kicks=[], now=None)
    hass = _hass_with_tasks()
    hass.services.async_call = AsyncMock()
    env.hass = hass

    async def save(_hass, data):
        store.clear()
        store.update(copy.deepcopy(data))

    async def setup(now, kickoff=True, entry_id="entry-1"):
        env.now = now
        hass.pending.clear()
        schedule_auto_purge(hass, SimpleNamespace(entry_id=entry_id), kickoff=kickoff)
        for coro in list(hass.pending):
            await coro

    env.setup = setup

    with patch.object(
        auto_purge, "_load", AsyncMock(side_effect=lambda _h: copy.deepcopy(store))
    ), patch.object(auto_purge, "_save", AsyncMock(side_effect=save)), patch.object(
        auto_purge,
        "async_track_point_in_time",
        lambda _h, _cb, when: env.armed.append(when) or MagicMock(),
    ), patch.object(
        auto_purge,
        "async_call_later",
        lambda _h, delay, cb: env.kicks.append((delay, cb)) or MagicMock(),
    ), patch.object(
        auto_purge.dt_util, "now", lambda *_a, **_k: env.now
    ):
        yield env


def _pending(every_days: int = 7, at: str = "04:10", **extra) -> dict:
    """A store as a run on 11 Oct leaves it: next run on 18 Oct at 04:10."""

    store = {
        "every_days": every_days,
        "at": at,
        "last_run": _rome(11, 4, 10).isoformat(),
        "last_ok": True,
        "next_due": _rome(18, 4, 10).isoformat(),
        "next_due_for": {"every_days": 7, "at": "04:10"},
    }
    store.update(extra)
    return store


def _legacy(**extra) -> dict:
    """The same store as written before next_due_for existed."""

    store = _pending(**extra)
    del store["next_due_for"]
    return store


async def test_a_pending_deadline_survives_a_restart(rome_time_zone) -> None:
    """A setup before the deadline arms the stored deadline, not now + N days."""

    store = _pending()
    stored_due = store["next_due"]

    with _persistent_store(store) as env:
        await env.setup(_rome(15, 12))

    assert env.armed == [_rome(18, 4, 10)]
    assert env.kicks == []
    assert store["next_due"] == stored_due


async def test_daily_restarts_still_reach_the_deadline(rome_time_zone) -> None:
    """The live failure: restarts every day must not postpone a weekly purge."""

    store = _pending()

    with _persistent_store(store) as env:
        for day in (12, 13, 14, 15, 16, 17):
            await env.setup(_rome(day, 9))

    assert env.armed == [_rome(18, 4, 10)] * 6
    assert env.kicks == []
    assert dt_util.parse_datetime(store["next_due"]) == _rome(18, 4, 10)


@pytest.mark.parametrize(
    "now", [_rome(15, 3), _rome(18, 3)], ids=["days before", "on the day"]
)
async def test_a_setup_before_at_keeps_the_deadline(rome_time_zone, now) -> None:
    """A restart in the small hours must not move the purge to that night.

    _next_run() returns today's `at` while it is still ahead, so recomputing on
    a 03:00 restart ran the purge at 04:10 however recently it had run. On the
    due day that is the deadline anyway; on any other day it is not.
    """

    store = _pending()

    with _persistent_store(store) as env:
        await env.setup(now)

    assert env.armed == [_rome(18, 4, 10)]
    assert env.kicks == []


async def test_an_unload_hands_the_pending_deadline_over(rome_time_zone) -> None:
    """async_unload_entry re-arms the schedule on a remaining entry.

    That is the path of every options save on the entry that owns the timer:
    it unloads, and another entry takes over with kickoff=False.
    """

    store = _pending()

    with _persistent_store(store) as env:
        await env.setup(_rome(15, 12), kickoff=False, entry_id="entry-2")

    assert env.armed == [_rome(18, 4, 10)]
    assert env.kicks == []
    assert store["owner"] == "entry-2"
    assert dt_util.parse_datetime(store["next_due"]) == _rome(18, 4, 10)


async def test_a_deadline_saved_before_the_record_existed_is_kept(
    rome_time_zone,
) -> None:
    """The first restarts after an upgrade must not postpone the purge either.

    The code before next_due_for rewrote next_due at every setup, so such a
    store holds a deadline on `at`, at most one period ahead.
    """

    store = _legacy()

    with _persistent_store(store) as env:
        await env.setup(_rome(15, 12))
        await env.setup(_rome(16, 12))

    assert env.armed == [_rome(18, 4, 10)] * 2
    assert env.kicks == []
    assert store["next_due_for"] == {"every_days": 7, "at": "04:10"}


@pytest.mark.parametrize(
    ("label", "store", "expected"),
    [
        # Options flow changed the frequency: the old deadline is not this
        # schedule's, even though it is less than three days ahead.
        (
            "every_days changed",
            _pending(every_days=3, next_due=_rome(17, 4, 10).isoformat()),
            _rome(18, 4, 10),
        ),
        ("at changed", _pending(at="05:30"), _rome(22, 5, 30)),
        # Stores written before next_due_for existed: only the deadline itself
        # can be checked against the schedule.
        (
            "no record, another time of day",
            _legacy(next_due=_rome(18, 5, 30).isoformat()),
            _rome(22, 4, 10),
        ),
        ("no record, beyond the new period", _legacy(every_days=2), _rome(17, 4, 10)),
        ("unparsable deadline", _pending(next_due="soon"), _rome(22, 4, 10)),
        # More than one period ahead: the clock was ahead when it was saved.
        ("too far ahead", _pending(next_due=_rome(30, 4, 10).isoformat()), _rome(22, 4, 10)),
        # Saved under another zone: same instant, wrong local hour.
        ("other time zone", _pending(next_due="2026-10-18T04:10:00+00:00"), _rome(22, 4, 10)),
    ],
)
async def test_a_deadline_from_another_schedule_is_recomputed(
    rome_time_zone, label, store, expected
) -> None:
    """Keep only what this schedule would have produced; recompute the rest."""

    with _persistent_store(store) as env:
        await env.setup(_rome(15, 12))

    assert env.armed == [expected], label
    assert dt_util.parse_datetime(store["next_due"]) == expected
    assert store["next_due_for"] == {"every_days": store["every_days"], "at": store["at"]}


def test_a_naive_deadline_is_not_kept(rome_time_zone) -> None:
    """Without an offset it cannot be ordered against now; recompute instead."""

    store = _pending(next_due="2026-10-18T04:10:00")

    assert auto_purge._kept_deadline(store, _rome(15, 12), auto_purge._parse_hhmm("04:10"), 7) is None


async def test_an_overdue_deadline_still_kicks_off_once(rome_time_zone) -> None:
    """Missed while HA was down: one delayed run, then the regular schedule.

    The next deadline lands after the DST change (+02:00 -> +01:00, 25 Oct).
    """

    store = _pending()

    with _persistent_store(store) as env:
        await env.setup(_rome(19, 9))

        assert [delay for delay, _cb in env.kicks] == [60]
        assert env.armed == [_rome(26, 4, 10)]

        await env.kicks[0][1]()

        env.hass.services.async_call.assert_awaited_once()
        assert env.armed[-1] == _rome(26, 4, 10)
        assert store["next_due_for"] == {"every_days": 7, "at": "04:10"}

        # A restart after that run keeps its deadline and does not kick again.
        await env.setup(_rome(20, 9))

    assert len(env.kicks) == 1
    assert env.armed[-1] == _rome(26, 4, 10)
    assert dt_util.parse_datetime(store["next_due"]) == _rome(26, 4, 10)
