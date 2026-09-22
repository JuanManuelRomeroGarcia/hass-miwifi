"""A tracker nobody can date must not be deleted on that basis alone.

A restart leaves every tracker the integration does not recreate with no
last-activity attribute and no entry in any updater's `devices` map. The purge
called that `entity_without_age` and, with `include_orphans_without_age` at its
default `true`, deleted it - on a mesh where one node does not enumerate its own
clients, that set includes devices connected at that moment.

The state still records when it last moved, and that is a floor on the client's
age. It is used here to rule a row *out* only: `last_changed` is reset by a
restart, so a recent value proves nothing except that deleting would be wrong.
"""

# pylint: disable=protected-access

from __future__ import annotations

import time
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from custom_components.miwifi.const import DOMAIN
from custom_components.miwifi.services import MiWifiPurgeInactiveDevicesServiceCall

RANDOMIZED_MAC: str = "FE:00:00:00:00:0A"
DAY: int = 86400


class _FakeEntityEntry:
    def __init__(self, entity_id: str, unique_id: str) -> None:
        self.entity_id = entity_id
        self.unique_id = unique_id
        self.platform = DOMAIN
        self.domain = "device_tracker"
        self.device_id = "dev-1"
        self.config_entry_id = "entry-1"


class _FakeEntityRegistry:
    def __init__(self, entries: list[_FakeEntityEntry]) -> None:
        self.entities = {entry.entity_id: entry for entry in entries}
        self.removed: list[str] = []

    def async_get(self, entity_id: str):
        return self.entities.get(entity_id)

    def async_remove(self, entity_id: str) -> None:
        self.removed.append(entity_id)
        self.entities.pop(entity_id, None)


class _FakeState:
    """A restored tracker: unavailable, no attributes, and a last_changed."""

    def __init__(self, changed_ts: float) -> None:
        self.state = "unavailable"
        self.attributes: dict = {}
        self.last_changed = SimpleNamespace(timestamp=lambda: changed_ts)


async def _run(last_changed_ts: float | None, **data) -> dict:
    entry = _FakeEntityEntry(
        "device_tracker.miwifi_fe_00_00_00_00_0a", f"{DOMAIN}-{RANDOMIZED_MAC.lower()}"
    )
    ent_reg = _FakeEntityRegistry([entry])

    hass = MagicMock()
    hass.states.get.return_value = (
        None if last_changed_ts is None else _FakeState(last_changed_ts)
    )

    notifier = MagicMock()
    notifier.get_translations = AsyncMock(return_value={})
    notifier.notify = AsyncMock()

    service = MiWifiPurgeInactiveDevicesServiceCall(hass)
    call = SimpleNamespace(
        data={
            "days": 7,
            "only_randomized": True,
            "include_orphans": False,
            "verbose": False,
            "apply": True,
            **data,
        }
    )

    with patch(
        "custom_components.miwifi.services.er",
        SimpleNamespace(
            async_get=lambda _hass: ent_reg,
            async_entries_for_device=lambda *_a, **_k: [],
        ),
    ), patch(
        "custom_components.miwifi.services.dr",
        SimpleNamespace(
            async_get=lambda _hass: SimpleNamespace(
                devices={},
                async_get=lambda _device_id: None,
                async_remove_device=lambda _device_id: None,
            )
        ),
    ), patch(
        "custom_components.miwifi.services.async_get_integrations", return_value={}
    ), patch(
        "custom_components.miwifi.services.async_dispatcher_send"
    ), patch(
        "custom_components.miwifi.services.MiWiFiNotifier", return_value=notifier
    ):
        await service.async_call_service(call)

    return {"removed": ent_reg.removed}


@pytest.mark.asyncio
async def test_recent_state_change_protects_an_undatable_tracker() -> None:
    """A row whose state moved an hour ago is not seven days inactive."""

    result = await _run(time.time() - 3600, include_orphans_without_age=True)

    assert result["removed"] == []


@pytest.mark.asyncio
async def test_undatable_and_long_untouched_still_purges() -> None:
    """The guard rules rows out, it does not keep everything forever."""

    result = await _run(time.time() - 30 * DAY, include_orphans_without_age=True)

    assert result["removed"] == ["device_tracker.miwifi_fe_00_00_00_00_0a"]


@pytest.mark.asyncio
async def test_flag_off_skips_undatable_rows_regardless() -> None:
    """include_orphans_without_age=False is still the outright answer."""

    result = await _run(time.time() - 30 * DAY, include_orphans_without_age=False)

    assert result["removed"] == []


@pytest.mark.asyncio
async def test_missing_state_falls_back_to_the_flag() -> None:
    """No state at all leaves the flag as the only signal, as before."""

    assert (await _run(None, include_orphans_without_age=False))["removed"] == []
    assert (await _run(None, include_orphans_without_age=True))["removed"] == [
        "device_tracker.miwifi_fe_00_00_00_00_0a"
    ]
