"""A roaming client belongs to the node serving it, and to that node only.

One entity per client MAC across the whole mesh is deliberate. The registry,
however, records a **device row per config entry** that ever published the
client, and nothing takes those rows away again: on the mesh this was traced on,
a phone that had roamed sat under two nodes at the same time, so no entry's
device list meant "the clients on this node".

Two things therefore have to happen, and the first alone is not enough - the
first cut of this moved one row and left the others exactly where they were,
which is what a live registry showed afterwards: an empty device sitting under a
node that serves nothing. The row carrying the tracker moves to the serving
node, and the rows left behind under our other entries go.

The order inside the move is the load-bearing part. The entity registry deletes
an entity when its device row changes config entry while the entity still points
at the old one, so dropping the old node before pointing the entity at the new
one deletes the tracker outright.

A row that still has entities on it is never removed: removing a row takes down
the entities belonging to that row's config entry.
"""

# pylint: disable=protected-access

from __future__ import annotations

import pytest
from unittest.mock import AsyncMock, MagicMock, patch

from homeassistant.helpers.update_coordinator import CoordinatorEntity

from custom_components.miwifi.const import ATTR_TRACKER_UPDATER_ENTRY_ID
from custom_components.miwifi.device_tracker import (
    MiWifiDeviceTracker,
    _reparent_client_device,
)

MAC: str = "00:00:00:00:00:01"
OLD: str = "entry_old"
NEW: str = "entry_new"
FOREIGN: str = "entry_of_another_integration"


class _Device:
    """One device registry row. Since core 2026.9 a row has a single entry."""

    _next: int = 0

    def __init__(self, config_entries: set[str], entities: int = 0) -> None:
        _Device._next += 1
        self.id = f"device_{_Device._next}"
        self.config_entries = set(config_entries)
        self.entities = entities


class _LegacyDeviceRegistry:
    """A core before 2026.9: no async_get_devices, one row holds every entry."""

    def __init__(self, rows: list[_Device], calls: list) -> None:
        self.rows = rows
        self._calls = calls

    def async_get_device(self, identifiers=None, connections=None):
        return self.rows[0] if self.rows else None

    def _row(self, device_id: str) -> _Device:
        return next(row for row in self.rows if row.id == device_id)

    def async_update_device(
        self,
        device_id,
        *,
        add_config_entry_id=None,
        remove_config_entry_id=None,
        new_config_entry_id=None,
        **kw,
    ):
        row = self._row(device_id)
        if new_config_entry_id is not None:
            row.config_entries = {new_config_entry_id}
            self._calls.append(("device-move", new_config_entry_id))
        if add_config_entry_id is not None:
            row.config_entries.add(add_config_entry_id)
            self._calls.append(("device-add", add_config_entry_id))
        if remove_config_entry_id is not None:
            row.config_entries.discard(remove_config_entry_id)
            self._calls.append(("device-remove", remove_config_entry_id))

    def async_remove_device(self, device_id) -> None:
        self.rows = [row for row in self.rows if row.id != device_id]
        self._calls.append(("row-remove", device_id))


class _DeviceRegistry(_LegacyDeviceRegistry):
    """Core 2026.9 and later: one row per config entry, all of them listed."""

    def async_get_devices(self, *, identifiers=None, connections=None, **kw):
        return list(self.rows)


class _EntityEntry:
    def __init__(self, config_entry_id: str, device_id: str | None = None) -> None:
        self.entity_id = f"device_tracker.miwifi_{MAC.replace(':', '_')}"
        self.config_entry_id = config_entry_id
        self.device_id = device_id


class _EntityRegistry:
    def __init__(self, entry: _EntityEntry | None, calls: list) -> None:
        self._entry = entry
        self._calls = calls

    def async_get_entity_id(self, domain, platform, unique_id):
        return self._entry.entity_id if self._entry else None

    def async_get(self, entity_id):
        return self._entry

    def async_update_entity(self, entity_id, *, config_entry_id=None, **kw):
        self._entry.config_entry_id = config_entry_id
        self._calls.append(("entity-move", config_entry_id))


def _run(
    rows: list[_Device],
    entity: _EntityEntry | None,
    owner: str = NEW,
    legacy: bool = False,
    modern_move: bool = False,
):
    """Drive the helper against fake registries; return (moved, calls, registry)."""

    calls: list = []
    hass = MagicMock()
    hass.config_entries.async_entries.return_value = [
        MagicMock(entry_id=OLD),
        MagicMock(entry_id=NEW),
    ]

    dev_reg = (_LegacyDeviceRegistry if legacy else _DeviceRegistry)(rows, calls)

    def _entries_for_device(registry, device_id, include_disabled_entities=False):
        return [object()] * dev_reg._row(device_id).entities

    with (
        patch(
            "custom_components.miwifi.device_tracker.dr.async_get",
            return_value=dev_reg,
        ),
        patch(
            "custom_components.miwifi.device_tracker.er.async_get",
            return_value=_EntityRegistry(entity, calls),
        ),
        patch(
            "custom_components.miwifi.device_tracker.er.async_entries_for_device",
            _entries_for_device,
        ),
        patch(
            "custom_components.miwifi.device_tracker._MOVES_WITH_NEW_CONFIG_ENTRY_ID",
            modern_move,
        ),
    ):
        moved = _reparent_client_device(hass, MAC, owner)

    return moved, calls, dev_reg


def test_a_roamed_client_ends_up_on_one_node_only() -> None:
    """The observed defect: the same MAC listed under two nodes at once."""

    row = _Device({OLD}, entities=1)
    entity = _EntityEntry(OLD, device_id=row.id)

    moved, _, _ = _run([row], entity)

    assert moved is True
    assert row.config_entries == {NEW}
    assert entity.config_entry_id == NEW


def test_the_entity_moves_before_the_old_node_is_dropped() -> None:
    """Reversed, HA deletes the tracker along with its history."""

    row = _Device({OLD}, entities=1)

    _, calls, _ = _run([row], _EntityEntry(OLD, device_id=row.id))

    assert calls.index(("entity-move", NEW)) < calls.index(("device-remove", OLD))
    assert calls.index(("device-add", NEW)) < calls.index(("device-remove", OLD))


def test_a_client_that_has_not_moved_is_left_alone() -> None:
    """The steady state is every cycle of every client: it must not write."""

    row = _Device({NEW}, entities=1)

    moved, calls, _ = _run([row], _EntityEntry(NEW, device_id=row.id))

    assert moved is False
    assert calls == []


def test_the_row_another_node_left_behind_is_removed() -> None:
    """The regression a live registry showed: an empty device under a node.

    Moving one row cleans nothing when the duplicate is a second row, which is
    how core 2026.9 records "this client was also seen over there".
    """

    kept = _Device({NEW}, entities=1)
    leftover = _Device({OLD}, entities=0)

    moved, calls, dev_reg = _run([kept, leftover], _EntityEntry(NEW, device_id=kept.id))

    assert moved is True
    assert dev_reg.rows == [kept]
    assert ("row-remove", leftover.id) in calls


def test_the_row_carrying_the_tracker_is_the_one_that_moves() -> None:
    """Move any other and the entity is left behind on a row about to go."""

    carries = _Device({OLD}, entities=1)
    empty = _Device({NEW}, entities=0)

    moved, calls, dev_reg = _run(
        [empty, carries], _EntityEntry(OLD, device_id=carries.id)
    )

    assert moved is True
    assert carries.config_entries == {NEW}
    assert dev_reg.rows == [carries]
    assert ("row-remove", empty.id) in calls


def test_an_occupied_row_is_never_removed() -> None:
    """Removing a row takes its entities with it. A stale listing is cheaper."""

    kept = _Device({NEW}, entities=1)
    occupied = _Device({OLD}, entities=2)

    moved, calls, dev_reg = _run([kept, occupied], _EntityEntry(NEW, device_id=kept.id))

    assert moved is False
    assert occupied in dev_reg.rows
    assert calls == []


def test_rows_belonging_to_other_integrations_are_not_touched() -> None:
    """The same hardware may legitimately be held by somebody else."""

    kept = _Device({NEW}, entities=1)
    foreign = _Device({FOREIGN}, entities=0)

    moved, calls, dev_reg = _run([kept, foreign], _EntityEntry(NEW, device_id=kept.id))

    assert moved is False
    assert foreign in dev_reg.rows
    assert calls == []


def test_a_second_link_on_one_row_is_still_dropped() -> None:
    """Cores before 2026.9 put several entries on a single row."""

    row = _Device({OLD, NEW, FOREIGN}, entities=1)

    moved, _, _ = _run([row], _EntityEntry(NEW, device_id=row.id))

    assert moved is True
    assert row.config_entries == {NEW, FOREIGN}


def test_an_older_core_without_async_get_devices_still_works() -> None:
    """There the single lookup is the whole truth, so it is enough."""

    row = _Device({OLD}, entities=1)

    moved, _, _ = _run([row], _EntityEntry(OLD, device_id=row.id), legacy=True)

    assert moved is True
    assert row.config_entries == {NEW}


def test_a_client_with_no_device_yet_is_not_an_error() -> None:
    """First sighting: the device is created by the platform, not here."""

    moved, calls, _ = _run([], None)

    assert moved is False
    assert calls == []


def test_an_entity_the_registry_cannot_place_still_picks_a_row() -> None:
    """A tracker with no device_id must not send us to an arbitrary row."""

    on_target = _Device({NEW}, entities=0)
    other = _Device({OLD}, entities=0)

    moved, calls, dev_reg = _run([other, on_target], _EntityEntry(NEW, device_id=None))

    assert moved is True
    assert dev_reg.rows == [on_target]
    assert ("row-remove", other.id) in calls


def test_a_recent_core_moves_the_row_with_one_call() -> None:
    """From 2026.9 the add/remove pair is deprecated: `new_config_entry_id`."""

    row = _Device({OLD}, entities=1)

    moved, calls, _ = _run(
        [row], _EntityEntry(OLD, device_id=row.id), modern_move=True
    )

    assert moved is True
    assert row.config_entries == {NEW}
    assert ("device-move", NEW) in calls
    assert not [call for call in calls if call[0] in ("device-add", "device-remove")]


def test_the_entity_still_moves_first_on_a_recent_core() -> None:
    """The rule that forces the order changed shape, not direction."""

    row = _Device({OLD}, entities=1)

    _, calls, _ = _run([row], _EntityEntry(OLD, device_id=row.id), modern_move=True)

    assert calls.index(("entity-move", NEW)) < calls.index(("device-move", NEW))


@pytest.mark.asyncio
async def test_the_cleanup_also_runs_when_the_tracker_is_first_added() -> None:
    """A restart never reaches the update branch, and that is when rows pile up.

    Adding the entity is what creates the client's device row, under the entry
    whose platform added it. On a live registry this left the previous node
    holding an empty row every single restart - three rows for one phone after
    three restarts - because only roaming was cleaning up.
    """

    entity = MagicMock()
    entity.hass.data = {}
    entity.unique_id = f"miwifi-{MAC}"
    entity.mac_address = MAC
    entity._device = {ATTR_TRACKER_UPDATER_ENTRY_ID: NEW}
    entity._enable_port_probe = False

    with (
        patch.object(CoordinatorEntity, "async_added_to_hass", AsyncMock()),
        patch(
            "custom_components.miwifi.device_tracker._reparent_client_device"
        ) as reparent,
    ):
        await MiWifiDeviceTracker.async_added_to_hass(entity)

    reparent.assert_called_once_with(entity.hass, MAC, NEW)


@pytest.mark.asyncio
async def test_a_tracker_with_no_serving_entry_is_left_alone() -> None:
    """Without an owner there is no row to keep, and removing any is guesswork."""

    entity = MagicMock()
    entity.hass.data = {}
    entity.unique_id = f"miwifi-{MAC}"
    entity.mac_address = MAC
    entity._device = {}
    entity._enable_port_probe = False

    with (
        patch.object(CoordinatorEntity, "async_added_to_hass", AsyncMock()),
        patch(
            "custom_components.miwifi.device_tracker._reparent_client_device"
        ) as reparent,
    ):
        await MiWifiDeviceTracker.async_added_to_hass(entity)

    reparent.assert_not_called()
