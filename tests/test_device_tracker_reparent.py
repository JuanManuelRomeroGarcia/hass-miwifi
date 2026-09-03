"""A roaming client belongs to the node serving it, and to that node only.

One entity per client MAC across the whole mesh is deliberate. The registry,
however, still recorded the client against whichever entry created its entity,
and Home Assistant lists a device under every config entry linked to it while
never unlinking one by itself. Links therefore accumulated: on the mesh this was
traced on, a phone that had roamed sat under two nodes at the same time, and no
entry's device list meant "the clients on this node".

The order of the three registry writes is the load-bearing part. HA removes the
entities of a config entry as soon as that entry comes off their device, so
dropping the old node before pointing the entity at the new one deletes the
tracker outright.
"""

# pylint: disable=protected-access

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from custom_components.miwifi.const import DOMAIN
from custom_components.miwifi.device_tracker import _reparent_client_device

MAC: str = "00:00:00:00:00:01"
OLD: str = "entry_old"
NEW: str = "entry_new"
FOREIGN: str = "entry_of_another_integration"


class _Device:
    def __init__(self, config_entries: set[str]) -> None:
        self.id = "device_id"
        self.config_entries = set(config_entries)


class _DeviceRegistry:
    def __init__(self, device: _Device | None, calls: list) -> None:
        self._device = device
        self._calls = calls

    def async_get_device(self, identifiers=None, connections=None):
        return self._device

    def async_update_device(
        self, device_id, *, add_config_entry_id=None, remove_config_entry_id=None, **kw
    ):
        if add_config_entry_id is not None:
            self._device.config_entries.add(add_config_entry_id)
            self._calls.append(("device-add", add_config_entry_id))
        if remove_config_entry_id is not None:
            self._device.config_entries.discard(remove_config_entry_id)
            self._calls.append(("device-remove", remove_config_entry_id))


class _EntityEntry:
    def __init__(self, config_entry_id: str) -> None:
        self.entity_id = f"device_tracker.miwifi_{MAC.replace(':', '_')}"
        self.config_entry_id = config_entry_id


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


def _run(device: _Device | None, entity: _EntityEntry | None, owner: str = NEW):
    """Drive the helper against fake registries; return (moved, call log)."""

    calls: list = []
    hass = MagicMock()
    hass.config_entries.async_entries.return_value = [
        MagicMock(entry_id=OLD),
        MagicMock(entry_id=NEW),
    ]

    with (
        patch(
            "custom_components.miwifi.device_tracker.dr.async_get",
            return_value=_DeviceRegistry(device, calls),
        ),
        patch(
            "custom_components.miwifi.device_tracker.er.async_get",
            return_value=_EntityRegistry(entity, calls),
        ),
    ):
        moved = _reparent_client_device(hass, MAC, owner)

    return moved, calls


def test_a_roamed_client_ends_up_on_one_node_only() -> None:
    """The observed defect: the same MAC listed under two nodes at once."""

    device = _Device({OLD})
    entity = _EntityEntry(OLD)

    moved, _ = _run(device, entity)

    assert moved is True
    assert device.config_entries == {NEW}
    assert entity.config_entry_id == NEW


def test_the_entity_moves_before_the_old_node_is_dropped() -> None:
    """Reversed, HA deletes the tracker along with its history."""

    _, calls = _run(_Device({OLD}), _EntityEntry(OLD))

    assert calls.index(("entity-move", NEW)) < calls.index(("device-remove", OLD))
    assert calls.index(("device-add", NEW)) < calls.index(("device-remove", OLD))


def test_a_client_that_has_not_moved_is_left_alone() -> None:
    """The steady state is every cycle of every client: it must not write."""

    moved, calls = _run(_Device({NEW}), _EntityEntry(NEW))

    assert moved is False
    assert calls == []


def test_links_belonging_to_other_integrations_are_not_touched() -> None:
    """The same hardware may legitimately be held by somebody else."""

    device = _Device({OLD, FOREIGN})

    moved, _ = _run(device, _EntityEntry(OLD))

    assert moved is True
    assert device.config_entries == {NEW, FOREIGN}


def test_stale_links_are_cleaned_even_when_the_entity_is_already_right() -> None:
    """Upgrading finds the accumulation already there, entity on the right node."""

    device = _Device({OLD, NEW})

    moved, calls = _run(device, _EntityEntry(NEW))

    assert moved is True
    assert device.config_entries == {NEW}
    assert ("entity-move", NEW) not in calls


def test_a_client_with_no_device_yet_is_not_an_error() -> None:
    """First sighting: the device is created by the platform, not here."""

    moved, calls = _run(None, None)

    assert moved is False
    assert calls == []
