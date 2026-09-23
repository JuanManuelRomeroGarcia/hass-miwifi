"""`_all_device_entries` must not use the device registry as a mapping.

From HA 2026.9 `DeviceRegistry.devices` is a view whose iteration yields
`DeviceEntry` objects; `.values()`, `.get()` and subscription are deprecated
and are removed in 2027.9. Custom integrations only get a log line today, so
the regression is silent - these tests are what makes it loud.
"""

from __future__ import annotations

import sys
import types
from unittest.mock import MagicMock

import pytest


def _load_helper():
    """Import `_all_device_entries` without dragging in Home Assistant."""

    from custom_components.miwifi.services import _all_device_entries

    return _all_device_entries


class _ModernView:
    """2026.9 `_DeprecatedDeviceRegistryItemsView`: iteration yields entries."""

    def __init__(self, entries):
        self._entries = list(entries)

    def __iter__(self):
        return iter(self._entries)

    def __len__(self):
        return len(self._entries)

    def __getattr__(self, name):
        raise AssertionError(f"deprecated mapping method used: {name}")

    def __getitem__(self, key):
        raise AssertionError("deprecated subscription used")


class _LegacyItems(dict):
    """Pre-2026.9 container: a dict, so iteration yields device ids."""


class _Registry:
    def __init__(self, devices):
        self.devices = devices

    def async_get(self, device_id):
        if isinstance(self.devices, _LegacyItems):
            return self.devices.get(device_id)
        raise AssertionError("async_get is only the legacy path")


def _entry(device_id):
    entry = MagicMock()
    entry.id = device_id
    return entry


def test_modern_view_is_iterated_not_mapped():
    a, b = _entry("a"), _entry("b")
    reg = _Registry(_ModernView([a, b]))

    assert _load_helper()(reg) == [a, b]


def test_legacy_dict_ids_are_resolved_to_entries():
    a, b = _entry("a"), _entry("b")
    reg = _Registry(_LegacyItems({"a": a, "b": b}))

    assert _load_helper()(reg) == [a, b]


def test_legacy_id_that_no_longer_resolves_is_dropped():
    """A row removed between the listing and the lookup must not become None."""

    a = _entry("a")
    items = _LegacyItems({"a": a, "gone": None})
    reg = _Registry(items)

    assert _load_helper()(reg) == [a]


def test_iteration_is_materialised_before_use():
    """The purge deletes rows while walking, so the list must be a snapshot."""

    a, b = _entry("a"), _entry("b")
    view = _ModernView([a, b])
    result = _load_helper()(_Registry(view))

    view._entries.clear()

    assert result == [a, b]
