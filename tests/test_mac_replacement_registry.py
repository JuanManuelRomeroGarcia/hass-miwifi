"""MAC replacement must read the device registry without the deprecated mapping API."""

from types import SimpleNamespace
from unittest.mock import patch

import pytest

from homeassistant.helpers import device_registry as dr
from homeassistant.helpers import entity_registry as er
from pytest_homeassistant_custom_component.common import MockConfigEntry

from custom_components.miwifi.mac_replacement import get_mac_replacement
from custom_components.miwifi.registry import all_devices

OLD = "02:00:00:00:00:31"


async def test_configure_reads_registry_clients_without_mapping_access(hass):
    """Saving the rules iterates the registry instead of calling `.values()`."""
    view = getattr(dr, "_DeprecatedDeviceRegistryItemsView", None)
    if view is None:
        pytest.skip("this core still returns a plain mapping")

    entry = MockConfigEntry(domain="miwifi")
    entry.add_to_hass(hass)
    device = dr.async_get(hass).async_get_or_create(
        config_entry_id=entry.entry_id, identifiers={("miwifi", OLD.lower())}, name="Watch"
    )
    er.async_get(hass).async_get_or_create(
        "device_tracker", "miwifi", f"miwifi-{OLD.lower()}",
        config_entry=entry, device_id=device.id, original_name="Watch",
    )

    with patch.object(view, "_report_deprecated_use", side_effect=AssertionError("mapping access")):
        await get_mac_replacement(hass).async_configure({"watch": ["Watch"]}, [])

    # The registry-only client was still found and associated by its name.
    assert OLD in get_mac_replacement(hass)._groups["watch"]["macs"]


def test_all_devices_accepts_both_registry_shapes() -> None:
    first, second = SimpleNamespace(id="a"), SimpleNamespace(id="b")

    # 2026.9+: iterating the view yields the entries.
    assert all_devices(SimpleNamespace(devices=[first, second])) == [first, second]

    # Older cores: a mapping, where iterating yields ids.
    rows = {"a": first, "b": second}
    legacy = SimpleNamespace(devices=rows, async_get=rows.get)
    assert all_devices(legacy) == [first, second]
