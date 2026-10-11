"""The bundled frontend no longer has a separate update entity."""

from types import SimpleNamespace
from unittest.mock import patch

from homeassistant.helpers import entity_registry as er
from homeassistant.helpers import device_registry as dr
from pytest_homeassistant_custom_component.common import MockConfigEntry

from custom_components.miwifi.update import async_setup_entry


async def test_remove_renamed_disabled_panel_preserve_other_updates(hass):
    entry = MockConfigEntry(domain="miwifi")
    entry.add_to_hass(hass)
    registry = er.async_get(hass)
    device = dr.async_get(hass).async_get_or_create(
        config_entry_id=entry.entry_id, identifiers={("miwifi", "miwifi_panel")},
        model="Panel Frontend", name="MiWiFi Panel",
    )
    panel = registry.async_get_or_create(
        "update", "miwifi", f"{entry.entry_id}_miwifi_panel",
        config_entry=entry, suggested_object_id="renamed_panel",
        device_id=device.id,
        disabled_by=er.RegistryEntryDisabler.USER,
    )
    firmware = registry.async_get_or_create(
        "update", "miwifi", f"{entry.entry_id}-firmware", config_entry=entry,
    )
    unrelated = registry.async_get_or_create(
        "update", "other", f"{entry.entry_id}_miwifi_panel", config_entry=entry,
    )
    updater = SimpleNamespace(supports_update=False, data={"topo_graph": {
        "graph": {"is_main": True},
    }})
    added = []
    with patch("custom_components.miwifi.update.async_get_updater", return_value=updater):
        await async_setup_entry(hass, entry, added.extend)
        await async_setup_entry(hass, entry, added.extend)
    assert registry.async_get(panel.entity_id) is None
    assert dr.async_get(hass).async_get(device.id) is None
    assert registry.async_get(firmware.entity_id) is not None
    assert registry.async_get(unrelated.entity_id) is not None
    assert added == []
