"""Validate selective purge inputs before any registry changes."""

import pytest
import voluptuous as vol
import datetime
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

from homeassistant.helpers import device_registry as dr, entity_registry as er
from pytest_homeassistant_custom_component.common import MockConfigEntry

from custom_components.miwifi.services import MiWifiPurgeInactiveDevicesServiceCall


@pytest.mark.parametrize("macs", [[], ["invalid"],
    ["02:11:22:33:44:55", "invalid"]])
def test_invalid_mac_allowlist_is_rejected(macs):
    with pytest.raises(vol.Invalid):
        MiWifiPurgeInactiveDevicesServiceCall.schema({"macs": macs})


def test_single_address_is_normalized_to_a_list():
    data = MiWifiPurgeInactiveDevicesServiceCall.schema({"macs": "02:11:22:33:44:55"})
    assert data["macs"] == ["02:11:22:33:44:55"]
    assert not data["apply"]


@pytest.mark.parametrize("protection", [None, "recent_node", "foreign_entity", "unselected", "recent_unknown"])
async def test_selected_sensor_remnants_preview_matches_apply(hass, protection):
    """Clean old sensor-only clients, preserving fresh and unrelated records."""
    entry = MockConfigEntry(domain="miwifi")
    entry.add_to_hass(hass)
    mac = "D6:0B:BE:26:F0:8B"
    device = dr.async_get(hass).async_get_or_create(
        config_entry_id=entry.entry_id, identifiers={("miwifi", mac.lower())},
    )
    registry = er.async_get(hass)
    sensors = [registry.async_get_or_create(
        "sensor", "miwifi", f"miwifi-dev-{mac.lower()}-{key}",
        config_entry=entry, device_id=device.id,
        disabled_by=er.RegistryEntryDisabler.USER if key == "signal" else None,
    ) for key in ("last_activity", "signal")]
    old = datetime.datetime.now() - datetime.timedelta(days=10)
    integrations = {"main": {"updater": SimpleNamespace(devices={
        mac: {"last_activity": old.strftime("%Y-%m-%dT%H:%M:%S")},
    }, async_purge_clients=AsyncMock()), "entry_id": entry.entry_id}}
    hass.states.async_set(sensors[0].entity_id, old.isoformat())
    if protection == "recent_node":
        integrations["mesh"] = {"updater": SimpleNamespace(devices={
            mac: {"last_activity": datetime.datetime.now().strftime("%Y-%m-%dT%H:%M:%S")},
        }, async_purge_clients=AsyncMock())}
    elif protection == "foreign_entity":
        registry.async_get_or_create("sensor", "other", "foreign", config_entry=entry, device_id=device.id)
    elif protection == "recent_unknown":
        integrations = {}
        hass.states.async_set(sensors[0].entity_id, "unavailable")
    data = {"macs": [mac if protection != "unselected" else "02:11:22:33:44:55"],
            "days": 1, "include_orphans": True, "include_orphans_without_age": True,
            "only_randomized": True, "verbose": False, "apply": False}
    notifier = SimpleNamespace(get_translations=AsyncMock(return_value={}), notify=AsyncMock())
    with patch("custom_components.miwifi.services.async_get_integrations", return_value=integrations), \
         patch("custom_components.miwifi.services.MiWiFiNotifier", return_value=notifier):
        service = MiWifiPurgeInactiveDevicesServiceCall(hass)
        preview = await service.async_call_service(SimpleNamespace(data=data))
        assert preview["entities"] == (2 if protection is None else 0)
        assert dr.async_get(hass).async_get(device.id) is not None
        assert all(registry.async_get(sensor.entity_id) for sensor in sensors)
        data["apply"] = True
        result = await service.async_call_service(SimpleNamespace(data=data))
        assert result["entities"] == preview["entities"]
        assert result["devices"] == preview["devices"] == (1 if protection is None else 0)
        assert (dr.async_get(hass).async_get(device.id) is None) == (protection is None)
        assert all((registry.async_get(sensor.entity_id) is None) == (protection is None) for sensor in sensors)


async def test_purge_counts_device_removed_by_signal_handler(hass):
    """The tracker cleanup may remove an empty device before the service does."""
    entry = MockConfigEntry(domain="miwifi")
    entry.add_to_hass(hass)
    mac = "D6:0B:BE:26:F0:8B"
    devices = dr.async_get(hass)
    device = devices.async_get_or_create(
        config_entry_id=entry.entry_id, identifiers={("miwifi", mac.lower())},
    )
    registry = er.async_get(hass)
    tracker = registry.async_get_or_create("device_tracker", "miwifi", f"miwifi-{mac.lower()}",
        config_entry=entry, device_id=device.id)
    old = (datetime.datetime.now() - datetime.timedelta(days=10)).strftime("%Y-%m-%dT%H:%M:%S")
    hass.states.async_set(tracker.entity_id, "not_home", {"mac": mac, "last_activity": old})
    integrations = {"main": {"entry_id": entry.entry_id}}
    notifier = SimpleNamespace(get_translations=AsyncMock(return_value={}), notify=AsyncMock())

    def remove_by_signal(_hass, _signal, entry_id, address):
        assert entry_id == entry.entry_id
        assert address == mac
        registry.async_remove(tracker.entity_id)
        devices.async_remove_device(device.id)

    with patch("custom_components.miwifi.services.async_get_integrations", return_value=integrations), \
         patch("custom_components.miwifi.services.MiWiFiNotifier", return_value=notifier), \
         patch("custom_components.miwifi.services.async_dispatcher_send", side_effect=remove_by_signal):
        result = await MiWifiPurgeInactiveDevicesServiceCall(hass).async_call_service(SimpleNamespace(data={
            "macs": [mac], "days": 1, "apply": True, "verbose": False,
        }))
    assert result["entities"] == 1
    assert result["devices"] == 1
    assert devices.async_get(device.id) is None
    assert registry.async_get(tracker.entity_id) is None
