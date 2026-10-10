"""Real-core regression for a roaming tracker losing its original platform (#332)."""

from unittest.mock import AsyncMock, Mock, patch

import pytest

from homeassistant.config_entries import ConfigEntryDisabler
from homeassistant.helpers import entity_registry as er
from pytest_homeassistant_custom_component.common import MockConfigEntry, MockEntityPlatform

from custom_components.miwifi.const import (
    ATTR_SENSOR_MODE, ATTR_STATE, ATTR_TRACKER_FIRST_SEEN, ATTR_TRACKER_IP,
    ATTR_TRACKER_MAC, ATTR_TRACKER_NAME, ATTR_TRACKER_UPDATER_ENTRY_ID,
    CONF_IS_TRACK_DEVICES, DOMAIN, UPDATER,
)
from custom_components.miwifi.device_tracker import async_setup_entry
from custom_components.miwifi.enum import Mode
from custom_components.miwifi.updater import LuciUpdater

MAC = "02:00:00:00:00:20"
UID = f"{DOMAIN}-{MAC.lower()}"


@pytest.fixture
def router_doubles():
    """No router traffic or notifications; use real updater/coordinator methods."""
    with (
        patch("custom_components.miwifi.updater.LuciClient"),
        patch("custom_components.miwifi.updater.get_async_client", return_value=Mock()),
        patch("custom_components.miwifi.update.MiWiFiNewDeviceNotifier.async_notify_new_device", new_callable=AsyncMock),
        patch.object(LuciUpdater, "_build_device", side_effect=lambda device, integrations: dict(device)),
    ):
        yield


def _node(hass, ip, tracking=True, force_load=True):
    entry = MockConfigEntry(domain=DOMAIN, title=ip, options={CONF_IS_TRACK_DEVICES: tracking})
    entry.add_to_hass(hass)
    updater = LuciUpdater(hass, ip, "test-password", entry_id=entry.entry_id, is_force_load=force_load)
    updater.update_interval = None
    updater.data = {ATTR_STATE: True, ATTR_SENSOR_MODE: Mode.MESH}
    hass.data.setdefault(DOMAIN, {})[entry.entry_id] = {UPDATER: updater}
    platform = MockEntityPlatform(hass, domain="device_tracker", platform_name=DOMAIN)
    platform.config_entry = entry
    platform.async_prepare()
    return entry, updater, platform


def _client(entry):
    return {
        ATTR_TRACKER_MAC: MAC, ATTR_TRACKER_NAME: "Test client",
        ATTR_TRACKER_IP: "192.0.2.20", ATTR_TRACKER_UPDATER_ENTRY_ID: entry.entry_id,
        ATTR_TRACKER_FIRST_SEEN: "2026-10-01T10:00:00+00:00",
    }


async def _setup(hass, entry, platform):
    await async_setup_entry(hass, entry, platform._async_schedule_add_entities)
    await hass.async_block_till_done()


async def _poll(hass, updater, device):
    await updater.add_device(device)
    updater.async_set_updated_data(dict(updater.data))
    await hass.async_block_till_done()


@pytest.mark.parametrize("disable_origin", [False, True])
@pytest.mark.parametrize("burst", [False, True])
@pytest.mark.parametrize("force_load", [False, True])
async def test_known_roaming_client_recovers_after_origin_unload(hass, router_doubles, caplog, disable_origin, burst, force_load):
    main, origin, main_platform = _node(hass, "192.0.2.1")
    leaf, destination, leaf_platform = _node(hass, "192.0.2.2", force_load=force_load)
    origin.devices[MAC] = _client(main)
    await _setup(hass, main, main_platform)
    registry = er.async_get(hass)
    entity_id = registry.async_get_entity_id("device_tracker", DOMAIN, UID)
    assert hass.states.get(entity_id).state == "home"

    # The leaf's first refresh precedes its platform setup. Initial fill then
    # reparents the row, while the live tracker stays on the original platform.
    await destination.add_device(_client(leaf))
    await _setup(hass, leaf, leaf_platform)
    origin.devices.clear()
    assert registry.async_get(entity_id).config_entry_id == leaf.entry_id
    assert entity_id in main_platform.entities
    assert not leaf_platform.entities

    await main._async_process_on_unload(hass)
    if origin.new_device_callback:
        origin.new_device_callback()
    if disable_origin:
        with patch.object(hass.config_entries, "async_reload", new_callable=AsyncMock):
            await hass.config_entries.async_set_disabled_by(main.entry_id, ConfigEntryDisabler.USER)
    await main_platform.async_reset()
    await hass.async_block_till_done()
    assert UID not in hass.data[DOMAIN]["device_tracker_entities"]

    # The client is known: add_device sends no new-client signal on any poll.
    for _ in range(3):
        if burst:
            await destination.add_device(_client(leaf))
        else:
            await _poll(hass, destination, _client(leaf))
    await hass.async_block_till_done()
    assert hass.states.get(entity_id).state == "home"
    assert entity_id in leaf_platform.entities
    assert registry.async_get(entity_id).config_entry_id == leaf.entry_id
    assert len(hass.data[DOMAIN]["device_tracker_entities"]) == 1
    assert "does not generate unique IDs" not in caplog.text

    # Loading the original platform again must not create a second tracker.
    if disable_origin:
        with patch.object(hass.config_entries, "async_reload", new_callable=AsyncMock):
            await hass.config_entries.async_set_disabled_by(main.entry_id, None)
    await _setup(hass, main, main_platform)
    await _poll(hass, destination, _client(leaf))
    assert entity_id in leaf_platform.entities
    assert not main_platform.entities
    assert len(hass.data[DOMAIN]["device_tracker_entities"]) == 1


async def test_refresh_does_not_duplicate_live_roaming_tracker(hass, router_doubles, caplog):
    main, origin, main_platform = _node(hass, "192.0.2.1")
    leaf, destination, leaf_platform = _node(hass, "192.0.2.2")
    origin.devices[MAC] = _client(main)
    await _setup(hass, main, main_platform)
    destination.devices[MAC] = _client(leaf)
    await _setup(hass, leaf, leaf_platform)
    for _ in range(3):
        await _poll(hass, destination, _client(leaf))
    assert len(main_platform.entities) == 1
    assert not leaf_platform.entities
    assert len(hass.data[DOMAIN]["device_tracker_entities"]) == 1
    assert "does not generate unique IDs" not in caplog.text


async def test_tracking_disabled_does_not_recover_clients(hass, router_doubles):
    leaf, destination, platform = _node(hass, "192.0.2.2", tracking=False)
    destination.devices[MAC] = _client(leaf)
    await _setup(hass, leaf, platform)
    await _poll(hass, destination, _client(leaf))
    assert not platform.entities


async def test_disabled_tracker_entity_stays_disabled(hass, router_doubles):
    leaf, destination, platform = _node(hass, "192.0.2.2")
    registry = er.async_get(hass)
    row = registry.async_get_or_create(
        "device_tracker", DOMAIN, UID, config_entry=leaf,
        disabled_by=er.RegistryEntryDisabler.USER,
    )
    destination.devices[MAC] = _client(leaf)
    await _setup(hass, leaf, platform)
    for _ in range(3):
        await _poll(hass, destination, _client(leaf))
    assert not platform.entities
    assert registry.async_get(row.entity_id).disabled_by == er.RegistryEntryDisabler.USER


async def test_recovering_known_client_does_not_send_new_device_notification(hass, router_doubles):
    leaf, destination, platform = _node(hass, "192.0.2.2")
    await _setup(hass, leaf, platform)
    known = _client(leaf)
    known.pop(ATTR_TRACKER_FIRST_SEEN)
    destination.devices[MAC] = dict(known)
    with patch.object(destination, "_async_notify_new_device", new_callable=AsyncMock) as notify:
        await _poll(hass, destination, known)
        notify.assert_not_awaited()
    assert len(platform.entities) == 1
