"""Explicit client identities survive router renames and mesh MAC changes."""

from types import SimpleNamespace
from unittest.mock import AsyncMock, Mock, patch

import pytest
from homeassistant.helpers import device_registry as dr, entity_registry as er
from pytest_homeassistant_custom_component.common import MockConfigEntry

from custom_components.miwifi.mac_replacement import MacReplacement, async_retire_macs, get_mac_replacement
from custom_components.miwifi.purged_clients import PurgedClients
from custom_components.miwifi.updater import LuciUpdater
from custom_components.miwifi.enum import Mode
from custom_components.miwifi.services import MiWifiConfigureMacReplacementServiceCall

OLD, NEW = "B6:C9:7F:2A:D3:AF", "CE:F2:A4:A0:37:46"


def nodes():
    return [SimpleNamespace(ip=ip, _scan_interval=20, timeout=20) for ip in ("192.0.2.1", "192.0.2.2")]


@pytest.mark.parametrize("case", ["replace", "both_online", "old_unknown", "invalid_flag", "missing_node", "stale_node", "same_mac"])
async def test_unique_online_identity_requires_fresh_all_node_evidence(hass, case):
    manager = MacReplacement(hass)
    await manager.async_configure({"watch": ["SM-L315F", "Reloj JuanMa"]}, [{"name": "SM-L315F", "mac": OLD}])
    updaters = nodes()
    new = {"name": "Reloj JuanMa", "mac": OLD if case == "same_mac" else NEW, "online": 1}
    assert await manager.async_candidates(updaters[0].ip, [new], updaters) == set()
    if case == "missing_node":
        return
    old_rows = []
    if case in ("both_online", "old_unknown", "invalid_flag"):
        old = {"name": "SM-L315F", "mac": OLD}
        if case != "old_unknown":
            old["online"] = 1 if case == "both_online" else "bad"
        old_rows = [old]
    if case == "stale_node":
        stamp, active, unknown = manager._reports[updaters[0].ip]
        manager._reports[updaters[0].ip] = (stamp - 1000, active, unknown)
    result = await manager.async_candidates(updaters[1].ip, old_rows, updaters)
    assert result == ({OLD} if case == "replace" else set())


async def test_rules_and_learned_router_alias_persist_after_restart(hass):
    manager = MacReplacement(hass)
    await manager.async_configure({"watch": ["SM-L315F"]}, [{"name": "SM-L315F", "mac": OLD}])
    updaters = nodes()[:1]
    assert await manager.async_candidates(updaters[0].ip, [{"mac": OLD, "name": "Reloj JuanMa", "online": 1}], updaters) == set()
    restored = MacReplacement(hass)
    assert await restored.async_candidates(updaters[0].ip, [{"mac": NEW, "name": "Reloj JuanMa", "online": 1}], updaters) == {OLD}
    await restored.async_configure({}, [])
    assert await restored.async_candidates(updaters[0].ip, [{"mac": OLD, "name": "SM-L315F", "online": 1}], updaters) == set()


async def test_duplicate_or_empty_aliases_rejected(hass):
    manager = MacReplacement(hass)
    for config in ({"a": []}, {"a": [" "]}, {"a": ["Watch"], "b": ["watch"]}):
        with pytest.raises(ValueError):
            await manager.async_configure(config, [])


async def test_configure_recognizes_unavailable_registry_only_client(hass):
    entry = MockConfigEntry(domain="miwifi")
    entry.add_to_hass(hass)
    devices, registry = dr.async_get(hass), er.async_get(hass)
    old = devices.async_get_or_create(
        config_entry_id=entry.entry_id, identifiers={("miwifi", OLD.lower())}, name="SM-L315F"
    )
    tracker = registry.async_get_or_create(
        "device_tracker", "miwifi", "miwifi-" + OLD.lower(), config_entry=entry, device_id=old.id
    )
    hass.states.async_set(tracker.entity_id, "unavailable")
    # A matching user display name on another device is not an identity alias.
    foreign_mac = "02:00:00:00:00:99"
    other = devices.async_get_or_create(
        config_entry_id=entry.entry_id, identifiers={("miwifi", foreign_mac)}, name="Other watch"
    )
    devices.async_update_device(other.id, name_by_user="Reloj JuanMa")
    registry.async_get_or_create(
        "device_tracker", "miwifi", "miwifi-" + foreign_mac, config_entry=entry, device_id=other.id
    )
    manager = MacReplacement(hass)
    await manager.async_configure({"watch": ["Reloj JuanMa", "SM-L315F"]}, [])
    updaters = nodes()
    new = {"name": "Reloj JuanMa", "mac": NEW, "online": 1}
    assert await manager.async_candidates(updaters[0].ip, [new], updaters) == set()
    assert await manager.async_candidates(updaters[1].ip, [], updaters) == {OLD}
    await async_retire_macs(hass, {OLD}, [])
    assert devices.async_get(old.id) is None
    assert devices.async_get(other.id) is not None


async def test_retire_today_client_preserve_current_and_foreign_entities(hass):
    entry = MockConfigEntry(domain="miwifi")
    entry.add_to_hass(hass)
    devices, registry = dr.async_get(hass), er.async_get(hass)
    old = devices.async_get_or_create(config_entry_id=entry.entry_id, identifiers={("miwifi", OLD.lower())})
    current = devices.async_get_or_create(config_entry_id=entry.entry_id, identifiers={("miwifi", NEW.lower())})
    tracker = registry.async_get_or_create("device_tracker", "miwifi", "miwifi-" + OLD.lower(), config_entry=entry, device_id=old.id)
    sensor = registry.async_get_or_create("sensor", "miwifi", "miwifi-dev-" + OLD.lower() + "-signal", config_entry=entry, device_id=old.id, disabled_by=er.RegistryEntryDisabler.USER)
    foreign = registry.async_get_or_create("sensor", "other", "foreign", config_entry=entry, device_id=old.id)
    current_tracker = registry.async_get_or_create("device_tracker", "miwifi", "miwifi-" + NEW.lower(), config_entry=entry, device_id=current.id)
    hass.states.async_set(tracker.entity_id, "not_home", {"last_activity": "2026-10-11T09:00:00"})
    updaters = nodes()
    for updater in updaters:
        updater._entry_id = entry.entry_id
        updater.async_purge_clients = AsyncMock()
    await async_retire_macs(hass, {OLD}, updaters)
    assert registry.async_get(tracker.entity_id) is None
    assert registry.async_get(sensor.entity_id) is None
    assert registry.async_get(foreign.entity_id) is not None
    assert devices.async_get(old.id) is not None
    assert devices.async_get(current.id) is not None
    assert registry.async_get(current_tracker.entity_id) is not None
    assert await PurgedClients(hass).async_blocked(OLD)
    for updater in updaters:
        updater.async_purge_clients.assert_awaited_once_with({OLD})


async def test_configuration_and_real_node_censuses_retire_previous_mac(hass):
    """Exercise the actual configuration action and both updater census hooks."""
    entry = MockConfigEntry(domain="miwifi")
    entry.add_to_hass(hass)
    with patch("custom_components.miwifi.updater.LuciClient", side_effect=[Mock(), Mock()]):
        main = LuciUpdater(hass, "192.0.2.1", "test", entry_id=entry.entry_id)
        leaf = LuciUpdater(hass, "192.0.2.2", "test", entry_id="leaf")
    try:
        hass.data.setdefault("miwifi", {}).update({
            entry.entry_id: {"ip_address": main.ip, "updater": main},
            "leaf": {"ip_address": leaf.ip, "updater": leaf},
        })
        main.data = {"mode": Mode.DEFAULT}
        leaf.data = {"mode": Mode.MESH_NODE}
        old_client = {"mac": OLD, "name": "SM-L315F"}
        main.devices[OLD] = dict(old_client)
        leaf.devices[OLD] = dict(old_client)
        await main._store.async_save({OLD: old_client})
        await leaf._store.async_save({OLD: old_client})
        registry, devices = er.async_get(hass), dr.async_get(hass)
        old_device = devices.async_get_or_create(config_entry_id=entry.entry_id, identifiers={("miwifi", OLD.lower())})
        old_tracker = registry.async_get_or_create("device_tracker", "miwifi", "miwifi-" + OLD.lower(), config_entry=entry, device_id=old_device.id)
        config = MiWifiConfigureMacReplacementServiceCall.schema({"clients": {"watch": ["SM-L315F", "Reloj JuanMa"]}})
        with patch("custom_components.miwifi.services.MiWiFiNotifier") as notifier:
            notifier.return_value.notify = AsyncMock()
            await MiWifiConfigureMacReplacementServiceCall(hass).async_call_service(SimpleNamespace(data=config))
        assert OLD in get_mac_replacement(hass)._groups["watch"]["macs"]
        main.luci.device_list = AsyncMock(return_value={"code": 0, "list": [{
            "mac": NEW, "name": "Reloj JuanMa", "online": 1,
            "ip": [{"ip": "192.0.2.100", "active": 1}],
        }]})
        leaf.luci.device_list = AsyncMock(return_value={"code": 0, "list": []})
        main.add_device = AsyncMock()
        with patch("custom_components.miwifi.updater.asyncio.sleep", new=AsyncMock()):
            await main._async_prepare_device_list(main.data)
            assert registry.async_get(old_tracker.entity_id) is not None
            await leaf._async_prepare_device_list(leaf.data)
        assert registry.async_get(old_tracker.entity_id) is None, (get_mac_replacement(hass)._groups, get_mac_replacement(hass)._reports)
        assert devices.async_get(old_device.id) is None
        assert OLD not in main.devices and OLD not in leaf.devices
        assert await main._store.async_load() == {}
        assert await leaf._store.async_load() == {}
        assert await PurgedClients(hass).async_blocked(OLD)
        assert not await PurgedClients(hass).async_blocked(NEW)
    finally:
        await main.async_shutdown()
        await leaf.async_shutdown()
