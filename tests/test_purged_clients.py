"""Purged clients stay absent after reload, but genuine reconnects still work."""

from unittest.mock import patch

import pytest

from custom_components.miwifi.purged_clients import PurgedClients, get_purged_clients
from custom_components.miwifi.updater import LuciUpdater
from custom_components.miwifi.enum import Mode, Connection


MAC = "D6:0B:BE:26:F0:8B"
OTHER = "CE:F2:A4:A0:37:46"


@pytest.mark.parametrize("reported", [None, {}, {"online": 0},
    {"online": 1, "ip": [{"active": 0}]}, {"online": "bad"},
    {"ip": [{"active": 0}]}])
async def test_persistent_suppression_preserves_offline_clients(hass, reported):
    state = get_purged_clients(hass)
    await state.async_mark({MAC.lower()})
    # Recreate the runtime object to exercise loading persisted state.
    reloaded = PurgedClients(hass)
    assert await reloaded.async_blocked(MAC, reported)
    assert not await reloaded.async_blocked(OTHER, reported)


@pytest.mark.parametrize("reported", [{"online": 1}, {"ip": [{"active": 1}]}])
async def test_confirmed_reconnection_releases_only_that_mac(hass, reported):
    state = get_purged_clients(hass)
    await state.async_mark({MAC, OTHER})
    assert not await state.async_blocked(MAC, reported)
    reloaded = PurgedClients(hass)
    assert not await reloaded.async_blocked(MAC)
    assert await reloaded.async_blocked(OTHER)


async def test_real_updaters_forget_stores_and_do_not_restore_or_readd_offline(hass):
    with patch("custom_components.miwifi.updater.LuciClient"):
        main = LuciUpdater(hass, "192.0.2.1", "test", entry_id="main")
        leaf = LuciUpdater(hass, "192.0.2.2", "test", entry_id="leaf")
    try:
        for updater in (main, leaf):
            updater.devices = {MAC: {"mac": MAC}}
            updater._moved_devices = [MAC, MAC]
            await updater._store.async_save({MAC.lower(): {"mac": MAC}})
        hass.data.setdefault("miwifi", {})["devices_cache"] = {
            MAC: {"mac": MAC}, OTHER: {"mac": OTHER},
        }
        await get_purged_clients(hass).async_mark({MAC})
        for updater in (main, leaf):
            await updater.async_purge_clients({MAC})
            assert updater.devices == {}
            assert updater._moved_devices == []
            assert await updater._store.async_load() == {}
        assert list(hass.data["miwifi"]["devices_cache"]) == [OTHER]
        # Even an old store written back by another refresh cannot restore it.
        await leaf._store.async_save({MAC: {"mac": MAC}})
        leaf.data = {"mode": Mode.MESH_NODE}
        await leaf._async_prepare_device_restore(leaf.data)
        assert leaf.devices == {}
        with patch.object(leaf, "_build_device") as build:
            await leaf.add_device({"mac": MAC, "online": 0}, is_from_parent=True)
            build.assert_not_called()
        leaf.reset_counter(is_force=True)
        with patch.object(leaf, "_build_device", return_value={
            "mac": MAC, "connection": Connection.WIFI_2_4,
        }):
            await leaf.add_device({"mac": MAC, "online": 1}, is_from_parent=True)
        assert MAC in leaf.devices
        assert leaf.data["devices"] == 1
        assert not await PurgedClients(hass).async_blocked(MAC)
    finally:
        await main.async_shutdown()
        await leaf.async_shutdown()
