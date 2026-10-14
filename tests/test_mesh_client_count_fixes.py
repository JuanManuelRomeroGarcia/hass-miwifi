"""Regression tests for mesh client counting and parent attribution."""

from custom_components.miwifi.updater import _ap_macs_by_ip, _find_leaf


def test_ap_macs_by_ip_uses_active_address() -> None:
    response = {
        "list": [
            {
                "isap": 1,
                "mac": "02:00:00:00:00:01",
                "ip": [
                    {"ip": "192.0.2.20", "active": 0},
                    {"ip": "192.0.2.21", "active": 1},
                ],
            }
        ]
    }

    assert _ap_macs_by_ip(response) == {
        "192.0.2.21": "02:00:00:00:00:01",
    }


def test_find_leaf_walks_nested_topology() -> None:
    graph = {
        "leafs": [
            {
                "ip": "192.0.2.2",
                "leafs": [{"ip": "192.0.2.3", "onlines": 4}],
            }
        ]
    }

    assert _find_leaf(graph, "192.0.2.3") == {
        "ip": "192.0.2.3",
        "onlines": 4,
    }


def test_find_leaf_ignores_invalid_leaf_lists() -> None:
    assert _find_leaf({"leafs": None}, "192.0.2.3") is None
    assert _find_leaf({"leafs": 1}, "192.0.2.3") is None


# Mesh nodes must never be tracked or restored as clients.

import asyncio
from contextlib import contextmanager
from types import SimpleNamespace
from unittest.mock import AsyncMock, Mock, patch

from custom_components.miwifi import helper as helper_module
from custom_components.miwifi import updater as updater_module
from custom_components.miwifi.const import DOMAIN, UPDATER
from custom_components.miwifi.updater import LuciUpdater

NODE_MAC = "02:00:00:00:00:0A"
CLIENT_MAC = "02:00:00:00:00:0B"
NODE_IP = "192.0.2.3"


def _hass(entry_ips=()):
    entries = [SimpleNamespace(data={"ip_address": ip}, options={}) for ip in entry_ips]
    return SimpleNamespace(
        data={DOMAIN: {}},
        config_entries=SimpleNamespace(async_entries=lambda domain: entries),
    )


def _updater(hass, entry_id, devices=None, ip="192.0.2.1"):
    updater = LuciUpdater.__new__(LuciUpdater)
    updater.hass = hass
    updater.ip = ip
    updater.data = {}
    updater.devices = dict(devices or {})
    updater._moved_devices = []
    updater._entry_id = entry_id
    updater._filter_macs = {}
    updater._is_first_update = True
    updater.add_device = AsyncMock()
    updater._mass_update_device = Mock(return_value=False)
    return updater


def _row(mac, ip, isap=0):
    return {"mac": mac, "isap": isap, "parent": "", "ip": [{"ip": ip, "active": 1}]}


@contextmanager
def _no_client_history():
    """Stub the purged-client and MAC-replacement stores, which need a real hass."""
    replacement = Mock(async_candidates=AsyncMock(return_value=set()))
    with (
        patch.object(updater_module, "get_purged_clients",
                     lambda hass: Mock(async_blocked=AsyncMock(return_value=False))),
        patch.object(updater_module, "get_mac_replacement", lambda hass: replacement),
        patch.object(updater_module, "async_retire_macs", AsyncMock()),
    ):
        yield


def _run_device_list(main, rows, integrations):
    """Run one device_list refresh; report the purge signals and node purges."""
    main.luci = SimpleNamespace(device_list=AsyncMock(return_value={"list": rows}))
    calls = SimpleNamespace(send=Mock(), purge=Mock(return_value=0))
    with (
        patch.object(updater_module, "async_get_integrations", return_value=integrations),
        patch.object(updater_module, "async_dispatcher_send", calls.send),
        patch.object(helper_module, "async_purge_client_entities", calls.purge),
        patch.object(updater_module.asyncio, "sleep", AsyncMock()),
        _no_client_history(),
    ):
        asyncio.run(main._async_prepare_device_list({}))
    return calls


def test_device_list_purges_stale_client_copies_of_a_reported_node() -> None:
    hass = _hass()
    main = _updater(hass, "main", {NODE_MAC: {"mac": NODE_MAC}})
    leaf = _updater(hass, "leaf", {NODE_MAC: {"mac": NODE_MAC}}, ip="192.0.2.4")
    hass.data[DOMAIN]["devices_cache"] = {NODE_MAC: {}}
    integrations = {
        "192.0.2.1": {UPDATER: main, "entry_id": "main"},
        "192.0.2.4": {UPDATER: leaf, "entry_id": "leaf"},
    }

    # First refresh: the platforms are not set up yet, so nothing is purged.
    calls = _run_device_list(main, [_row(NODE_MAC, NODE_IP, isap=8)], integrations)

    assert NODE_MAC not in main.devices
    assert NODE_MAC not in leaf.devices
    assert NODE_MAC not in hass.data[DOMAIN]["devices_cache"]
    main.add_device.assert_not_awaited()
    calls.purge.assert_not_called()

    # Next cycle: purged once, across every entry, without a scoped signal.
    main._is_first_update = False
    calls = _run_device_list(main, [_row(NODE_MAC, NODE_IP, isap=8)], integrations)
    calls.purge.assert_called_once_with(hass, NODE_MAC)
    calls.send.assert_not_called()

    # And not again on every cycle.
    calls = _run_device_list(main, [_row(NODE_MAC, NODE_IP, isap=8)], integrations)
    calls.purge.assert_not_called()


def test_device_list_skips_a_node_listed_without_isap() -> None:
    hass = _hass(entry_ips=["192.0.2.1", NODE_IP])
    main = _updater(hass, "main")
    integrations = {"192.0.2.1": {UPDATER: main, "entry_id": "main"}}

    # By the IP of a configured entry, before the node was ever reported.
    calls = _run_device_list(main, [_row(NODE_MAC, NODE_IP)], integrations)
    main.add_device.assert_not_awaited()
    calls.send.assert_not_called()
    calls.purge.assert_not_called()

    # By a MAC reported earlier with isap > 0, whatever IP it now has.
    hass = _hass()
    hass.data[DOMAIN][updater_module.MESH_NODE_MACS] = {NODE_MAC}
    main = _updater(hass, "main")
    _run_device_list(main, [_row(NODE_MAC, "192.0.2.50")], integrations)
    main.add_device.assert_not_awaited()


def test_device_list_still_adds_clients() -> None:
    hass = _hass(entry_ips=["192.0.2.1", NODE_IP])
    main = _updater(hass, "main")
    integrations = {"192.0.2.1": {UPDATER: main, "entry_id": "main"}}

    _run_device_list(main, [_row(NODE_MAC, NODE_IP, isap=8), _row(CLIENT_MAC, "192.0.2.50")], integrations)

    main.add_device.assert_awaited_once()
    assert main.add_device.await_args.args[0]["mac"] == CLIENT_MAC


def _restore(hass, stored_devices):
    leaf = _updater(hass, "leaf", ip="192.0.2.4")
    leaf._async_load_devices = AsyncMock(return_value=stored_devices)
    leaf._clean_devices = Mock()
    send = Mock()
    with (
        patch.object(updater_module, "async_get_integrations", return_value={}),
        patch.object(updater_module, "async_dispatcher_send", send),
        _no_client_history(),
    ):
        asyncio.run(leaf._async_prepare_device_restore({}))
    return leaf, send


def _stored(mac, ip):
    return {"mac": mac, "ip": ip, "connection": 0, "entry_id": "leaf"}


def test_restore_skips_a_stored_node_by_entry_ip() -> None:
    leaf, send = _restore(
        _hass(entry_ips=[NODE_IP]),
        {NODE_MAC: _stored(NODE_MAC, NODE_IP), CLIENT_MAC: _stored(CLIENT_MAC, "192.0.2.50")},
    )

    assert list(leaf.devices) == [CLIENT_MAC]
    assert send.call_count == 1


def test_restore_skips_a_stored_node_by_reported_mac() -> None:
    hass = _hass()
    hass.data[DOMAIN][updater_module.MESH_NODE_MACS] = {NODE_MAC}
    leaf, send = _restore(
        hass,
        {NODE_MAC: _stored(NODE_MAC, "192.0.2.60"), CLIENT_MAC: _stored(CLIENT_MAC, "192.0.2.50")},
    )

    assert list(leaf.devices) == [CLIENT_MAC]
    assert send.call_count == 1
