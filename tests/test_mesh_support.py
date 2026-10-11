"""Support reports preserve topology relationships without leaking identifiers."""

import copy
import json
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

from custom_components.miwifi.mesh_diagnostics import (
    MeshTrace, SupportAliases, build_mesh_support,
)


def test_census_is_bounded_independent_and_private():
    trace = MeshTrace()
    response = {"list": [{
        "mac": "AA:BB:CC:DD:EE:FF", "parent": "11:22:33:44:55:66",
        "name": "Private laptop", "token": "secret", "type": 5,
        "ip": [{"ip": "10.30.0.55", "active": 1}],
    }]}
    original = copy.deepcopy(response)
    for _ in range(15):
        trace.census(response, {"11:22:33:44:55:66": "10.30.0.2"})
    assert response == original
    response["list"][0]["ip"][0]["active"] = 0
    assert trace.censuses[-1]["clients"][0]["addresses"][0]["active"] == 1
    assert len(trace.censuses) == 12
    aliases = SupportAliases()
    report = aliases.clean(list(trace.censuses))
    row = report[-1]["clients"][0]
    assert report[-1]["parent_routes"][row["parent"]] == row["target_ip"]
    assert row["parent_matched"] and row["has_active_ip"]
    encoded = json.dumps(report)
    for private in ("Private laptop", "secret", "10.30.0", "AA:BB", "11:22"):
        assert private not in encoded
    assert aliases.clean(list(trace.censuses)) == report
    assert SupportAliases().clean(list(trace.censuses)) != report


def test_all_nodes_export_whitespace_and_reset_history(hass):
    trace = MeshTrace()
    for _ in range(65):
        trace.event("before_reset", {"devices": 8, "devices_5_0": 8, "token": "secret"})
    trace.event("update_complete", {"devices": 0})
    updater = SimpleNamespace(
        data={"device_mac_address": "11:22:33:44:55:66", "mode": 1,
              "devices": 0, "topo_graph": {"graph": {
                  "ip": "10.30.0.1", "name": "Private router",
                  "leafs": [{"ip": "10.30.0.2\n", "mac": "11:22:33:44:55:66",
                             "onlines": 8}]} }},
        devices={}, _mesh_trace=trace, _entry_id=None, is_force_load=False,
    )
    integrations = {"10.30.0.2": {"updater": updater}}
    report = build_mesh_support(hass, integrations)
    node = report["nodes"][0]
    leaf = node["topology"]["nodes"][1]
    assert leaf["ip_has_surrounding_whitespace"]
    assert leaf["ip"] == node["ip"]
    assert leaf["mac"] == node["mac"]
    assert len(node["counter_events"]) == 60
    assert node["counter_events"][-2]["counts"]["devices"] == 8
    assert node["counter_events"][-1]["counts"]["devices"] == 0
    assert build_mesh_support(hass, integrations)["nodes"] == report["nodes"]
    encoded = json.dumps(report)
    assert "10.30.0" not in encoded and "Private router" not in encoded


def test_large_and_malformed_census():
    trace = MeshTrace()
    trace.census({"list": [None] + [{"mac": "AA", "ip": None}] * 600}, {})
    census = trace.censuses[-1]
    assert census["truncated"] and census["reported_rows"] == 601
    assert len(census["clients"]) == 511
    assert not census["clients"][0]["has_active_ip"]
    trace.census({"list": None}, {})
    assert trace.censuses[-1]["clients"] == []


async def test_real_updater_records_routing_and_parent_counter_reset(hass):
    from custom_components.miwifi.const import DOMAIN
    from custom_components.miwifi.updater import LuciUpdater

    with patch("custom_components.miwifi.updater.LuciClient"):
        main = LuciUpdater(hass, "10.30.0.1", "test", entry_id="main",
                           scan_interval=21, timeout=37)
        leaf = LuciUpdater(hass, "10.30.0.2", "test", entry_id="leaf")
    main.data = {"device_mac_address": "00:00:00:00:00:01"}
    leaf.data = {"device_mac_address": "00:00:00:00:00:02", "devices": 8}
    hass.data[DOMAIN] = {
        "main": {"ip_address": main.ip, "updater": main},
        "leaf": {"ip_address": leaf.ip, "updater": leaf},
    }
    main.luci.device_list = AsyncMock(return_value={"list": [
        {"mac": "AA:BB:CC:DD:EE:FF", "parent": "00:00:00:00:00:02",
         "ip": [{"ip": "10.30.0.55", "active": 1}], "type": 5},
        {"mac": "AA:BB:CC:DD:EE:11", "ip": [{"active": 0}]},
    ]})
    leaf.add_device = AsyncMock()
    try:
        with patch("custom_components.miwifi.updater.asyncio.sleep", new=AsyncMock()):
            await main._async_prepare_device_list(main.data)
        leaf.add_device.assert_awaited_once()
        assert leaf.add_device.call_args.kwargs["is_from_parent"]
        assert leaf.data["devices"] == 0
        assert leaf._mesh_trace.events[0]["counts"]["devices"] == 8
        assert leaf._mesh_trace.events[1]["reason"] == "parent_push_complete"
        assert leaf._mesh_trace.events[1]["pushed_clients"] == 1
        row = main._mesh_trace.censuses[-1]["clients"][0]
        assert row["parent_matched"] and row["target_ip"] == leaf.ip
        assert not main._mesh_trace.censuses[-1]["clients"][1]["has_active_ip"]
        # Exercise freshness with the real constructor, not an API double that
        # could accidentally invent a private timeout field.
        from custom_components.miwifi.enum import Mode
        assert main.timeout == 37 and not hasattr(main, "_timeout")
        leaf.data.update({"mode": Mode.MESH_NODE, "devices": 10})
        main.data["topo_graph"] = {"graph": {
            "leafs": [{"ip": leaf.ip, "onlines": 4}],
        }}
        for _ in range(3):
            leaf._counters_reset_this_cycle = False
            await leaf._async_apply_leaf_client_count()
            assert leaf.data["devices"] == 10
        # The configured 21-second interval and 37-second timeout yield 100s.
        leaf._parent_census_at -= 101
        await leaf._async_apply_leaf_client_count()
        assert leaf.data["devices"] == 4
    finally:
        await main.async_shutdown()
        await leaf.async_shutdown()


async def test_real_parent_push_counts_returning_moved_client(hass):
    from custom_components.miwifi.enum import Connection, Mode
    from custom_components.miwifi.updater import LuciUpdater

    with patch("custom_components.miwifi.updater.LuciClient"):
        updater = LuciUpdater(hass, "192.0.2.2", "test", entry_id="leaf")
    mac = "AA:BB:CC:DD:EE:FF"
    updater.data = {"mode": Mode.MESH_NODE}
    updater.devices[mac] = {"mac": mac}
    updater._moved_devices = [mac, mac]
    updater.reset_counter(is_force=True)
    try:
        with patch.object(updater, "_build_device", return_value={
            "mac": mac, "connection": Connection.WIFI_2_4,
        }):
            await updater.add_device({"mac": mac}, is_from_parent=True)
        assert updater.data["devices"] == 1
        assert updater.data["devices_2_4"] == 1
        assert updater._moved_devices == []
    finally:
        await updater.async_shutdown()
