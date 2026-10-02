"""Client counters of a node that counts its own clients, without a HA runtime.

A repeater or access point without force load skips the counter reset at the
top of the cycle, because the main pushes its clients in. When the node's own
misystem/devicelist lists clients with no parent among the configured nodes -
the main of a mesh in access point mode does - it counts them itself, and the
counters must hold this cycle's clients, not the sum of every cycle so far.

The real LuciUpdater methods are executed from their AST with API doubles, as
in test_issue_regressions.py. Run: python -B tests/test_self_counted_clients.py
"""
from __future__ import annotations

import ast
import asyncio
import contextlib
from datetime import datetime
import importlib
from pathlib import Path
import sys
from types import ModuleType
import unittest
from unittest.mock import AsyncMock, Mock

ROOT = Path(__file__).resolve().parents[1]
COMPONENT = ROOT / "custom_components/miwifi"

try:
    import homeassistant.const  # noqa: F401
except ImportError:
    class _Platform:
        def __getattr__(self, name):
            return name.lower()

    _ha = ModuleType("homeassistant")
    _ha_const = ModuleType("homeassistant.const")
    _ha_const.Platform = _Platform()
    _ha.const = _ha_const
    sys.modules.setdefault("homeassistant", _ha)
    sys.modules.setdefault("homeassistant.const", _ha_const)

# const.py and enum.py need nothing from HA but Platform: load them without
# running the integration's __init__.py.
_package = ModuleType("_miwifi_self_counted")
_package.__path__ = [str(COMPONENT)]
sys.modules[_package.__name__] = _package
const = importlib.import_module(f"{_package.__name__}.const")
enum = importlib.import_module(f"{_package.__name__}.enum")
Connection, DeviceAction, Mode = enum.Connection, enum.DeviceAction, enum.Mode

UPDATER_METHODS = {
    "is_repeater",
    "_counters_pushed_by_parent",
    "reset_counter",
    "add_device",
    "_async_prepare_device_list",
    "_leaf_entry_from_other_nodes",
    "_async_apply_leaf_client_count",
}

MAIN_IP, LEAF_IP = "192.0.2.1", "192.0.2.2"
MAIN_MAC, LEAF_MAC = "00:00:00:00:00:01", "00:00:00:00:00:02"


def _parse(filename):
    return ast.parse((COMPONENT / filename).read_text(encoding="utf-8"))


def _exec(node, filename, namespace):
    module = ast.Module(
        body=[ast.ImportFrom(module="__future__", names=[ast.alias(name="annotations")], level=0), node],
        type_ignores=[],
    )
    exec(compile(ast.fix_missing_locations(module), filename, "exec"), namespace)


def load_updater(integrations):
    """Return LuciUpdater with only the counter paths, and its namespace."""

    namespace = {name: getattr(const, name) for name in dir(const) if name.isupper()}
    namespace |= {
        "asyncio": Mock(sleep=AsyncMock()),
        "contextlib": contextlib,
        "datetime": datetime,
        "Connection": Connection,
        "DeviceAction": DeviceAction,
        "Mode": Mode,
        "_LOGGER": Mock(),
        "async_dispatcher_send": Mock(),
        "async_get_integrations": lambda hass: integrations,
    }

    tree = _parse("updater.py")
    for item in tree.body:
        if isinstance(item, ast.FunctionDef) and item.name in {"_find_leaf", "_ap_macs_by_ip"}:
            _exec(item, "updater.py", namespace)
        elif isinstance(item, ast.AnnAssign) and getattr(item.target, "id", None) == "REPEATER_SKIP_ATTRS":
            _exec(item, "updater.py", namespace)

    node = next(item for item in tree.body if isinstance(item, ast.ClassDef) and item.name == "LuciUpdater")
    node.bases = []
    node.body = [
        item
        for item in node.body
        if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef)) and item.name in UPDATER_METHODS
    ]
    _exec(node, "updater.py", namespace)
    return namespace["LuciUpdater"]


def client(number, connection, parent=""):
    return {
        "mac": f"00:00:00:00:01:{number:02X}",
        "parent": parent,
        "isap": 0,
        "ip": [{"ip": f"192.0.2.{100 + number}", "active": 1}],
        "connection": connection,
    }


def node(mac, ip):
    """A mesh node as misystem/devicelist lists it: skipped, but maps `parent`."""

    return {"mac": mac, "parent": "", "isap": 8, "ip": [{"ip": ip, "active": 1}]}


class Mesh:
    """Configured nodes, keyed by IP like async_get_integrations()."""

    def __init__(self):
        self.integrations = {}
        self.cls = load_updater(self.integrations)

    def add(self, ip, mac, mode, is_force_load=False):
        updater = self.cls()
        updater.ip = ip
        updater.is_force_load = is_force_load
        updater.data = {const.ATTR_SENSOR_MODE: mode, const.ATTR_DEVICE_MAC_ADDRESS: mac}
        updater.devices = {}
        updater.luci = Mock()
        updater.hass = Mock(data={})
        updater.new_device_callback = None
        updater._entry_id = f"entry-{ip}"
        updater._moved_devices = []
        updater._counters_reset_this_cycle = False
        updater._parent_push_pending = False
        updater._build_device = lambda device, integrations=None: dict(device)
        updater._mass_update_device = lambda device, integrations: False
        updater._has_dedicated_iot_wifi = lambda: False
        self.integrations[ip] = {const.UPDATER: updater}
        return updater


async def cycle(updater, devicelist):
    """The counter steps of LuciUpdater.update(), in their order."""

    updater._counters_reset_this_cycle = False  # update()
    if not (updater.is_repeater and updater.is_force_load):  # _async_prepare_devices()
        updater.reset_counter()
    updater.luci.device_list = AsyncMock(return_value={"list": devicelist})
    await updater._async_prepare_device_list(updater.data)
    await updater._async_apply_leaf_client_count()


def counters(updater):
    return {
        key: updater.data.get(key, 0)
        for key in (
            const.ATTR_SENSOR_DEVICES,
            const.ATTR_SENSOR_DEVICES_LAN,
            const.ATTR_SENSOR_DEVICES_2_4,
            const.ATTR_SENSOR_DEVICES_5_0,
        )
    }


OWN_CLIENTS = [
    client(1, Connection.LAN),
    client(2, Connection.LAN),
    client(3, Connection.WIFI_2_4),
    client(4, Connection.WIFI_5_0),
]
OWN_COUNTERS = {"devices": 4, "devices_lan": 2, "devices_2_4": 1, "devices_5_0": 1}


class SelfCountedClientTests(unittest.IsolatedAsyncioTestCase):
    async def test_access_point_counts_its_own_clients_once_per_cycle(self):
        mesh = Mesh()
        main = mesh.add(MAIN_IP, MAIN_MAC, Mode.ACCESS_POINT)

        for _ in range(3):
            await cycle(main, OWN_CLIENTS)

        self.assertEqual(counters(main), OWN_COUNTERS)

    async def test_access_point_follows_clients_that_leave(self):
        mesh = Mesh()
        main = mesh.add(MAIN_IP, MAIN_MAC, Mode.ACCESS_POINT)

        await cycle(main, OWN_CLIENTS)
        await cycle(main, OWN_CLIENTS[:1])
        self.assertEqual(counters(main), {"devices": 1, "devices_lan": 1, "devices_2_4": 0, "devices_5_0": 0})

        await cycle(main, [])
        self.assertEqual(counters(main)[const.ATTR_SENSOR_DEVICES], 0)

    async def test_mesh_main_counts_its_own_clients_and_pushes_the_leafs(self):
        mesh = Mesh()
        main = mesh.add(MAIN_IP, MAIN_MAC, Mode.ACCESS_POINT)
        leaf = mesh.add(LEAF_IP, LEAF_MAC, Mode.MESH_NODE)
        devicelist = [
            node(LEAF_MAC, LEAF_IP),
            *OWN_CLIENTS,
            client(10, Connection.WIFI_2_4, parent=LEAF_MAC),
            client(11, Connection.WIFI_5_0, parent=LEAF_MAC),
        ]

        for _ in range(3):
            await cycle(main, devicelist)

        self.assertEqual(counters(main), OWN_COUNTERS)
        self.assertEqual(counters(leaf), {"devices": 2, "devices_lan": 0, "devices_2_4": 1, "devices_5_0": 1})

    async def test_leaf_with_no_client_of_its_own_keeps_the_pushed_counts(self):
        mesh = Mesh()
        main = mesh.add(MAIN_IP, MAIN_MAC, Mode.ACCESS_POINT)
        leaf = mesh.add(LEAF_IP, LEAF_MAC, Mode.MESH_NODE)
        main.data["topo_graph"] = {"graph": {"is_main": True, "leafs": [{"ip": LEAF_IP, "onlines": 2}]}}
        pushed = [client(10, Connection.WIFI_2_4, parent=LEAF_MAC), client(11, Connection.WIFI_5_0, parent=LEAF_MAC)]

        for _ in range(3):
            await cycle(main, [node(LEAF_MAC, LEAF_IP), *pushed])
            await cycle(leaf, [])

        self.assertEqual(counters(leaf)[const.ATTR_SENSOR_DEVICES], 2)

    async def test_leaf_that_lists_its_clients_under_itself_does_not_grow(self):
        mesh = Mesh()
        leaf = mesh.add(LEAF_IP, LEAF_MAC, Mode.MESH_NODE)
        own = [client(10, Connection.WIFI_2_4, parent=LEAF_MAC), client(11, Connection.WIFI_5_0, parent=LEAF_MAC)]

        for _ in range(3):
            await cycle(leaf, own)

        self.assertEqual(counters(leaf)[const.ATTR_SENSOR_DEVICES], 2)

    async def test_force_load_leaf_is_unchanged(self):
        mesh = Mesh()
        leaf = mesh.add(LEAF_IP, LEAF_MAC, Mode.MESH_NODE, is_force_load=True)

        for _ in range(3):
            await cycle(leaf, OWN_CLIENTS)

        # Force load counts through wifi_connect_devices; devicelist never increments it.
        self.assertEqual(counters(leaf)[const.ATTR_SENSOR_DEVICES], 0)

    async def test_gateway_is_unchanged(self):
        mesh = Mesh()
        gateway = mesh.add(MAIN_IP, MAIN_MAC, Mode.DEFAULT)

        for _ in range(3):
            await cycle(gateway, OWN_CLIENTS)

        self.assertEqual(counters(gateway), OWN_COUNTERS)


if __name__ == "__main__":
    unittest.main()
