"""A node's role on its first refresh, over a scripted router API.

A wired-backhaul leaf answers `xqnetwork/mode` with 0/default, and only the
topology graph says it is a mesh node (see test_updater_topology_role.py). A
node stores its own graph at the end of a refresh, and on a full restart every
entry refreshes at once, so the main has not stored its graph either when the
leaf reaches the mode step. So when nothing places the node yet, the mode step
reads the node's own graph itself. Without that, the leaf stays a gateway for
its whole first refresh: it is asked the mode probe, and with force load the
clients on its own radios are not listed.

These run complete refreshes of real updaters. Each router answers over HTTP
from a script, so the client's own mode fallback runs too, and every request
is noted. The role the first refresh gives must be the one the second keeps,
for the leaf and for every node the endpoint already types right.
"""

# pylint: disable=protected-access

from __future__ import annotations

import asyncio
from unittest.mock import AsyncMock, patch

import httpx
import pytest
from homeassistant.core import HomeAssistant

from custom_components.miwifi.const import ATTR_SENSOR_MODE, ATTR_STATE, DOMAIN
from custom_components.miwifi.enum import Mode
from custom_components.miwifi.sensor import MIWIFI_SENSORS, MiWifiSensor
from custom_components.miwifi.updater import LuciUpdater
from tests.setup import async_setup

MAIN_IP: str = "192.0.2.1"
LEAF_IP: str = "192.0.2.3"
NODE_IP: str = "192.0.2.5"
OTHER_IP: str = "192.0.2.9"

MAIN_MAC: str = "02:00:00:00:00:01"
LEAF_MAC: str = "02:00:00:00:00:03"
NODE_MAC: str = "02:00:00:00:00:05"
OTHER_MAC: str = "02:00:00:00:00:09"

# On the leaf's own radios.
RADIO_CLIENT: str = "02:00:00:00:00:10"

MODE: str = "xqnetwork/mode"
NETMODE: str = "xqnetwork/get_netmode"
TOPOLOGY: str = "misystem/topo_graph"
RADIO_LIST: str = "xqnetwork/wifi_connect_devices"

# Asked only on a first refresh: the session and the node's identity.
FIRST_REFRESH_ONLY: frozenset[str] = frozenset({"xqsystem/login", "xqsystem/init_info"})

# A node's own graph. A mesh node lists nothing below it.
NODE_GRAPH: dict = {"code": 0, "show": 0, "graph": {"mode": 3}}
GATEWAY_GRAPH: dict = {"code": 0, "show": 1, "graph": {"mode": 0}}
REPEATER_GRAPH: dict = {"code": 0, "show": 0, "graph": {"mode": 1}}

# The root of the mesh, an access point listing the leaf as a wired one.
MAIN_GRAPH: dict = {
    "code": 0,
    "show": 1,
    "graph": {
        "mode": 2,
        "leafs": [
            {"ip": LEAF_IP, "hardware": "RA82", "mode": 1, "onlines": 1, "link_type": "wired"}
        ],
    },
}


class Router:
    """One router's HTTP API: answers from a script and notes every request.

    A dict answer is sent as JSON. A number is an HTTP status sent with an
    error page, which the client cannot parse; a path with no answer gets 404.
    """

    def __init__(
        self, ip: str, mac: str, hardware: str, log: list[tuple[str, str]], answers: dict
    ) -> None:
        self.ip = ip
        self.log = log
        self.delay: float = 0
        self.requests: list[str] = []
        self.answers: dict = {
            "xqsystem/login": {"code": 0, "token": "token"},
            "xqsystem/init_info": {
                "code": 0,
                "model": f"xiaomi.router.{hardware.lower()}",
                "hardware": hardware,
                "routername": hardware,
                "romversion": "1.0.0",
                "countrycode": "EU",
            },
            "misystem/status": {
                "code": 0,
                "hardware": {"mac": mac, "sn": "0", "version": "1.0.0"},
                "upTime": "100",
                "mem": {"usage": 0.5},
                "wan": {},
            },
            "xqsystem/vpn_status": {"code": 0, "uptime": 0},
            "xqsystem/check_rom_update": {"code": 0, "needUpdate": 0},
            MODE: {"code": 0, "mode": 0},
            "xqnetwork/wan_info": {"code": 0, "info": {}},
            "misystem/led": {"code": 0, "status": 1},
            "xqnetwork/wifi_detail_all": {"code": 0, "info": []},
            RADIO_LIST: {"code": 0, "list": []},
            "xqnetwork/wifi_macfilter_info": {"code": 0, "list": []},
            "misystem/devicelist": {"code": 0, "mac": mac, "list": []},
            "misystem/device_list": {"code": 0, "devices": []},
            "misystem/newstatus": {"code": 0, "count": 0},
            "xqnetwork/wifiap_signal": {"code": 0, "signal": 60},
        } | answers

    async def handle(self, request: httpx.Request) -> httpx.Response:
        """Answer one request."""

        path = request.url.path.partition("/api/")[2]
        if not path:  # web/logout
            return httpx.Response(200, text="")

        self.requests.append(path)
        self.log.append((self.ip, path))
        await asyncio.sleep(self.delay)

        answer = self.answers.get(path, 404)
        if isinstance(answer, int):
            return httpx.Response(answer, text="<html>error</html>")

        return httpx.Response(200, json=answer)


class Mesh:
    """Configured entries, each served by its scripted router."""

    def __init__(self, hass: HomeAssistant) -> None:
        self.hass = hass
        self.log: list[tuple[str, str]] = []
        self._clients: list[httpx.AsyncClient] = []
        self._updaters: list[LuciUpdater] = []

    async def add(
        self,
        ip: str,
        mac: str,
        hardware: str,
        answers: dict | None = None,
        *,
        force_load: bool = False,
        ap_mode: bool = False,
    ) -> tuple[LuciUpdater, Router]:
        """Register an entry, as setup does before its first refresh."""

        updater, _ = await async_setup(self.hass, ip, is_force=force_load)
        updater.is_ap_mode = ap_mode

        router = Router(ip, mac, hardware, self.log, answers or {})
        client = httpx.AsyncClient(transport=httpx.MockTransport(router.handle))
        updater.luci._client = client
        updater.luci._client_factory = lambda: client

        self._clients.append(client)
        self._updaters.append(updater)

        return updater, router

    async def async_close(self) -> None:
        """Stop every entry."""

        for updater in self._updaters:
            await updater.async_shutdown()
        for client in self._clients:
            await client.aclose()
        self.hass.data[DOMAIN].clear()


@pytest.fixture
async def mesh(hass: HomeAssistant):
    """Entries that start with no data, like on a restart."""

    # No pause between router calls. The capability probe of a main asks the
    # mode endpoint again after its first refresh; it is not what these watch.
    with patch("custom_components.miwifi.updater.DEFAULT_CALL_DELAY", 0), patch(
        "custom_components.miwifi.compatibility.CompatibilityChecker.run",
        return_value={"device_list": True, "wifi_config": True, "portforward": False},
    ):
        built = Mesh(hass)
        yield built
        await built.async_close()


async def _refresh(updater: LuciUpdater, router: Router) -> list[str]:
    """Run one complete refresh and return what it asked the router."""

    mark = len(router.requests)
    data = await updater.update()
    assert data[ATTR_STATE] is True

    return router.requests[mark:]


def _mode_sensor(updater: LuciUpdater) -> str:
    """What the node's mode sensor shows from the current data."""

    description = next(d for d in MIWIFI_SENSORS if d.key == ATTR_SENSOR_MODE)

    return MiWifiSensor(f"{updater.entry_id}-{ATTR_SENSOR_MODE}", description, updater).native_value


@pytest.mark.parametrize("main_state", ["not-refreshed", "refreshing", "refreshed"])
async def test_a_wired_leaf_is_a_mesh_node_from_its_first_refresh(
    mesh: Mesh, main_state: str
) -> None:
    """The leaf behind a main in access point mode, as on a full restart.

    `not-refreshed`: the main is registered and has no data yet.
    `refreshing`: both first refreshes run at once, as setup runs them.
    `refreshed`: the main stored its graph first, as when only the leaf reloads.
    """

    main, main_api = await mesh.add(
        MAIN_IP, MAIN_MAC, "RD28", {TOPOLOGY: MAIN_GRAPH}, force_load=True, ap_mode=True
    )
    leaf, leaf_api = await mesh.add(
        LEAF_IP,
        LEAF_MAC,
        "RA82",
        {
            TOPOLOGY: NODE_GRAPH,
            RADIO_LIST: {"code": 0, "list": [{"mac": RADIO_CLIENT, "wifiIndex": 1, "signal": 80}]},
            "misystem/newstatus": {"code": 0, "count": 1, "2g": {"online_sta_count": 1}},
        },
        force_load=True,
    )

    if main_state == "refreshing":
        main_api.delay = leaf_api.delay = 0.02
        results = await asyncio.gather(main.update(), leaf.update())
        assert all(data[ATTR_STATE] for data in results)
        main_api.delay = leaf_api.delay = 0

        # The leaf was past its mode step before the main stored its graph.
        assert mesh.log.index((LEAF_IP, "misystem/led")) < mesh.log.index(
            (MAIN_IP, TOPOLOGY)
        )
        first = list(leaf_api.requests)
    else:
        if main_state == "refreshed":
            await _refresh(main, main_api)
        first = await _refresh(leaf, leaf_api)

    assert leaf.data[ATTR_SENSOR_MODE] == Mode.MESH_NODE
    assert leaf.is_repeater
    assert _mode_sensor(leaf) == Mode.MESH_NODE.phrase
    assert not {MODE, NETMODE} & set(first)

    # With force load, the clients on the node's own radios are its clients.
    assert RADIO_CLIENT in leaf.devices

    if main_state == "refreshed":
        # The main's graph places the leaf, so its own is read once, as before.
        assert first.count(TOPOLOGY) == 1

    second = await _refresh(leaf, leaf_api)

    assert leaf.data[ATTR_SENSOR_MODE] == Mode.MESH_NODE
    assert RADIO_CLIENT in leaf.devices
    assert second.count(TOPOLOGY) == 1

    # Apart from the session and the identity, the first refresh asks the leaf
    # for nothing the second does not.
    assert set(first) - FIRST_REFRESH_ONLY <= set(second)


@pytest.mark.parametrize(
    ("answers", "ap_mode", "entries", "role", "is_main", "probes"),
    [
        pytest.param(
            {TOPOLOGY: GATEWAY_GRAPH}, False, 1, Mode.DEFAULT, True, [MODE],
            id="standalone-gateway",
        ),
        pytest.param(
            {TOPOLOGY: GATEWAY_GRAPH}, False, 2, Mode.DEFAULT, True, [MODE],
            id="gateway-beside-another-entry",
        ),
        # A single entry is taken for the main, whatever its graph says.
        pytest.param(
            {TOPOLOGY: NODE_GRAPH}, False, 1, Mode.DEFAULT, True, [MODE],
            id="single-entry-with-a-leaf-graph",
        ),
        pytest.param(
            {TOPOLOGY: MAIN_GRAPH}, False, 2, Mode.DEFAULT, True, [MODE],
            id="mesh-main",
        ),
        pytest.param(
            {TOPOLOGY: MAIN_GRAPH, MODE: {"code": 0, "mode": 2}}, False, 2,
            Mode.ACCESS_POINT, True, [MODE],
            id="mesh-main-access-point",
        ),
        pytest.param(
            {TOPOLOGY: MAIN_GRAPH}, True, 2, Mode.ACCESS_POINT, True, [],
            id="mesh-main-ap-option",
        ),
        pytest.param(
            {TOPOLOGY: 404}, False, 1, Mode.DEFAULT, True, [MODE],
            id="no-topology-single-entry",
        ),
        pytest.param(
            {TOPOLOGY: 404}, False, 2, Mode.DEFAULT, False, [MODE],
            id="no-topology-gateway",
        ),
        pytest.param(
            {TOPOLOGY: 404, MODE: {"code": 0, "mode": 1}}, False, 2,
            Mode.REPEATER, False, [MODE],
            id="no-topology-repeater",
        ),
        pytest.param(
            {TOPOLOGY: REPEATER_GRAPH, MODE: {"code": 0, "mode": 1}}, False, 2,
            Mode.REPEATER, False, [MODE],
            id="wifi-repeater",
        ),
        # Not the main, and its own graph says access point.
        pytest.param(
            {TOPOLOGY: {"code": 0, "show": 0, "graph": {"mode": 2}}}, False, 2,
            Mode.ACCESS_POINT, False, [],
            id="access-point-graph",
        ),
        # xqnetwork/mode fails with HTTP 500, and get_netmode answers.
        pytest.param(
            {TOPOLOGY: 404, MODE: 500, NETMODE: {"code": 0, "netmode": 2}}, False, 2,
            Mode.ACCESS_POINT, False, [MODE, NETMODE],
            id="mode-500-netmode-fallback",
        ),
        # The same node, when its own graph says mesh node.
        pytest.param(
            {TOPOLOGY: NODE_GRAPH, MODE: 500, NETMODE: {"code": 0, "netmode": 2}}, False, 2,
            Mode.MESH_NODE, False, [],
            id="mode-500-own-graph",
        ),
    ],
)
async def test_the_first_refresh_gives_the_role_the_second_keeps(
    mesh: Mesh,
    answers: dict,
    ap_mode: bool,
    entries: int,
    role: Mode,
    is_main: bool,
    probes: list[str],
) -> None:
    """A node is typed on its first refresh as on every later one.

    With two entries, the other one is registered and never refreshed.
    """

    if entries == 2:
        await mesh.add(OTHER_IP, OTHER_MAC, "RD28")
    node, api = await mesh.add(NODE_IP, NODE_MAC, "RD28", answers, ap_mode=ap_mode)

    first = await _refresh(node, api)

    assert node.data[ATTR_SENSOR_MODE] == role
    assert _mode_sensor(node) == role.phrase
    assert [path for path in first if path in (MODE, NETMODE)] == probes
    assert bool(node.data["topo_graph"]["graph"].get("is_main")) is is_main

    second = await _refresh(node, api)

    assert node.data[ATTR_SENSOR_MODE] == role
    assert bool(node.data["topo_graph"]["graph"].get("is_main")) is is_main
    assert second.count(TOPOLOGY) == 1


async def test_a_lone_leaf_is_a_mesh_node_when_the_main_was_chosen(mesh: Mesh) -> None:
    """The saved main is another node, whose entry is not registered yet.

    A single entry is otherwise taken for the main. The saved main says it is
    not, so the leaf's own graph types it from the first refresh.
    """

    leaf, api = await mesh.add(LEAF_IP, LEAF_MAC, "RA82", {TOPOLOGY: NODE_GRAPH})

    with patch(
        "custom_components.miwifi.frontend.async_load_manual_main_mac",
        AsyncMock(return_value=MAIN_MAC),
    ):
        first = await _refresh(leaf, api)

        assert leaf.data[ATTR_SENSOR_MODE] == Mode.MESH_NODE
        assert not {MODE, NETMODE} & set(first)
        assert not leaf.data["topo_graph"]["graph"].get("is_main")

        await _refresh(leaf, api)

    assert leaf.data[ATTR_SENSOR_MODE] == Mode.MESH_NODE
