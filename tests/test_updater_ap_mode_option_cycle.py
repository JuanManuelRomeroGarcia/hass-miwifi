"""The access point option over complete update cycles, with and without topology.

`test_updater_ap_mode_option.py` checks each guarded step on its own. These run
the whole cycle of a real updater on a mesh node, with every router endpoint
mocked, so they also show what the option does not touch: the same node is run
with the option off and on, and the two cycles must differ only in the gateway
requests the option exists to skip.
"""

# pylint: disable=protected-access

from __future__ import annotations

import json
from unittest.mock import AsyncMock, patch

import pytest
from homeassistant.core import HomeAssistant
from pytest_homeassistant_custom_component.common import load_fixture

from custom_components.miwifi.const import (
    ATTR_SENSOR_DEVICES,
    ATTR_SENSOR_DEVICES_2_4,
    ATTR_SENSOR_DEVICES_5_0,
    ATTR_SENSOR_DEVICES_5_0_GAME,
    ATTR_SENSOR_DEVICES_GUEST,
    ATTR_SENSOR_DEVICES_LAN,
    ATTR_SENSOR_MODE,
    ATTR_SENSOR_WAN_DOWNLOAD_SPEED,
    ATTR_SENSOR_WAN_UPLOAD_SPEED,
    ATTR_STATE,
    DOMAIN,
)
from custom_components.miwifi.enum import Mode
from custom_components.miwifi.exceptions import LuciRequestError
from tests.setup import MOCK_IP_ADDRESS, async_mock_luci_client, async_setup

# The leaf the main's topology fixture lists.
NODE_IP: str = "192.168.31.62"

COUNTERS: tuple[str, ...] = (
    ATTR_SENSOR_DEVICES,
    ATTR_SENSOR_DEVICES_LAN,
    ATTR_SENSOR_DEVICES_2_4,
    ATTR_SENSOR_DEVICES_5_0,
    ATTR_SENSOR_DEVICES_5_0_GAME,
    ATTR_SENSOR_DEVICES_GUEST,
)

# The gateway requests the option skips, and nothing else.
GATEWAY_REQUESTS: frozenset[str] = frozenset({"mode", "wan_info", "macfilter_info"})


async def _run_node(hass: HomeAssistant, *, is_ap_mode: bool, topology: bool) -> dict:
    """Run two complete cycles of a mesh node and report the second.

    The first cycle also logs in and reads the node's identity, so the second
    is the one compared.

    With `topology`, the main lists the node as a leaf and the node's own graph
    calls it a mesh node, as on a wired-backhaul mesh. Without it, the node's
    graph request fails and no other entry lists it.

    :return dict: the second cycle's mode and data, whether the node keeps its
        WAN speed sensors, the client MACs and the router requests it made
    """

    with patch("custom_components.miwifi.updater.LuciClient") as client, patch(
        "custom_components.miwifi.async_start_discovery", return_value=None
    ), patch("custom_components.miwifi.updater.asyncio.sleep", new=AsyncMock()):
        await async_mock_luci_client(client)
        luci = client.return_value

        # A second entry, the main. With a single entry the node would be taken
        # for the main itself, and the main never takes a role from the graph.
        main, _ = await async_setup(hass, MOCK_IP_ADDRESS)
        node, _ = await async_setup(hass, NODE_IP)
        node.is_ap_mode = is_ap_mode

        if topology:
            main_graph: dict = json.loads(load_fixture("topo_graph_data.json"))
            main_graph["graph"]["is_main"] = True
            main.data = {"topo_graph": main_graph}

            own_graph: dict = json.loads(load_fixture("topo_graph_data.json"))
            own_graph["graph"].update(ip=NODE_IP, mode=Mode.MESH_NODE.value, leafs=[])
            luci.topo_graph = AsyncMock(return_value=own_graph)
        else:
            luci.topo_graph = AsyncMock(side_effect=LuciRequestError("no topology"))

        try:
            await node.update()

            for name in dir(luci):
                if isinstance(method := getattr(luci, name), AsyncMock):
                    method.reset_mock()

            data: dict = await node.update()

            return {
                "data": data,
                "supports_wan": node.supports_wan,
                "macs": sorted(node.devices),
                "requests": {
                    name
                    for name in dir(luci)
                    if isinstance(method := getattr(luci, name), AsyncMock)
                    and method.await_count
                },
            }
        finally:
            await node.async_shutdown()
            await main.async_shutdown()
            hass.data[DOMAIN].clear()


@pytest.mark.parametrize(
    ("topology", "role_without_option", "skipped"),
    [
        # The endpoint is the only source of the role, so it is asked.
        pytest.param(False, Mode.DEFAULT, GATEWAY_REQUESTS, id="no-topology"),
        # The topology already replaces the mode probe; WAN and MAC filter
        # are still asked without the option.
        pytest.param(
            True,
            Mode.MESH_NODE,
            GATEWAY_REQUESTS - {"mode"},
            id="topology",
        ),
    ],
)
async def test_option_skips_only_the_gateway_requests(
    hass: HomeAssistant, topology: bool, role_without_option: Mode, skipped: frozenset
) -> None:
    """Off and on differ in the gateway requests, and in nothing a client sees."""

    off = await _run_node(hass, is_ap_mode=False, topology=topology)
    on = await _run_node(hass, is_ap_mode=True, topology=topology)

    assert off["data"][ATTR_SENSOR_MODE] == role_without_option
    assert on["data"][ATTR_SENSOR_MODE] == Mode.ACCESS_POINT
    assert off["data"][ATTR_STATE] is True
    assert on["data"][ATTR_STATE] is True

    # Exactly the gateway requests go, and the option asks for nothing new.
    assert off["requests"] - on["requests"] == skipped
    assert on["requests"] - off["requests"] == set()
    assert skipped <= off["requests"]
    assert not GATEWAY_REQUESTS & on["requests"]

    # The clients are listed and counted the same way.
    assert on["macs"] == off["macs"] != []
    for counter in COUNTERS:
        assert on["data"].get(counter) == off["data"].get(counter), counter
    assert on["data"][ATTR_SENSOR_DEVICES] == len(on["macs"])


@pytest.mark.parametrize("topology", [False, True], ids=["no-topology", "topology"])
async def test_option_keeps_the_wan_speed_sensors(hass: HomeAssistant, topology: bool) -> None:
    """The WAN speeds come from misystem/status, which the option does not skip.

    Without the option the WAN state from wan_info lets the speed sensors be
    created; with it, wan_info is never asked and the counters status reports
    take its place. Either way the node keeps them, with the same values.
    """

    off = await _run_node(hass, is_ap_mode=False, topology=topology)
    on = await _run_node(hass, is_ap_mode=True, topology=topology)

    assert "wan_info" in off["requests"]
    assert "wan_info" not in on["requests"]

    assert off["supports_wan"] is True
    assert on["supports_wan"] is True
    for speed in (ATTR_SENSOR_WAN_DOWNLOAD_SPEED, ATTR_SENSOR_WAN_UPLOAD_SPEED):
        assert on["data"][speed] == off["data"][speed] > 0, speed
