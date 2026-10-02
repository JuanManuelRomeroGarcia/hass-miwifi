"""Node role taken from the topology graph, not just xqnetwork/mode.

A wired-backhaul leaf answers `xqnetwork/mode` with 0/default, which types it as
a standalone gateway: the coordinator then asks it for WAN and MAC filter data it
has no way to serve, and the mode sensor reads `default` for a mesh node. The
graph knows better, both from what the node says about itself and from what the
node above it says about the node.
"""

# pylint: disable=no-member,protected-access

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from custom_components.miwifi.const import ATTR_SENSOR_MODE, UPDATER
from custom_components.miwifi.enum import Mode
from custom_components.miwifi.updater import LuciUpdater, _find_leaf

LEAF_IP: str = "192.0.2.104"
MAIN_IP: str = "192.0.2.101"


def _updater(ip: str = LEAF_IP) -> LuciUpdater:
    """Build an updater shell with only the attributes these paths touch."""

    updater = LuciUpdater.__new__(LuciUpdater)
    updater.ip = ip
    updater.is_force_load = False
    updater.data = {}
    updater.luci = MagicMock()
    updater._is_cb0401v2 = False
    updater._topology_role_logged = False

    hass = MagicMock()

    async def _run(func, *args):
        return func(*args)

    hass.async_add_executor_job = _run
    updater.hass = hass

    return updater


def _main_with_leaf(leaf_ip: str = LEAF_IP, **leaf_fields) -> LuciUpdater:
    """A main whose graph lists one leaf."""

    main = _updater(ip=MAIN_IP)
    main.data = {
        "topo_graph": {
            "graph": {
                "ip": MAIN_IP,
                "mode": 0,
                "is_main": True,
                "leafs": [{"ip": leaf_ip, "hardware": "RA82", "mode": 1, **leaf_fields}],
            }
        }
    }

    return main


def _patch_integrations(*updaters: LuciUpdater):
    """Present the given updaters as the configured MiWiFi entries."""

    return patch(
        "custom_components.miwifi.updater.async_get_integrations",
        return_value={up.ip: {UPDATER: up} for up in updaters},
    )


# --------------------------------------------------------------------------
# Graph walking
# --------------------------------------------------------------------------


def test_leafs_are_found_through_nesting_and_past_malformed_entries() -> None:
    """Real graphs carry leaves with no ip, and leaves under leaves."""

    graph = {
        "leafs": [
            {"ip": "", "name": "Incorrect"},
            {"name": "no ip at all"},
            "not a dict",
            {"ip": "192.0.2.102", "leafs": [{"ip": LEAF_IP, "onlines": 3}]},
        ]
    }

    assert _find_leaf(graph, LEAF_IP) == {"ip": LEAF_IP, "onlines": 3}
    assert _find_leaf(graph, "192.0.2.199") is None
    assert _find_leaf({}, LEAF_IP) is None


# --------------------------------------------------------------------------
# Classification
# --------------------------------------------------------------------------


def test_the_node_classifies_itself_from_its_own_graph() -> None:
    """A node that knows it is a mesh node says so, whatever the endpoint says."""

    updater = _updater()
    updater.data["topo_graph"] = {"graph": {"mode": Mode.MESH_NODE.value}}

    with _patch_integrations(updater):
        assert updater._topology_role() == Mode.MESH_NODE


def test_a_leaf_is_classified_from_the_graph_of_the_main() -> None:
    """The leaf's own graph is empty on the first cycle; the main's is not."""

    updater = _updater()
    main = _main_with_leaf()

    with _patch_integrations(updater, main):
        assert updater._topology_role() == Mode.MESH_NODE


def test_the_main_is_never_classified_as_a_leaf() -> None:
    """Whatever anyone lists, the node holding the root graph is the gateway."""

    main = _main_with_leaf()

    with _patch_integrations(main):
        assert main._topology_role() is None


def test_an_unknown_node_leaves_the_endpoint_in_charge() -> None:
    """Nothing here may push a node towards default."""

    updater = _updater()

    with _patch_integrations(updater):
        assert updater._topology_role() is None


def test_a_gateway_graph_does_not_make_a_role() -> None:
    """mode 0 is not a mesh role, so the probe still decides."""

    updater = _updater()
    updater.data["topo_graph"] = {"graph": {"mode": 0}}

    with _patch_integrations(updater):
        assert updater._topology_role() is None


# --------------------------------------------------------------------------
# What the classification changes
# --------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_a_classified_leaf_skips_the_gateway_mode_probe() -> None:
    """The endpoint answers `default` here, and asking costs a round trip."""

    updater = _updater()
    updater.luci.mode = AsyncMock()
    main = _main_with_leaf()
    data: dict = {}

    with _patch_integrations(updater, main):
        await updater._async_prepare_mode(data)

    updater.luci.mode.assert_not_awaited()
    assert data[ATTR_SENSOR_MODE] == Mode.MESH_NODE


@pytest.mark.asyncio
async def test_a_gateway_is_still_probed() -> None:
    """Nothing changes for a node the topology does not place."""

    updater = _updater()
    updater.luci.mode = AsyncMock(return_value={"mode": 0})
    data: dict = {}

    with _patch_integrations(updater):
        await updater._async_prepare_mode(data)

    updater.luci.mode.assert_awaited_once()
    assert data[ATTR_SENSOR_MODE] == Mode.DEFAULT
