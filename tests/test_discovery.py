"""Discovery through unauthenticated topology responses and HA config flows."""

import json
from unittest.mock import patch

import httpx
import pytest
from homeassistant.core import HomeAssistant
from pytest_homeassistant_custom_component.common import load_fixture

from custom_components.miwifi.const import DOMAIN
from custom_components.miwifi.discovery import async_start_discovery


@pytest.mark.parametrize(
    ("fixture", "expected"),
    [
        ("topo_graph_data.json", {"192.168.31.1", "192.168.31.62"}),
        ("topo_graph_sub_leaf_data.json", {"192.168.31.1", "192.168.31.62", "192.168.31.162"}),
    ],
)
async def test_discovery(hass: HomeAssistant, fixture, expected):
    """Starting discovery twice still creates one flow per topology node."""
    graph = json.loads(load_fixture(fixture))
    client = httpx.AsyncClient(
        transport=httpx.MockTransport(lambda request: httpx.Response(200, json=graph))
    )
    with patch("custom_components.miwifi.discovery.get_async_client", return_value=client):
        async_start_discovery(hass)
        async_start_discovery(hass)
        await hass.async_block_till_done()
    await client.aclose()
    flows = hass.config_entries.flow.async_progress()
    assert {flow["context"]["unique_id"] for flow in flows} == expected
    for flow in flows:
        assert flow["handler"] == DOMAIN
        assert flow["step_id"] == "discovery_confirm"
        assert flow["context"]["source"] == "integration_discovery"


async def test_discovery_error(hass: HomeAssistant):
    """Unreachable HTTP and HTTPS endpoints produce no config flows."""
    requests = []

    def unreachable(request):
        requests.append(request)
        raise httpx.ConnectError("offline", request=request)

    client = httpx.AsyncClient(transport=httpx.MockTransport(unreachable))
    with patch("custom_components.miwifi.discovery.get_async_client", return_value=client):
        async_start_discovery(hass)
        await hass.async_block_till_done()
    await client.aclose()
    assert len(requests) == 6
    assert not hass.config_entries.flow.async_progress()


async def test_discovery_invalid_device(hass: HomeAssistant):
    """A topology without a main IP does not create a partially valid flow."""
    graph = {"code": 0, "graph": {"leafs": []}}
    client = httpx.AsyncClient(
        transport=httpx.MockTransport(lambda request: httpx.Response(200, json=graph))
    )
    with patch("custom_components.miwifi.discovery.get_async_client", return_value=client):
        async_start_discovery(hass)
        await hass.async_block_till_done()
    await client.aclose()
    assert not hass.config_entries.flow.async_progress()
