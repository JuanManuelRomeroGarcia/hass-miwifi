from __future__ import annotations

import asyncio
from typing import Any

from homeassistant import config_entries
from homeassistant.const import CONF_IP_ADDRESS
from homeassistant.core import HomeAssistant, callback
from homeassistant.helpers.event import async_track_time_interval
from homeassistant.helpers.httpx_client import get_async_client
from httpx import AsyncClient

from .const import (
    CLIENT_ADDRESS,
    CLIENT_ADDRESS_IP,
    CLIENT_ADDRESS_DEFAULT,
    DEFAULT_CHECK_TIMEOUT,
    DISCOVERY,
    DISCOVERY_INTERVAL,
    DOMAIN,
)
from .exceptions import LuciConnectionError, LuciError
from .logger import _LOGGER


TOPO_PATH = "/cgi-bin/luci/api/misystem/topo_graph"


async def _fetch_topo_graph_raw(client: AsyncClient, host: str) -> dict:
    """Fetch topo_graph without relying on LuciClient URL/protocol logic."""
    last_exc: Exception | None = None

    for scheme in ("http", "https"):
        url = f"{scheme}://{host}{TOPO_PATH}"
        try:
            _LOGGER.debug("[MiWiFi] Discovery trying topo_graph: %s", url)
            r = await client.get(url, timeout=DEFAULT_CHECK_TIMEOUT, follow_redirects=True)
            r.raise_for_status()
            data = r.json()

            # Xiaomi suele devolver {"code":0, "graph":{...}} cuando OK
            if isinstance(data, dict) and data.get("code") == 0 and "graph" in data:
                _LOGGER.debug("[MiWiFi] Discovery topo_graph OK via %s", url)
                return data

            _LOGGER.debug("[MiWiFi] Discovery topo_graph not OK via %s -> %s", url, data)
        except Exception as e:
            last_exc = e
            _LOGGER.debug("[MiWiFi] Discovery topo_graph failed via %s: %s", url, e)

    raise LuciError(f"Discovery topo_graph failed for host={host}: {last_exc}")


@callback
def async_start_discovery(hass: HomeAssistant) -> None:
    data: dict = hass.data.setdefault(DOMAIN, {})
    if DISCOVERY in data:
        return

    data[DISCOVERY] = True

    async def _async_discovery(*_: Any) -> None:
        try:
            client = get_async_client(hass, False)
            devices = await async_discover_devices(hass, client)
            async_trigger_discovery(hass, devices)
        except Exception:
            _LOGGER.exception("[MiWiFi] Discovery task crashed")

    # usa el loop de HA, no asyncio.create_task “pelado”
    hass.async_create_task(_async_discovery())
    async_track_time_interval(hass, _async_discovery, DISCOVERY_INTERVAL)


async def async_discover_devices(hass: HomeAssistant, client: AsyncClient) -> list[str]:
    response: dict = {}

    for address in (CLIENT_ADDRESS, CLIENT_ADDRESS_IP, CLIENT_ADDRESS_DEFAULT):
        try:
            response = await _fetch_topo_graph_raw(client, address)
            break
        except LuciError:
            continue

    graph = response.get("graph") if isinstance(response, dict) else None
    ip = (graph or {}).get("ip") if isinstance(graph, dict) else None
    if not ip:
        _LOGGER.debug("[MiWiFi] Discovery: topo_graph returned no ip: %s", response)
        return []

    devices: list[str] = []
    main_ip = str(ip).strip()

    # aquí mantenemos tu check (pero si falla por LuciError, tu lógica ya lo acepta)
    devices.append(main_ip)

    leafs = (graph or {}).get("leafs")
    if isinstance(leafs, list) and leafs:
        devices = await async_prepare_leafs(client, devices, leafs)

    _LOGGER.debug("[MiWiFi] Discovery found devices: %s", devices)
    return devices


@callback
def async_trigger_discovery(hass: HomeAssistant, discovered_devices: list[str]) -> None:
    """Trigger config flows for discovered devices, skipping already configured."""
    for ip in discovered_devices:
        if _already_configured(hass, ip):
            _LOGGER.debug("[MiWiFi] Discovery: %s already configured, skipping", ip)
            continue

        hass.async_create_task(
            hass.config_entries.flow.async_init(
                DOMAIN,
                context={"source": config_entries.SOURCE_INTEGRATION_DISCOVERY},
                data={CONF_IP_ADDRESS: ip},
            )
        )


async def async_prepare_leafs(client: AsyncClient, devices: list[str], leafs: list) -> list[str]:
    for leaf in leafs:
        ip = (leaf or {}).get("ip")
        hw = (leaf or {}).get("hardware")
        if not ip or not hw:
            continue

        leaf_ip = str(ip).strip()
        if leaf_ip in devices:
            continue
        devices.append(leaf_ip)

        sub = leaf.get("leafs")
        if isinstance(sub, list) and sub:
            devices = await async_prepare_leafs(client, devices, sub)

    return devices


async def async_check_ip_address(client: AsyncClient, ip_address: str) -> bool:
    try:
        # Reutilizamos la misma llamada raw para validar rápido
        await _fetch_topo_graph_raw(client, ip_address)
    except LuciConnectionError:
        return False
    except LuciError:
        # Si “no es válido” por API, igual lo consideramos alcanzable (tu lógica original)
        return True

    return True


def _already_configured(hass: HomeAssistant, ip: str) -> bool:
    for e in hass.config_entries.async_entries(DOMAIN):
        if e.data.get(CONF_IP_ADDRESS) == ip:
            return True
    return False