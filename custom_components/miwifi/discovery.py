"""The MiWifi integration discovery."""

from __future__ import annotations

import asyncio
from .logger import _LOGGER
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
from .luci import LuciClient




@callback
def async_start_discovery(hass: HomeAssistant) -> None:
    """Start discovery.

    :param hass: HomeAssistant: Home Assistant object
    """

    data: dict = hass.data.setdefault(DOMAIN, {})
    if DISCOVERY in data:
        return

    data[DISCOVERY] = True

    async def _async_discovery(*_: Any) -> None:
        """Async discovery

        :param _: Any
        """

        async_trigger_discovery(
            hass, await async_discover_devices(hass, get_async_client(hass, False))

        )

    # Do not block startup since discovery takes 31s or more
    asyncio.create_task(_async_discovery())

    async_track_time_interval(hass, _async_discovery, DISCOVERY_INTERVAL)


async def async_discover_devices(client: AsyncClient, hass: HomeAssistant) -> list:
    """Discover devices.

    :param client: AsyncClient: Async Client object
    :return list: List found IP
    """

    response: dict = {}

    for address in [CLIENT_ADDRESS, CLIENT_ADDRESS_IP, CLIENT_ADDRESS_DEFAULT]:
        try:
            response = await LuciClient(client, address).topo_graph()

            break
        except LuciError:
            continue

    if (
        "graph" not in response
        or "ip" not in response["graph"]
        or len(response["graph"]["ip"]) == 0
    ):
        return []

    devices: list = []

    if await async_check_ip_address(client, response["graph"]["ip"].strip()):
        devices.append(response["graph"]["ip"].strip())

    if "leafs" in response["graph"]:
        devices = await async_prepare_leafs(client, devices, response["graph"]["leafs"])

    await hass.async_add_executor_job(_LOGGER.debug, "Found devices: %s", devices)

    return devices


@callback
def async_trigger_discovery(hass: HomeAssistant, discovered_devices: list) -> None:
    """Trigger config flows for discovered devices."""
    for ip in discovered_devices:
        async def _launch(ip_address: str) -> None:
            model = "MiWiFi"
            try:
                client = get_async_client(hass)
                luci = LuciClient(client, ip_address)
                response = await luci.topo_graph()
                await hass.async_add_executor_job(_LOGGER.debug, "[MiWiFi] topo_graph for %s: %s", ip_address, response)

                model = (
                    response.get("hardware") or
                    response.get("model") or
                    response.get("graph", {}).get("hardware") or
                    response.get("graph", {}).get("model") or
                    "MiWiFi"
                )
            except Exception as e:
                 await hass.async_add_executor_job(_LOGGER.warning, "[MiWiFi] Failed to get model from %s: %s", ip_address, e)

            hass.async_create_task(
                hass.config_entries.flow.async_init(
                    DOMAIN,
                    context={
                        "source": config_entries.SOURCE_INTEGRATION_DISCOVERY,
                        "title_placeholders": {
                            "name": f"MiWifi {model} ({ip_address})"
                        }
                    },
                    data={
                        CONF_IP_ADDRESS: ip_address,
                        "model": model
                    },
                )
            )

        hass.async_create_task(_launch(ip))


async def async_prepare_leafs(client: AsyncClient, devices: list, leafs: list) -> list:
    """Recursive prepare leafs.

    :param client: AsyncClient: Async Client object
    :param devices: list: ip list
    :param leafs: list: leaf devices
    :return list
    """

    for leaf in leafs:
        if (
            "ip" not in leaf
            or len(leaf["ip"]) == 0
            or "hardware" not in leaf
            or len(leaf["hardware"]) == 0
        ):
            continue

        if await async_check_ip_address(client, leaf["ip"].strip()):
            devices.append(leaf["ip"].strip())

        if "leafs" in leaf and len(leaf["leafs"]) > 0:
            devices = await async_prepare_leafs(client, devices, leaf["leafs"])

    return devices


async def async_check_ip_address(client: AsyncClient, ip_address: str) -> bool:
    """Check ip address

    :param client: AsyncClient: Async Client object
    :param ip_address: str: IP address
    :return bool
    """

    try:
        await LuciClient(client, ip_address, timeout=DEFAULT_CHECK_TIMEOUT).topo_graph()
    except LuciConnectionError:
        return False
    except LuciError:
        pass

    return True
