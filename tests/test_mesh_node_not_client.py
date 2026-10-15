"""A mesh node must never be tracked, restored or kept as a client.

Runs on a real Home Assistant core (pytest-homeassistant-custom-component):
real LuciUpdater instances, device stores, entity and device registries, and
the purge handlers that the device_tracker and sensor platforms connect.
"""

from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import AsyncMock, Mock, patch

import pytest

from homeassistant.const import CONF_IP_ADDRESS
from homeassistant.helpers import device_registry as dr
from homeassistant.helpers import entity_registry as er
from pytest_homeassistant_custom_component.common import MockConfigEntry, MockEntityPlatform

from custom_components.miwifi import device_tracker, helper, sensor
from custom_components.miwifi.const import (
    ATTR_DEVICE_MAC_ADDRESS,
    ATTR_SENSOR_MODE,
    ATTR_STATE,
    ATTR_TRACKER_ENTRY_ID,
    ATTR_TRACKER_IP,
    ATTR_TRACKER_MAC,
    ATTR_TRACKER_UPDATER_ENTRY_ID,
    CONF_ENABLE_DEVICE_SENSORS,
    CONF_IS_TRACK_DEVICES,
    DOMAIN,
    UPDATER,
)
from custom_components.miwifi.enum import Mode
from custom_components.miwifi.helper import get_store
from custom_components.miwifi.sensor import MIWIFI_DEVICE_SENSORS
from custom_components.miwifi.updater import LuciUpdater

MAIN_IP = "192.0.2.1"
NODE_IP = "192.0.2.3"
NODE_MAC = "02:00:00:00:00:0a"
CLIENT_MAC = "02:00:00:00:00:0b"
CLIENT_IP = "192.0.2.50"


@pytest.fixture
def router_doubles():
    """No router traffic or notifications; real updater, store and registries."""
    with (
        patch("custom_components.miwifi.updater.LuciClient"),
        patch("custom_components.miwifi.updater.get_async_client", return_value=Mock()),
        patch(
            "custom_components.miwifi.update.MiWiFiNewDeviceNotifier.async_notify_new_device",
            new_callable=AsyncMock,
        ),
        patch.object(LuciUpdater, "_build_device", side_effect=lambda device, integrations: dict(device)),
        patch.object(sensor, "_async_add_all_sensors_later", new_callable=AsyncMock),
    ):
        yield


def _entry(hass, ip):
    entry = MockConfigEntry(
        domain=DOMAIN,
        title=ip,
        data={CONF_IP_ADDRESS: ip},
        options={CONF_IS_TRACK_DEVICES: True, CONF_ENABLE_DEVICE_SENSORS: True},
    )
    entry.add_to_hass(hass)
    return entry


def _updater(hass, entry, ip, *, is_main):
    updater = LuciUpdater(
        hass, ip, "test-password", store=get_store(hass, ip), entry_id=entry.entry_id
    )
    updater.update_interval = None
    updater.data = {
        ATTR_STATE: True,
        ATTR_SENSOR_MODE: Mode.DEFAULT if is_main else Mode.MESH_NODE,
        "topo_graph": {"graph": {"is_main": int(is_main)}},
    }
    hass.data.setdefault(DOMAIN, {})[entry.entry_id] = {UPDATER: updater}
    return updater


def _platform(hass, entry, domain):
    platform = MockEntityPlatform(hass, domain=domain, platform_name=DOMAIN)
    platform.config_entry = entry
    platform.async_prepare()
    return platform


async def _connect_platforms(hass, entry):
    """Set up the tracker and sensor platforms, which connect the purge handlers."""
    for module, domain in ((device_tracker, "device_tracker"), (sensor, "sensor")):
        platform = _platform(hass, entry, domain)
        await module.async_setup_entry(hass, entry, platform._async_schedule_add_entities)
    await hass.async_block_till_done()


def _row(mac, ip, isap=0):
    return {"mac": mac.upper(), "isap": isap, "parent": "", "ip": [{"ip": ip, "active": 1}]}


async def _refresh(hass, updater, rows):
    updater.luci.device_list = AsyncMock(return_value={"code": 0, "list": rows})
    with patch("custom_components.miwifi.updater.asyncio.sleep", AsyncMock()):
        await updater._async_prepare_device_list({})
    await hass.async_block_till_done()


@pytest.mark.parametrize("known_by", ["configured_mac", "reported_isap"])
async def test_force_load_wifi_list_skips_known_mesh_nodes(hass, router_doubles, known_by):
    parent_entry, node_entry = _entry(hass, MAIN_IP), _entry(hass, NODE_IP)
    parent = _updater(hass, parent_entry, MAIN_IP, is_main=False)
    node = _updater(hass, node_entry, NODE_IP, is_main=False)
    if known_by == "configured_mac":
        node.data[ATTR_DEVICE_MAC_ADDRESS] = NODE_MAC
    else:
        hass.data[DOMAIN]["mesh_node_macs"] = {NODE_MAC}
    parent.is_force_load = True
    parent.devices[NODE_MAC] = {ATTR_TRACKER_MAC: NODE_MAC}
    node.devices[NODE_MAC] = {ATTR_TRACKER_MAC: NODE_MAC}
    hass.data[DOMAIN]["devices_cache"] = {NODE_MAC: {ATTR_TRACKER_MAC: NODE_MAC}}
    parent.luci.wifi_connect_devices = AsyncMock(
        return_value={
            "list": [
                {"mac": NODE_MAC, "signal": 80, "wifiIndex": 1},
                {"mac": CLIENT_MAC, "signal": 65, "wifiIndex": 2},
            ]
        }
    )
    parent.luci.macfilter_info = AsyncMock(return_value={"flist": [], "list": []})
    parent.add_device = AsyncMock()
    parent._mass_update_device = Mock(return_value=False)

    await parent._async_prepare_devices(parent.data)

    parent.add_device.assert_awaited_once()
    assert parent.add_device.await_args.args[0][ATTR_TRACKER_MAC] == CLIENT_MAC
    parent._mass_update_device.assert_called_once()
    assert NODE_MAC not in parent.devices
    assert NODE_MAC not in node.devices
    assert NODE_MAC not in parent._signals
    assert NODE_MAC not in hass.data[DOMAIN]["devices_cache"]


def _stored(mac, ip, entry):
    return {
        ATTR_TRACKER_MAC: mac.upper(),
        ATTR_TRACKER_IP: ip,
        ATTR_TRACKER_ENTRY_ID: entry.entry_id,
        ATTR_TRACKER_UPDATER_ENTRY_ID: entry.entry_id,
        "connection": 0,
    }


async def test_node_listed_without_isap_is_skipped_and_clients_are_tracked(hass, router_doubles):
    main_entry, node_entry = _entry(hass, MAIN_IP), _entry(hass, NODE_IP)
    main = _updater(hass, main_entry, MAIN_IP, is_main=True)
    _updater(hass, node_entry, NODE_IP, is_main=False)
    await _connect_platforms(hass, main_entry)

    # The node rejoins the mesh: listed with isap 0 and its own address.
    await _refresh(hass, main, [_row(NODE_MAC, NODE_IP), _row(CLIENT_MAC, CLIENT_IP)])

    assert NODE_MAC.upper() not in main.devices
    assert CLIENT_MAC.upper() in main.devices
    registry = er.async_get(hass)
    assert registry.async_get_entity_id("device_tracker", DOMAIN, f"{DOMAIN}-{NODE_MAC}") is None
    assert registry.async_get_entity_id("device_tracker", DOMAIN, f"{DOMAIN}-{CLIENT_MAC}")


@pytest.mark.parametrize("reported_by", ["entry_ip", "isap"])
async def test_restart_does_not_restore_a_stored_node(hass, router_doubles, reported_by):
    main_entry, node_entry = _entry(hass, MAIN_IP), _entry(hass, NODE_IP)
    # A store written by an earlier session that tracked the node as a client.
    node_ip = NODE_IP if reported_by == "entry_ip" else "192.0.2.60"
    await get_store(hass, MAIN_IP).async_save({
        NODE_MAC.upper(): _stored(NODE_MAC, node_ip, main_entry),
        CLIENT_MAC.upper(): _stored(CLIENT_MAC, CLIENT_IP, main_entry),
    })
    if reported_by == "isap":
        hass.data.setdefault(DOMAIN, {})["mesh_node_macs"] = {NODE_MAC.upper()}

    # A fresh updater is what a restart or an entry reload builds.
    main = _updater(hass, main_entry, MAIN_IP, is_main=True)
    _updater(hass, node_entry, NODE_IP, is_main=False)
    assert main._is_first_update
    await main._async_prepare_device_restore({})
    await _connect_platforms(hass, main_entry)

    assert list(main.devices) == [CLIENT_MAC.upper()]
    registry = er.async_get(hass)
    assert registry.async_get_entity_id("device_tracker", DOMAIN, f"{DOMAIN}-{NODE_MAC}") is None


async def test_node_purge_waits_for_platforms_and_keeps_other_entities(hass, router_doubles):
    main_entry, node_entry = _entry(hass, MAIN_IP), _entry(hass, NODE_IP)
    other_entry = MockConfigEntry(domain="other")
    other_entry.add_to_hass(hass)
    dev_reg, registry = dr.async_get(hass), er.async_get(hass)
    connection = {(dr.CONNECTION_NETWORK_MAC, NODE_MAC)}

    # Left by an earlier session: the node as a client - tracker plus client
    # sensors, enabled and disabled, on one device row of the main's entry.
    client_row = dev_reg.async_get_or_create(
        config_entry_id=main_entry.entry_id, identifiers={(DOMAIN, NODE_MAC)}, connections=connection
    )
    tracker = registry.async_get_or_create(
        "device_tracker", DOMAIN, f"{DOMAIN}-{NODE_MAC}",
        config_entry=main_entry, device_id=client_row.id,
    )
    client_sensors = [
        registry.async_get_or_create(
            "sensor", DOMAIN, f"{DOMAIN}-dev-{NODE_MAC}-{desc.key}",
            config_entry=main_entry, device_id=client_row.id,
            disabled_by=None if index % 2 else er.RegistryEntryDisabler.INTEGRATION,
        )
        for index, desc in enumerate(MIWIFI_DEVICE_SENSORS)
    ]
    # Must survive: the node's own router entity, another integration's device
    # for the same MAC, and an ordinary client.
    router_row = dev_reg.async_get_or_create(
        config_entry_id=node_entry.entry_id, identifiers={(DOMAIN, NODE_MAC.upper())}, connections=connection
    )
    router_entity = registry.async_get_or_create(
        "sensor", DOMAIN, f"{NODE_IP}_uptime", config_entry=node_entry, device_id=router_row.id
    )
    other_row = dev_reg.async_get_or_create(config_entry_id=other_entry.entry_id, connections=connection)
    other_entity = registry.async_get_or_create(
        "sensor", "other", "node-temperature", config_entry=other_entry, device_id=other_row.id
    )

    main = _updater(hass, main_entry, MAIN_IP, is_main=True)
    _updater(hass, node_entry, NODE_IP, is_main=False)

    # First refresh: it runs before the platforms are set up, so nothing may
    # be purged yet - a signal now would reach no handler and be lost.
    await _refresh(hass, main, [_row(NODE_MAC, NODE_IP, isap=8), _row(CLIENT_MAC, CLIENT_IP)])
    assert registry.async_get(tracker.entity_id) is not None
    main._is_first_update = False

    await _connect_platforms(hass, main_entry)
    client_tracker = registry.async_get_entity_id("device_tracker", DOMAIN, f"{DOMAIN}-{CLIENT_MAC}")
    assert client_tracker

    # Next refresh, platforms listening: every client entity of the node goes.
    await _refresh(hass, main, [_row(NODE_MAC, NODE_IP, isap=8), _row(CLIENT_MAC, CLIENT_IP)])

    assert registry.async_get(tracker.entity_id) is None
    assert all(registry.async_get(entity.entity_id) is None for entity in client_sensors)
    assert dev_reg.async_get(client_row.id) is None

    assert registry.async_get(router_entity.entity_id) is not None
    assert dev_reg.async_get(router_row.id) is not None
    assert registry.async_get(other_entity.entity_id) is not None
    assert dev_reg.async_get(other_row.id) is not None
    assert registry.async_get(client_tracker) is not None


def test_empty_row_shared_with_another_integration_only_loses_the_miwifi_link() -> None:
    """Older cores share one row between entries: unlink MiWiFi, keep the row."""
    hass = SimpleNamespace(
        config_entries=SimpleNamespace(
            async_entries=lambda domain: [SimpleNamespace(entry_id="miwifi-entry")]
        )
    )
    row = SimpleNamespace(config_entries={"miwifi-entry", "other-entry"})
    dev_reg = Mock(async_get=Mock(return_value=row))
    with (
        patch.object(helper.dr, "async_get", return_value=dev_reg),
        patch.object(helper.er, "async_get"),
        patch.object(helper.er, "async_entries_for_device", return_value=[]),
    ):
        helper.async_remove_empty_client_device(hass, "row-id")

    dev_reg.async_remove_device.assert_not_called()
    dev_reg.async_update_device.assert_called_once_with("row-id", remove_config_entry_id="miwifi-entry")


def _leftover_client_entities(hass, entry, *, legacy: bool = False):
    """A node's client tracker and sensors, left on `entry` by an earlier session."""
    dev_reg, registry = dr.async_get(hass), er.async_get(hass)
    row = dev_reg.async_get_or_create(
        config_entry_id=entry.entry_id,
        identifiers={(DOMAIN, NODE_MAC)},
        connections={(dr.CONNECTION_NETWORK_MAC, NODE_MAC)},
    )
    tracker_uid = f"{DOMAIN}-{entry.entry_id}-{NODE_MAC.upper()}" if legacy else f"{DOMAIN}-{NODE_MAC}"
    entities = [
        registry.async_get_or_create(
            "device_tracker", DOMAIN, tracker_uid, config_entry=entry, device_id=row.id
        )
    ] + [
        registry.async_get_or_create(
            "sensor", DOMAIN, f"{DOMAIN}-dev-{NODE_MAC}-{desc.key}",
            config_entry=entry, device_id=row.id,
            disabled_by=er.RegistryEntryDisabler.INTEGRATION,
        )
        for desc in MIWIFI_DEVICE_SENSORS
    ]
    return row, entities


@pytest.mark.parametrize("later_row", ["isap_0", "omitted"])
async def test_node_seen_only_in_the_first_refresh_is_still_purged(hass, router_doubles, later_row):
    main_entry, node_entry = _entry(hass, MAIN_IP), _entry(hass, NODE_IP)
    row, entities = _leftover_client_entities(hass, main_entry)
    main = _updater(hass, main_entry, MAIN_IP, is_main=True)
    _updater(hass, node_entry, NODE_IP, is_main=False)
    registry, dev_reg = er.async_get(hass), dr.async_get(hass)

    # The only positive identification comes while nothing may be purged yet.
    await _refresh(hass, main, [_row(NODE_MAC, NODE_IP, isap=8), _row(CLIENT_MAC, CLIENT_IP)])
    assert all(registry.async_get(entity.entity_id) for entity in entities)
    main._is_first_update = False

    # From then on the node is listed as a client again, or not at all.
    rows = [_row(CLIENT_MAC, CLIENT_IP)]
    if later_row == "isap_0":
        rows.insert(0, _row(NODE_MAC, NODE_IP))
    await _refresh(hass, main, rows)

    assert all(registry.async_get(entity.entity_id) is None for entity in entities)
    assert dev_reg.async_get(row.id) is None
    assert NODE_MAC.upper() in hass.data[DOMAIN]["mesh_node_purged"]
    assert CLIENT_MAC.upper() in main.devices


async def test_a_node_known_only_by_its_address_is_skipped_but_not_purged(hass, router_doubles):
    main_entry, node_entry = _entry(hass, MAIN_IP), _entry(hass, NODE_IP)
    row, entities = _leftover_client_entities(hass, main_entry)
    main = _updater(hass, main_entry, MAIN_IP, is_main=True)
    _updater(hass, node_entry, NODE_IP, is_main=False)
    main._is_first_update = False

    # Never reported with isap > 0: the entry's address keeps it out of the
    # clients, but is no licence to delete what the registry holds for the MAC.
    await _refresh(hass, main, [_row(NODE_MAC, NODE_IP), _row(CLIENT_MAC, CLIENT_IP)])
    await _refresh(hass, main, [_row(NODE_MAC, NODE_IP), _row(CLIENT_MAC, CLIENT_IP)])

    assert NODE_MAC.upper() not in main.devices
    registry = er.async_get(hass)
    assert all(registry.async_get(entity.entity_id) for entity in entities)
    assert dr.async_get(hass).async_get(row.id) is not None
    assert NODE_MAC.upper() not in hass.data[DOMAIN].get("mesh_node_purged", set())


async def test_purge_reaches_a_legacy_tracker_owned_by_another_entry(hass, router_doubles):
    main_entry, node_entry = _entry(hass, MAIN_IP), _entry(hass, NODE_IP)
    leaf_entry = _entry(hass, "192.0.2.4")
    other_entry = MockConfigEntry(domain="other")
    other_entry.add_to_hass(hass)
    registry, dev_reg = er.async_get(hass), dr.async_get(hass)

    # The node's client entities were made by a leaf under the per-entry legacy
    # ID. That leaf's platforms are not set up, so no handler of its listens.
    row, entities = _leftover_client_entities(hass, leaf_entry, legacy=True)
    other_row = dev_reg.async_get_or_create(
        config_entry_id=other_entry.entry_id,
        connections={(dr.CONNECTION_NETWORK_MAC, NODE_MAC)},
    )
    other_entity = registry.async_get_or_create(
        "sensor", "other", "node-temperature", config_entry=other_entry, device_id=other_row.id
    )
    router_row = dev_reg.async_get_or_create(
        config_entry_id=node_entry.entry_id, identifiers={(DOMAIN, NODE_MAC.upper())}
    )
    router_entity = registry.async_get_or_create(
        "sensor", DOMAIN, f"{NODE_IP}_uptime", config_entry=node_entry, device_id=router_row.id
    )

    main = _updater(hass, main_entry, MAIN_IP, is_main=True)
    _updater(hass, node_entry, NODE_IP, is_main=False)
    main._is_first_update = False
    await _connect_platforms(hass, main_entry)

    # The main reports the node; the purge is the main's, the entities the leaf's.
    await _refresh(hass, main, [_row(NODE_MAC, NODE_IP, isap=8), _row(CLIENT_MAC, CLIENT_IP)])

    assert all(registry.async_get(entity.entity_id) is None for entity in entities)
    assert dev_reg.async_get(row.id) is None
    assert NODE_MAC.upper() in hass.data[DOMAIN]["mesh_node_purged"]

    assert registry.async_get(other_entity.entity_id) is not None
    assert dev_reg.async_get(other_row.id) is not None
    assert registry.async_get(router_entity.entity_id) is not None
    assert dev_reg.async_get(router_row.id) is not None
    assert registry.async_get_entity_id("device_tracker", DOMAIN, f"{DOMAIN}-{CLIENT_MAC}")


async def test_a_purged_client_row_frees_the_node_alias_it_blocked(hass, router_doubles):
    """The node's second MAC is recorded once the client row holding it is gone.

    The main lists the node under a second MAC, and the node's entry still has a
    client row under it: the registry refuses the alias (from core 2026.9 a row
    of the same entry, before it any row), and the census stops asking. Purging
    that client row has to let the next census record the alias.
    """
    node_own = "02:00:00:00:00:0c"
    main_entry, node_entry = _entry(hass, MAIN_IP), _entry(hass, NODE_IP)
    client_row, entities = _leftover_client_entities(hass, node_entry)
    dev_reg = dr.async_get(hass)
    node_row = dev_reg.async_get_or_create(
        config_entry_id=node_entry.entry_id,
        identifiers={(DOMAIN, node_own)},
        connections={(dr.CONNECTION_NETWORK_MAC, node_own)},
    )
    main = _updater(hass, main_entry, MAIN_IP, is_main=True)
    node = _updater(hass, node_entry, NODE_IP, is_main=False)
    node.data[ATTR_DEVICE_MAC_ADDRESS] = node_own.upper()
    hass.data[DOMAIN][node_entry.entry_id][CONF_IP_ADDRESS] = NODE_IP
    rows = [_row(NODE_MAC, NODE_IP, isap=8), _row(CLIENT_MAC, CLIENT_IP)]
    alias = (dr.CONNECTION_NETWORK_MAC, NODE_MAC)

    # First census: nothing may be purged yet, and the client row has the MAC.
    await _refresh(hass, main, rows)
    assert node.backhaul_mac == NODE_MAC.upper()
    assert alias not in dev_reg.async_get(node_row.id).connections
    main._is_first_update = False

    # Second: the alias is still skipped when its step runs, then the purge
    # removes the client row.
    await _refresh(hass, main, rows)
    assert dev_reg.async_get(client_row.id) is None
    assert alias not in dev_reg.async_get(node_row.id).connections

    # Third: the alias is recorded on the node's own row.
    await _refresh(hass, main, rows)
    assert alias in dev_reg.async_get(node_row.id).connections
    assert device_tracker._ensure_via_device_exists(hass, NODE_MAC).id == node_row.id
