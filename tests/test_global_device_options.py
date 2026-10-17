"""Global mesh settings and per-node options in the options flow."""

from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

import pytest
import voluptuous as vol
from homeassistant import config_entries, data_entry_flow
from homeassistant.const import (
    CONF_IP_ADDRESS,
    CONF_PASSWORD,
    CONF_SCAN_INTERVAL,
    CONF_TIMEOUT,
)
from homeassistant.core import HomeAssistant
from pytest_homeassistant_custom_component.common import MockConfigEntry

from custom_components.miwifi import async_update_options, helper
from custom_components.miwifi.const import (
    CONF_ACTIVITY_DAYS,
    CONF_AUTO_PURGE_AT,
    CONF_AUTO_PURGE_EVERY_DAYS,
    CONF_DEVICE_SENSORS_GLOBAL,
    CONF_ENABLE_DEVICE_SENSORS,
    CONF_ENABLE_PANEL,
    CONF_ENABLE_PORT_PROBE,
    CONF_ENCRYPTION_ALGORITHM,
    CONF_IS_FORCE_LOAD,
    CONF_IS_TRACK_DEVICES,
    CONF_LOG_LEVEL,
    CONF_PROTOCOL,
    CONF_STAY_ONLINE,
    CONF_WAN_SPEED_UNIT,
    DEVICE_SENSORS_MESH,
    DOMAIN,
    UPDATER,
)
from custom_components.miwifi.helper import (
    get_global_auto_purge,
    get_global_log_level,
    get_global_panel_state,
    get_mesh_device_sensors_enabled,
)

NODE_IP = "192.0.2.2"


@pytest.fixture(autouse=True)
def isolate_global_caches(monkeypatch):
    """The global log level and panel state are cached per process."""
    monkeypatch.setattr(helper, "_global_log_level_cache", None)
    monkeypatch.setattr(helper, "_global_panel_state_cache", None)


def _entry(hass: HomeAssistant, options: dict | None = None, ip: str = "192.0.2.1") -> MockConfigEntry:
    entry = MockConfigEntry(
        domain=DOMAIN,
        title=ip,
        unique_id=ip,
        data={CONF_IP_ADDRESS: ip, CONF_PASSWORD: "x"},
        options=options or {},
    )
    entry.add_to_hass(hass)
    return entry


def _load(hass: HomeAssistant, entry: MockConfigEntry, role: str) -> None:
    """Give the entry a running updater, as async_setup_entry does."""
    if role == "unloaded":
        return
    data = {} if role == "no topology" else {"topo_graph": {"graph": {"is_main": role == "main"}}}
    hass.data.setdefault(DOMAIN, {})[entry.entry_id] = {
        UPDATER: SimpleNamespace(data=data, is_repeater=role == "repeater"),
    }


def _defaults(result: dict) -> dict:
    """What the frontend submits when no field of the form is touched."""
    return {
        str(key): key.default()
        for key in result["data_schema"].schema
        if key.default is not vol.UNDEFINED
    }


async def _open(hass: HomeAssistant, entry: MockConfigEntry, step: str) -> dict:
    result = await hass.config_entries.options.async_init(entry.entry_id)
    assert result["type"] == data_entry_flow.FlowResultType.MENU
    return await hass.config_entries.options.async_configure(
        result["flow_id"], {"next_step_id": step}
    )


async def _save_global(hass: HomeAssistant, entry: MockConfigEntry, **changes) -> dict:
    form = await _open(hass, entry, "global_settings")
    return await hass.config_entries.options.async_configure(
        form["flow_id"], {**_defaults(form), **changes}
    )


@pytest.mark.parametrize(
    ("roles", "offered"),
    [
        # A standalone router, before and after its topology names it the main.
        ({"router": "unloaded"}, {"router"}),
        ({"router": "no topology"}, {"router"}),
        ({"router": "main"}, {"router"}),
        # A mesh that has not loaded, or whose main is not added to HA.
        ({"a": "unloaded", "b": "unloaded"}, {"a", "b"}),
        ({"a": "no topology", "b": "no topology"}, {"a", "b"}),
        ({"a": "node", "b": "node"}, {"a", "b"}),
        # Once an entry is identified as the main, only the main offers them.
        ({"a": "main", "b": "node"}, {"a"}),
        ({"a": "main", "b": "unloaded"}, {"a"}),
        ({"a": "main", "b": "no topology"}, {"a"}),
        # Two separate routers, each its own main.
        ({"a": "main", "b": "main"}, {"a", "b"}),
    ],
)
async def test_global_settings_stay_reachable_without_a_main(
    hass: HomeAssistant, roles: dict[str, str], offered: set[str]
) -> None:
    entries = {}
    for index, (name, role) in enumerate(roles.items()):
        entries[name] = _entry(hass, ip=f"192.0.2.{index + 1}")
        _load(hass, entries[name], role)

    for name, entry in entries.items():
        result = await hass.config_entries.options.async_init(entry.entry_id)
        expected = ["device_settings"]
        if name in offered:
            expected.insert(0, "global_settings")
        assert result["menu_options"] == expected, name


@pytest.mark.parametrize(
    ("first", "second", "enabled"),
    [
        # Never saved: on when any entry enables it, as before the split.
        ({}, {}, False),
        ({}, {CONF_ENABLE_DEVICE_SENSORS: True}, True),
        # Saved: the saved value decides, whatever the other entries say.
        ({CONF_ENABLE_DEVICE_SENSORS: False, CONF_DEVICE_SENSORS_GLOBAL: 1}, {CONF_ENABLE_DEVICE_SENSORS: True}, False),
        ({CONF_ENABLE_DEVICE_SENSORS: True, CONF_DEVICE_SENSORS_GLOBAL: 1}, {CONF_ENABLE_DEVICE_SENSORS: False}, True),
        # The latest save wins, on whichever entry it was made.
        ({CONF_ENABLE_DEVICE_SENSORS: True, CONF_DEVICE_SENSORS_GLOBAL: 1}, {CONF_ENABLE_DEVICE_SENSORS: False, CONF_DEVICE_SENSORS_GLOBAL: 2}, False),
        ({CONF_ENABLE_DEVICE_SENSORS: True, CONF_DEVICE_SENSORS_GLOBAL: 3}, {CONF_ENABLE_DEVICE_SENSORS: False, CONF_DEVICE_SENSORS_GLOBAL: 2}, True),
        # True counts as one save.
        ({CONF_ENABLE_DEVICE_SENSORS: False, CONF_DEVICE_SENSORS_GLOBAL: True}, {CONF_ENABLE_DEVICE_SENSORS: True}, False),
        # A value that is not a positive counter is no save.
        ({CONF_ENABLE_DEVICE_SENSORS: False, CONF_DEVICE_SENSORS_GLOBAL: "x"}, {CONF_ENABLE_DEVICE_SENSORS: True}, True),
        ({CONF_ENABLE_DEVICE_SENSORS: False, CONF_DEVICE_SENSORS_GLOBAL: -1}, {CONF_ENABLE_DEVICE_SENSORS: True}, True),
    ],
)
def test_mesh_client_sensor_setting(
    hass: HomeAssistant, first: dict, second: dict, enabled: bool
) -> None:
    _entry(hass, first)
    _entry(hass, second, ip=NODE_IP)

    assert get_mesh_device_sensors_enabled(hass) is enabled


def test_legacy_vote_from_the_setup_form_still_counts(hass: HomeAssistant) -> None:
    """An entry never saved from the options keeps its setup values in data."""
    _entry(hass)
    MockConfigEntry(
        domain=DOMAIN, data={CONF_IP_ADDRESS: NODE_IP, CONF_ENABLE_DEVICE_SENSORS: True}
    ).add_to_hass(hass)

    assert get_mesh_device_sensors_enabled(hass)


async def test_latest_global_save_wins_on_any_entry(hass: HomeAssistant) -> None:
    """Without a main every entry offers the step, so either may save it."""
    first = _entry(hass)
    second = _entry(hass, ip=NODE_IP)

    await _save_global(hass, first, **{CONF_ENABLE_DEVICE_SENSORS: True})
    assert get_mesh_device_sensors_enabled(hass)
    await _save_global(hass, second, **{CONF_ENABLE_DEVICE_SENSORS: False})
    assert not get_mesh_device_sensors_enabled(hass)
    await _save_global(hass, first, **{CONF_ENABLE_DEVICE_SENSORS: True})
    assert get_mesh_device_sensors_enabled(hass)

    assert first.options[CONF_DEVICE_SENSORS_GLOBAL] == 3
    assert second.options[CONF_DEVICE_SENSORS_GLOBAL] == 2


async def test_global_save_keeps_log_level_and_purge_in_their_stores(
    hass: HomeAssistant,
) -> None:
    legacy = {
        CONF_ACTIVITY_DAYS: 30,
        CONF_LOG_LEVEL: "debug",
        CONF_AUTO_PURGE_EVERY_DAYS: 7,
        CONF_AUTO_PURGE_AT: "00:00",
        CONF_ENABLE_DEVICE_SENSORS: False,
    }
    main = _entry(hass, dict(legacy))
    node = _entry(hass, {CONF_ENABLE_DEVICE_SENSORS: True}, ip=NODE_IP)
    _load(hass, main, "main")
    _load(hass, node, "node")

    result = await _save_global(
        hass,
        main,
        **{
            CONF_ENABLE_PANEL: False,
            CONF_LOG_LEVEL: "warning",
            CONF_AUTO_PURGE_EVERY_DAYS: 3,
            CONF_AUTO_PURGE_AT: "01:30:00",
            CONF_ENABLE_DEVICE_SENSORS: False,
        },
    )

    assert result["type"] == data_entry_flow.FlowResultType.CREATE_ENTRY
    # Nothing reads the log level or the schedule from the entry, so the
    # entry keeps what it had and only the values read from it change.
    assert main.options == {
        **legacy,
        CONF_ENABLE_PANEL: False,
        CONF_ENABLE_DEVICE_SENSORS: False,
        CONF_DEVICE_SENSORS_GLOBAL: 1,
    }
    assert node.options == {CONF_ENABLE_DEVICE_SENSORS: True}
    assert await get_global_log_level(hass) == "warning"
    assert await get_global_panel_state(hass) is False
    assert await get_global_auto_purge(hass) == {"every_days": 3, "at": "01:30"}
    # The node's legacy vote no longer counts once the setting is saved.
    assert not get_mesh_device_sensors_enabled(hass)


@pytest.fixture
def reload(hass: HomeAssistant):
    """Run the real update listener without reloading anything."""
    with (
        patch.object(hass.config_entries, "async_reload", AsyncMock()) as reload,
        patch("custom_components.miwifi.async_register_panel", AsyncMock()),
        patch("custom_components.miwifi.async_remove_miwifi_panel", AsyncMock()),
        patch("custom_components.miwifi.read_local_version", AsyncMock(return_value="0")),
    ):
        yield reload


def _listen(hass: HomeAssistant, *entries: MockConfigEntry) -> None:
    hass.data[DOMAIN][DEVICE_SENSORS_MESH] = get_mesh_device_sensors_enabled(hass)
    for entry in entries:
        entry.add_update_listener(async_update_options)


async def test_global_save_reloads_the_mesh_only_when_client_sensors_change(
    hass: HomeAssistant, reload: AsyncMock
) -> None:
    main = _entry(hass, {CONF_ENABLE_DEVICE_SENSORS: False})
    node = _entry(hass, {CONF_ENABLE_DEVICE_SENSORS: True}, ip=NODE_IP)
    _load(hass, main, "main")
    _load(hass, node, "node")
    _listen(hass, main, node)

    # The node's legacy vote has them on, so saving them on changes nothing
    # for the other entries.
    await _save_global(hass, main, **{CONF_ENABLE_DEVICE_SENSORS: True})
    await hass.async_block_till_done()
    assert [call.args[0] for call in reload.await_args_list] == [main.entry_id]

    reload.reset_mock()
    await _save_global(hass, main, **{CONF_ENABLE_DEVICE_SENSORS: False})
    await hass.async_block_till_done()
    assert sorted(call.args[0] for call in reload.await_args_list) == sorted(
        [main.entry_id, node.entry_id]
    )


NODE_OPTIONS = {
    CONF_IP_ADDRESS: NODE_IP,
    CONF_PASSWORD: "x",
    CONF_ENCRYPTION_ALGORITHM: "sha256",
    CONF_PROTOCOL: "auto",
    CONF_IS_TRACK_DEVICES: True,
    CONF_STAY_ONLINE: 30,
    CONF_SCAN_INTERVAL: 30,
    CONF_ACTIVITY_DAYS: 30,
    CONF_TIMEOUT: 20,
    CONF_WAN_SPEED_UNIT: "Mbps",
    CONF_ENABLE_PORT_PROBE: False,
    # Saved by the single form of earlier releases or by the global step.
    # The per-node step does not show them.
    CONF_ENABLE_PANEL: True,
    CONF_LOG_LEVEL: "debug",
    CONF_AUTO_PURGE_EVERY_DAYS: 7,
    CONF_AUTO_PURGE_AT: "00:00",
    CONF_ENABLE_DEVICE_SENSORS: True,
    CONF_DEVICE_SENSORS_GLOBAL: 2,
}


async def _save_node(hass: HomeAssistant, entry: MockConfigEntry, **changes) -> dict:
    form = await _open(hass, entry, "device_settings")
    with patch(
        "custom_components.miwifi.config_flow.async_verify_access",
        AsyncMock(return_value=(200, "")),
    ):
        return await hass.config_entries.options.async_configure(
            form["flow_id"], {**_defaults(form), **changes}
        )


@pytest.mark.parametrize("force_load", [False, True])
@pytest.mark.parametrize("role", ["repeater", "gateway", "unloaded"])
async def test_saving_the_node_form_unchanged_changes_no_option(
    hass: HomeAssistant, role: str, force_load: bool
) -> None:
    options = {**NODE_OPTIONS, CONF_IS_FORCE_LOAD: force_load}
    entry = _entry(hass, dict(options), ip=NODE_IP)
    _load(hass, entry, role)

    form = await _open(hass, entry, "device_settings")
    # Force-load is offered on repeaters and wherever it is on. A node that
    # reads as a gateway for a moment must not hide a force-load in effect.
    assert (CONF_IS_FORCE_LOAD in _defaults(form)) is (role != "gateway" or force_load)

    result = await _save_node(hass, entry)

    assert result["type"] == data_entry_flow.FlowResultType.CREATE_ENTRY
    assert entry.options == options


async def test_force_load_left_on_a_gateway_can_be_turned_off(
    hass: HomeAssistant,
) -> None:
    entry = _entry(hass, {**NODE_OPTIONS, CONF_IS_FORCE_LOAD: True}, ip=NODE_IP)
    _load(hass, entry, "gateway")

    await _save_node(hass, entry, **{CONF_IS_FORCE_LOAD: False})

    assert entry.options[CONF_IS_FORCE_LOAD] is False
    form = await _open(hass, entry, "device_settings")
    assert CONF_IS_FORCE_LOAD not in _defaults(form)


async def test_node_save_keeps_the_legacy_client_sensor_vote(
    hass: HomeAssistant, reload: AsyncMock
) -> None:
    """Until the global step is saved, a node keeps its vote when it saves."""
    main = _entry(hass)
    node = _entry(hass, {**NODE_OPTIONS, CONF_DEVICE_SENSORS_GLOBAL: 0}, ip=NODE_IP)
    _load(hass, main, "main")
    _load(hass, node, "repeater")
    _listen(hass, main, node)
    assert get_mesh_device_sensors_enabled(hass)

    await _save_node(hass, node, **{CONF_SCAN_INTERVAL: 60})
    await hass.async_block_till_done()

    assert node.options[CONF_ENABLE_DEVICE_SENSORS] is True
    assert get_mesh_device_sensors_enabled(hass)
    assert [call.args[0] for call in reload.await_args_list] == [node.entry_id]


async def test_setup_asks_for_client_sensors_until_the_global_setting_is_saved(
    hass: HomeAssistant,
) -> None:
    result = await hass.config_entries.flow.async_init(
        DOMAIN, context={"source": config_entries.SOURCE_USER}
    )
    assert CONF_ENABLE_DEVICE_SENSORS in _defaults(result)

    # Once saved, the global value decides and a new entry's vote is unused.
    _entry(hass, {CONF_ENABLE_DEVICE_SENSORS: False, CONF_DEVICE_SENSORS_GLOBAL: 1})
    result = await hass.config_entries.flow.async_init(
        DOMAIN, context={"source": config_entries.SOURCE_USER}
    )
    assert CONF_ENABLE_DEVICE_SENSORS not in _defaults(result)
