"""Global mesh settings and per-node options in the options flow."""

from __future__ import annotations

from types import SimpleNamespace

import pytest
import voluptuous as vol
from homeassistant import data_entry_flow
from homeassistant.const import (
    CONF_IP_ADDRESS,
    CONF_PASSWORD,
)
from homeassistant.core import HomeAssistant
from pytest_homeassistant_custom_component.common import MockConfigEntry

from custom_components.miwifi import helper
from custom_components.miwifi.const import (
    CONF_DEVICE_SENSORS_GLOBAL,
    CONF_ENABLE_DEVICE_SENSORS,
    DOMAIN,
    UPDATER,
)
from custom_components.miwifi.helper import (
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
