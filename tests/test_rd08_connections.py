"""RD08 1.1.96 client types differ from the legacy Connection enum (#356).

Synthetic rows reproduce the public report's native UI and API comparison:
LAN type 1; 2.4 GHz type 2 (wifiIndex 1); 5 GHz type 3 (wifiIndex 2).
No reporter identifiers, names or addresses are retained.
"""

from copy import deepcopy
from unittest.mock import AsyncMock, patch

import pytest

from custom_components.miwifi.const import (
    ATTR_DEVICE_MAC_ADDRESS,
    ATTR_DEVICE_MODEL,
    ATTR_MODEL,
    ATTR_SENSOR_MODE,
    ATTR_TRACKER_CONNECTION,
    ATTR_TRACKER_ENTRY_ID,
    UPDATER,
)
from custom_components.miwifi.enum import Connection, Mode, Model
from custom_components.miwifi.updater import LuciUpdater


def _updater(hass, model=Model.RD08, *, force=False):
    updater = LuciUpdater.__new__(LuciUpdater)
    updater.hass = hass
    updater.data = {
        ATTR_MODEL: model,
        ATTR_DEVICE_MODEL: f"xiaomi.router.{model.value}",
        ATTR_DEVICE_MAC_ADDRESS: "02:00:00:00:00:01",
        ATTR_SENSOR_MODE: Mode.DEFAULT,
        "features": {"wifi": {"iot_dev": "1" if model in (Model.RD08, Model.RC01) else "0"}},
    }
    updater.is_force_load = force
    updater.devices = {}
    updater._signals = {}
    updater._filter_macs = {}
    updater._entry_id = "source-entry"
    updater.ip = "192.0.2.1"
    updater._moved_devices = []
    updater.new_device_callback = None
    updater._parent_push_pending = False
    updater._counters_reset_this_cycle = False
    return updater


@pytest.mark.parametrize("raw,expected", [
    (1, Connection.LAN), (2, Connection.WIFI_2_4),
    (3, Connection.WIFI_5_0), ("1", Connection.LAN),
    ("2", Connection.WIFI_2_4), ("3", Connection.WIFI_5_0),
    (7, Connection.GUEST), ("7", Connection.GUEST),
    (9, Connection.WIFI_IOT), ("9", Connection.WIFI_IOT),
])
def test_rd08_native_types_reach_client_attributes(hass, raw, expected):
    updater = _updater(hass)
    row = {"mac": "02:00:00:00:00:10", "type": raw, "entry_id": "source-entry"}

    built = updater._build_device(row)

    assert built[ATTR_TRACKER_CONNECTION] is expected
    assert "_miwifi_connection" not in built


@pytest.mark.parametrize("raw", [None, "", "invalid", 4, 99])
def test_unknown_rd08_codes_are_not_guessed_as_guest(hass, raw):
    assert _updater(hass)._resolve_connection({"type": raw}) is None


@pytest.mark.parametrize("model,raw,expected", [
    (Model.RC01, 0, Connection.LAN),
    (Model.RC01, 1, Connection.WIFI_2_4),
    (Model.RC01, 2, Connection.WIFI_5_0),
    (Model.RC01, 3, Connection.GUEST),
    (Model.RC01, 5, Connection.WIFI_5_0_GAME),
    (Model.RC01, 6, Connection.WIFI_IOT),
    (Model.R3600, 0, Connection.LAN),
    (Model.R3600, 1, Connection.WIFI_2_4),
    (Model.R3600, 2, Connection.WIFI_5_0),
    (Model.R3600, 3, Connection.GUEST),
])
def test_other_models_keep_their_connection_codes(hass, model, raw, expected):
    assert _updater(hass, model)._resolve_connection({"type": raw}) is expected


@pytest.mark.parametrize("index,expected", [
    (1, Connection.WIFI_2_4), (2, Connection.WIFI_5_0),
    (3, Connection.WIFI_5_0_GAME),
])
def test_legacy_force_load_wifi_indices_are_unchanged(hass, index, expected):
    assert _updater(hass, Model.R3600, force=True)._resolve_connection(
        {"wifiIndex": index}
    ) is expected


async def test_rd08_client_counters_follow_the_correct_bands(hass):
    updater = _updater(hass)
    blocked = AsyncMock(return_value=False)
    with patch("custom_components.miwifi.updater.get_purged_clients") as purge:
        purge.return_value.async_blocked = blocked
        for index, code in enumerate((1, 1, 2, 3, 7, 9), start=10):
            await updater.add_device({
                "mac": f"02:00:00:00:00:{index:02X}",
                "entry_id": updater._entry_id, "type": code,
            })

    assert updater.data["devices"] == 6
    assert updater.data["devices_lan"] == 2
    assert updater.data["devices_2_4"] == 1
    assert updater.data["devices_5_0"] == 1
    assert updater.data["devices_guest"] == 1
    assert updater.data["devices_iot"] == 1
    assert all("_miwifi_connection" not in row for row in updater.devices.values())


@pytest.mark.parametrize("source_model,target_model,raw,expected", [
    (Model.RD08, Model.RC01, 1, Connection.LAN),
    (Model.RD08, Model.RC01, 2, Connection.WIFI_2_4),
    (Model.RD08, Model.RC01, 3, Connection.WIFI_5_0),
    (Model.RD08, Model.RC01, 7, Connection.GUEST),
    (Model.RD08, Model.RC01, 9, Connection.WIFI_IOT),
    (Model.RC01, Model.RD08, 1, Connection.WIFI_2_4),
    (Model.RC01, Model.RD08, 3, Connection.GUEST),
    (Model.R3600, Model.RD08, 5, None),
])
async def test_parent_census_keeps_the_reporting_routers_schema(
    hass, source_model, target_model, raw, expected,
):
    """A parent's raw type is not a type code supplied by the receiving leaf."""
    source = _updater(hass, source_model)
    target = _updater(hass, target_model)
    target.ip = "192.0.2.2"
    target._entry_id = "target-entry"
    target.data[ATTR_SENSOR_MODE] = Mode.MESH_NODE
    target.data[ATTR_DEVICE_MAC_ADDRESS] = "02:00:00:00:00:02"
    target._parent_push_pending = False
    source._async_record_backhaul_aliases = AsyncMock()
    source._moved_devices = []
    source._parent_push_pending = False
    source._counters_reset_this_cycle = True
    source.luci = AsyncMock()
    row = {
        "mac": "02:00:00:00:00:10", "type": raw, "isap": 0,
        "parent": "02:00:00:00:00:02", "online": 1,
        "ip": [{"ip": "192.0.2.100", "active": 1}],
    }
    source.luci.device_list.return_value = {"code": 0, "list": [deepcopy(row)]}
    observed = []

    async def add_device(device, **kwargs):
        observed.append(target._build_device(device))
        await LuciUpdater.add_device(target, device, **kwargs)

    target.add_device = add_device
    integrations = {
        source.ip: {UPDATER: source, ATTR_TRACKER_ENTRY_ID: source._entry_id},
        target.ip: {UPDATER: target, ATTR_TRACKER_ENTRY_ID: target._entry_id},
    }
    manager = AsyncMock()
    manager.async_candidates.return_value = set()
    with (
        patch("custom_components.miwifi.updater.async_get_integrations", return_value=integrations),
        patch("custom_components.miwifi.updater.get_mac_replacement", return_value=manager),
        patch("custom_components.miwifi.updater.async_retire_macs", new=AsyncMock()),
        patch("custom_components.miwifi.updater.get_purged_clients") as purge,
    ):
        purge.return_value.async_blocked = AsyncMock(return_value=False)
        await source._async_prepare_device_list(source.data)

    assert len(observed) == 1
    assert observed[0][ATTR_TRACKER_CONNECTION] is expected
    assert "_miwifi_connection" not in observed[0]
    counter = (expected or Connection.LAN).name.replace("WIFI_", "").lower()
    assert target.data["devices"] == 1
    assert target.data[f"devices_{counter}"] == 1

    # A later census can report another band. Reusing a response in a test
    # must not make the private routing hint override the fresh raw type.
    source.luci.device_list.return_value["list"][0]["type"] = 2
    with (
        patch("custom_components.miwifi.updater.async_get_integrations", return_value=integrations),
        patch("custom_components.miwifi.updater.get_mac_replacement", return_value=manager),
        patch("custom_components.miwifi.updater.async_retire_macs", new=AsyncMock()),
        patch("custom_components.miwifi.updater.get_purged_clients") as purge,
    ):
        purge.return_value.async_blocked = AsyncMock(return_value=False)
        await source._async_prepare_device_list(source.data)
    refreshed = Connection.WIFI_2_4 if source_model == Model.RD08 else Connection.WIFI_5_0
    assert observed[-1][ATTR_TRACKER_CONNECTION] is refreshed
    counter = refreshed.name.replace("WIFI_", "").lower()
    assert target.data["devices"] == 1
    assert target.data[f"devices_{counter}"] == 1
