"""HA entity translations preserve client identities and valid canonical states."""
import logging
import re
from dataclasses import replace
from unittest.mock import AsyncMock

import pytest
from homeassistant.helpers import entity_registry as er
from homeassistant.helpers.translation import async_get_translations
from homeassistant.helpers.update_coordinator import DataUpdateCoordinator
from pytest_homeassistant_custom_component.common import MockConfigEntry, MockEntityPlatform

from custom_components.miwifi.const import DOMAIN
from custom_components.miwifi.enum import Connection
from custom_components.miwifi.sensor import MIWIFI_DEVICE_SENSORS, MiWifiDeviceAttributeSensor


@pytest.mark.parametrize(("language", "label", "no_signal"), [
    ("es", "Última actividad", "Sin señal"), ("en", "Last activity", "No signal"),
    ("de", "Letzte Aktivität", "Kein Signal"), ("fr", "Dernière activité", "Aucun signal"),
    ("pt-BR", "Última atividade", "Sem sinal"), ("ru", "Последняя активность", "Нет сигнала"),
    ("tr", "Son etkinlik", "Sinyal yok"), ("zh-Hans", "最后活动", "无信号"),
])
async def test_ha_loads_all_client_entity_names_and_states(hass, language, label, no_signal):
    translations = await async_get_translations(hass, language, "entity", {DOMAIN})
    prefix = "component.miwifi.entity.sensor."
    assert translations[prefix + "last_activity.name"] == label
    assert translations[prefix + "signal_quality.state.no_signal"] == no_signal
    for desc in MIWIFI_DEVICE_SENSORS:
        assert translations[prefix + desc.key + ".name"]
    for desc in MIWIFI_DEVICE_SENSORS:
        for state in desc.options or []:
            assert re.fullmatch(r"[a-z0-9]+(?:[_-][a-z0-9]+)*", state)
            assert translations[prefix + desc.key + ".state." + state]


async def test_translated_client_keeps_registry_id_and_custom_name(hass):
    hass.config.language = "es"
    entry = MockConfigEntry(domain=DOMAIN, data={"ip_address": "192.0.2.1"})
    entry.add_to_hass(hass)
    updater = DataUpdateCoordinator(hass, logging.getLogger(__name__), name="test", config_entry=entry, update_method=AsyncMock(return_value={}))
    updater.data = {}
    mac = "02:00:00:00:00:41"
    device = {"mac": mac, "name": "Test client", "connection": Connection.WIFI_5_0_GAME,
              "internet_blocked": False, "signal": 0}
    updater.devices = {mac: device}
    selected = [replace(desc, entity_registry_enabled_default=True) for desc in MIWIFI_DEVICE_SENSORS
                if desc.key in ("signal_quality", "internet_blocked", "connection")]
    entities = [MiWifiDeviceAttributeSensor(updater, device, desc) for desc in selected]
    registry = er.async_get(hass)
    for entity in entities:
        registry.async_get_or_create("sensor", DOMAIN, entity.unique_id, suggested_object_id=entity.entity_id.split(".")[1], config_entry=entry)
    custom = entities[0]
    registry.async_update_entity(custom.entity_id, name="Mi nombre personalizado")
    platform = MockEntityPlatform(hass, domain="sensor", platform_name=DOMAIN)
    platform.config_entry = entry
    platform.async_prepare()
    await platform.platform_data.async_load_translations()
    before = {entity.unique_id: entity.entity_id for entity in entities}
    await platform.async_add_entities(entities)
    for entity in entities:
        assert entity.entity_id == before[entity.unique_id]
        assert entity.translation_key == entity.entity_description.key
        assert registry.async_get(entity.entity_id).unique_id == entity.unique_id
        assert registry.async_get(entity.entity_id).translation_key == entity.entity_description.key
        if entity.entity_description.key == "internet_blocked":
            assert hass.states.get(entity.entity_id).attributes["friendly_name"] == "Test client Acceso a Internet bloqueado"
    assert hass.states.get(custom.entity_id).attributes["friendly_name"] == "Mi nombre personalizado"
    states = {entity.entity_description.key: hass.states.get(entity.entity_id).state for entity in entities}
    assert states == {"connection": "wifi_5_game", "signal_quality": "no_signal", "internet_blocked": "false"}
    assert device["connection"] == Connection.WIFI_5_0_GAME
    assert device["internet_blocked"] is False


@pytest.mark.parametrize(("signal", "connection", "expected"), [
    (None, Connection.WIFI_5_0_GAME, None),
    ("", Connection.WIFI_5_0_GAME, None),
    ("invalid", Connection.WIFI_5_0_GAME, None),
    (0, Connection.WIFI_5_0_GAME, "no_signal"),
    (80, Connection.WIFI_5_0_GAME, "very_strong"),
    (80, Connection.LAN, None),
])
async def test_missing_signal_is_unknown_not_a_zero_measurement(hass, signal, connection, expected):
    entry = MockConfigEntry(domain=DOMAIN)
    entry.add_to_hass(hass)
    updater = DataUpdateCoordinator(hass, logging.getLogger(__name__), name="signal", config_entry=entry)
    updater.data = {}
    device = {"mac": "02:00:00:00:00:42", "signal": signal, "connection": connection}
    updater.devices = {device["mac"]: device}
    desc = next(desc for desc in MIWIFI_DEVICE_SENSORS if desc.key == "signal_quality")
    sensor = MiWifiDeviceAttributeSensor(updater, device, desc)
    sensor.hass = hass
    assert sensor.native_value == expected


@pytest.mark.parametrize("signal", [None, 0, 80])
async def test_wifi_census_does_not_invent_zero_for_a_missing_signal(hass, signal):
    from custom_components.miwifi.updater import LuciUpdater
    from custom_components.miwifi.enum import Mode
    entry = MockConfigEntry(domain=DOMAIN, data={"ip_address": "192.0.2.1"})
    entry.add_to_hass(hass)
    updater = LuciUpdater(hass, "192.0.2.1", "synthetic", entry_id=entry.entry_id)
    updater.update_interval = None
    updater.data = {"mode": Mode.DEFAULT, "state": True}
    row = {"mac": "02:00:00:00:00:43"}
    if signal is not None:
        row["signal"] = signal
    updater.luci.wifi_connect_devices = AsyncMock(return_value={"code": 0, "list": [row]})
    updater.luci.macfilter_info = AsyncMock(return_value={"code": 0, "list": []})
    try:
        await updater._async_prepare_devices(updater.data)
        assert updater._signals[row["mac"]] == signal
    finally:
        await updater.async_shutdown()
