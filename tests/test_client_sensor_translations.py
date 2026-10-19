"""HA entity translations preserve client identities and raw automation states."""
import logging
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
            assert translations[prefix + desc.key + ".state." + state]


async def test_translated_client_keeps_registry_id_raw_state_and_custom_name(hass):
    hass.config.language = "es"
    entry = MockConfigEntry(domain=DOMAIN, data={"ip_address": "192.0.2.1"})
    entry.add_to_hass(hass)
    updater = DataUpdateCoordinator(hass, logging.getLogger(__name__), name="test", config_entry=entry, update_method=AsyncMock(return_value={}))
    updater.data = {}
    mac = "02:00:00:00:00:41"
    device = {"mac": mac, "name": "Test client", "connection": Connection.WIFI_5_0_GAME,
              "internet_blocked": False, "signal": None}
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
    assert states == {"connection": "5G Game", "signal_quality": "no_signal", "internet_blocked": "False"}
