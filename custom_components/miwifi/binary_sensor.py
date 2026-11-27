from __future__ import annotations

from .logger import _LOGGER
from typing import Final

from homeassistant.components.binary_sensor import (
    ENTITY_ID_FORMAT,
    BinarySensorDeviceClass,
    BinarySensorEntity,
    BinarySensorEntityDescription,
)
from homeassistant.config_entries import ConfigEntry
from homeassistant.const import STATE_OFF, STATE_ON
from homeassistant.core import HomeAssistant
from homeassistant.helpers.entity import EntityCategory
from homeassistant.helpers.entity_platform import AddEntitiesCallback

from .const import (
    ATTR_BINARY_SENSOR_DUAL_BAND,
    ATTR_BINARY_SENSOR_DUAL_BAND_NAME,
    ATTR_BINARY_SENSOR_WAN_STATE,
    ATTR_BINARY_SENSOR_WAN_STATE_NAME,
    ATTR_BINARY_SENSOR_WAN_LINK,
    ATTR_BINARY_SENSOR_WAN_LINK_NAME,
    ATTR_BINARY_SENSOR_VPN_STATE,
    ATTR_BINARY_SENSOR_VPN_STATE_NAME,
    ATTR_STATE,
    ATTR_STATE_NAME,
)
from .entity import MiWifiEntity
from .cpe_ipv6 import is_cb0401v2, parse_ipv6
from .updater import LuciUpdater, async_get_updater

PARALLEL_UPDATES = 0

ICONS: Final = {
    f"{ATTR_STATE}_{STATE_ON}": "mdi:router-wireless",
    f"{ATTR_STATE}_{STATE_OFF}": "mdi:router-wireless-off",
}

MIWIFI_BINARY_SENSORS: tuple[BinarySensorEntityDescription, ...] = (
    BinarySensorEntityDescription(
        key=ATTR_STATE,
        name=ATTR_STATE_NAME,
        icon=ICONS[f"{ATTR_STATE}_{STATE_ON}"],
        entity_category=EntityCategory.DIAGNOSTIC,
        entity_registry_enabled_default=True,
    ),
    BinarySensorEntityDescription(
        key=ATTR_BINARY_SENSOR_WAN_STATE,
        name=ATTR_BINARY_SENSOR_WAN_STATE_NAME,
        icon="mdi:wan",
        device_class=BinarySensorDeviceClass.CONNECTIVITY,
        entity_category=EntityCategory.DIAGNOSTIC,
        entity_registry_enabled_default=True,
    ),
    BinarySensorEntityDescription(
        key=ATTR_BINARY_SENSOR_VPN_STATE,
        name=ATTR_BINARY_SENSOR_VPN_STATE_NAME,
        icon="mdi:security-network",
        device_class=BinarySensorDeviceClass.CONNECTIVITY,
        entity_category=EntityCategory.DIAGNOSTIC,
        entity_registry_enabled_default=False,
    ),
    BinarySensorEntityDescription(
        key=ATTR_BINARY_SENSOR_DUAL_BAND,
        name=ATTR_BINARY_SENSOR_DUAL_BAND_NAME,
        icon="mdi:wifi-plus",
        entity_category=EntityCategory.DIAGNOSTIC,
        entity_registry_enabled_default=False,
    ),
    BinarySensorEntityDescription(
        key=ATTR_BINARY_SENSOR_WAN_LINK,
        name=ATTR_BINARY_SENSOR_WAN_LINK_NAME,
        icon="mdi:wan",
        device_class=BinarySensorDeviceClass.CONNECTIVITY,
        entity_category=EntityCategory.DIAGNOSTIC,
        entity_registry_enabled_default=True,
    ),
)




async def async_setup_entry(
    hass: HomeAssistant,
    config_entry: ConfigEntry,
    async_add_entities: AddEntitiesCallback,
) -> None:
    updater: LuciUpdater = async_get_updater(hass, config_entry.entry_id)

    entities: list[MiWifiBinarySensor] = [
        MiWifiBinarySensor(
            f"{config_entry.entry_id}-{description.key}",
            description,
            updater,
        )
        for description in MIWIFI_BINARY_SENSORS
    ]
    if is_cb0401v2(updater):
        description = BinarySensorEntityDescription(
            key="mobile_ipv6_interface", name="Mobile IPv6 interface", icon="mdi:ip-network",
            entity_category=EntityCategory.DIAGNOSTIC,
        )
        entities.append(MiWifiIPv6Interface(f"{config_entry.entry_id}-{description.key}", description, updater))
    async_add_entities(entities)


class MiWifiBinarySensor(MiWifiEntity, BinarySensorEntity):
    def __init__(
        self,
        unique_id: str,
        description: BinarySensorEntityDescription,
        updater: LuciUpdater,
    ) -> None:
        super().__init__(unique_id, description, updater, ENTITY_ID_FORMAT)

        self._attr_available: bool = (
            updater.data.get(ATTR_STATE, False)
            if description.key != ATTR_STATE
            else True
        )

        self._attr_is_on = updater.data.get(description.key, False)

    @property
    def icon(self) -> str | None:
        state = STATE_ON if self._attr_is_on else STATE_OFF
        return ICONS.get(
            f"{self.entity_description.key}_{state}", self.entity_description.icon
        )

    def _handle_coordinator_update(self) -> None:
        is_available: bool = (
            self._updater.data.get(ATTR_STATE, False)
            if self.entity_description.key != ATTR_STATE
            else True
        )

        is_on: bool = self._updater.data.get(self.entity_description.key, False)

        if self._attr_is_on == is_on and self._attr_available == is_available:
            return

        self._attr_available = is_available
        self._attr_is_on = is_on

        self.async_write_ha_state()


class MiWifiIPv6Interface(MiWifiBinarySensor):
    """Router-reported interface status, not an internet connectivity test."""

    @property
    def is_on(self):
        response = self._updater.data.get("mobile_net_info")
        return parse_ipv6(response.get("ipv6info") if isinstance(response, dict) else None)["up"]

    @property
    def available(self):
        return super().available and self._updater.data.get("mobile_ipv6_query_ok") is not False

    def _handle_coordinator_update(self):
        self._attr_available = self._updater.data.get(ATTR_STATE, False)
        self.async_write_ha_state()
