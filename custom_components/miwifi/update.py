"""Update component."""

from __future__ import annotations

import asyncio

from .logger import _LOGGER
from typing import Any, Final
from .enum import Connection
from .notifier import MiWiFiNotifier

from homeassistant.components.update import (
    ATTR_IN_PROGRESS,
    ENTITY_ID_FORMAT,
    UpdateDeviceClass,
    UpdateEntity,
    UpdateEntityDescription,
    UpdateEntityFeature,
)
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant
from homeassistant.exceptions import HomeAssistantError
from homeassistant.helpers.entity import EntityCategory
from homeassistant.helpers.entity_platform import AddEntitiesCallback
from homeassistant.helpers import entity_registry as er
from homeassistant.helpers import device_registry as dr



from .const import (
    ATTR_MODEL,
    ATTR_STATE,
    ATTR_UPDATE_CURRENT_VERSION,
    ATTR_UPDATE_DOWNLOAD_URL,
    ATTR_UPDATE_FILE_HASH,
    ATTR_UPDATE_FILE_SIZE,
    ATTR_UPDATE_FIRMWARE,
    ATTR_UPDATE_FIRMWARE_NAME,
    ATTR_UPDATE_LATEST_VERSION,
    ATTR_UPDATE_RELEASE_URL,
    ATTR_UPDATE_TITLE,
    REPOSITORY,
    DOMAIN,
)

from .entity import MiWifiEntity
from .enum import Model
from .exceptions import LuciError
from .helper import device_config_entry_ids
from .updater import LuciUpdater, async_get_updater

PARALLEL_UPDATES = 0

FIRMWARE_UPDATE_WAIT: Final = 180
FIRMWARE_UPDATE_RETRY: Final = 721

ATTR_CHANGES: Final = (
    ATTR_UPDATE_TITLE,
    ATTR_UPDATE_CURRENT_VERSION,
    ATTR_UPDATE_LATEST_VERSION,
    ATTR_UPDATE_RELEASE_URL,
    ATTR_UPDATE_DOWNLOAD_URL,
    ATTR_UPDATE_FILE_SIZE,
    ATTR_UPDATE_FILE_HASH,
)

MAP_FEATURE: Final = {
    ATTR_UPDATE_FIRMWARE: UpdateEntityFeature.INSTALL
    | UpdateEntityFeature.RELEASE_NOTES
}

MAP_NOTES: Final = {
    ATTR_UPDATE_FIRMWARE: "\n\n<ha-alert alert-type='warning'>"
    + "The firmware update takes an average of 3 to 15 minutes."
    + "</ha-alert>\n\n"
}

MIWIFI_UPDATES: tuple[UpdateEntityDescription, ...] = (
    UpdateEntityDescription(
        key=ATTR_UPDATE_FIRMWARE,
        name=ATTR_UPDATE_FIRMWARE_NAME,
        device_class=UpdateDeviceClass.FIRMWARE,
        entity_category=EntityCategory.CONFIG,
        entity_registry_enabled_default=True,
    ),
)

async def async_setup_entry(
    hass: HomeAssistant,
    config_entry: ConfigEntry,
    async_add_entities: AddEntitiesCallback,
) -> None:
    # Match the integration-owned unique ID, including renamed/disabled entities.
    registry = er.async_get(hass)
    panel_devices = set()
    for entity in er.async_entries_for_config_entry(registry, config_entry.entry_id):
        if (entity.domain == "update" and entity.platform == DOMAIN
                and entity.unique_id == f"{config_entry.entry_id}_miwifi_panel"):
            if entity.device_id:
                panel_devices.add(entity.device_id)
            registry.async_remove(entity.entity_id)

    devices = dr.async_get(hass)
    for device_id in panel_devices:
        device = devices.async_get(device_id)
        if (device is not None and device.model == "Panel Frontend"
                and device_config_entry_ids(device) == {config_entry.entry_id}
                and not er.async_entries_for_device(registry, device_id,
                                                    include_disabled_entities=True)):
            devices.async_remove_device(device_id)

    updater: LuciUpdater = async_get_updater(hass, config_entry.entry_id)

    entities: list[UpdateEntity] = []

    entities += [
        MiWifiUpdate(
            f"{config_entry.entry_id}-{description.key}",
            description,
            updater,
        )
        for description in MIWIFI_UPDATES
        if description.key != ATTR_UPDATE_FIRMWARE or updater.supports_update
    ]

    if entities:
        async_add_entities(entities)

class MiWifiUpdate(MiWifiEntity, UpdateEntity):
    _update_data: dict[str, Any]

    def __init__(self, unique_id: str, description: UpdateEntityDescription, updater: LuciUpdater) -> None:
        MiWifiEntity.__init__(self, unique_id, description, updater, ENTITY_ID_FORMAT)
        if description.key in MAP_FEATURE:
            self._attr_supported_features = MAP_FEATURE[description.key]

        self._update_data = updater.data.get(description.key, {})
        self._attr_available = (
            updater.data.get(ATTR_STATE, False) and len(self._update_data) > 0
        )
        self._attr_title = self._update_data.get(ATTR_UPDATE_TITLE, None)
        self._attr_installed_version = self._update_data.get(ATTR_UPDATE_CURRENT_VERSION, None)
        self._attr_latest_version = self._update_data.get(ATTR_UPDATE_LATEST_VERSION, None)
        self._attr_release_url = self._update_data.get(ATTR_UPDATE_RELEASE_URL, None)

    async def async_added_to_hass(self) -> None:
        await MiWifiEntity.async_added_to_hass(self)

    @property
    def entity_picture(self) -> str | None:
        model: Model = self._updater.data.get(ATTR_MODEL, Model.NOT_KNOWN)
        return (
            f"https://raw.githubusercontent.com/{REPOSITORY}/main/"
            f"custom_components/miwifi/www/images/{model.name}.png"
        )

    def _handle_coordinator_update(self) -> None:
        if self.state_attributes.get(ATTR_IN_PROGRESS, False):
            return
        _update_data = self._updater.data.get(self.entity_description.key, {})
        is_available = (
            self._updater.data.get(ATTR_STATE, False) and len(_update_data) > 0
        )
        attr_changed = [
            attr
            for attr in ATTR_CHANGES
            if self._update_data.get(attr) != _update_data.get(attr)
        ]
        if self._attr_available == is_available and not attr_changed:
            return
        self._attr_available = is_available
        self._update_data = _update_data
        self._attr_title = self._update_data.get(ATTR_UPDATE_TITLE)
        self._attr_installed_version = self._update_data.get(ATTR_UPDATE_CURRENT_VERSION)
        self._attr_latest_version = self._update_data.get(ATTR_UPDATE_LATEST_VERSION)
        self._attr_release_url = self._update_data.get(ATTR_UPDATE_RELEASE_URL)
        self.async_write_ha_state()

    async def _firmware_install(self) -> None:
        try:
            await self._updater.luci.rom_upgrade({
                "url": self._update_data.get(ATTR_UPDATE_DOWNLOAD_URL),
                "filesize": self._update_data.get(ATTR_UPDATE_FILE_SIZE),
                "hash": self._update_data.get(ATTR_UPDATE_FILE_HASH),
                "needpermission": 1,
            })
        except LuciError as e:
            raise HomeAssistantError(str(e)) from e

        try:
            await self._updater.luci.flash_permission()
        except LuciError as e:
            await self.hass.async_add_executor_job(_LOGGER.error, "Clear permission error: %r", e)

        await asyncio.sleep(FIRMWARE_UPDATE_WAIT)
        for _ in range(1, FIRMWARE_UPDATE_RETRY):
            if self._updater.data.get(ATTR_STATE, False):
                break
            await asyncio.sleep(1)

    async def async_install(self, version: str | None, backup: bool, **kwargs: Any) -> None:
        if action := getattr(self, f"_{self.entity_description.key}_install"):
            await action()
            self._attr_installed_version = self._attr_latest_version
            self.async_write_ha_state()

    async def async_release_notes(self) -> str | None:
        return MAP_NOTES[self.entity_description.key]

class MiWiFiNewDeviceNotifier:
    def __init__(self, hass):
        self.hass = hass
        self.translator = MiWiFiNotifier(hass, domain=DOMAIN)

    async def async_notify_new_device(self, router_ip: str, mac: str, new_device: dict, notified_store):
        stored = await notified_store[router_ip].async_load() or {}
        if mac in stored:
            return

        name = new_device.get("name", "Unknown")
        ip = new_device.get("ip", "N/A")
        conn_type = new_device.get("connection")

        try:
            conn_enum = Connection(int(conn_type))
            conn_key = conn_enum.name.lower()
            conn_phrase = conn_enum.phrase
        except (ValueError, TypeError):
            conn_key = "unknown"
            conn_phrase = "Unknown"

        translations = await self.translator.get_translations()

        translations_type = translations.get("connection_type", {})
        translations_notify = translations.get("notifications", {})
        title = translations_notify.get("new_device_title", "New Device Detected on MiWiFi")
        conn_str = translations_type.get(conn_key, conn_phrase)

        message_template = translations_notify.get(
            "new_device_message",
            "📶 New device connected: **{name}**\n💻 MAC: `{mac}`\n🌐 IP: `{ip}`\n📡 Connection: `{conn}`"
        )

        if any(p not in message_template for p in ("{name}", "{mac}", "{ip}", "{conn}")):
            message_template = (
                "📶 New device connected: **{name}**\n"
                "💻 MAC: `{mac}`\n"
                "🌐 IP: `{ip}`\n"
                "📡 Connection: `{conn}`"
            )

        message = message_template.format(name=name, mac=mac, ip=ip, conn=conn_str)

        await self.translator.notify(
            message,
            title=title,
            notification_id=f"miwifi_new_device_{mac.replace(':', '_')}"
        )

        stored[mac] = True
        await notified_store[router_ip].async_save(stored)
