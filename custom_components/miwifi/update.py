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
from homeassistant.const import __name__ as ha_const_ns



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

    topo_graph = (updater.data or {}).get("topo_graph", {})

    if not isinstance(topo_graph, dict):
        topo_graph = {}

    is_main = topo_graph.get("graph", {}).get("is_main", False)

    if is_main:
        try:
            panel_entity = MiWifiPanelUpdate(f"{config_entry.entry_id}_miwifi_panel", updater)
            entities.append(panel_entity)
        except Exception as e:
            await hass.async_add_executor_job(_LOGGER.warning, f"[MiWiFi] The panel update entity could not be created: {e}")
    else:
        await hass.async_add_executor_job(_LOGGER.debug, "[MiWiFi] Panel update entity not created because this router is not the main one.")

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

from homeassistant.helpers.entity import DeviceInfo

class MiWifiPanelUpdate(MiWifiEntity, UpdateEntity):
    """Keep the existing panel entity as bundled-version information."""

    def __init__(self, unique_id: str, updater) -> None:
        description = UpdateEntityDescription(
            key="miwifi_panel",
            name="MiWiFi Panel Frontend",
            entity_category=EntityCategory.CONFIG,
            entity_registry_enabled_default=True,
        )
        super().__init__(unique_id, description, updater, ENTITY_ID_FORMAT)
        self._attr_translation_key = "panel_title"
        self._attr_supported_features = UpdateEntityFeature(0)
        self._attr_should_poll = False
        self._attr_device_info = DeviceInfo(
            identifiers={(DOMAIN, updater.data.get("mac", "miwifi_panel"))},
            name="MiWiFi Panel",
            manufacturer="Xiaomi",
            model="Panel Frontend",
        )

    def _update_from_coordinator_data(self) -> None:
        version = self._updater.data.get("panel_local_version")
        self._attr_installed_version = version
        self._attr_latest_version = version
        self._attr_available = version is not None

    def _handle_coordinator_update(self) -> None:
        self._update_from_coordinator_data()
        self.async_write_ha_state()

    async def async_added_to_hass(self) -> None:
        await super().async_added_to_hass()
        self._update_from_coordinator_data()
        self.async_write_ha_state()

    @property
    def release_summary(self) -> str:
        return "The frontend is bundled with MiWiFi. Update the integration through HACS."

    @property
    def release_url(self) -> str:
        return "https://github.com/JuanManuelRomeroGarcia/hass-miwifi/releases"

    async def async_install(self, version: str | None, backup: bool, **kwargs: Any) -> None:
        raise HomeAssistantError("Update the MiWiFi integration through HACS to update its panel.")


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
