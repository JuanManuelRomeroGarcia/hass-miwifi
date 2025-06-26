"""Update component."""

from __future__ import annotations

import asyncio
import aiohttp
import httpx
from .logger import _LOGGER
from typing import Any, Final
from datetime import datetime
from homeassistant.util import dt as dt_util


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
from homeassistant.components.persistent_notification import async_create
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
from .frontend import (
    async_download_panel_if_needed,
    async_remove_miwifi_panel,
    async_register_panel,
    read_local_version,
    read_remote_version
)
import homeassistant.components.persistent_notification as pn
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
            _LOGGER.warning(f"[MiWiFi] The panel update entity could not be created: {e}")
    else:
        _LOGGER.debug("[MiWiFi] Panel update entity not created because this router is not the main one.")

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
        return f"https://raw.githubusercontent.com/{REPOSITORY}/main/images/{model.name}.png"

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
            _LOGGER.error("Clear permission error: %r", e)

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
    def __init__(self, unique_id: str, updater) -> None:
        description = UpdateEntityDescription(
            key="miwifi_panel",
            name="MiWiFi Panel Frontend",
            device_class=UpdateDeviceClass.FIRMWARE,
            entity_category=EntityCategory.CONFIG,
            entity_registry_enabled_default=True,
        )
        super().__init__(unique_id, description, updater, ENTITY_ID_FORMAT)

        self._attr_translation_key = "panel_title"
        self._attr_supported_features = UpdateEntityFeature.INSTALL | UpdateEntityFeature.RELEASE_NOTES
        self._attr_should_poll = False

        self._attr_device_info = DeviceInfo(
            identifiers={(DOMAIN, updater.data.get("mac", "miwifi_panel"))},
            name="MiWiFi Panel",
            manufacturer="Xiaomi",
            model="Panel Frontend",
        )

    def _update_from_coordinator_data(self) -> None:
        local = self._updater.data.get("panel_local_version", "0.0")
        remote = self._updater.data.get("panel_remote_version", "0.0")

        self._attr_installed_version = local
        self._attr_latest_version = remote
        self._attr_available = local != remote

    def _handle_coordinator_update(self) -> None:
        prev_local = self._attr_installed_version
        prev_remote = self._attr_latest_version

        self._update_from_coordinator_data()

        if (
            prev_local != self._attr_installed_version
            or prev_remote != self._attr_latest_version
        ):
            _LOGGER.info(
                f"[MiWiFi] Panel update check → local: {self._attr_installed_version}, remote: {self._attr_latest_version}"
            )
            self.async_write_ha_state()

    @property
    def release_summary(self) -> str | None:
        version = self._attr_latest_version
        return f"📱 Mobile layout fixes, topbar improvements and responsive tweaks in v{version}"


    @property
    def entity_picture(self) -> str | None:
        return "https://raw.githubusercontent.com/JuanManuelRomeroGarcia/miwifi-panel-frontend/main/assets/icon_panel.png"

    @property
    def release_url(self) -> str | None:
        return "https://github.com/JuanManuelRomeroGarcia/miwifi-panel-frontend/releases"

    @property
    def extra_state_attributes(self) -> dict[str, Any]:
        return {
            "last_checked": dt_util.now().isoformat(),
        }
        
    @property
    def available(self) -> bool:
        """Return if entity is available."""
        return (
            self._attr_installed_version != "0.0"
            and self._attr_latest_version != "0.0"
        )

    
    async def async_added_to_hass(self) -> None:
        await super().async_added_to_hass()
        self._update_from_coordinator_data()
        self.async_write_ha_state()


    async def async_release_notes(self) -> str | None:
        version = self._attr_latest_version
        if not version:
            return None

        try:
            url = f"https://api.github.com/repos/JuanManuelRomeroGarcia/miwifi-panel-frontend/releases/tags/v{version}"
            async with httpx.AsyncClient(timeout=10) as client:
                response = await client.get(url)

            if response.status_code == 200:
                data = response.json()
                return data.get("body", f"No release notes found for v{version}")
            else:
                _LOGGER.warning(f"GitHub release not found for v{version}: {response.status_code}")
                return None

        except Exception as e:
            _LOGGER.error(f"Error fetching GitHub release notes for v{version}: {e}")
            return None

    async def async_install(self, version: str | None, backup: bool, **kwargs: Any) -> None:
        from .frontend import async_download_panel_if_needed, async_register_panel, read_local_version

        hass = self._updater.hass

        remote_version = await async_download_panel_if_needed(hass)
        await async_register_panel(hass, remote_version)

        new_local_version = await read_local_version(hass)

        self._attr_installed_version = new_local_version
        self._attr_latest_version = remote_version
        self._attr_available = new_local_version != remote_version

        if isinstance(self._attr_device_info, dict):
            self._attr_device_info["sw_version"] = new_local_version

        await asyncio.sleep(1.5)
        self.async_write_ha_state()
        self._attr_available = True

        translations = (
            hass.data.get("translations", {})
            .get(hass.config.language, {})
            .get("component", {})
            .get(DOMAIN, {})
            .get("panel_update", {})
        )

        title = translations.get("update_title", "MiWiFi Panel Updated")
        message_template = translations.get(
            "update_message",
            "✅ MiWiFi Panel has been updated to version <b>{version}</b>.<br>Please <b>refresh your browser (Ctrl+F5)</b> to see the changes."
        )
        message = message_template.replace("{version}", remote_version)

        async_create(hass, message, title)