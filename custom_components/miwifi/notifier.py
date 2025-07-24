import os
from homeassistant.util.json import load_json
import homeassistant.components.persistent_notification as pn
from logging import getLogger

_LOGGER = getLogger("miwifi")

class MiWiFiNotifier:
    def __init__(self, hass, domain: str = "miwifi"):
        self.hass = hass
        self.domain = domain

    @staticmethod
    def build_nested_translations(flat: dict[str, str]) -> dict:
        """Converts flat translation keys into nested dict format."""
        nested = {}
        for key, value in flat.items():
            parts = key.split(".")
            d = nested
            for part in parts[:-1]:
                d = d.setdefault(part, {})
            d[parts[-1]] = value
        return nested

    async def get_translations(self) -> dict:
        """Load nested translations for the current HA language."""
        lang = self.hass.config.language
        translations = self.hass.data.get("translations", {}).get(lang, {}).get("component", {}).get(self.domain)

        if not translations:
            try:
                translation_path = f"{self.hass.config.path('custom_components')}/{self.domain}/translations/{lang}.json"
                flat_translations = await self.hass.async_add_executor_job(load_json, translation_path)
                nested = self.build_nested_translations(flat_translations)

                self.hass.data.setdefault("translations", {}).setdefault(lang, {}).setdefault("component", {})[self.domain] = nested
                await self.hass.async_add_executor_job(_LOGGER.debug, "[MiWiFi] 📥 Translations for '%s' loaded from disk.", lang)
                translations = nested
            except Exception as e:
                await self.hass.async_add_executor_job(_LOGGER.warning, "[MiWiFi] ❌ Could not load translations for '%s': %s", lang, e)
                translations = {}

        return translations

    async def notify(self, message: str, title: str = "MiWiFi", notification_id: str = "miwifi_generic") -> None:
        """Show a persistent notification in HA."""
        pn.async_create(self.hass, message, title, notification_id)
