from pathlib import Path
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
        cache = self.hass.data.setdefault("miwifi_notification_translations", {})
        if lang in cache:
            return cache[lang]

        def read_translations():
            base = Path(__file__).parent
            merged = {}
            for language in dict.fromkeys(("en", lang)):
                for folder in ("translations", "notification_translations"):
                    path = base / folder / f"{language}.json"
                    if not path.is_file():
                        continue
                    for key, value in load_json(str(path)).items():
                        if isinstance(value, dict) and isinstance(merged.get(key), dict):
                            merged[key] = {**merged[key], **value}
                        else:
                            merged[key] = value
            return merged

        translations = await self.hass.async_add_executor_job(read_translations)
        cache[lang] = translations
        return translations

    async def notify(self, message: str, title: str = "MiWiFi", notification_id: str = "miwifi_generic") -> None:
        """Show a persistent notification in HA."""
        pn.async_create(self.hass, message, title, notification_id)
