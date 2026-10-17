"""Persistent notifications use translated private-download and MAC messages."""

from types import SimpleNamespace

import pytest

from custom_components.miwifi.notifier import MiWiFiNotifier


@pytest.mark.parametrize("language", ["en", "es", "de", "fr", "pt-BR", "ru", "tr", "zh-Hans"])
async def test_private_notifications_have_native_translations(hass, language):
    local_hass = SimpleNamespace(
        config=SimpleNamespace(language=language), data={},
        async_add_executor_job=hass.async_add_executor_job,
    )
    notifier = MiWiFiNotifier(local_hass)
    translated = await notifier.get_translations()
    notifications = translated["notifications"]
    assert await notifier.get_translations() is translated
    for key in ("dump_ready_private", "logs_ready_private", "mac_replacement_configured", "none", "purge_preview_title"):
        assert notifications[key]
        if language != "en":
            english_hass = SimpleNamespace(
                config=SimpleNamespace(language="en"), data={},
                async_add_executor_job=hass.async_add_executor_job,
            )
            english = await MiWiFiNotifier(english_hass).get_translations()
            assert notifications[key] != english["notifications"][key]
    assert "{clients}" in notifications["mac_replacement_configured"]
    assert "{url}" not in notifications["dump_ready_private"]
    assert "{url}" not in notifications["logs_ready_private"]
