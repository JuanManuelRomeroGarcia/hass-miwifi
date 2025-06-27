"""MiWifi diagnostic."""

from __future__ import annotations

import sys
from typing import Final
import urllib.parse
import homeassistant.components.persistent_notification as pn
from .const import DOMAIN, NAME
from .enum import Model, Mode
from .logger import _LOGGER
from homeassistant.loader import async_get_integration

from homeassistant.components.diagnostics import async_redact_data
from homeassistant.config_entries import ConfigEntry
from homeassistant.const import (
    CONF_ID,
    CONF_PASSWORD,
    CONF_TOKEN,
    CONF_URL,
    CONF_USERNAME,
)
from homeassistant.core import HomeAssistant

from .updater import async_get_updater

TO_REDACT: Final = {
    CONF_PASSWORD,
    CONF_USERNAME,
    CONF_URL,
    CONF_TOKEN,
    CONF_ID,
    "routerId",
    "gateWay",
    "hostname",
    "ipv4",
    "ssid",
    "pwd",
}


async def async_get_config_entry_diagnostics(
    hass: HomeAssistant, config_entry: ConfigEntry
) -> dict:
    """Return diagnostics for a config entry."""

    _data: dict = {"config_entry": async_redact_data(config_entry.as_dict(), TO_REDACT)}

    if _updater := async_get_updater(hass, config_entry.entry_id):
        if hasattr(_updater, "data"):
            _data["data"] = async_redact_data(_updater.data, TO_REDACT)

        if hasattr(_updater, "devices"):
            _data["devices"] = _updater.devices

        if len(_updater.luci.diagnostics) > 0:
            _data["requests"] = async_redact_data(_updater.luci.diagnostics, TO_REDACT)

    return _data

async def async_get_config_entry_diagnostics(
    hass: HomeAssistant, config_entry: ConfigEntry
) -> dict:
    """Return diagnostics for a config entry."""

    _data: dict = {"config_entry": async_redact_data(config_entry.as_dict(), TO_REDACT)}

    if _updater := async_get_updater(hass, config_entry.entry_id):
        if hasattr(_updater, "data"):
            _data["data"] = async_redact_data(_updater.data, TO_REDACT)

        if hasattr(_updater, "devices"):
            _data["devices"] = _updater.devices

        if len(_updater.luci.diagnostics) > 0:
            _data["requests"] = async_redact_data(_updater.luci.diagnostics, TO_REDACT)

    return _data


async def async_get_config_entry_diagnostics(
    hass: HomeAssistant, config_entry: ConfigEntry
) -> dict:
    """Return diagnostics for a config entry."""

    _data: dict = {"config_entry": async_redact_data(config_entry.as_dict(), TO_REDACT)}

    if _updater := async_get_updater(hass, config_entry.entry_id):
        if hasattr(_updater, "data"):
            _data["data"] = async_redact_data(_updater.data, TO_REDACT)

        if hasattr(_updater, "devices"):
            _data["devices"] = _updater.devices

        if len(_updater.luci.diagnostics) > 0:
            _data["requests"] = async_redact_data(_updater.luci.diagnostics, TO_REDACT)

    return _data


async def suggest_unsupported_issue(
    hass: HomeAssistant,
    model: str | Model,
    compatibility: dict[str, bool | None],
    mode: Mode | str | None = None
) -> None:
    """Suggest adding a known model to the UNSUPPORTED registry based on compatibility check."""

    failed = [key for key, supported in compatibility.items() if supported is False]
    if not failed:
        return  # Nothing failed — no suggestion needed

    model_name = model.name if isinstance(model, Model) else str(model)

    if not model_name.isidentifier():
        _LOGGER.warning("[MiWiFi] Model name '%s' may not be valid for enum entry.", model_name)

    integration = await async_get_integration(hass, DOMAIN)
    if "homeassistant.const" in sys.modules:
        from homeassistant.const import __version__ as HA_VERSION
    else:
        HA_VERSION = "unknown"


    # Block of code to suggest for UNSUPPORTED
    code_lines = [
        f'    "{feature}": [Model.{model_name.upper()}],' for feature in failed
    ]
    code_block = "UNSUPPORTED = {\n" + "\n".join(code_lines) + "\n}"

    checklist = "\n".join(f" * {feature}: ❌" for feature in failed)
    mode_str = mode.name if isinstance(mode, Mode) else str(mode or "unknown")

    body = (
        f"Model: {model_name}\n"
        f"Mode: {mode_str}\n\n"
        f"Failed compatibility checks:\n{checklist}\n\n"
        f"Suggested code for unsupported.py:\n\n"
        f"```python\n{code_block}\n```\n\n"
        f"Versions:\n"
        f" * MiWiFi Integration: {integration.version}\n"
        f" * Home Assistant: {HA_VERSION}"
    )

    issue_url = (
        f"{integration.issue_tracker}/new?title="
        + urllib.parse.quote_plus(f"Update UNSUPPORTED registry for model {model_name}")
        + "&body="
        + urllib.parse.quote_plus(body)
    )

    message = (
        f"🚫 Detected unsupported features for model: {model_name} (mode: {mode_str})\n\n"
        f"{checklist}\n\n"
        f"<a href=\"{issue_url}\" target=\"_blank\">\n"
        f"📬 Create a GitHub issue to update unsupported.py\n"
        f"</a>"
    )

    pn.async_create(hass, message, NAME)
