"""Unsupported models registry (base + user overrides in HA Storage)."""

from __future__ import annotations

import asyncio
import importlib.util
from pathlib import Path
from typing import Any

from homeassistant.core import HomeAssistant
from homeassistant.helpers.storage import Store

from . import const as C
from .enum import Model
from .logger import _LOGGER

DOMAIN = getattr(C, "DOMAIN", "miwifi")
STORAGE_VERSION = getattr(C, "STORAGE_VERSION", 1)

# Stored at: .storage/<DOMAIN>/<STORE_UNSUPPORTED_USER>
STORE_UNSUPPORTED_USER = getattr(C, "STORE_UNSUPPORTED_USER", "unsupported_user.json")

# Legacy file (old behavior)
LEGACY_USER_FILE = Path(__file__).with_name("unsupported_user.py")

_LOCK_KEY = "_unsupported_user_lock"
_MIGRATED_KEY = "_unsupported_user_legacy_migrated"


def _store(hass: HomeAssistant) -> Store:
    return Store(hass, STORAGE_VERSION, f"{DOMAIN}/{STORE_UNSUPPORTED_USER}")


def _get_lock(hass: HomeAssistant) -> asyncio.Lock:
    data = hass.data.setdefault(DOMAIN, {})
    lock = data.get(_LOCK_KEY)
    if lock is None:
        lock = asyncio.Lock()
        data[_LOCK_KEY] = lock
    return lock


def parse_model(value: Any) -> Model | None:
    """Parse Model from str/Model, accepting both enum NAME and enum VALUE."""
    if value is None:
        return None

    if isinstance(value, Model):
        return value

    s = str(value).strip()
    if not s:
        return None

    # Accept "Model.R3600"
    if s.lower().startswith("model."):
        s = s.split(".", 1)[1].strip()

    # 1) NAME lookup (e.g. "R3600")
    try:
        return Model[s.upper()]
    except Exception:
        pass

    # 2) VALUE lookup (e.g. "r3600")
    try:
        return Model(s.lower())
    except Exception:
        return None


def _deserialize_user(raw: Any) -> dict[str, list[Model]]:
    """Storage -> {feature: [Model,...]}.
    Accepts either:
      - {"feature": ["R3600", "RA70", ...]}
      - {"unsupported": {...}} (future-proof)
    """
    if not isinstance(raw, dict):
        return {}

    if "unsupported" in raw and isinstance(raw["unsupported"], dict):
        raw = raw["unsupported"]

    out: dict[str, list[Model]] = {}
    for feature, items in raw.items():
        if not isinstance(feature, str) or not feature:
            continue
        models: list[Model] = []
        if isinstance(items, list):
            for it in items:
                m = parse_model(it)
                if m and m not in models:
                    models.append(m)
        if models:
            out[feature] = models
        else:
            out.setdefault(feature, [])
    return out


def _serialize_user(data: dict[str, list[Model]]) -> dict[str, list[str]]:
    """{feature:[Model]} -> storage with model names."""
    out: dict[str, list[str]] = {}
    for feature, models in (data or {}).items():
        if not isinstance(feature, str) or not feature:
            continue
        out[feature] = [m.name for m in models if isinstance(m, Model)]
    return out


async def _load_raw(hass: HomeAssistant) -> dict[str, Any]:
    return await _store(hass).async_load() or {}


async def _save_raw(hass: HomeAssistant, data: dict[str, Any]) -> None:
    await _store(hass).async_save(data)


async def _migrate_legacy_py_if_needed(hass: HomeAssistant) -> None:
    """If legacy unsupported_user.py exists, migrate it once into HA Storage."""
    data = hass.data.setdefault(DOMAIN, {})
    if data.get(_MIGRATED_KEY):
        return
    data[_MIGRATED_KEY] = True

    if not LEGACY_USER_FILE.exists():
        return

    try:
        spec = importlib.util.spec_from_file_location(f"{DOMAIN}.unsupported_user_legacy", str(LEGACY_USER_FILE))
        if spec is None or spec.loader is None:
            return

        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)

        legacy = getattr(mod, "UNSUPPORTED", {})
        if not isinstance(legacy, dict):
            return

        migrated: dict[str, list[Model]] = {}
        for feature, items in legacy.items():
            if not isinstance(feature, str) or not feature:
                continue
            models: list[Model] = []
            if isinstance(items, list):
                for it in items:
                    m = parse_model(it)
                    if m and m not in models:
                        models.append(m)
            if models:
                migrated[feature] = models

        if migrated:
            await _save_raw(hass, _serialize_user(migrated))
            await hass.async_add_executor_job(
                _LOGGER.info,
                "[MiWiFi] Migrated legacy unsupported_user.py -> .storage/%s/%s",
                DOMAIN,
                STORE_UNSUPPORTED_USER,
            )
    except Exception as e:
        await hass.async_add_executor_job(_LOGGER.debug, "[MiWiFi] Legacy migrate failed: %s", e)


async def async_load_user_unsupported(hass: HomeAssistant) -> dict[str, list[Model]]:
    await _migrate_legacy_py_if_needed(hass)
    raw = await _load_raw(hass)
    return _deserialize_user(raw)


async def async_add_user_unsupported(hass: HomeAssistant, feature: str, model: Model) -> bool:
    """Add (feature, model) into HA Storage. True if added."""
    feature = (feature or "").strip()
    if not feature:
        return False

    lock = _get_lock(hass)
    async with lock:
        user = await async_load_user_unsupported(hass)
        cur = user.get(feature, [])
        if model in cur:
            return False

        cur.append(model)
        user[feature] = cur
        await _save_raw(hass, _serialize_user(user))
        return True


async def get_combined_unsupported(hass: HomeAssistant) -> dict[str, list[Model]]:
    """Merge base UNSUPPORTED with user storage unsupported."""
    combined = {k: v.copy() for k, v in UNSUPPORTED.items()}

    user_data = await async_load_user_unsupported(hass)
    for feature, models in user_data.items():
        combined.setdefault(feature, [])
        for m in models:
            if m not in combined[feature]:
                combined[feature].append(m)

    return combined


async def is_feature_unsupported(hass: HomeAssistant, feature: str, model: str | Model) -> bool:
    m = parse_model(model)
    if m is None:
        return False
    data = await get_combined_unsupported(hass)
    return m in data.get(feature, [])


async def safe_call_with_support(hass: HomeAssistant, luci, feature: str, coro, model: str | Model):
    """Safely call a Luci API, skipping unsupported features and returning placeholders."""
    if await is_feature_unsupported(hass, feature, model):
        _LOGGER.info("⚠️ [MiWiFi] Skipping unsupported feature '%s' for model '%s'", feature, model)
        return {"error": "unsupported"}

    try:
        result = await coro
        if not result:
            _LOGGER.warning("❌ [MiWiFi] No data returned for '%s' on model '%s'", feature, model)
            return {"error": "no data"}
        return result
    except Exception as e:
        _LOGGER.warning("❌ [MiWiFi] Failed to get '%s' on model '%s': %s", feature, model, e)
        return {"error": "no data"}


# -------------------------
# Base UNSUPPORTED registry
# -------------------------
UNSUPPORTED: dict[str, list[Model]] = {
    "new_status": [
        Model.R1D,
        Model.R2D,
        Model.R1CM,
        Model.R1CL,
        Model.R3P,
        Model.R3D,
        Model.R3L,
        Model.R3A,
        Model.R3,
        Model.R3G,
        Model.R4,
        Model.R4A,
        Model.R4AC,
        Model.R4C,
        Model.R4CM,
        Model.D01,
        Model.RN06,
    ],

    "wifi_config": [
        Model.CR8806,
    ],

    "mac_filter": [
        Model.RM1800,Model.R3600,
    ],

    "mac_filter_info": [
        Model.R3600,
    ],

    "guest_wifi": [
        Model.R3600,
    ],
    
    "per_device_qos": [
        Model.R3600,
    ],

    "device_list": [
        Model.R3600,
    ],
    "qos_info": [],
    "vpn_control": [],
}
