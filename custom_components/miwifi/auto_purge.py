"""Auto-purge helper functions."""

from __future__ import annotations

from datetime import timedelta, time as dtime
from typing import Any, Dict

from homeassistant.core import HomeAssistant
from homeassistant.config_entries import ConfigEntry
from homeassistant.helpers.event import async_track_point_in_time, async_call_later
from homeassistant.helpers.storage import Store
from homeassistant.util import dt as dt_util

from . import const as C

DOMAIN = C.DOMAIN
STORAGE_VERSION = C.STORAGE_VERSION

CONF_AUTO_PURGE_EVERY_DAYS = getattr(C, "CONF_AUTO_PURGE_EVERY_DAYS", "auto_purge_every_days")
DEFAULT_AUTO_PURGE_EVERY_DAYS = getattr(C, "DEFAULT_AUTO_PURGE_EVERY_DAYS", 1)

CONF_AUTO_PURGE_AT = getattr(C, "CONF_AUTO_PURGE_AT", "auto_purge_at")
DEFAULT_AUTO_PURGE_AT = getattr(C, "DEFAULT_AUTO_PURGE_AT", "04:10")

STORE_AUTO_PURGE = getattr(C, "STORE_AUTO_PURGE", "auto_purge.json")

AUTO_PURGE_UNSUB = "_auto_purge_global_unsub"
AUTO_PURGE_FIRST = "_auto_purge_global_first"
AUTO_PURGE_OWNER = "_auto_purge_owner"  


def _store(hass: HomeAssistant) -> Store:
    return Store(hass, STORAGE_VERSION, f"{DOMAIN}/{STORE_AUTO_PURGE}")


def _parse_hhmm(v: str) -> dtime:
    """Accept 'HH:MM' o 'HH:MM:SS'."""
    try:
        parts = str(v).split(":")
        hh = int(parts[0])
        mm = int(parts[1]) if len(parts) > 1 else 0
        ss = int(parts[2]) if len(parts) > 2 else 0
        return dtime(hour=hh, minute=mm, second=ss)
    except Exception:
        hh, mm = DEFAULT_AUTO_PURGE_AT.split(":")[0:2]
        return dtime(hour=int(hh), minute=int(mm), second=0)


def _next_run(now, at: dtime, every_days: int):
    if every_days < 1:
        every_days = 1
    cand = now.replace(hour=at.hour, minute=at.minute, second=at.second, microsecond=0)
    if cand <= now:
        cand += timedelta(days=every_days)
    return cand


async def _load(hass: HomeAssistant) -> Dict[str, Any]:
    return await _store(hass).async_load() or {}


async def _save(hass: HomeAssistant, data: Dict[str, Any]) -> None:
    await _store(hass).async_save(data)


def cancel_auto_purge(hass: HomeAssistant, entry_id: str | None = None) -> None:
    """Cancels scheduled tasks; clears owner if matched."""
    data = hass.data.setdefault(DOMAIN, {})
    for key in (AUTO_PURGE_UNSUB, AUTO_PURGE_FIRST):
        unsub = data.pop(key, None)
        if callable(unsub):
            try:
                unsub()
            except Exception:
                pass
    if entry_id and data.get(AUTO_PURGE_OWNER) == entry_id:
        data.pop(AUTO_PURGE_OWNER, None)


def schedule_auto_purge(hass: HomeAssistant, entry: ConfigEntry, kickoff: bool = True) -> None:
    """
    GLOBAL Scheduler (single). ALWAYS reads the GLOBAL configuration from the store:
    - every_days: frequency (N)
    - at: time "HH:MM" or "HH:MM:SS"
    • Inactivity threshold = frequency → 'days' passed to the service will be N.
    """
    data = hass.data.setdefault(DOMAIN, {})
    owner_id = data.get(AUTO_PURGE_OWNER)
    if owner_id and owner_id != entry.entry_id and data.get(AUTO_PURGE_UNSUB):
        # Ya hay otro dueño con scheduler activo -> no reprogramar
        return

   
    cancel_auto_purge(hass, entry_id=owner_id)
    data[AUTO_PURGE_OWNER] = entry.entry_id

    async def _current_cfg() -> tuple[dtime, int, str]:
        """Lee hora/frecuencia del store global (con defaults)."""
        s = await _load(hass)
        at_str = str(s.get("at") or DEFAULT_AUTO_PURGE_AT)
        every_days = int(s.get("every_days") or DEFAULT_AUTO_PURGE_EVERY_DAYS)
        return _parse_hhmm(at_str), every_days, at_str

    async def _job(_now=None):
        # 1) Reprogramar siguiente ejecución
        now = dt_util.now()
        at_time, every_days, at_str = await _current_cfg()
        next_dt = _next_run(now, at_time, every_days)
        data[AUTO_PURGE_UNSUB] = async_track_point_in_time(hass, _job, next_dt)

        # 2) Llamar al servicio de purga con parámetros compatibles
        #    (only_randomized=False => purga TODOS, no solo MAC aleatorias)
        params = {
            "days": int(every_days),
            "only_randomized": False,
            "include_orphans": True,
            "include_orphans_without_age": True, 
            "verbose": False,
            "apply": True,
        }

        ok, result = True, None
        try:
            result = await hass.services.async_call(
                DOMAIN, "purge_inactive_devices", params, blocking=True
            )
        except Exception:
            ok = False

        # 3) Guardar histórico en el store
        sdata = await _load(hass)
        hist = (sdata.get("history") or [])[-29:]
        rec = {"at": now.isoformat(), "ok": bool(ok)}
        if isinstance(result, dict):
            rec.update({"entities": result.get("entities"), "devices": result.get("devices")})
        hist.append(rec)

        sdata.update({
            "last_run": now.isoformat(),
            "last_ok": bool(ok),
            "last_params": params,
            "last_result": result if isinstance(result, dict) else None,
            "next_due": next_dt.isoformat(),
            "every_days": every_days,
            "at": at_str,
            "owner": entry.entry_id,
        })
        await _save(hass, sdata)

    async def _prime():
        # Programa la primera ejecución y opcionalmente un kickoff rápido
        at_time, every_days, _ = await _current_cfg()
        first = _next_run(dt_util.now(), at_time, every_days)
        data[AUTO_PURGE_UNSUB] = async_track_point_in_time(hass, _job, first)
        if kickoff:
            data[AUTO_PURGE_FIRST] = async_call_later(hass, 60, _job)

    hass.async_create_task(_prime())
