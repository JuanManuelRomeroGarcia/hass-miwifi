"""Auto-purge helper functions."""

from __future__ import annotations

import logging
from datetime import timedelta, time as dtime
from typing import Any, Dict

from homeassistant.core import HomeAssistant
from homeassistant.config_entries import ConfigEntry
from homeassistant.helpers.event import async_track_point_in_time, async_call_later
from homeassistant.helpers.storage import Store
from homeassistant.util import dt as dt_util

from . import const as C

_LOGGER = logging.getLogger(__name__)

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

    IMPORTANT FIX:
    - Avoid running purge on every HA restart/reload.
    - The previous implementation executed a "kickoff" 60s after startup with apply=True.
    """

    data = hass.data.setdefault(DOMAIN, {})
    owner_id = data.get(AUTO_PURGE_OWNER)
    if owner_id and owner_id != entry.entry_id and data.get(AUTO_PURGE_UNSUB):
        # Ya hay otro dueño con scheduler activo -> no reprogramar
        return

    cancel_auto_purge(hass, entry_id=owner_id)
    data[AUTO_PURGE_OWNER] = entry.entry_id

    async def _current_cfg() -> tuple[dtime, int, str]:
        """Lee hora/frecuencia del store global (con defaults).

        `every_days == 0` means the scheduled purge is off, so the value has to
        survive the read. `or DEFAULT` treated it as missing and handed back the
        default instead, which turned "never" into "every day" - the opposite of
        what the user asked for, on a job that deletes registry rows unattended.
        """

        s = await _load(hass)
        at_str = str(s.get("at") or DEFAULT_AUTO_PURGE_AT)

        raw = s.get("every_days")
        try:
            every_days = DEFAULT_AUTO_PURGE_EVERY_DAYS if raw is None else int(raw)
        except (TypeError, ValueError):
            every_days = DEFAULT_AUTO_PURGE_EVERY_DAYS
        if every_days < 0:
            every_days = DEFAULT_AUTO_PURGE_EVERY_DAYS

        return _parse_hhmm(at_str), every_days, at_str

    def _parse_iso(dt_str: str | None):
        if not dt_str:
            return None
        try:
            return dt_util.parse_datetime(dt_str)
        except Exception:
            return None

    async def _job(_now=None):
        # 1) Reprogramar siguiente ejecución
        now = dt_util.now()
        at_time, every_days, at_str = await _current_cfg()

        # Turned off while a run was already pending: do not purge, and do not
        # queue another one.
        if every_days == 0:
            _LOGGER.debug(
                "[MiWiFi] Scheduled purge is disabled (every_days=0); nothing scheduled"
            )
            return

        next_dt = _next_run(now, at_time, every_days)
        data[AUTO_PURGE_UNSUB] = async_track_point_in_time(hass, _job, next_dt)

        # 2) Llamar al servicio de purga (ejecución normal programada)
        #
        # This runs unattended with apply=True and nobody reads a preview first,
        # so it takes the conservative end of every option the manual call
        # leaves open:
        #
        # - only_randomized: a stable MAC belongs to a device that can come back,
        #   and its tracker carries history worth keeping. A randomised MAC that
        #   goes away never returns under the same address, which is what makes
        #   it safe to collect automatically.
        # - include_orphans_without_age: an unknown age is a question, not an
        #   answer. A restart leaves every tracker the integration did not
        #   recreate undatable - including clients that are connected - so
        #   deleting on "don't know" deletes live devices once a week.
        #
        # A user who wants the wider sweep still has the manual service, where a
        # dry run is one click away.
        params = {
            "days": int(every_days),
            "only_randomized": True,
            "include_orphans": True,
            "include_orphans_without_age": False,
            "verbose": False,
            "apply": True,
        }

        ok = True
        try:
            # Nota: async_call devuelve None; el servicio debe gestionar notificación/resultado internamente.
            await hass.services.async_call(DOMAIN, "purge_inactive_devices", params, blocking=True)
        except Exception:
            ok = False

        # 3) Guardar histórico en el store
        sdata = await _load(hass)
        hist = (sdata.get("history") or [])[-29:]
        hist.append({"at": now.isoformat(), "ok": bool(ok)})

        sdata.update(
            {
                "last_run": now.isoformat(),
                "last_ok": bool(ok),
                "last_params": params,
                "next_due": next_dt.isoformat(),
                "every_days": every_days,
                "at": at_str,
                "owner": entry.entry_id,
                "history": hist,
            }
        )
        await _save(hass, sdata)

    async def _prime():
        # Programa la próxima ejecución según configuración
        at_time, every_days, at_str = await _current_cfg()
        now = dt_util.now()

        if every_days == 0:
            s0 = await _load(hass)
            s0.update({"next_due": None, "every_days": 0, "at": at_str, "owner": entry.entry_id})
            await _save(hass, s0)
            _LOGGER.debug(
                "[MiWiFi] Scheduled purge is disabled (every_days=0); no run scheduled"
            )
            return

        first = _next_run(now, at_time, every_days)
        data[AUTO_PURGE_UNSUB] = async_track_point_in_time(hass, _job, first)

        # Kickoff seguro:
        # - SOLO si kickoff=True
        # - y si nunca se ha ejecutado (last_run ausente) o está vencido (next_due <= now)
        # - y NUNCA ejecuta en cada reinicio si ya hay last_run reciente
        if kickoff:
            s = await _load(hass)
            last_run = _parse_iso(s.get("last_run"))
            next_due = _parse_iso(s.get("next_due"))

            should_kick = False
            if last_run is None:
                should_kick = True
            elif next_due is not None and next_due <= now:
                should_kick = True

            # Además, si la última ejecución fue “hoy” (o dentro de la ventana), no kick.
            if last_run is not None:
                try:
                    if (now - last_run) < timedelta(hours=12):
                        should_kick = False
                except Exception:
                    pass

            if should_kick:
                # Ejecuta una sola vez, diferida, sin depender del restart continuo
                data[AUTO_PURGE_FIRST] = async_call_later(hass, 60, _job)

        # Persistimos configuración actual para visibilidad
        s2 = await _load(hass)
        s2.update(
            {
                "next_due": first.isoformat(),
                "every_days": every_days,
                "at": at_str,
                "owner": entry.entry_id,
            }
        )
        await _save(hass, s2)

    hass.async_create_task(_prime())
