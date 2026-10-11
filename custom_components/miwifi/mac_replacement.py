"""Opt-in replacement of old MACs for clients with confirmed unique names."""

import asyncio
import re
from time import monotonic

from homeassistant.helpers import device_registry as dr, entity_registry as er
from homeassistant.helpers.storage import Store

from .const import DOMAIN
from .purged_clients import get_purged_clients, _confirmed_online


def _mac(value):
    value = str(value or "").strip().upper()
    return value if re.fullmatch(r"(?:[0-9A-F]{2}:){5}[0-9A-F]{2}", value) else None


class MacReplacement:
    """Configured identity aliases and fresh complete client lists from each node."""

    def __init__(self, hass):
        self.hass = hass
        self._store = Store(hass, 1, "miwifi/mac_replacement")
        self._lock = asyncio.Lock()
        self._loaded = False
        self._groups = {}
        self._reports = {}

    async def _load(self):
        if not self._loaded:
            self._groups = await self._store.async_load() or {}
            self._loaded = True

    async def async_configure(self, clients, known_clients):
        """Replace the explicit configuration; an empty object disables it."""
        async with self._lock:
            await self._load()
            groups = {}
            used = set()
            for key, names in clients.items():
                aliases = sorted({name.strip().casefold() for name in names})
                if not aliases or "" in aliases or used.intersection(aliases):
                    raise ValueError("Each client needs unique, non-empty name aliases")
                used.update(aliases)
                groups[key] = {"names": aliases, "macs": list(self._groups.get(key, {}).get("macs", []))}
            # Unavailable clients may remain only in HA's registry after roaming.
            # Use integration-provided names, never a user's display-name override.
            registered_clients = []
            registry = er.async_get(self.hass)
            for device in dr.async_get(self.hass).devices.values():
                trackers = [entry for entry in er.async_entries_for_device(
                    registry, device.id, include_disabled_entities=True
                ) if entry.platform == DOMAIN and entry.domain == "device_tracker"]
                for domain, identifier in device.identifiers:
                    mac = _mac(identifier) if domain == DOMAIN else None
                    if not mac:
                        continue
                    pattern = re.compile(r"^miwifi-(?:.*-)?" + re.escape(mac) + r"(?:_\d+)?$", re.I)
                    matching = [entry for entry in trackers if pattern.fullmatch(entry.unique_id)]
                    if not matching:
                        continue
                    for name in [device.name, *(entry.original_name for entry in matching)]:
                        if name:
                            registered_clients.append({"name": name, "mac": mac})
            for row in [*known_clients, *registered_clients]:
                name = str(row.get("name") or "").strip().casefold()
                mac = _mac(row.get("mac"))
                for group in groups.values():
                    if mac and name in group["names"] and mac not in group["macs"]:
                        group["macs"].append(mac)
            await self._store.async_save(groups)
            self._groups = groups
            self._reports = {}

    async def async_configuration(self):
        """Return an independent copy of configured aliases for the settings UI."""
        async with self._lock:
            await self._load()
            return {key: list(group["names"]) for key, group in self._groups.items()}

    async def async_candidates(self, source_ip, clients, updaters):
        """Retire only non-active MACs when exactly one MAC identifies the client."""
        async with self._lock:
            await self._load()
            if not self._groups:
                return set()
            active, unknown = set(), set()
            changed = False
            for row in clients:
                if not isinstance(row, dict):
                    continue
                try:
                    if int(row.get("isap", 0) or 0) > 0:
                        continue
                except (TypeError, ValueError):
                    continue
                mac = _mac(row.get("mac"))
                if not mac:
                    continue
                name = str(row.get("name") or "").strip().casefold()
                for group in self._groups.values():
                    if name not in group["names"] and mac not in group["macs"]:
                        continue
                    if mac in group["macs"] and name and name not in group["names"]:
                        if any(name in other["names"] for other in self._groups.values() if other is not group):
                            unknown.update(group["macs"])
                            continue
                        if _confirmed_online(row):
                            group["names"].append(name)
                            changed = True
                    if mac not in group["macs"]:
                        group["macs"].append(mac)
                        changed = True
                    if _confirmed_online(row):
                        active.add(mac)
                    else:
                        try:
                            flags = ([int(row["online"])] if "online" in row else []) + [
                                int(address["active"]) for address in row.get("ip", []) or []
                                if isinstance(address, dict) and "active" in address
                            ]
                            if not flags or any(flag not in (0, 1) for flag in flags):
                                unknown.add(mac)
                        except (TypeError, ValueError):
                            unknown.add(mac)
            if changed:
                await self._store.async_save(self._groups)
            self._reports[source_ip] = (monotonic(), active, unknown)
            sources = {updater.ip: max(60, 3 * updater._scan_interval + updater.timeout) for updater in updaters}
            now = monotonic()
            if not sources or any(
                ip not in self._reports or now - self._reports[ip][0] > ttl
                for ip, ttl in sources.items()
            ):
                return set()
            active = set().union(*(self._reports[ip][1] for ip in sources))
            unknown = set().union(*(self._reports[ip][2] for ip in sources))
            candidates = set()
            for group in self._groups.values():
                macs = set(group["macs"])
                if len(macs & active) != 1:
                    continue
                for mac in macs - active - unknown:
                    if not await get_purged_clients(self.hass).async_blocked(mac):
                        candidates.add(mac)
            return candidates


def get_mac_replacement(hass):
    key = "miwifi_mac_replacement"
    if key not in hass.data:
        hass.data[key] = MacReplacement(hass)
    return hass.data[key]


async def async_retire_macs(hass, macs, updaters):
    """Remove only MiWiFi client entities for explicitly associated old MACs."""
    if not macs:
        return
    from .helper import device_config_entry_ids, device_registry_rows

    registry, devices = er.async_get(hass), dr.async_get(hass)
    targets = []
    touched = set()
    for mac in macs:
        tracker = re.compile(r"^miwifi-(?:.*-)?" + re.escape(mac) + r"(?:_\d+)?$", re.I)
        sensor = f"miwifi-dev-{mac.lower()}-"
        for entry in list(registry.entities.values()):
            if entry.platform == DOMAIN and (
                (entry.domain == "device_tracker" and tracker.fullmatch(entry.unique_id))
                or (entry.domain == "sensor" and entry.unique_id.lower().startswith(sensor))
            ):
                targets.append(entry.entity_id)
                if entry.device_id:
                    touched.add(entry.device_id)
        for row in device_registry_rows(devices, identifiers={(DOMAIN, mac.lower()), (DOMAIN, mac)}):
            touched.add(row.id)
    await get_purged_clients(hass).async_mark(macs)
    for updater in updaters:
        await updater.async_purge_clients(macs)
    for entity_id in targets:
        if registry.async_get(entity_id):
            registry.async_remove(entity_id)
    for device_id in touched:
        device = devices.async_get(device_id)
        if device is not None and len(device_config_entry_ids(device)) == 1 and not er.async_entries_for_device(
            registry, device_id, include_disabled_entities=True
        ):
            devices.async_remove_device(device_id)
