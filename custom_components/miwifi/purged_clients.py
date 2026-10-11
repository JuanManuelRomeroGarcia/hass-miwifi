"""Remember purged clients until a router confirms they are online again."""

import asyncio

from homeassistant.helpers.storage import Store


class PurgedClients:
    """One persistent MAC set shared by all configured nodes."""

    def __init__(self, hass):
        self._store = Store(hass, 1, "miwifi/purged_clients")
        self._lock = asyncio.Lock()
        self._loaded = False
        self._macs: set[str] = set()

    async def _load(self):
        if not self._loaded:
            data = await self._store.async_load()
            self._macs = {mac.strip().upper() for mac in data or [] if isinstance(mac, str)}
            self._loaded = True

    async def async_mark(self, macs):
        """Persist suppression before deleting registry rows or cached clients."""
        async with self._lock:
            await self._load()
            updated = self._macs | {mac.strip().upper() for mac in macs}
            await self._store.async_save(sorted(updated))
            self._macs = updated

    async def async_blocked(self, mac, reported=None):
        """Stored snapshots cannot release suppression; confirmed online data can."""
        async with self._lock:
            await self._load()
            mac = mac.strip().upper()
            if mac not in self._macs:
                return False
            if reported is None or not _confirmed_online(reported):
                return True
            updated = self._macs - {mac}
            await self._store.async_save(sorted(updated))
            self._macs = updated
            return False


def _confirmed_online(device):
    """Require explicit evidence rather than defaulting a missing flag to online."""
    try:
        addresses = device.get("ip") or []
        active = [address["active"] for address in addresses if isinstance(address, dict) and "active" in address]
        if "online" in device:
            return int(device["online"]) == 1 and (not active or any(int(flag) == 1 for flag in active))
        return any(int(flag) == 1 for flag in active)
    except (TypeError, ValueError, IndexError, KeyError):
        return False


def get_purged_clients(hass):
    """Keep the shared state outside the integration's per-entry map."""
    key = "miwifi_purged_clients"
    if key not in hass.data:
        hass.data[key] = PurgedClients(hass)
    return hass.data[key]
