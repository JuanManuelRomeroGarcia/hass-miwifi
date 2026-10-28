"""Scoped RC01 IoT configuration, with preflight and read-back verification."""
from __future__ import annotations

import asyncio
from copy import deepcopy
from html import unescape
import re
import secrets

from .const import DOMAIN, UPDATER
from .exceptions import LuciError


class IotError(Exception):
    """A public error code without router data or credentials."""


def supported(updater) -> bool:
    data = updater.data or {}
    graph = (data.get("topo_graph") or {}).get("graph") or {}
    return (str(data.get("model", "")).lower() == "rc01"
            and graph.get("is_main") is True
            and re.match(r"^1\.1\.56(?:\s|\(|$)", str(data.get("device_sw_version", ""))) is not None)


def _parse(payload) -> dict:
    if not isinstance(payload, dict) or payload.get("code") != 0:
        raise IotError("read_failed")
    basic, advanced = payload.get("basicInfo"), payload.get("advanceInfo")
    if not isinstance(basic, list) or len(basic) != 2 or not isinstance(advanced, dict):
        raise IotError("read_failed")
    if advanced.get("enable") not in (0, 1) or advanced.get("wifi5mode") not in (0, 1):
        raise IotError("unsupported")
    rows = []
    # RC01 1.1.56 getIotWifiDeviceInfo inserts iot_2g then iot_5g.
    for item in basic:
        if not isinstance(item, dict) or any(not isinstance(item.get(key), str) for key in ("ssid", "password", "encryption")):
            raise IotError("read_failed")
        rows.append({"ssid": unescape(item["ssid"]) if item.get("ssidHtmlEncode") in (1, "1") else item["ssid"],
                     "password": item["password"], "encryption": item["encryption"]})
    return {"enabled": bool(advanced["enable"]), "wifi5mode": advanced["wifi5mode"], "bands": rows}


def _ssid(value):
    if not isinstance(value, str):
        raise IotError("invalid")
    try:
        length = len(value.encode("utf-8"))
    except UnicodeError:
        raise IotError("invalid") from None
    if not 1 <= length <= 32 or any(ord(c) < 32 or ord(c) == 127 for c in value):
        raise IotError("invalid")
    return value


class IotManager:
    def __init__(self, hass, entry_id, updater):
        self.hass, self.entry_id, self.updater = hass, entry_id, updater
        self.lock = asyncio.Lock()
        self.snapshot = None
        self.revision = None

    def _current(self):
        stored = self.hass.data.get(DOMAIN, {}).get(self.entry_id, {})
        if stored.get(UPDATER) is not self.updater or not supported(self.updater):
            raise IotError("unsupported")

    async def _read(self):
        self._current()
        try:
            payload = await self.updater.luci.get("xqnetwork/get_iotwifi_info", timeout=4)
        except (Exception, LuciError):
            raise IotError("read_failed") from None
        self._current()
        return _parse(payload)

    def _public(self, current):
        if current != self.snapshot or self.revision is None:
            self.revision = secrets.token_urlsafe(24)
            self.snapshot = deepcopy(current)
        return {"entry_id": self.entry_id, "revision": self.revision,
                "enabled": current["enabled"],
                "writable": all(b["encryption"] == "psk2" for b in current["bands"]),
                "bands": [{"ssid": b["ssid"], "encryption": b["encryption"],
                           "has_password": bool(b["password"]), "password": b["password"]}
                          for b in current["bands"]]}

    async def read(self):
        async with self.lock:
            return self._public(await self._read())

    async def write(self, revision, enabled, bands):
        async with self.lock:
            if not self.snapshot or revision != self.revision:
                raise IotError("stale")
            previous = deepcopy(self.snapshot)
            current = await self._read()
            if current != previous:
                self._public(current)
                raise IotError("stale")
            if not all(b["encryption"] == "psk2" for b in current["bands"]):
                raise IotError("unsupported")
            if not isinstance(enabled, bool) or not isinstance(bands, list) or len(bands) != 2:
                raise IotError("invalid")
            desired = deepcopy(current)
            desired["enabled"] = enabled
            for target, edit in zip(desired["bands"], bands):
                if not isinstance(edit, dict):
                    raise IotError("invalid")
                target["ssid"] = _ssid(edit.get("ssid"))
                password = edit.get("password", "")
                if not isinstance(password, str):
                    raise IotError("invalid")
                if password:
                    if not 8 <= len(password) <= 63 or any(ord(c) < 32 or ord(c) > 126 for c in password):
                        raise IotError("invalid")
                    target["password"] = password
                if not (8 <= len(target["password"]) <= 63 or re.fullmatch(r"[0-9a-fA-F]{64}", target["password"])):
                    raise IotError("invalid")
            if desired == current:
                return self._public(current)
            params = {"enable": int(enabled), "wifi5mode": current["wifi5mode"]}
            for suffix, band in zip(("2g", "5g"), desired["bands"]):
                params.update({"ssid" + suffix: band["ssid"], "password" + suffix: band["password"],
                               "encryption" + suffix: band["encryption"]})
            self._current()
            # The firmware applies this via wifi update. Never retry a write.
            self.revision = None
            try:
                await self.updater.luci.set_iot_wifi(params, timeout=4)
            except (Exception, LuciError):
                raise IotError("unverified") from None
            try:
                after = await self._read()
            except IotError:
                raise IotError("unverified") from None
            if after != desired:
                self._public(after)
                raise IotError("unverified")
            self.snapshot = None
            return self._public(after)


def manager(hass, entry_id):
    stored = hass.data.get(DOMAIN, {}).get(entry_id)
    updater = stored.get(UPDATER) if isinstance(stored, dict) else None
    if updater is None or not supported(updater):
        raise IotError("unsupported")
    cached = stored.get("_iot_manager")
    if cached is None or cached.updater is not updater:
        cached = stored["_iot_manager"] = IotManager(hass, entry_id, updater)
    return cached
