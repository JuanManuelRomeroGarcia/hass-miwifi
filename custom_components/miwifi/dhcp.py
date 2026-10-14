"""On-demand static DHCP management, isolated from coordinator client polling."""
from __future__ import annotations

import asyncio
import hashlib
import ipaddress
import json
import re

from .exceptions import LuciError

# Add profiles only after confirming native request shapes and incremental CRUD.
# AX1800 / stock 3.0.34 (#314) is still awaiting the contributor's captures.
WRITE_PROFILES = frozenset({("RC01", "1.1.56")})


class DhcpError(Exception):
    """A stable, translated UI error code, never a raw router response."""


def normalize_mac(value: str) -> str:
    """Accept a single unicast MAC, including locally administered addresses."""
    if not isinstance(value, str) or not re.fullmatch(r"[0-9a-fA-F]{2}([:-][0-9a-fA-F]{2}){5}", value.strip()):
        raise DhcpError("invalid_mac")
    mac = value.strip().replace("-", ":").upper()
    if mac == "00:00:00:00:00:00" or int(mac[:2], 16) & 1:
        raise DhcpError("invalid_mac")
    return mac


def _ipv4(value) -> ipaddress.IPv4Address:
    if not isinstance(value, str):
        raise DhcpError("invalid_ip")
    try:
        return ipaddress.IPv4Address(value)
    except (ValueError, TypeError, ipaddress.AddressValueError) as err:
        raise DhcpError("invalid_ip") from err


def _name(value) -> str:
    if not isinstance(value, str) or len(value.encode("utf-8")) > 128 or any(ord(char) < 32 or ord(char) == 127 for char in value):
        raise DhcpError("invalid_name")
    return value


def _rows(raw: dict, key: str, *, clients: bool = False) -> list[dict]:
    if not isinstance(raw, dict) or raw.get("code") != 0 or not isinstance(raw.get(key), list):
        raise DhcpError("invalid_response")
    rows, used_macs, used_ips = [], set(), set()
    for item in raw[key]:
        if not isinstance(item, dict):
            raise DhcpError("invalid_response")
        try:
            mac = normalize_mac(item.get("mac"))
            ip = item.get("ip")
            # Native candidate lists also contain offline clients without an IP.
            ip = "" if clients and ip in (None, "", "0.0.0.0") else str(_ipv4(ip))
            name = _name(item.get("name", ""))
        except DhcpError as err:
            raise DhcpError("invalid_response") from err
        if mac in used_macs or (not clients and ip in used_ips):
            raise DhcpError("invalid_response")
        used_macs.add(mac)
        used_ips.add(ip)
        rows.append({"mac": mac, "ip": ip, "name": name})
    return sorted(rows, key=lambda row: row["mac"])


class DhcpManager:
    """Serialize operations for one loaded updater and reject stale editors."""

    def __init__(self, luci, is_current=lambda: True):
        self.luci = luci
        self.is_current = is_current
        self.lock = asyncio.Lock()

    def _check_current(self):
        if not self.is_current():
            raise DhcpError("router_changed")

    async def _snapshot(self) -> dict:
        self._check_current()
        try:
            bindings = await self.luci.dhcp_bindings()
            settings = await self.luci.dhcp_settings()
            identity = await self.luci.init_info()
            self._check_current()
            rows = _rows(bindings, "list")
            clients = _rows(bindings, "devicelist", clients=True)
            if not isinstance(settings, dict) or settings.get("code") != 0:
                raise DhcpError("invalid_response")
            info = settings.get("info")
            if not isinstance(info, dict) or str(info.get("ignore")) not in {"0", "1"}:
                raise DhcpError("invalid_response")
            addresses = info.get("lanIp")
            if not isinstance(addresses, list) or not addresses or not isinstance(addresses[0], dict):
                raise DhcpError("invalid_response")
            router_ip = str(_ipv4(addresses[0].get("ip")))
            mask = addresses[0].get("mask") or bindings.get("lanmask")
            if not isinstance(mask, str):
                raise DhcpError("invalid_response")
            subnet = ipaddress.IPv4Network(f"{router_ip}/{mask}", strict=False)
            if not isinstance(identity, dict) or identity.get("code") != 0:
                raise DhcpError("invalid_response")
            profile = (str(identity.get("hardware", "")).upper(), str(identity.get("romversion", "")))
            enabled = str(info["ignore"]) == "0"
            snapshot = {"bindings": rows, "clients": clients, "router_ip": router_ip,
                        "subnet": str(subnet), "enabled": enabled,
                        "model": profile[0], "firmware": profile[1],
                        "writable": enabled and profile in WRITE_PROFILES}
            # Candidates can roam while the editor is open. Revalidate them at
            # write time, but don't make unrelated client activity stale an edit.
            stable = {key: value for key, value in snapshot.items() if key != "clients"}
            snapshot["revision"] = hashlib.sha256(json.dumps(stable, sort_keys=True).encode()).hexdigest()
            return snapshot
        except DhcpError:
            raise
        except (LuciError, Exception) as err:
            raise DhcpError("read_failed") from err

    async def async_read(self) -> dict:
        async with self.lock:
            return await self._snapshot()

    async def async_write(self, action: str, revision: str, mac: str, ip: str = "", name: str = "") -> dict:
        """Perform one explicit upsert/delete, then verify all unrelated records."""
        if action not in {"add", "edit", "delete"}:
            raise DhcpError("invalid_action")
        mac = normalize_mac(mac)
        if action != "delete":
            ip, name = str(_ipv4(ip.strip())), _name(name).strip()
        async with self.lock:
            before = await self._snapshot()
            if revision != before["revision"]:
                raise DhcpError("stale")
            if not before["enabled"]:
                raise DhcpError("disabled")
            if not before["writable"]:
                raise DhcpError("unsupported")
            previous = {row["mac"]: row for row in before["bindings"]}
            if (action == "add" and mac in previous) or (action != "add" and mac not in previous):
                raise DhcpError("stale")
            if action != "delete":
                address = _ipv4(ip)
                subnet = ipaddress.IPv4Network(before["subnet"])
                if address not in subnet or address in (subnet.network_address, subnet.broadcast_address, _ipv4(before["router_ip"])):
                    raise DhcpError("invalid_ip")
                if any(row["ip"] == ip and row["mac"] != mac for row in before["bindings"] + before["clients"]):
                    raise DhcpError("conflict")
            self._check_current()
            expected = dict(previous)
            try:
                if action == "delete":
                    await self.luci.dhcp_unbind(mac)
                    expected.pop(mac)
                else:
                    row = {"mac": mac, "ip": ip, "name": name}
                    await self.luci.dhcp_bind(row)
                    expected[mac] = row
                after = await self._snapshot()
                if {row["mac"]: row for row in after["bindings"]} != expected:
                    raise DhcpError("unverified")
                return after
            except (LuciError, Exception) as err:
                # Neither a timeout nor a readback failure proves the POST did
                # not apply. No retry/automatic rollback over concurrent changes.
                raise DhcpError("unverified") from err


def get_manager(hass, entry_id: str) -> DhcpManager:
    """Resolve an explicit loaded entry; never fall back to a different router."""
    from .const import DOMAIN, UPDATER

    def current():
        entry = hass.data.get(DOMAIN, {}).get(entry_id)
        return entry.get(UPDATER) if isinstance(entry, dict) else None

    updater = current()
    if updater is None:
        raise DhcpError("router_changed")
    manager = getattr(updater, "_dhcp_manager", None)
    if manager is None:
        manager = DhcpManager(updater.luci, lambda: current() is updater)
        updater._dhcp_manager = manager
    return manager
