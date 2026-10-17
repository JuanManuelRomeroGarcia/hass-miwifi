"""Bounded, fresh router diagnostics from a fixed read-only API catalogue."""

from __future__ import annotations

import asyncio
from dataclasses import dataclass
from datetime import UTC, datetime
from ipaddress import IPv4Address, IPv6Address
import json
import re
from time import monotonic

from .exceptions import LuciError

REQUEST_SECONDS = 4
ROUTER_SECONDS = 45
CAPTURE_SECONDS = 120
MAX_RESPONSE_BYTES = 1_000_000
MAX_CAPTURE_BYTES = 8_000_000
MAX_ROUTERS = 32


@dataclass(frozen=True)
class ReadQuery:
    key: str
    path: str
    sections: tuple[str, ...]
    parameters: tuple[tuple[str, object], ...] = ()
    main_only: bool = False
    rd08_only: bool = False


# GET alone is not evidence of a read: vendor setters also use GET. Never add a
# setter, reboot, firmware upgrade, login, logout or arbitrary user-supplied URL.
READ_QUERIES = (
    ReadQuery("init_info", "xqsystem/init_info", ("system",)),
    ReadQuery("status", "misystem/status", ("system",)),
    ReadQuery("mode", "xqnetwork/mode", ("network",)),
    ReadQuery("netmode", "xqnetwork/get_netmode", ("network",)),
    ReadQuery("topo_graph", "misystem/topo_graph", ("network",)),
    ReadQuery("new_status", "misystem/newstatus", ("system",)),
    ReadQuery("wan_info", "xqnetwork/wan_info", ("network",), main_only=True),
    ReadQuery("multiwan", "misystem/get_ps_service", ("api",), (("service", "multiwan"),), True, True),
    ReadQuery("wan2", "xqnetwork/wan_info", ("api",), (("wan_name", "WAN2"),), True, True),
    ReadQuery("wan_status", "xqnetwork/get_wan_status", ("api",), main_only=True, rd08_only=True),
    ReadQuery("port_map", "misystem/get_ps_map", ("api",), main_only=True, rd08_only=True),
    ReadQuery("wifi_detail_all", "xqnetwork/wifi_detail_all", ("network", "wifi_config")),
    ReadQuery("wifi_diag_detail_all", "xqnetwork/wifi_diag_detail_all", ("network", "wifi_config")),
    ReadQuery("wifi_ap_signal", "xqnetwork/wifiap_signal", ("network",)),
    ReadQuery("device_list", "misystem/devicelist", ("devices",)),
    ReadQuery("wifi_connect_devices", "xqnetwork/wifi_connect_devices", ("devices",)),
    ReadQuery("mac_filter_info", "xqnetwork/wifi_macfilter_info", ("devices",)),
    ReadQuery("nat_single", "xqnetwork/portforward", ("nat_rules",), (("ftype", 1),), True),
    ReadQuery("nat_ranges", "xqnetwork/portforward", ("nat_rules",), (("ftype", 2),), True),
    ReadQuery("qos_info", "misystem/qos_info", ("qos",), main_only=True),
    ReadQuery("macbind_info", "xqnetwork/macbind_info", ("api",), main_only=True),
    ReadQuery("lan_dhcp", "xqnetwork/lan_dhcp", ("api",), main_only=True),
    ReadQuery("vpn_status", "xqsystem/vpn_status", ("system",)),
    ReadQuery("led", "misystem/led", ("api",)),
    ReadQuery("rom_update", "xqsystem/check_rom_update", ("system",)),
    ReadQuery("flash_permission", "xqsystem/flash_permission", ("system",)),
)


def _queries(data: dict, full: bool, selected: set[str]) -> list[ReadQuery]:
    queries = [q for q in READ_QUERIES if full or selected.intersection(q.sections)]
    if full:
        try:
            adapters = min(4, max(1, int(data.get("wifi_adapter_length") or 2)))
        except (TypeError, ValueError):
            adapters = 2
        queries.extend(ReadQuery(f"channel_{index}", "xqnetwork/avaliable_channels",
                                 ("api",), (("wifiIndex", index),))
                       for index in range(1, adapters + 1))
        if "cb0401" in str(data.get("device_model", "")).lower():
            queries.extend((
                ReadQuery("cpe_detect", "xqdtcustom/cpe_detect", ("api",)),
                ReadQuery("mobile_net_info", "xqdtcustom/get_mobile_net_info", ("api",)),
                ReadQuery("cpe_newstatus", "xqdtcustom/newstatus", ("api",)),
            ))
    return queries


async def async_collect_reads(updaters: list, options: dict, unsupported: dict) -> dict:
    """Return raw reads to the private exporter, which must redact before writing.

    No history replay, mutations, support-registry changes or parallel requests
    on the same session. Authentication uses the loaded integration's client.
    """
    full = bool(options.get("api_diagnostics"))
    selected = {key for key, enabled in options.items() if enabled}
    report = {"schema_version": 1, "routers": [], "limits": {
        "request_seconds": REQUEST_SECONDS, "router_seconds": ROUTER_SECONDS,
        "capture_seconds": CAPTURE_SECONDS, "response_bytes": MAX_RESPONSE_BYTES,
        "capture_response_bytes": MAX_CAPTURE_BYTES,
        "routers": MAX_ROUTERS,
    }}
    if len(updaters) > MAX_ROUTERS:
        report.update(error="router_count_limit", routers_omitted=len(updaters) - MAX_ROUTERS)
    deadline = monotonic() + CAPTURE_SECONDS
    used_bytes = 0
    for index, updater in enumerate(updaters[:MAX_ROUTERS], 1):
        data = updater.data or {}
        main = ((data.get("topo_graph") or {}).get("graph") or {}).get("is_main") is True
        rd08 = str(data.get("model", "")).lower() == "rd08" or str(data.get("device_model", "")).lower() == "xiaomi.router.rd08"
        router = {"router": f"router_{index}", "ip": updater.ip,
                  "mac": data.get("device_mac_address"),
                  "model": str(data.get("model", "unknown")),
                  "device_model": data.get("device_model"), "is_main": main,
                  "firmware": data.get("device_sw_version"),
                  "mode": data.get("mode"), "requests": []}
        router["cached_counts"] = {key: data.get(key) for key in (
            "devices", "devices_lan", "devices_2_4", "devices_5_0",
            "devices_5_0_game", "devices_guest", "devices_iot",
        )}
        report["routers"].append(router)
        router_deadline = min(deadline, monotonic() + ROUTER_SECONDS)
        multiwan_enabled = False
        for query in _queries(data, full, selected):
            record = {"id": query.key, "method": "GET", "path": query.path,
                      "parameters": dict(query.parameters), "response": None}
            router["requests"].append(record)
            reason = None
            if query.main_only and not main:
                reason = "main_router_only"
            elif query.rd08_only and not rd08:
                reason = "unverified_model"
            elif query.key == "wan2" and not multiwan_enabled:
                reason = "multiwan_not_confirmed_enabled"
            elif data.get("model") in unsupported.get(
                "portforward" if query.key.startswith("nat_") else
                "channels" if query.key.startswith("channel_") else query.key, []
            ):
                reason = "unsupported_by_registry"
            if reason:
                record.update(outcome="skipped", reason=reason)
                continue
            remaining = router_deadline - monotonic()
            if remaining <= 0 or used_bytes >= MAX_CAPTURE_BYTES:
                record.update(outcome="skipped", error="capture_limit")
                continue
            started = monotonic()
            record["started_at"] = datetime.now(UTC).isoformat()
            response = None
            try:
                # The fixed catalogue owns both paths and parameters. Never use
                # request parameters as a source of router API paths.
                response = await asyncio.wait_for(
                    updater.luci.get(query.path, dict(query.parameters),
                                     timeout=min(REQUEST_SECONDS, remaining)),
                    timeout=min(REQUEST_SECONDS, remaining),
                )
                record["outcome"] = "ok"
                if query.key == "multiwan" and isinstance(response, dict):
                    service = response.get("multiwan")
                    multiwan_enabled = isinstance(service, dict) and service.get("enable") in (1, "1")
            except TimeoutError:
                record.update(outcome="timeout", error="timeout")
            except (Exception, LuciError) as exc:
                record.update(outcome="error", error=type(exc).__name__)
                response = getattr(exc, "response", None)
            record["duration_ms"] = round((monotonic() - started) * 1000)
            if response is not None:
                if not isinstance(response, (dict, list)):
                    record["response"] = {"body_omitted": "non_json"}
                    continue
                size = len(json.dumps(response, default=str).encode("utf-8"))
                if size > MAX_RESPONSE_BYTES or used_bytes + size > MAX_CAPTURE_BYTES:
                    record.update(outcome="truncated", error="response_size_limit",
                                  response_bytes=size)
                    continue
                used_bytes += size
                record["response"] = response
        router["summary"] = {outcome: sum(r.get("outcome") == outcome for r in router["requests"])
                             for outcome in ("ok", "error", "timeout", "skipped", "truncated")}
    return report


MAC = re.compile(r"(?<![0-9a-f])(?:[0-9a-f]{2}[:-]){5}[0-9a-f]{2}(?![0-9a-f])", re.I)
BARE_MAC = re.compile(r"(?<![0-9a-z])[0-9a-f]{12}(?![0-9a-z])", re.I)
IPV4 = re.compile(r"(?<![\w.])(?:\d{1,3}\.){3}\d{1,3}(?![\w.])")
IPV6 = re.compile(r"(?<![\w:])(?:[0-9a-f]{0,4}:){2,}[0-9a-f:.]*(?:%[a-z0-9_.-]+)?(?![\w:])", re.I)
SECRET_KEY = re.compile(r"password|passwd|pwd|token|stok|cookie|authorization|secret|nonce|privatekey|psk|key$", re.I)
IDENTIFIER_KEYS = {"name", "hostname", "devicename", "routername", "nickname", "oname", "pushname", "originname", "routerid", "serial", "sn", "uuid", "duid", "deviceid", "clientid", "entryid", "displayname", "devname", "username", "imei"}


class DumpRedactor:
    """Always remove credentials; optionally pseudonymize network identifiers.

    One instance serves the complete archive so aliases retain relationships.
    Mappings are neither exported nor persisted.
    """

    def __init__(self, hide_identifiers: bool = True, secrets: tuple = ()):
        self.hide_identifiers = hide_identifiers
        self.secrets = sorted({value for value in secrets if isinstance(value, str) and value}, key=len, reverse=True)
        self.macs: dict[str, str] = {}
        self.ips: dict[str, str] = {}
        self.ipv6: dict[str, str] = {}
        self.names: dict[str, str] = {}
        self.original_macs: set[str] = set()
        self.original_ips: set[str] = set()
        self.original_ipv6: set[str] = set()

    def redact(self, data):
        self._find_secrets(data)
        # Reserve original addresses before generating valid distinct aliases.
        text = json.dumps(data, default=str)
        self.original_macs = {m.group().replace("-", ":").upper() for m in MAC.finditer(text)}
        self.original_macs.update(":".join(m.group()[i:i+2] for i in range(0, 12, 2)).upper()
                                  for m in BARE_MAC.finditer(text))
        self.original_ips = {m.group() for m in IPV4.finditer(text)}
        for match in IPV6.finditer(text):
            try:
                self.original_ipv6.add(str(IPv6Address(match.group())))
            except ValueError:
                pass
        return self._walk(data)

    def _find_secrets(self, value, private=False):
        if isinstance(value, dict):
            for key, child in value.items():
                normalized = re.sub(r"[^a-z0-9]", "", str(key).lower())
                self._find_secrets(child, private or bool(SECRET_KEY.search(normalized)))
        elif isinstance(value, (list, tuple)):
            for child in value:
                self._find_secrets(child, private)
        elif private and isinstance(value, str) and value and value not in self.secrets:
            self.secrets.append(value)
            self.secrets.sort(key=len, reverse=True)

    def _mac(self, match):
        value = match.group().replace("-", ":").upper()
        if ":" not in value:
            value = ":".join(value[i:i+2] for i in range(0, 12, 2))
        if value not in self.macs:
            index = len(self.macs) + 1
            while True:
                candidate = "02:FE:" + ":".join(f"{part:02X}" for part in index.to_bytes(4, "big"))
                if candidate not in self.original_macs and candidate not in self.macs.values():
                    break
                index += 1
            self.macs[value] = candidate
        return self.macs[value]

    def _ip(self, match):
        value = match.group()
        try:
            IPv4Address(value)
        except ValueError:
            return value
        if value not in self.ips:
            index = len(self.ips) + 1
            while True:
                candidate = str(IPv4Address(int(IPv4Address("198.18.0.0")) + index))
                if candidate not in self.original_ips and candidate not in self.ips.values():
                    break
                index += 1
            self.ips[value] = candidate
        return self.ips[value]

    def _text(self, value: str, mask_identifiers: bool = True) -> str:
        for secret in self.secrets:
            value = value.replace(secret, "REDACTED")
        value = re.sub(r"(?i)(;stok=|[?&](?:token|password|pwd|key|nonce)=)[^/\s&#\"<>]+", r"\1REDACTED", value)
        if self.hide_identifiers and mask_identifiers:
            value = MAC.sub(self._mac, value)
            value = BARE_MAC.sub(self._mac, value)
            value = IPV6.sub(self._ip6, value)
            value = IPV4.sub(self._ip, value)
        return value

    def _ip6(self, match):
        try:
            value = str(IPv6Address(match.group()))
        except ValueError:
            return match.group()
        if value not in self.ipv6:
            index = len(self.ipv6) + 1
            while True:
                candidate = str(IPv6Address(int(IPv6Address("2001:db8:ffff::")) + index))
                if candidate not in self.original_ipv6 and candidate not in self.ipv6.values():
                    break
                index += 1
            self.ipv6[value] = candidate
        return self.ipv6[value]

    def _walk(self, value, key=""):
        normalized = re.sub(r"[^a-z0-9]", "", key.lower())
        if SECRET_KEY.search(normalized) or normalized in {"key", "wifikey"}:
            return "REDACTED"
        if isinstance(value, dict):
            return {self._text(str(k)): self._walk(v, str(k)) for k, v in value.items()}
        if isinstance(value, (list, tuple)):
            return [self._walk(item, key) for item in value]
        if isinstance(value, str):
            if normalized in {"mask", "netmask", "subnetmask", "lanmask", "wanmask", "version", "romversion", "fwversion", "firmwareversion"}:
                return self._text(value, mask_identifiers=False)
            if self.hide_identifiers and (MAC.fullmatch(value) or IPV4.fullmatch(value) or IPV6.fullmatch(value)):
                return self._text(value)
            if self.hide_identifiers and ("mac" in normalized or normalized == "bssid") and re.fullmatch(r"[0-9a-fA-F]{12}", value):
                return self._text(":".join(value[i:i+2] for i in range(0, 12, 2)))
            if self.hide_identifiers and (normalized in IDENTIFIER_KEYS or "ssid" in normalized) and value:
                if re.fullmatch(r"(?:WAN|LAN)\d*", value, re.I):
                    return value
                if value not in self.names:
                    self.names[value] = f"name_{len(self.names) + 1}"
                return self.names[value]
            return self._text(value)
        return value
