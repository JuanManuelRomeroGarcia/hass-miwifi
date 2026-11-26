#!/usr/bin/env python3
"""Capture three LuCI client lists with allowlisted, pseudonymized output.

Authentication creates a router session. All subsequent API calls are reads.
No requests are made on import; this tool is separate from the integration.
"""
from __future__ import annotations

import asyncio
from datetime import datetime, timezone
import getpass
import hashlib
import hmac
import importlib
import importlib.util
import ipaddress
import json
import logging
from pathlib import Path
import re
import secrets
import sys
import time
import types
from enum import StrEnum
import warnings

ENDPOINTS = ("misystem/devicelist", "misystem/device_list", "xqnetwork/wifi_connect_devices")
ROLES = ("main", "r3", "r4")
MAC = re.compile(r"^[0-9a-fA-F]{2}(?:(?P<sep>[:-])[0-9a-fA-F]{2})(?:(?P=sep)[0-9a-fA-F]{2}){4}$")
PRIVATE_NETWORKS = tuple(ipaddress.ip_network(network) for network in
                         ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"))


def private_ipv4(value):
    """Accept only local RFC 1918 IPv4 addresses."""
    address = ipaddress.ip_address(value.strip())
    if address.version != 4 or not any(address in network for network in PRIVATE_NETWORKS):
        raise ValueError("invalid local address")
    return str(address)


class Capture:
    def __init__(self):
        self.key = secrets.token_bytes(32)
        self.start = time.monotonic()
        self.report = {"schema": 1, "alias_scope": "this capture only", "router_aliases": {}, "targets": {}, "observations": []}

    def alias(self, kind, value):
        digest = hmac.new(self.key, (kind + ":" + value).encode(), hashlib.sha256).hexdigest()[:20]
        return kind + "_" + digest

    def mac_alias(self, value):
        if not isinstance(value, str) or not MAC.fullmatch(value.strip()):
            return None
        return self.alias("mac", value.strip().upper().replace("-", ":"))

    def register_router(self, role, macs):
        if role not in ROLES:
            raise ValueError("invalid role")
        aliases = [self.mac_alias(mac) for mac in macs]
        if any(alias is None for alias in aliases):
            raise ValueError("invalid router MAC")
        self.report["router_aliases"][role] = aliases

    def register_target(self, role, mac):
        if role not in ("ethernet", "wifi_stable", "roaming"):
            raise ValueError("invalid client role")
        alias = self.mac_alias(mac)
        if alias is None:
            raise ValueError("invalid client MAC")
        self.report["targets"][role] = alias

    def client(self, row):
        result = {"mac": self.mac_alias(row.get("mac"))}
        if "parent" not in row:
            parent = {"state": "missing"}
        elif row["parent"] is None:
            parent = {"state": "null"}
        elif row["parent"] == "":
            parent = {"state": "empty"}
        elif value := self.mac_alias(row["parent"]):
            parent = {"state": "value", "mac": value}
        else:
            parent = {"state": "invalid"}
        result["parent"] = parent
        for key in ("online", "type", "isap", "wifiIndex", "active"):
            value = row.get(key)
            if isinstance(value, (int, bool)) and -1 <= int(value) <= 65535:
                result[key] = int(value)
            elif isinstance(value, str) and re.fullmatch(r"[0-9]{1,5}", value):
                result[key] = int(value)
        for key in ("interface", "ifname", "connection"):
            value = row.get(key)
            if isinstance(value, str) and value and len(value) <= 128:
                result[key] = self.alias("interface", value)
            elif isinstance(value, int) and 0 <= value <= 65535:
                result[key] = value
        addresses = row.get("ip")
        if isinstance(addresses, list):
            result["ip_activity"] = [self.client_activity(item) for item in addresses[:64] if isinstance(item, dict)]
        return result

    @staticmethod
    def client_activity(row):
        value = row.get("active")
        return {"active": int(value)} if str(value) in ("0", "1") else {}

    async def sample(self, observer, client, phase):
        if observer not in ROLES or phase not in ("before", "during", "after"):
            raise ValueError("invalid observer or phase")
        for endpoint in ENDPOINTS:
            record = {"observer": observer, "phase": phase, "endpoint": endpoint,
                      "time_utc": datetime.now(timezone.utc).isoformat(),
                      "elapsed_seconds": round(time.monotonic() - self.start, 3)}
            try:
                response = await client.get(endpoint, timeout=8, retry_auth=False)
                if not isinstance(response, dict):
                    record["status"] = "invalid_response"
                elif response.get("code") in (404, 410, "404", "410"):
                    record["status"] = "unavailable"
                elif response.get("code") not in (0, "0"):
                    record["status"] = "error"
                else:
                    rows = response.get("devices" if endpoint == ENDPOINTS[1] else "list")
                    if not isinstance(rows, list):
                        record["status"] = "invalid_response"
                    else:
                        record["status"] = "data" if rows else "empty"
                        record["count"] = len(rows)
                        record["truncated"] = len(rows) > 2048
                        record["clients"] = [self.client(row) for row in rows[:2048] if isinstance(row, dict)]
            except BaseException as exc:
                # Exception messages may contain tokens, IPs or response data.
                if isinstance(exc, (KeyboardInterrupt, SystemExit, asyncio.CancelledError)):
                    raise
                payload = getattr(exc, "response", None)
                code = payload.get("code") if isinstance(payload, dict) else None
                record["status"] = "unavailable" if code in (404, 410, "404", "410") else "error"
            self.report["observations"].append(record)


def load_luci():
    """Use the repository's LuCI implementation without loading HA integration setup."""
    root = Path(__file__).resolve().parents[1]
    package = "_miwifi_capture"
    pkg = types.ModuleType(package)
    pkg.__path__ = [str(root / "custom_components" / "miwifi")]
    sys.modules[package] = pkg
    logger = types.ModuleType(package + ".logger")
    logger._LOGGER = logging.getLogger("miwifi_capture_silent")
    logger._LOGGER.disabled = True
    sys.modules[logger.__name__] = logger
    # const.py only needs Platform to construct its unused PLATFORMS list.
    # Provide that small compatibility shim when HA is absent, then remove it.
    shim = importlib.util.find_spec("homeassistant") is None
    if shim:
        class Platform(StrEnum):
            BINARY_SENSOR = "binary_sensor"
            SENSOR = "sensor"
            LIGHT = "light"
            BUTTON = "button"
            SWITCH = "switch"
            SELECT = "select"
            DEVICE_TRACKER = "device_tracker"
            UPDATE = "update"
        ha = types.ModuleType("homeassistant")
        const = types.ModuleType("homeassistant.const")
        const.Platform = Platform
        sys.modules["homeassistant"] = ha
        sys.modules["homeassistant.const"] = const
    try:
        return importlib.import_module(package + ".luci").LuciClient
    finally:
        if shim:
            del sys.modules["homeassistant.const"]
            del sys.modules["homeassistant"]


def make_client(client_class, transport, address, password, algorithm):
    """Disable debug logging and the shared client's closed-transport retry."""
    address = private_ipv4(address)
    client = client_class(transport, ip=address, password=password, encryption=algorithm, protocol="http", timeout=8)
    client._debug = lambda *args, **kwargs: None

    async def request_once(method, url, **kwargs):
        base = f"http://{address}/cgi-bin/luci"
        token = client._token
        login = (method == "post" and url == f"{base}/api/xqsystem/login"
                 and set(kwargs) <= {"data", "timeout"})
        read = (method == "get" and isinstance(token, str)
                and re.fullmatch(r"[A-Za-z0-9_-]+", token) is not None
                and url in {f"{base}/;stok={token}/api/{endpoint}" for endpoint in ENDPOINTS}
                and set(kwargs) <= {"timeout"})
        if not (login or read):
            raise ValueError("request is outside the read-only allowlist")
        return await getattr(transport, method)(url, **kwargs)

    client._request_with_retry = request_once
    return client


async def run():
    from httpx import AsyncClient

    # HTTP debug logs can contain session tokens in URLs.
    logging.getLogger("httpx").disabled = True
    logging.getLogger("httpcore").disabled = True
    path = Path(input("Archivo de salida nuevo (.json): ").strip())
    if path.exists() or not path.parent.is_dir():
        raise ValueError("output path unavailable")
    if not sys.stdin.isatty():
        raise ValueError("interactive terminal required")
    capture = Capture()
    clients = {}
    async with AsyncClient(trust_env=False, follow_redirects=False, timeout=8) as transport:
        LuciClient = load_luci()
        for role in ROLES:
            address = private_ipv4(input(f"IP privada de {role}: "))
            raw_aliases = input(f"MAC conocidas de {role}, separadas por comas (opcional): ").strip()
            capture.register_router(role, [item.strip() for item in raw_aliases.split(",")] if raw_aliases else [])
            algorithm = input(f"Algoritmo de {role} (sha1/sha256): ").strip().lower()
            if algorithm not in ("sha1", "sha256"):
                raise ValueError("invalid algorithm")
            with warnings.catch_warnings():
                warnings.simplefilter("error", getpass.GetPassWarning)
                password = getpass.getpass(f"Contraseña de {role}: ")
            client = make_client(LuciClient, transport, address, password, algorithm)
            try:
                await client.login()  # Login establishes a session, not a configuration change.
            except BaseException as exc:
                if isinstance(exc, (KeyboardInterrupt, SystemExit, asyncio.CancelledError)):
                    raise
                print(f"Autenticación fallida en {role}; no se captura esa entrada.")
                client = None
            clients[role] = client
            del password
        for role in ("ethernet", "wifi_stable", "roaming"):
            mac = input(f"MAC del cliente {role} (opcional): ").strip()
            if mac:
                capture.register_target(role, mac)
        for phase, prompt in (("before", "Antes del roaming"), ("during", "Durante: cliente en R4"), ("after", "Después: cliente en RC06")):
            input(f"{prompt}. Pulsa Intro para registrar las tres entradas: ")
            await asyncio.gather(*(capture.sample(role, client, phase) for role, client in clients.items() if client))
            for role, client in clients.items():
                if client is None:
                    for endpoint in ENDPOINTS:
                        capture.report["observations"].append({"observer": role, "phase": phase, "endpoint": endpoint,
                            "time_utc": datetime.now(timezone.utc).isoformat(),
                            "elapsed_seconds": round(time.monotonic() - capture.start, 3), "status": "authentication_failed"})
    with path.open("x", encoding="utf-8") as output:
        json.dump(capture.report, output, indent=2, ensure_ascii=False)
        output.write("\n")
    print("Informe anonimizado guardado. Revísalo antes de compartirlo.")


if __name__ == "__main__":
    try:
        asyncio.run(run())
    except (EOFError, KeyboardInterrupt):
        print("Captura cancelada; no se ha guardado informe.")
    except Exception:
        print("No se pudo completar la captura; no se muestran detalles privados.", file=sys.stderr)
        sys.exit(1)
