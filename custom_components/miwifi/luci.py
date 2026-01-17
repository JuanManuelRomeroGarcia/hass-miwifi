
# custom_components/miwifi/luci.py
# -*- coding: utf-8 -*-
"""
Luci API Client.
Cliente para el API LuCI de routers Xiaomi/Mi/Redmi (MiWiFi).
Gestiona autenticación y llamadas a endpoints misystem/xqsystem/xqnetwork.

Incluye:
- Detección de protocolo (HTTP/HTTPS)
- Login/logout con token (stok)
- Métodos de consulta comunes (status, init_info, wifi, WAN)
- Endpoint añadido: xqnetwork/wan_statistics (velocidades y contadores WAN)
"""
from __future__ import annotations
import hashlib
import json
import random
import time
import urllib.parse
import uuid
from datetime import datetime
from typing import Any, Dict, Optional

from httpx import AsyncClient, ConnectError, HTTPError, Response, TransportError

from .logger import _LOGGER
from .const import (
    CLIENT_ADDRESS,
    CLIENT_LOGIN_TYPE,
    CLIENT_NONCE_TYPE,
    CLIENT_PUBLIC_KEY,
    CLIENT_URL,
    CLIENT_USERNAME,
    DEFAULT_TIMEOUT,
    DIAGNOSTIC_CONTENT,
    DIAGNOSTIC_DATE_TIME,
    DIAGNOSTIC_MESSAGE,
    PROTOCOL_AUTO,
    PROTOCOL_HTTP,
    PROTOCOL_HTTPS,
    DEFAULT_PROTOCOL,
)
from .enum import EncryptionAlgorithm
from .exceptions import LuciConnectionError, LuciError, LuciRequestError

API_PATHS: Dict[str, str] = {
    "login": "xqsystem/login",
    "logout": "web/logout",
    "topo_graph": "misystem/topo_graph",
    "init_info": "xqsystem/init_info",
    "status": "misystem/status",
    "new_status": "misystem/newstatus",
    "mode": "xqnetwork/mode",
    "netmode": "xqnetwork/get_netmode",
    "wifi_ap_signal": "xqnetwork/wifiap_signal",
    "wifi_detail_all": "xqnetwork/wifi_detail_all",
    "wifi_diag_detail_all": "xqnetwork/wifi_diag_detail_all",
    "vpn_status": "xqsystem/vpn_status",
    "set_wifi": "xqnetwork/set_wifi",
    "set_guest_wifi": "xqnetwork/set_wifi_without_restart",
    "avaliable_channels": "xqnetwork/avaliable_channels",
    "wifi_connect_devices": "xqnetwork/wifi_connect_devices",
    "device_list": "misystem/devicelist",
    "qos_switch": "misystem/qos_switch",
    "qos_info": "misystem/qos_info",
    "wan_info": "xqnetwork/wan_info",
    "wan_statistics": "xqnetwork/wan_statistics",
    "reboot": "xqsystem/reboot",
    "led": "misystem/led",
    "set_mac_filter": "xqsystem/set_mac_filter",
    "mac_filter_info": "xqnetwork/wifi_macfilter_info",
    "portforward": "xqnetwork/portforward",
    "add_redirect": "xqnetwork/add_redirect",
    "add_range_redirect": "xqnetwork/add_range_redirect",
    "redirect_apply": "xqnetwork/redirect_apply",
    "delete_redirect": "xqnetwork/delete_redirect",
    "rom_update": "xqsystem/check_rom_update",
    "rom_upgrade": "xqsystem/upgrade_rom",
    "flash_permission": "xqsystem/flash_permission",
}

# pylint: disable=too-many-public-methods,too-many-arguments
class LuciClient:
    """Cliente del API LuCI."""

    # Propiedades principales
    ip: str = CLIENT_ADDRESS  # pylint: disable=invalid-name
    _client: AsyncClient
    _password: Optional[str] = None
    _encryption: str = EncryptionAlgorithm.SHA1
    _timeout: int = DEFAULT_TIMEOUT
    _token: Optional[str] = None
    _url: Optional[str]
    _protocol: str
    _detected_protocol: Optional[str]
    # Rutas de API
    _api_paths: Dict[str, str]

    def __init__(
        self,
        client: AsyncClient,
        ip: str = CLIENT_ADDRESS,  # pylint: disable=invalid-name
        password: Optional[str] = None,
        encryption: str = EncryptionAlgorithm.SHA1,
        timeout: int = DEFAULT_TIMEOUT,
        protocol: str = DEFAULT_PROTOCOL,
    ) -> None:
        """Inicializa el cliente de API.
        :param client: AsyncClient inyectado (persistente)
        :param ip: IP del router
        :param password: contraseña admin del router
        :param encryption: algoritmo de hash (SHA1/SHA256)
        :param timeout: timeout de peticiones
        :param protocol: protocolo preferido (auto/http/https)
        """
        ip = ip.removesuffix("/")
        self._client = client
        self.ip = ip  # pylint: disable=invalid-name
        self._password = password
        self._encryption = encryption
        self._timeout = timeout
        self._protocol = protocol
        self._detected_protocol = None
        # URL base (se configura tras detectar protocolo)
        self._url = None
        # Diagnósticos por endpoint
        self.diagnostics: Dict[str, Any] = {}
        # Copia de rutas (permite ajustar por modelo si hiciera falta)
        self._api_paths = API_PATHS.copy()

    async def _detect_protocol(self) -> str:
        """Detecta protocolo correcto para el router (https o http)."""
        if self._detected_protocol is not None:
            return self._detected_protocol
        if self._protocol != PROTOCOL_AUTO:
            self._detected_protocol = self._protocol
            return self._detected_protocol
        # Primero intentamos HTTPS y luego HTTP
        protocols_to_try = [PROTOCOL_HTTPS, PROTOCOL_HTTP]
        for protocol in protocols_to_try:
            test_url = CLIENT_URL.format(protocol=protocol, ip=self.ip)
            try:
                response = await self._client.get(f"{test_url}/", timeout=5)
                # Cualquier respuesta <500 nos vale para detectar que hay servidor
                if response.status_code < 500:
                    self._detected_protocol = protocol
                    return protocol
            except Exception:
                continue
        # Si ambos fallan, forzamos HTTP
        self._detected_protocol = PROTOCOL_HTTP
        return PROTOCOL_HTTP

    def _get_url(self, protocol: Optional[str] = None) -> str:
        """Compone la URL base con protocolo especificado o detectado."""
        if protocol is None:
            protocol = self._detected_protocol or PROTOCOL_HTTP
        return CLIENT_URL.format(protocol=protocol, ip=self.ip)

    async def aclose(self) -> None:
        """Cierra el AsyncClient persistente (opcional, al descargar la integración)."""
        try:
            await self._client.aclose()
        except Exception:
            pass

    async def login(self) -> dict:
        """Login contra el router; obtiene y guarda el token."""
        # Detecta protocolo si no se ha hecho
        protocol = await self._detect_protocol()
        self._url = self._get_url(protocol)

        _method: str = self._api_paths["login"]
        _nonce: str = self.generate_nonce()
        _url: str = f"{self._url}/api/{_method}"
        _request_data: dict = {
            "username": CLIENT_USERNAME,
            "logtype": str(CLIENT_LOGIN_TYPE),
            "password": self.generate_password_hash(_nonce, str(self._password)),
            "nonce": _nonce,
        }
        try:
            self._debug("Start request", _url, json.dumps(_request_data), _method, True)
            response: Response = await self._client.post(
                _url,
                data=_request_data,
                timeout=self._timeout,
            )
            self._debug("Successful request", _url, response.content, _method)
            _data: dict = json.loads(response.content)
        except (HTTPError, ConnectError, TransportError, ValueError, TypeError) as _e:
            self._debug("Connection error", _url, _e, _method)
            raise LuciConnectionError("Connection error") from _e

        if response.status_code != 200 or "token" not in _data:
            self._debug("Failed to get token", _url, _data, _method)
            raise LuciRequestError("Failed to get token")
        self._token = _data["token"]
        return _data

    async def logout(self) -> None:
        """Logout (si hay token)."""
        if self._token is None:
            return
        # Asegura URL base
        if self._url is None and self._detected_protocol:
            self._url = self._get_url()
        if self._url is None:
            return
        _method: str = self._api_paths["logout"]
        _url: str = f"{self._url}/;stok={self._token}/{_method}"
        try:
            response: Response = await self._client.get(_url, timeout=self._timeout)
            self._debug("Successful request", _url, response.content, _method)
        except (HTTPError, ConnectError, TransportError, ValueError, TypeError) as _e:
            self._debug("Logout error", _url, _e, _method)

    async def get(
        self,
        path: str,
        query_params: Optional[dict] = None,
        use_stok: bool = True,
        errors: Optional[Dict[int, str]] = None,
    ) -> dict:
        """Método GET genérico.
        :param path: ruta de API
        :param query_params: parámetros de consulta (añadidos a la URL)
        :param use_stok: si debe usar el token en la ruta
        :param errors: mapa de códigos LuCI -> mensaje de error (para raise LuciError)
        """
        if use_stok and self._token is None:
            raise LuciRequestError("Token not found")

        if query_params:
            path += f"?{urllib.parse.urlencode(query_params, doseq=True)}"

        # Asegura URL base
        if self._url is None and self._detected_protocol:
            self._url = self._get_url()
        if self._url is None:
            raise LuciRequestError("No URL configured - protocol detection may have failed")

        _stok: str = f";stok={self._token}/" if use_stok else ""
        _url: str = f"{self._url}/{_stok}api/{path}"
        try:
            response: Response = await self._client.get(_url, timeout=self._timeout)
            self._debug("Successful request", _url, response.content, path)
            # Preferir parseo directo a JSON; usar fallback si el servidor no marca cabeceras
            try:
                _data: dict = response.json()
            except ValueError:
                _data = json.loads(response.content)
        except (
            HTTPError,
            ConnectError,
            TransportError,
            ValueError,
            TypeError,
            json.JSONDecodeError,
        ) as _e:
            self._debug("Connection error", _url, _e, path)
            raise LuciConnectionError("Connection error") from _e

        if "code" not in _data or _data["code"] > 0:
            _code: int = -1 if "code" not in _data else int(_data["code"])
            self._debug("Invalid error code received", _url, _data, path)
            if "code" in _data and errors is not None and _data["code"] in errors:
                raise LuciError(errors[_data["code"]])
            raise LuciRequestError(
                _data.get("msg", f"Invalid error code received: {_code}")
            )
        return _data

    # ---- Endpoints LuCI / misystem / xqsystem / xqnetwork --------------------
    async def topo_graph(self) -> dict:
        """misystem/topo_graph"""
        return await self.get(self._api_paths["topo_graph"], use_stok=False)

    async def init_info(self) -> dict:
        """xqsystem/init_info"""
        return await self.get(self._api_paths["init_info"])

    async def status(self) -> dict:
        """misystem/status"""
        return await self.get(self._api_paths["status"])

    async def misystem_info(self) -> dict:
        """Devuelve la info global misystem (dev, wan, mem, etc.)."""
        try:
            data = await self.status()
            if isinstance(data, dict) and "dev" in data:
                return data
        except Exception as e:
            self._debug(
                "misystem_info status() failed",
                self._url or "",
                e,
                "misystem_info",
            )
        try:
            return await self.get("misystem/")
        except Exception as e:
            self._debug(
                "misystem_info misystem/ failed",
                self._url or "",
                e,
                "misystem_info",
            )
        return {}

    async def new_status(self) -> dict:
        """misystem/newstatus"""
        return await self.get(self._api_paths["new_status"])

    async def mode(self) -> dict:
        """xqnetwork/mode con fallback a get_netmode."""
        try:
            return await self.get(self._api_paths["mode"])
        except Exception:
            _LOGGER.info("Primary endpoint failed, load xqnetwork/get_netmode")
            try:
                return await self.netmode()
            except Exception as e:
                _LOGGER.error("Fallback endpoint also failed: %s", e)
                return {"mode": 0}

    async def netmode(self) -> dict:
        """Alias (compatibilidad) de xqnetwork/mode."""
        return await self.get(self._api_paths["netmode"])

    async def wifi_ap_signal(self) -> dict:
        """xqnetwork/wifiap_signal"""
        return await self.get(self._api_paths["wifi_ap_signal"])

    async def wifi_detail_all(self) -> dict:
        """xqnetwork/wifi_detail_all"""
        return await self.get(self._api_paths["wifi_detail_all"])

    async def wifi_diag_detail_all(self) -> dict:
        """xqnetwork/wifi_diag_detail_all"""
        return await self.get(self._api_paths["wifi_diag_detail_all"])

    async def vpn_status(self) -> dict:
        """xqsystem/vpn_status"""
        return await self.get(self._api_paths["vpn_status"])

    async def set_wifi(self, data: dict) -> dict:
        """xqnetwork/set_wifi (algunos modelos aceptan parámetros por querystring)."""
        return await self.get(self._api_paths["set_wifi"], data)

    async def set_guest_wifi(self, data: dict) -> dict:
        """xqnetwork/set_wifi_without_restart (guest WiFi)."""
        return await self.get(self._api_paths["set_guest_wifi"], data)

    async def avaliable_channels(self, index: int = 1) -> dict:
        """xqnetwork/avaliable_channels"""
        return await self.get(self._api_paths["avaliable_channels"], {"wifiIndex": index})

    async def wan_info(self) -> dict:
        """xqnetwork/wan_info"""
        return await self.get(self._api_paths["wan_info"])

    async def wan_statistics(self) -> dict:
        """xqnetwork/wan_statistics: velocidades y contadores WAN.
        Devuelve campos como statistics.downspeed, statistics.upspeed,
        statistics.download, statistics.upload, etc.
        """
        return await self.get(self._api_paths["wan_statistics"])

    async def reboot(self) -> dict:
        """xqsystem/reboot"""
        return await self.get(self._api_paths["reboot"])

    async def led(self, state: Optional[int] = None) -> dict:
        """misystem/led (on/off)."""
        data: dict = {}
        if state is not None:
            data["on"] = state
        return await self.get(self._api_paths["led"], data)

    async def qos_toggle(self, qosState: int = 0) -> dict:
        """misystem/qos_switch: 0/1 para activar/desactivar QOS."""
        return await self.get(self._api_paths["qos_switch"], {"on": qosState})

    async def qos_info(self) -> dict:
        """misystem/qos_info"""
        return await self.get(self._api_paths["qos_info"])

    async def device_list(self) -> dict:
        """misystem/devicelist"""
        return await self.get(self._api_paths["device_list"])

    async def wifi_connect_devices(self) -> dict:
        """xqnetwork/wifi_connect_devices"""
        return await self.get(self._api_paths["wifi_connect_devices"])

    async def set_mac_filter(self, mac: str, allow: bool) -> dict:
        """
        xqsystem/set_mac_filter: bloquea/desbloquea acceso WAN para un dispositivo.
        allow=True -> WAN permitido (unblocked)
        allow=False -> WAN bloqueado
        """
        data = {"mac": mac, "wan": "1" if allow else "0"}
        return await self.get(self._api_paths["set_mac_filter"], data)

    async def macfilter_info(self) -> dict:
        """xqnetwork/wifi_macfilter_info: estado actual de MAC filtradas."""
        return await self.get(self._api_paths["mac_filter_info"])

    async def check_mac_filter_support(self) -> bool:
        """Comprueba si el router soporta set_mac_filter API."""
        try:
            await self.set_mac_filter("00:00:00:00:00:00", True)
            return True
        except Exception:
            return False

    async def portforward(self, ftype: int = 1) -> dict:
        """Obtiene reglas NAT (ftype 1 = puerto único, 2 = rango)."""
        _LOGGER.debug("Requesting NAT rules with ftype=%s", ftype)
        try:
            data = await self.get(self._api_paths["portforward"], {"ftype": ftype})
            _LOGGER.debug("NAT response for ftype=%s → %s", ftype, data)
            return data
        except Exception as e:
            _LOGGER.warning("[MiWiFi] Failed to retrieve NAT rules for ftype=%s: %s", ftype, e)
            return {}

    async def add_redirect(self, name: str, proto: int, sport: int, ip: str, dport: int) -> dict:
        """Añade regla NAT de puerto único."""
        # Asegura URL
        if self._url is None and self._detected_protocol:
            self._url = self._get_url()
        if self._url is None:
            raise LuciRequestError("No URL configured - protocol detection may have failed")
        _url = f"{self._url}/;stok={self._token}/api/{self._api_paths['add_redirect']}"
        data = {"name": name, "proto": proto, "sport": sport, "ip": ip, "dport": dport}
        response = await self._client.post(_url, data=data, timeout=self._timeout)
        _data = json.loads(response.content)
        if response.status_code != 200 or _data.get("code", 1) != 0:
            raise LuciRequestError(f"Failed to add rule: {_data}")
        return _data

    async def add_range_redirect(self, name: str, proto: int, fport: int, tport: int, ip: str) -> dict:
        """Añade regla NAT de rango de puertos."""
        # Asegura URL
        if self._url is None and self._detected_protocol:
            self._url = self._get_url()
        if self._url is None:
            raise LuciRequestError("No URL configured - protocol detection may have failed")
        _url = f"{self._url}/;stok={self._token}/api/{self._api_paths['add_range_redirect']}"
        data = {"name": name, "proto": proto, "fport": fport, "tport": tport, "ip": ip}
        response = await self._client.post(_url, data=data, timeout=self._timeout)
        _data = json.loads(response.content)
        if response.status_code != 200 or _data.get("code", 1) != 0:
            raise LuciRequestError(f"Failed to add port range: {_data}")
        return _data

    async def redirect_apply(self) -> dict:
        """Aplica cambios de NAT tras añadir/eliminar reglas."""
        return await self.get(self._api_paths["redirect_apply"])

    async def delete_redirect(self, port: int, proto: int) -> dict:
        """Elimina una regla NAT."""
        # Asegura URL
        if self._url is None and self._detected_protocol:
            self._url = self._get_url()
        if self._url is None:
            raise LuciRequestError("No URL configured - protocol detection may have failed")
        _url = f"{self._url}/;stok={self._token}/api/{self._api_paths['delete_redirect']}"
        data = {"port": port, "proto": proto}
        response = await self._client.post(_url, data=data, timeout=self._timeout)
        _data = json.loads(response.content)
        if response.status_code != 200 or _data.get("code", 1) != 0:
            raise LuciRequestError(f"Failed to delete rule: {_data}")
        return _data

    async def rom_update(self) -> dict:
        """xqsystem/check_rom_update"""
        return await self.get(self._api_paths["rom_update"])

    async def rom_upgrade(self, data: dict) -> dict:
        """xqsystem/upgrade_rom (con mapa de errores conocido)."""
        return await self.get(
            self._api_paths["rom_upgrade"],
            data,
            errors={
                6: "Download failed",
                7: "No disk space",
                8: "Download failed",
                9: "Upgrade package verification failed",
                10: "Failed to flash",
            },
        )

    async def flash_permission(self) -> dict:
        """xqsystem/flash_permission"""
        return await self.get(self._api_paths["flash_permission"])

    # ---- Utilidades de cifrado / debug ---------------------------------------
    def sha(self, key: str) -> str:
        """Calcula SHA del texto dado (SHA1/SHA256 según configuración)."""
        if self._encryption == EncryptionAlgorithm.SHA256:
            return hashlib.sha256(key.encode()).hexdigest()
        return hashlib.sha1(key.encode()).hexdigest()

    @staticmethod
    def get_mac_address() -> str:
        """Genera una dirección MAC 'fake' para el nonce."""
        as_hex: str = f"{uuid.getnode():012x}"
        return ":".join(as_hex[i : i + 2] for i in range(0, 12, 2))

    def generate_nonce(self) -> str:
        """Genera nonce para login."""
        rand: str = f"{int(time.time())}_{int(random.random() * 1000)}"
        return f"{CLIENT_NONCE_TYPE}_{self.get_mac_address()}_{rand}"

    def generate_password_hash(self, nonce: str, password: str) -> str:
        """Genera hash de contraseña+nonce según algoritmo configurado."""
        return self.sha(nonce + self.sha(password + CLIENT_PUBLIC_KEY))

    def _debug(
        self, message: str, url: str, content: Any, path: str, is_only_log: bool = False
    ) -> None:
        """Registra diagnóstico por endpoint."""
        # _LOGGER.debug("%s (%s): %s", message, url, str(content))
        if is_only_log:
            return
        _content: Dict[str, Any] | str = {}
        try:
            _content = json.loads(content)
        except (ValueError, TypeError):
            _content = str(content)
        self.diagnostics[path] = {
            DIAGNOSTIC_DATE_TIME: datetime.now().replace(microsecond=0).isoformat(),
            DIAGNOSTIC_MESSAGE: message,
            DIAGNOSTIC_CONTENT: _content,
        }
