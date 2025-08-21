# ws_api.py
from __future__ import annotations

import re
from homeassistant.core import HomeAssistant
from homeassistant.components import websocket_api
from .const import DOMAIN, UPDATER


def _pick_updater(hass: HomeAssistant):
    """
    Selecciona un updater desde hass.data[DOMAIN].
    - Prioriza el router marcado como main (topo_graph.graph.is_main = True).
    - Si no hay main, devuelve el primero que encuentre.
    """
    store = hass.data.get(DOMAIN, {})
    if not isinstance(store, dict) or not store:
        return None


    updaters = []
    for entry in store.values():
        if isinstance(entry, dict) and UPDATER in entry:
            updaters.append(entry[UPDATER])

    if not updaters:
        return None

   
    for upd in updaters:
        data = getattr(upd, "data", {}) or {}
        graph = (data.get("topo_graph") or {}).get("graph") or {}
        if graph.get("is_main"):
            return upd

    
    return updaters[0]


@websocket_api.websocket_command({"type": "miwifi/get_download_url"})
@websocket_api.require_admin
async def handle_get_download_url(hass: HomeAssistant, connection, msg) -> None:
    """Devuelve la última URL disponible para descargar logs/dump."""
    url = hass.data.get(DOMAIN, {}).get("last_log_zip_url")
    if url:
        connection.send_result(msg["id"], {"url": url})
    else:
        connection.send_error(msg["id"], "no_file", "No download available yet.")


@websocket_api.websocket_command({
    "type": "miwifi/get_wifis",
    
    "hide_sensitive": bool,
})
@websocket_api.require_admin  
@websocket_api.async_response
async def websocket_get_wifis(hass: HomeAssistant, connection, msg) -> None:
    """Devuelve detalle de wifis (guest/2g/5g/game) consultando al router vía luci."""
    hide_sensitive = bool(msg.get("hide_sensitive", False))

    updater = _pick_updater(hass)
    if updater is None:
        connection.send_error(msg["id"], "no_updater", "No MiWiFi updater available.")
        return

    luci = getattr(updater, "luci", None)
    if luci is None:
        connection.send_error(msg["id"], "no_luci", "No luci client on updater.")
        return

  
    try:
        try:
            diag = await luci.wifi_diag_detail_all()
        except Exception:
            diag = {}
        details = await luci.wifi_detail_all()
    except Exception as err:
        connection.send_error(msg["id"], "router_error", f"{type(err).__name__}: {err}")
        return

    d_info = (details or {}).get("info", []) or []
    g_info = (diag or {}).get("info", []) or []
  
    all_info = list(g_info) + [it for it in d_info if it not in g_info]

    def _norm_bool(v):
        return str(v).strip().lower() in ("1", "true", "on", "yes")

    def _chan(it: dict):
        """Devuelve el canal como int cuando sea posible.
        Prioriza channelInfo.channel sobre el campo plano 'channel'."""
        ci = it.get("channelInfo") or {}
        ch_ci = ci.get("channel")
        ch_raw = it.get("channel")
        ch = ch_ci if ch_ci not in (None, "", "0") else ch_raw
        try:
            return int(ch)
        except (TypeError, ValueError):
            return None


    def _band_str(it: dict):
        return (it.get("band") or it.get("radio") or "").lower()

    def _is_24g(it: dict) -> bool:
        """Detecta 2.4 GHz por canal, banda o patrón de ifname."""
        ch = _chan(it)
        if isinstance(ch, int) and ch <= 14 and ch > 0:
            return True
        b = (it.get("band") or it.get("radio") or "").lower()
        if "2.4" in b or "2g" in b or "2ghz" in b:
            return True
       
        if (it.get("ifname") or "").lower() in {"wl1"}:
            return True
        
        return str(it.get("iftype")) == "1"

    def _is_5g(it: dict):
        """Detecta 5 GHz por canal, banda o patrón de ifname."""
        ch = _chan(it)
        if isinstance(ch, int) and ch > 14:
            return True
        b = (it.get("band") or it.get("radio") or "").lower()
        if "5g" in b or "5ghz" in b:
            return True
       
        if (it.get("ifname") or "").lower() in {"wl0", "wl2", "wl20", "wl22", "wl23", "wl32"}:
            return True
       
        return str(it.get("iftype")) == "2"

    def _is_game_5g(it: dict):
        
        if (it.get("ifname") or "").lower() == "wl2":
            return True
        ssid = (it.get("ssid") or "").lower()
        return "game" in ssid or "gaming" in ssid

    def _wifi_index_from_device(dev: str | None):
        if not dev or not isinstance(dev, str):
            return None
        m = re.search(r"wifi(\d+)\.network", dev)
        return int(m.group(1)) if m else None

    def _find_guest():
       
        for it in all_info:
            if str(it.get("iftype")) == "3":
                return it
            if (it.get("ifname") or "").lower() in ("wl14", "wl33"):
                return it
        return None

    def _find_2g():
        for it in all_info:
            if _is_24g(it) and not _is_game_5g(it):
                return it
        return None

    def _find_game():
        for it in all_info:
            if _is_5g(it) and _is_game_5g(it):
                return it
        return None

    def _find_5g():
        
        for it in all_info:
            if _is_5g(it) and not _is_game_5g(it):
                return it
        return None

    def _pack(it: dict | None):
        if not it:
            return None
        pwd = it.get("password")
        return {
            "wifiIndex": _wifi_index_from_device(it.get("device")),
            "ifname": it.get("ifname"),
            "enabled": _norm_bool(it.get("enabled", it.get("status", 0))),
            "ssid": it.get("ssid"),
            "encryption": it.get("encryption") or it.get("enctype"),
            "hidden": it.get("hidden"),
            "channel": _chan(it),
            "bandwidth": (it.get("channelInfo") or {}).get("bandwidth"),
            "txpwr": it.get("txpwr"),
            
            "password": (None if hide_sensitive else pwd) if pwd is not None else None,
        }

    data = {
        "guest": _pack(_find_guest()),
        "2g": _pack(_find_2g()),
        "5g": _pack(_find_5g()),
        "game": _pack(_find_game()),
    }

    connection.send_result(msg["id"], {"wifis": data})
