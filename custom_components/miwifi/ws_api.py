# ws_api.py
from __future__ import annotations

import re
import voluptuous as vol
from homeassistant.core import HomeAssistant
from homeassistant.components import websocket_api
from .const import DOMAIN, UPDATER, ATTR_DEVICE_NAME, ATTR_DEVICE_MODEL, ATTR_DEVICE_MAC_ADDRESS
from .mac_replacement import get_mac_replacement
from .registry import get_device


@websocket_api.websocket_command({"type": "miwifi/iot_read", "router_mac": str})
@websocket_api.require_admin
@websocket_api.async_response
async def websocket_iot_read(hass: HomeAssistant, connection, msg) -> None:
    from .iot_wifi import IotError, manager, supported
    normalize = lambda value: str(value or "").lower().replace(":", "").replace("-", "")
    matches = []
    for entry in hass.config_entries.async_entries(DOMAIN):
        stored = hass.data.get(DOMAIN, {}).get(entry.entry_id)
        updater = stored.get(UPDATER) if isinstance(stored, dict) else None
        if updater is None or not supported(updater):
            continue
        data = updater.data or {}
        graph = (data.get("topo_graph") or {}).get("graph") or {}
        if normalize(msg["router_mac"]) and normalize(msg["router_mac"]) in {
            normalize(data.get(ATTR_DEVICE_MAC_ADDRESS)), normalize(graph.get("mac"))
        }:
            matches.append(entry.entry_id)
    if len(matches) != 1:
        connection.send_error(msg["id"], "unsupported", "IoT configuration is not verified for this router.")
        return
    try:
        result = await manager(hass, matches[0]).read()
    except IotError as err:
        connection.send_error(msg["id"], str(err), "IoT configuration could not be read.")
    else:
        connection.send_result(msg["id"], result)


@websocket_api.websocket_command({"type": "miwifi/iot_write", "entry_id": str,
    "revision": str, "enabled": bool, "bands": [dict]})
@websocket_api.require_admin
@websocket_api.async_response
async def websocket_iot_write(hass: HomeAssistant, connection, msg) -> None:
    from .iot_wifi import IotError, manager
    try:
        result = await manager(hass, msg["entry_id"]).write(msg["revision"], msg["enabled"], msg["bands"])
    except IotError as err:
        connection.send_error(msg["id"], str(err), "Reload IoT configuration and check the router state.")
    else:
        connection.send_result(msg["id"], result)


@websocket_api.websocket_command({"type": "miwifi/router_wifi_state"})
@websocket_api.require_admin
def websocket_router_wifi_state(hass: HomeAssistant, connection, msg) -> None:
    """Return cached per-router unification flags, without extra router calls."""
    from homeassistant.helpers import entity_registry as er
    registry = er.async_get(hass)
    routers = []
    for entry in hass.config_entries.async_entries(DOMAIN):
        stored = hass.data.get(DOMAIN, {}).get(entry.entry_id)
        updater = stored.get(UPDATER) if isinstance(stored, dict) else None
        if updater is None:
            continue
        data = updater.data or {}
        graph = (data.get("topo_graph") or {}).get("graph") or {}
        unified = data.get("dual_band")
        routers.append({"mac": data.get(ATTR_DEVICE_MAC_ADDRESS) or graph.get("mac"),
                        "graph_mac": graph.get("mac"), "ip": updater.ip,
                        "unified": unified if isinstance(unified, bool) else None,
                        "switches": {band: entity_id for band, key in (
                            ("2g", "wifi_2_4"), ("5g", "wifi_5_0"), ("game", "wifi_5_0_game"))
                            if (entity_id := registry.async_get_entity_id("switch", DOMAIN, f"{entry.entry_id}-{key}"))}})
    connection.send_result(msg["id"], {"routers": routers})


@websocket_api.websocket_command({"type": "miwifi/router_specific"})
@websocket_api.require_admin
@websocket_api.async_response
async def websocket_router_specific(hass: HomeAssistant, connection, msg) -> None:
    """Read reviewed RC01/RC06 fields only when requested by an administrator."""
    import asyncio
    from time import monotonic
    from .router_panel import MODELS, async_panel_reads, model_of

    domain = hass.data.setdefault(DOMAIN, {})
    state = domain.setdefault("_router_specific_panel", {"lock": asyncio.Lock()})
    if state["lock"].locked():
        connection.send_error(msg["id"], "busy", "Router read already in progress.")
        return
    async with state["lock"]:
        selected = []
        for entry in hass.config_entries.async_entries(DOMAIN):
            stored = domain.get(entry.entry_id)
            updater = stored.get(UPDATER) if isinstance(stored, dict) else None
            if updater is not None and model_of(updater) in MODELS:
                selected.append((entry, updater))
        signature = tuple((entry.entry_id, id(updater)) for entry, updater in selected)
        if state.get("signature") == signature and monotonic() - state.get("time", 0) < 15:
            connection.send_result(msg["id"], state["result"])
            return
        reads = await async_panel_reads([updater for _, updater in selected])
        for row, (entry, updater) in zip(reads, selected):
            row["name"] = _dhcp_router_name(hass, entry, updater)
            graph = ((updater.data or {}).get("topo_graph") or {}).get("graph") or {}
            row["is_main"] = graph.get("is_main") is True
            row["mac"] = (updater.data or {}).get(ATTR_DEVICE_MAC_ADDRESS) or graph.get("mac")
            row["graph_mac"] = graph.get("mac")
            row["ip"] = updater.ip
        from datetime import UTC, datetime
        result = {"routers": reads, "captured_at": datetime.now(UTC).isoformat()}
        state.update(signature=signature, time=monotonic(), result=result)
        connection.send_result(msg["id"], result)


def _dhcp_router_name(hass, entry, updater) -> str:
    """Use the HA router name override or router data, rather than its IP title."""
    from homeassistant.helpers import device_registry as dr

    data = updater.data or {}
    identity = data.get(ATTR_DEVICE_MAC_ADDRESS) or updater.ip
    device = get_device(dr.async_get(hass), entry.entry_id, identifier=(DOMAIN, identity))
    topology = data.get("topo_graph")
    graph = topology.get("graph") if isinstance(topology, dict) else None
    graph = graph if isinstance(graph, dict) else {}
    for candidate in (
        device.name_by_user if device else None,
        data.get(ATTR_DEVICE_NAME), graph.get("name"), graph.get("locale"),
        device.name if device else None, entry.title, data.get(ATTR_DEVICE_MODEL),
    ):
        if isinstance(candidate, str) and (name := candidate.strip()) and name != updater.ip:
            return name
    return "MiWiFi"


@websocket_api.websocket_command({"type": "miwifi/dhcp_routers"})
@websocket_api.require_admin
def websocket_dhcp_routers(hass: HomeAssistant, connection, msg) -> None:
    """Offer only loaded main routers; mesh nodes cannot manage reservations."""
    from .dhcp import is_main_updater

    routers = []
    for entry in hass.config_entries.async_entries(DOMAIN):
        stored = hass.data.get(DOMAIN, {}).get(entry.entry_id)
        updater = stored.get(UPDATER) if isinstance(stored, dict) else None
        if updater is not None and is_main_updater(updater):
            routers.append({"entry_id": entry.entry_id, "name": _dhcp_router_name(hass, entry, updater),
                            "ip": updater.ip})
    connection.send_result(msg["id"], {"routers": routers})


@websocket_api.websocket_command({"type": "miwifi/dhcp_read", "entry_id": str})
@websocket_api.require_admin
@websocket_api.async_response
async def websocket_dhcp_read(hass: HomeAssistant, connection, msg) -> None:
    from .dhcp import DhcpError, get_manager

    try:
        result = await get_manager(hass, msg["entry_id"]).async_read()
    except DhcpError as err:
        connection.send_error(msg["id"], str(err), "DHCP list could not be loaded.")
    else:
        connection.send_result(msg["id"], result)


@websocket_api.websocket_command({
    "type": "miwifi/dhcp_write", "entry_id": str, "revision": str,
    "action": vol.In(["add", "edit", "delete"]), "mac": str,
    vol.Optional("ip", default=""): str, vol.Optional("name", default=""): str,
})
@websocket_api.require_admin
@websocket_api.async_response
async def websocket_dhcp_write(hass: HomeAssistant, connection, msg) -> None:
    from .dhcp import DhcpError, get_manager

    try:
        result = await get_manager(hass, msg["entry_id"]).async_write(
            msg["action"], msg["revision"], msg["mac"], msg.get("ip", ""), msg.get("name", ""))
    except DhcpError as err:
        connection.send_error(msg["id"], str(err), "DHCP operation could not be verified.")
    else:
        connection.send_result(msg["id"], result)


@websocket_api.websocket_command({"type": "miwifi/get_mac_replacement"})
@websocket_api.require_admin
@websocket_api.async_response
async def websocket_get_mac_replacement(hass: HomeAssistant, connection, msg) -> None:
    """Read replacement rules and router client names across all loaded nodes."""
    from .updater import async_get_integrations

    names = {}
    for integration in async_get_integrations(hass).values():
        updater = integration.get(UPDATER)
        if updater is None:
            continue
        rows = list(updater.devices.values())
        stored = await updater._async_load_devices()
        if isinstance(stored, dict):
            rows.extend(stored.values())
        for row in rows:
            if not isinstance(row, dict):
                continue
            name = str(row.get("name") or "").strip()
            if name:
                names.setdefault(name.casefold(), name)
    clients = await get_mac_replacement(hass).async_configuration()
    connection.send_result(msg["id"], {
        "clients": {key: [names.get(name.casefold(), name) for name in aliases] for key, aliases in clients.items()},
        "available_names": sorted(names.values(), key=str.casefold),
    })


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


@websocket_api.websocket_command({"type": "miwifi/get_download_url", "kind": str})
@websocket_api.require_admin
def handle_get_download_url(hass: HomeAssistant, connection, msg) -> None:
    """Return a private export path to an authenticated administrator."""
    kind = msg["kind"]
    if kind not in ("logs", "dump"):
        connection.send_error(msg["id"], "invalid_kind", "Unknown export kind.")
        return

    key = "last_log_zip_url" if kind == "logs" else "last_dump_zip_url"
    url = hass.data.get(DOMAIN, {}).get(key)
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

    bsd = (details or {}).get("bsd")
    unified = True if bsd in (1, "1") else False if bsd in (0, "0") else None
    connection.send_result(msg["id"], {"wifis": data, "unified": unified})
