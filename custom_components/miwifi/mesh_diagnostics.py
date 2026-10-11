"""Bounded, privacy-preserving mesh support snapshots; no router requests."""

from collections import deque
from datetime import datetime, timezone
from enum import Enum
import hashlib
import hmac
import secrets


class MeshTrace:
    """Keep recent observations without credentials or client names."""

    def __init__(self):
        self.events = deque(maxlen=60)
        self.censuses = deque(maxlen=12)
        self.startup_events = []
        self.first_census = None
        self.first_censuses_by_source = {}

    def event(self, reason, data, **flags):
        event = {
            "time": datetime.now(timezone.utc).isoformat(),
            "reason": reason,
            "counts": counters(data),
            **flags,
        }
        self.events.append(event)
        if len(self.startup_events) < 12:
            self.startup_events.append(event)

    def census(self, response, routes, source="misystem/devicelist"):
        rows = response.get("list", [])
        if not isinstance(rows, list):
            rows = []
        clients = []
        for row in rows[:512]:
            if not isinstance(row, dict):
                continue
            addresses = row.get("ip")
            addresses = addresses if isinstance(addresses, list) else []
            active = any(isinstance(ip, dict) and str(ip.get("active")) == "1"
                         for ip in addresses)
            parent = str(row.get("parent") or "").strip().upper()
            clients.append({
                "mac": row.get("mac"), "parent": parent,
                "isap": row.get("isap"), "type": row.get("type"),
                "online": row.get("online"),
                "wifiIndex": row.get("wifiIndex"), "signal": row.get("signal"),
                "addresses": [{"ip": ip.get("ip"), "active": ip.get("active")}
                              for ip in addresses if isinstance(ip, dict)],
                "has_active_ip": active,
                "parent_matched": parent in routes,
                "target_ip": routes.get(parent),
            })
        self.censuses.append({
            "time": datetime.now(timezone.utc).isoformat(),
            "source": source,
            "reported_rows": len(rows), "truncated": len(rows) > 512,
            "parent_routes": dict(routes), "clients": clients,
        })
        if self.first_census is None:
            self.first_census = self.censuses[-1]
        self.first_censuses_by_source.setdefault(source, self.censuses[-1])


def counters(data):
    """Select only client counters, including per-band counters."""
    return {key: value for key, value in (data or {}).items()
            if key == "devices" or key.startswith("devices_")}


class SupportAliases:
    """Correlate identifiers across downloads during one HA runtime."""

    def __init__(self):
        self.secret = secrets.token_bytes(32)

    def alias(self, kind, value):
        if value in (None, ""):
            return None
        normalized = str(value).strip()
        if kind == "mac":
            normalized = normalized.upper().replace("-", ":")
        digest = hmac.new(self.secret, (kind + ":" + normalized).encode(),
                          hashlib.sha256).hexdigest()[:16]
        return kind + "_" + digest

    def clean(self, value, key=""):
        if isinstance(value, dict):
            if key == "parent_routes":
                return {self.alias("mac", mac): self.alias("ip", ip)
                        for mac, ip in value.items()}
            return {field: self.clean(item, field) for field, item in value.items()}
        if isinstance(value, (list, tuple, deque)):
            return [self.clean(item, key) for item in value]
        if key in {"mac", "parent", "router_mac", "device_mac_address"}:
            return self.alias("mac", value)
        if key in {"ip", "target_ip", "source_ip"}:
            return self.alias("ip", value)
        if key in {"entry_id", "updater_entry_id"}:
            return self.alias("entry", value)
        if isinstance(value, Enum):
            return value.value
        return value


def topology_rows(graph):
    """Flatten allowlisted topology fields and preserve address anomalies."""
    rows = []
    pending = [(graph, None)]
    while pending and len(rows) < 512:
        node, parent = pending.pop()
        if not isinstance(node, dict):
            continue
        raw_ip = node.get("ip")
        rows.append({
            "ip": raw_ip, "mac": node.get("mac"), "parent": parent,
            "ip_has_surrounding_whitespace": isinstance(raw_ip, str)
                and raw_ip != raw_ip.strip(),
            **{key: node.get(key) for key in
               ("hardware", "mode", "onlines", "is_main", "is_main_auto")},
        })
        leaves = node.get("leafs")
        if isinstance(leaves, list):
            pending.extend((leaf, node.get("mac")) for leaf in leaves)
    return {"nodes": rows, "truncated": bool(pending)}


def build_mesh_support(hass, integrations):
    """Export all configured nodes with consistent runtime-only aliases."""
    # Separate from hass.data[DOMAIN], whose dictionaries represent entries.
    if "miwifi_support_aliases" not in hass.data:
        hass.data["miwifi_support_aliases"] = SupportAliases()
    aliases = hass.data["miwifi_support_aliases"]
    nodes = []
    for ip, integration in integrations.items():
        updater = integration["updater"]
        data = updater.data or {}
        trace = getattr(updater, "_mesh_trace", None)
        entry_id = getattr(updater, "_entry_id", None)
        entry = hass.config_entries.async_get_entry(entry_id) if entry_id else None
        options = {**entry.data, **entry.options} if entry else {}
        safe_options = {key: value for key, value in options.items()
                        if isinstance(value, (bool, int, float))}
        clients = [{key: client.get(key) for key in
                    ("mac", "router_mac", "ip", "online", "connection",
                     "entry_id", "updater_entry_id", "is_restored")}
                   for client in list(updater.devices.values())[:512]
                   if isinstance(client, dict)]
        graph = (data.get("topo_graph") or {}).get("graph", {})
        nodes.append({
            "ip": ip, "entry_id": entry_id,
            "model": data.get("device_model"),
            "firmware": data.get("device_sw_version"),
            "mac": data.get("device_mac_address"),
            "mode": data.get("mode"),
            "force_load": updater.is_force_load,
            "scan_interval": getattr(updater, "_scan_interval", None),
            "numeric_options": safe_options,
            "last_update_success": getattr(updater, "last_update_success", None),
            "counts": counters(data),
            "counter_flags": {key: getattr(updater, key, None) for key in
                              ("_counters_reset_this_cycle", "_parent_push_pending")},
            "topology": topology_rows(graph),
            "stored_clients": clients,
            "moved_clients": [aliases.alias("mac", mac) for mac in
                              getattr(updater, "_moved_devices", [])[:512]],
            "stored_clients_truncated": len(updater.devices) > 512,
            "recent_censuses": list(trace.censuses) if trace else [],
            "first_census": trace.first_census if trace else None,
            "first_censuses_by_source": trace.first_censuses_by_source if trace else {},
            "startup_events": trace.startup_events if trace else [],
            "counter_events": list(trace.events) if trace else [],
        })
    return aliases.clean({
        "schema_version": 1,
        "captured_at": datetime.now(timezone.utc).isoformat(),
        "identifier_scope": "same HA runtime; aliases change after restart",
        "limits": {"censuses_per_node": 12, "events_per_node": 60,
                   "startup_events_per_node": 12, "first_census_per_node": 1,
                   "clients_per_census": 512},
        "nodes": nodes,
    })
