"""Normalize the CB0401V2 IPv6 payload without assuming network prefixes."""
from ipaddress import IPv6Address, IPv6Interface
from enum import Enum


def is_cb0401v2(updater):
    """Require the exact model; the legacy CPE profile also matches other models."""
    data = updater.data or {}
    if "cpe_ipv6_model_exact" in data:
        return data["cpe_ipv6_model_exact"] is True
    model = data.get("device_model") or data.get("model") or data.get("hardware_model")
    if isinstance(model, Enum):
        return model.name.upper() == "CB0401V2" or str(model.value).strip().upper().split(".")[-1] == "CB0401V2"
    return isinstance(model, str) and model.strip().upper().split(".")[-1] == "CB0401V2"


def _addresses(value):
    if isinstance(value, list):
        result = []
        for item in value:
            result.extend(_addresses(item))
        return result
    if not isinstance(value, str) or not value.strip() or len(value) > 255:
        return []
    value = value.strip()
    try:
        # Keep the exact supplied prefix length; never synthesize one.
        IPv6Interface(value) if "/" in value else IPv6Address(value)
    except ValueError:
        return []
    return [value]


def parse_ipv6(info):
    info = info if isinstance(info, dict) else {}
    up = info.get("up")
    if isinstance(up, bool):
        pass
    elif isinstance(up, (int, str)) and up in (0, 1, "0", "1"):
        up = up in (1, "1")
    else:
        up = None
    wan = _addresses(info.get("ip6addr"))
    lan = _addresses(info.get("lan_ip6addr"))
    prefix = _addresses(info.get("lan_ip6prefix"))
    gateway = _addresses(info.get("ip6gw"))
    mode = info.get("ipv6_mode")
    if not isinstance(mode, str) or not mode.strip() or len(mode) > 255:
        mode = None
    return {"up": up, "wan": next(iter(wan), None), "lan": next(iter(lan), None),
            "prefix": next(iter(prefix), None), "mode": mode, "gateway": next(iter(gateway), None),
            "dns": _addresses(info.get("dns")), "wan_addresses": wan, "lan_addresses": lan,
            "prefixes": prefix}
