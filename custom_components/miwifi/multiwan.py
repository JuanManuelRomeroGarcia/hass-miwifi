"""Allowlisted read-only fields verified on RD08 firmware 1.1.96 (#355)."""

from ipaddress import IPv4Address


def is_rd08(data: dict) -> bool:
    """Do not apply an unverified vendor API to other router models."""
    return (
        str(data.get("model") or "").strip().lower() == "rd08"
        or str(data.get("device_model") or "").strip().lower() == "xiaomi.router.rd08"
    )


def parse_service(response: dict) -> bool:
    """Accept explicit enable/disable flags; an incomplete reply is unknown."""
    if not isinstance(response, dict) or response.get("code") != 0:
        raise ValueError("Unsupported multi-WAN service response")
    service = response.get("multiwan")
    if not isinstance(service, dict) or service.get("enable") not in (0, 1, "0", "1"):
        raise ValueError("Missing multi-WAN capability flag")
    return str(service["enable"]) == "1"


def parse_wan2(response: dict) -> dict:
    """Extract WAN2 state without publishing credentials or guessing traffic."""
    if not isinstance(response, dict) or response.get("code") != 0:
        raise ValueError("Unsupported WAN2 response")
    info = response.get("info")
    if not isinstance(info, dict):
        raise ValueError("Missing WAN2 info")
    flags = []
    for key in ("link", "status"):
        if info.get(key) not in (0, 1, "0", "1"):
            raise ValueError("Missing WAN2 status")
        flags.append(str(info[key]) == "1")
    addresses = info.get("ipv4")
    address = None
    if isinstance(addresses, list):
        for item in addresses:
            if isinstance(item, dict) and item.get("ip"):
                candidate = IPv4Address(item["ip"])
                if not candidate.is_unspecified:
                    address = str(candidate)
                    break
    details = info.get("details")
    kind = details.get("wanType") if isinstance(details, dict) else None
    if not isinstance(kind, str) or len(kind) > 32:
        kind = None
    # A disconnected port must not retain a DHCP lease as its current address.
    return {
        "ip": address if any(flags) else None,
        "type": kind,
        "link": flags[0],
        "connected": flags[1],
    }
