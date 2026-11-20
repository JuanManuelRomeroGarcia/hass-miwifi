"""Identify the guest interface without guessing its router index."""
import re


def _index(row):
    device = row.get("device")
    match = re.fullmatch(r"wifi(\d+)\.network\d+", device) if isinstance(device, str) else None
    return int(match.group(1)) if match else None


def _guest(row):
    return str(row.get("iftype")) == "3" or str(row.get("ifname") or "").lower() in ("wl14", "wl33")


def resolve_guest(diag, details):
    """Combine unique matching interfaces; return (row, index, ambiguous)."""
    diagnostics = [row for row in diag if isinstance(row, dict)]
    configs = [row for row in details if isinstance(row, dict)]
    candidates = [row for row in diagnostics if _guest(row)]
    if not candidates:
        candidates = [row for row in configs if _guest(row)]
        if len(candidates) != 1:
            return (candidates[0] if candidates else None), None, len(candidates) > 1
        return dict(candidates[0]), _index(candidates[0]), False
    if len(candidates) != 1:
        return dict(candidates[0]), None, True
    source = candidates[0]
    name = str(source.get("ifname") or "").lower()
    device = source.get("device")
    matches = [row for row in configs if (name and str(row.get("ifname") or "").lower() == name)
               or (not name and device and row.get("device") == device)]
    merged = dict(source)
    if len(matches) > 1:
        return merged, None, True
    if matches:
        other = matches[0]
        left, right = _index(source), _index(other)
        if (left is not None and right is not None and left != right) or (
            device and other.get("device") and device != other["device"]
        ):
            return merged, None, True
        for key, value in other.items():
            if (key not in merged or merged[key] is None or merged[key] == "") and value is not None and value != "":
                merged[key] = value
        return merged, left if left is not None else right, False
    return merged, _index(source), False
