"""MiWiFi utilities."""

def parse_memory_to_mb(value: str | int | float) -> int:
    """Convert memory string with units (e.g., '2GB', '512MB') to MB."""
    if value is None:
        return 0
    if isinstance(value, (int, float)):
        return int(value)
    try:
        val = str(value).strip().upper()
        number = float("".join(c for c in val if c.isdigit() or c == "."))
        if "GB" in val:
            return int(number * 1024)
        if "MB" in val:
            return int(number)
        return int(number)
    except Exception:
        return 0
