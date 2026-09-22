"""Config-entry-scoped device lookups with support for older Home Assistant."""

def get_device(registry, config_entry_id, *, identifier=None, connection=None):
    """Avoid selecting another integration's device with the same MAC."""
    if hasattr(registry, "async_get_device_by_identifier"):
        if not config_entry_id:
            return None
        if identifier is not None:
            return registry.async_get_device_by_identifier(identifier, config_entry_id)
        return registry.async_get_device_by_connection(connection, config_entry_id)
    device = registry.async_get_device(
        identifiers={identifier} if identifier is not None else set(),
        connections={connection} if connection is not None else set(),
    )
    if device is not None and config_entry_id not in device.config_entries:
        return None
    return device
