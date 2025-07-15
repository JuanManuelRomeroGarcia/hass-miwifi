import logging
import os
from logging.handlers import RotatingFileHandler
from homeassistant.helpers import storage

# Log folder at/config/miwifi/logs
log_dir = os.path.join(storage.STORAGE_DIR, '..', 'miwifi', 'logs')
os.makedirs(log_dir, exist_ok=True)

_LOGGER = logging.getLogger("miwifi")
_LOGGER.setLevel(logging.NOTSET)

# Handlers level
def add_level_handler(level, filename):
    path = os.path.join(log_dir, filename)
    handler = RotatingFileHandler(path, maxBytes=2_000_000, backupCount=3)
    formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
    handler.setFormatter(formatter)
    handler.setLevel(logging.NOTSET)
    handler.addFilter(lambda record: record.levelno == level)
    _LOGGER.addHandler(handler)

# Add always-on logs
add_level_handler(logging.INFO, "miwifi_info.log")
add_level_handler(logging.WARNING, "miwifi_warning.log")
add_level_handler(logging.ERROR, "miwifi_error.log")
add_level_handler(logging.CRITICAL, "miwifi_critical.log")
add_level_handler(logging.DEBUG, "miwifi_debug.log")  # Activated if global level is DEBUG

__all__ = ["_LOGGER"]

# Startup message
if _LOGGER.isEnabledFor(logging.DEBUG):
    _LOGGER.info("✅ MiWiFi started in DEBUG mode")
else:
    _LOGGER.info("ℹ️ MiWiFi started in non-debug mode (INFO or higher)")

def recreate_log_handlers():
    """Recreate all handlers and empty log files."""
    global _LOGGER

    # Remove current handlers
    for handler in list(_LOGGER.handlers):
        _LOGGER.removeHandler(handler)

    # Delete log files
    for file in os.listdir(log_dir):
        if file.startswith("miwifi_") and (file.endswith(".log") or ".log." in file):
            try:
                os.remove(os.path.join(log_dir, file))
            except Exception as e:
                _LOGGER.warning("Log could not be eliminated %s: %s", file, e)

    # Recreate handlers
    add_level_handler(logging.INFO, "miwifi_info.log")
    add_level_handler(logging.WARNING, "miwifi_warning.log")
    add_level_handler(logging.ERROR, "miwifi_error.log")
    add_level_handler(logging.CRITICAL, "miwifi_critical.log")
    add_level_handler(logging.DEBUG, "miwifi_debug.log")

    _LOGGER.info("🧹 MiWiFi logs cleared and handlers recreated.")
