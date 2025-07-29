import logging
import os
import time
from logging.handlers import RotatingFileHandler
from homeassistant.helpers import storage

log_dir = os.path.join(storage.STORAGE_DIR, '..', 'miwifi', 'logs')
os.makedirs(log_dir, exist_ok=True)

_LOGGER = logging.getLogger("miwifi")
_LOGGER.setLevel(logging.NOTSET)

class RateLimitFilter(logging.Filter):
    """Limit identical log messages to avoid flooding."""
    def __init__(self, max_per_minute=30):
        super().__init__()
        self.max_per_minute = max_per_minute
        self.msg_counts = {}
        self.reset_time = time.time()

    def filter(self, record):
        now = time.time()
        if now - self.reset_time > 60:
            self.msg_counts.clear()
            self.reset_time = now
        msg_key = record.getMessage()
        count = self.msg_counts.get(msg_key, 0)
        if count >= self.max_per_minute:
            return False
        self.msg_counts[msg_key] = count + 1
        return True

_LOGGER.addFilter(RateLimitFilter(max_per_minute=30))

def _create_handler(path):
    return RotatingFileHandler(path, maxBytes=2_000_000, backupCount=3, delay=False)

async def async_add_level_handler(hass, level, filename):
    path = os.path.join(log_dir, filename)
    handler = await hass.async_add_executor_job(_create_handler, path)
    formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
    handler.setFormatter(formatter)
    handler.setLevel(logging.NOTSET)
    handler.addFilter(lambda record: record.levelno == level)
    # Evitar añadir duplicados
    for existing in _LOGGER.handlers:
        if isinstance(existing, RotatingFileHandler) and existing.baseFilename == handler.baseFilename:
            return
    _LOGGER.addHandler(handler)

async def async_init_log_handlers(hass):
    """Initialize log handlers only once."""
    if hass.data.get("_miwifi_logger_initialized"):
        return

    await async_add_level_handler(hass, logging.INFO, "miwifi_info.log")
    await async_add_level_handler(hass, logging.WARNING, "miwifi_warning.log")
    await async_add_level_handler(hass, logging.ERROR, "miwifi_error.log")
    await async_add_level_handler(hass, logging.CRITICAL, "miwifi_critical.log")
    await async_add_level_handler(hass, logging.DEBUG, "miwifi_debug.log")

    hass.data["_miwifi_logger_initialized"] = True

async def async_warmup_log_handlers(hass):
    """Force open of all log files by doing an initial emit in executor."""
    def _warmup():
        for handler in _LOGGER.handlers:
            try:
                handler.acquire()
                handler.emit(logging.LogRecord(
                    name="miwifi",
                    level=logging.DEBUG,
                    pathname=__file__,
                    lineno=0,
                    msg="Pre-opening log file",
                    args=(),
                    exc_info=None
                ))
            finally:
                handler.release()
    await hass.async_add_executor_job(_warmup)

__all__ = ["_LOGGER", "async_init_log_handlers", "async_recreate_log_handlers", "async_warmup_log_handlers"]

async def async_recreate_log_handlers(hass):
    """Recreate all handlers and empty log files asynchronously."""
    global _LOGGER

    for handler in list(_LOGGER.handlers):
        try:
            handler.close()
        except Exception:
            pass
        _LOGGER.removeHandler(handler)

    def _clear_logs():
        for file in os.listdir(log_dir):
            if file.startswith("miwifi_") and (file.endswith(".log") or ".log." in file):
                try:
                    os.remove(os.path.join(log_dir, file))
                except Exception as e:
                    _LOGGER.warning("Log could not be eliminated %s: %s", file, e)
    await hass.async_add_executor_job(_clear_logs)
    hass.data["_miwifi_logger_initialized"] = False 
    await async_init_log_handlers(hass)
    await async_warmup_log_handlers(hass)
    await hass.async_add_executor_job(_LOGGER.info, "🧹 MiWiFi logs cleared and handlers recreated.")
