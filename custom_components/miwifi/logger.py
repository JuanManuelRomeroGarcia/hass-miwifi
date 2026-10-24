import logging
import asyncio
import os
import time
from logging.handlers import QueueHandler, QueueListener, RotatingFileHandler
from queue import SimpleQueue
from homeassistant.const import EVENT_HOMEASSISTANT_STOP

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

def _create_handler(path, level):
    """Open files in the executor and emit/rotate only on the listener thread."""
    os.makedirs(os.path.dirname(path), exist_ok=True)
    sink = RotatingFileHandler(path, maxBytes=2_000_000, backupCount=3, encoding="utf-8")
    sink.setFormatter(logging.Formatter('%(asctime)s - %(levelname)s - %(message)s'))
    queue = SimpleQueue()
    handler = QueueHandler(queue)
    handler.addFilter(lambda record: record.levelno == level)
    handler._miwifi_path = path
    handler._miwifi_sink = sink
    handler._miwifi_listener = QueueListener(queue, sink)
    handler._miwifi_listener.start()
    return handler


def _close_handler(handler):
    handler._miwifi_listener.stop()
    handler._miwifi_sink.close()
    handler.close()

async def async_add_level_handler(hass, level, filename):
    path = hass.config.path("miwifi", "logs", filename)
    # Avoid opening a duplicate file at all.
    for existing in _LOGGER.handlers:
        if getattr(existing, "_miwifi_path", None) == path:
            return
    handler = await hass.async_add_executor_job(_create_handler, path, level)
    _LOGGER.addHandler(handler)

async def _init_log_handlers(hass):
    """Initialize log handlers only once."""
    if hass.data.get("_miwifi_logger_initialized"):
        return

    await async_add_level_handler(hass, logging.INFO, "miwifi_info.log")
    await async_add_level_handler(hass, logging.WARNING, "miwifi_warning.log")
    await async_add_level_handler(hass, logging.ERROR, "miwifi_error.log")
    await async_add_level_handler(hass, logging.CRITICAL, "miwifi_critical.log")
    await async_add_level_handler(hass, logging.DEBUG, "miwifi_debug.log")

    hass.data["_miwifi_logger_initialized"] = True


async def _remove_log_handlers(hass):
    for handler in list(_LOGGER.handlers):
        if getattr(handler, "_miwifi_listener", None) is not None:
            _LOGGER.removeHandler(handler)
            await hass.async_add_executor_job(_close_handler, handler)
    hass.data["_miwifi_logger_initialized"] = False


async def async_init_log_handlers(hass):
    async with hass.data.setdefault("_miwifi_logger_lock", asyncio.Lock()):
        try:
            await _init_log_handlers(hass)
        except BaseException:
            await _remove_log_handlers(hass)
            raise
        if not hass.data.get("_miwifi_logger_stop_registered"):
            async def stop(_event):
                async with hass.data["_miwifi_logger_lock"]:
                    await _remove_log_handlers(hass)
            hass.bus.async_listen_once(EVENT_HOMEASSISTANT_STOP, stop)
            hass.data["_miwifi_logger_stop_registered"] = True

async def async_warmup_log_handlers(hass):
    """Compatibility hook: files were already opened in the setup executor."""
    return

__all__ = ["_LOGGER", "async_init_log_handlers", "async_recreate_log_handlers", "async_warmup_log_handlers"]

async def _recreate_log_handlers(hass):
    """Recreate all handlers and empty log files asynchronously."""
    global _LOGGER

    await _remove_log_handlers(hass)

    def _clear_logs():
        log_dir = hass.config.path("miwifi", "logs")
        os.makedirs(log_dir, exist_ok=True)
        for file in os.listdir(log_dir):
            if file.startswith("miwifi_") and (file.endswith(".log") or ".log." in file):
                try:
                    os.remove(os.path.join(log_dir, file))
                except Exception as e:
                    _LOGGER.warning("Log could not be eliminated %s: %s", file, e)
    await hass.async_add_executor_job(_clear_logs)
    hass.data["_miwifi_logger_initialized"] = False 
    await _init_log_handlers(hass)
    await async_warmup_log_handlers(hass)
    await hass.async_add_executor_job(_LOGGER.info, "🧹 MiWiFi logs cleared and handlers recreated.")


async def async_recreate_log_handlers(hass):
    """Serialize reset with setup; all file work happens off the event loop."""
    async with hass.data.setdefault("_miwifi_logger_lock", asyncio.Lock()):
        await _recreate_log_handlers(hass)
