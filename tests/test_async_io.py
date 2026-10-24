"""Regressions for filesystem work and log rotation on HA's event loop."""
import asyncio
import logging
import threading
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch
import pytest
from homeassistant.const import EVENT_HOMEASSISTANT_STOP

from custom_components.miwifi import frontend, logger, unsupported


async def test_manual_mac_save_load_clear_use_executor(hass, tmp_path):
    target = tmp_path / "nested" / "main.json"
    loop_thread = threading.get_ident()
    real_make, real_read, real_remove = frontend.os.makedirs, frontend._read_json_file, frontend.os.remove
    def make(*args, **kwargs):
        assert threading.get_ident() != loop_thread
        return real_make(*args, **kwargs)
    def read(*args):
        assert threading.get_ident() != loop_thread
        return real_read(*args)
    def remove(*args):
        assert threading.get_ident() != loop_thread
        return real_remove(*args)
    updater = SimpleNamespace(async_request_refresh=AsyncMock())
    with patch.object(hass.config, "path", return_value=str(target)), \
         patch.object(frontend.os, "makedirs", side_effect=make), \
         patch.object(frontend, "_read_json_file", new=read), \
         patch.object(frontend.os, "remove", new=remove), \
         patch("custom_components.miwifi.updater.async_get_integrations", return_value={"router": {"updater": updater}}):
        assert await frontend.async_load_manual_main_mac(hass) is None
        await frontend.async_save_manual_main_mac(hass, "02:00:00:00:00:01")
        assert await frontend.async_load_manual_main_mac(hass) == "02:00:00:00:00:01"
        updater.async_request_refresh.assert_awaited_once()
        await frontend.async_clear_manual_main_mac(hass)
        await frontend.async_clear_manual_main_mac(hass)  # Already absent is harmless.
    assert not target.exists()


async def test_bad_manual_mac_file_is_handled(hass, tmp_path):
    target = tmp_path / "main.json"
    await hass.async_add_executor_job(target.write_text, "not JSON")
    with patch.object(hass.config, "path", return_value=str(target)):
        assert await frontend.async_load_manual_main_mac(hass) is None


async def test_logger_import_has_no_filesystem_side_effects():
    # Import a fresh module name, keeping the actual integration logger intact.
    import importlib.util
    spec = importlib.util.spec_from_file_location("_miwifi_logger_io_check", logger.__file__)
    module = importlib.util.module_from_spec(spec)
    with patch.object(logger.os, "makedirs", side_effect=AssertionError("Import must not create directories")):
        spec.loader.exec_module(module)
    logger._LOGGER.removeFilter(module._LOGGER.filters[-1])


async def test_logging_setup_emit_rotation_and_reset_are_off_loop(hass, tmp_path):
    loop_thread = threading.get_ident()
    thread_ids = []
    original_emit = logger.RotatingFileHandler.emit
    def emit(handler, record):
        thread_ids.append(threading.get_ident())
        assert threading.get_ident() != loop_thread
        original_emit(handler, record)
    original_level = logger._LOGGER.level
    logger._LOGGER.setLevel(logging.DEBUG)
    root = tmp_path / "config"
    def config_path(*parts):
        return str(root.joinpath(*parts))
    try:
        with patch.object(hass.config, "path", side_effect=config_path), \
             patch.object(logger.RotatingFileHandler, "emit", new=emit):
            await asyncio.gather(logger.async_init_log_handlers(hass), logger.async_init_log_handlers(hass))
            handlers = [h for h in logger._LOGGER.handlers if getattr(h, "_miwifi_listener", None)]
            assert len(handlers) == 5
            # Force an actual rollover while the event loop emits the record.
            for handler in handlers:
                handler._miwifi_sink.maxBytes = 1
            logger._LOGGER.warning("Queue rotation test")
            await logger._remove_log_handlers(hass)  # Drains the listeners.
            assert thread_ids and loop_thread not in thread_ids
            path = root / "miwifi" / "logs" / "miwifi_warning.log"
            text = await hass.async_add_executor_job(path.read_text)
            assert "Queue rotation test" in text
            assert "Queue rotation test" not in await hass.async_add_executor_job((path.parent / "miwifi_info.log").read_text)
            await logger.async_recreate_log_handlers(hass)
            await logger._remove_log_handlers(hass)
    finally:
        await logger._remove_log_handlers(hass)
        logger._LOGGER.setLevel(original_level)


async def test_legacy_file_loading_runs_in_executor(hass):
    thread_id = threading.get_ident()
    def load():
        assert threading.get_ident() != thread_id
        return {}
    with patch.object(unsupported, "_read_legacy_user_file", new=load):
        await unsupported._migrate_legacy_py_if_needed(hass)


async def test_logger_setup_failure_closes_partial_handlers(hass, tmp_path):
    original = logger._create_handler
    def create(path, level):
        if level == logging.WARNING:
            raise OSError("test file unavailable")
        return original(path, level)
    with patch.object(hass.config, "path", side_effect=lambda *parts: str(tmp_path.joinpath(*parts))), \
         patch.object(logger, "_create_handler", new=create):
        with pytest.raises(OSError):
            await logger.async_init_log_handlers(hass)
    assert not hass.data.get("_miwifi_logger_initialized")
    assert not any(getattr(handler, "_miwifi_listener", None) for handler in logger._LOGGER.handlers)


async def test_logger_shutdown_drains_and_closes_files(hass, tmp_path):
    with patch.object(hass.config, "path", side_effect=lambda *parts: str(tmp_path.joinpath(*parts))):
        await logger.async_init_log_handlers(hass)
        logger._LOGGER.error("Shutdown drain check")
        hass.bus.async_fire(EVENT_HOMEASSISTANT_STOP)
        await hass.async_block_till_done()
    assert not hass.data.get("_miwifi_logger_initialized")
    assert not any(getattr(handler, "_miwifi_listener", None) for handler in logger._LOGGER.handlers)
    text = await hass.async_add_executor_job((tmp_path / "miwifi" / "logs" / "miwifi_error.log").read_text)
    assert "Shutdown drain check" in text
