"""Separate maintained HA tests from the pre-existing legacy suite (#325)."""

import asyncio

import freezegun
import pytest
from unittest.mock import patch

# These modules assert old entity names, service signatures or removed HA APIs.
# Their failures are reported by a separate CI job, never silently skipped.
# Remove a module here once its behavior and expectations have been reviewed.
LEGACY_TEST_FILES = frozenset({
    "test_binary_sensors.py", "test_button.py", "test_config_flow.py",
    "test_device_tracker.py", "test_diagnostics.py", "test_discovery.py",
    "test_init.py", "test_light.py", "test_luci.py", "test_select.py",
    "test_self_check.py", "test_sensor.py", "test_services.py", "test_switch.py",
    "test_update.py", "test_updater_ap_mode.py", "test_updater_default_mode.py",
    "test_updater_main.py", "test_updater_mesh_mode.py", "test_updater_repeater_mode.py",
})

# Already run without a Home Assistant runtime by validate.yml.
STANDALONE_TEST_FILES = frozenset({
    "test_issue_regressions.py", "test_security_exports.py", "test_self_counted_clients.py",
})


def pytest_addoption(parser):
    parser.addoption("--ha-suite", choices=("maintained", "legacy"), default=None)


@pytest.fixture
async def legacy_clock(configure_event_loop, hass):
    """Advance wall time and timer deadlines while asyncio keeps ticking."""
    loop = asyncio.get_running_loop()
    with freezegun.freeze_time(real_asyncio=True) as clock:
        # HA binds loop.time directly on the instance. Freezegun's real_asyncio
        # option only restores the loop class method, leaving this binding frozen.
        # Time-change callbacks fire scheduled timers, but HA debouncers also
        # compare loop.time() with their cooldown deadlines. Advancing only wall
        # time leaves those callbacks waiting on a real-time cooldown.
        offset = [0.0]
        original_move_to = clock.move_to

        def move_to(when):
            before = clock()
            original_move_to(when)
            offset[0] += (clock() - before).total_seconds()

        clock.move_to = move_to
        with patch.object(loop, "time", lambda: freezegun.api.real_monotonic() + offset[0]):
            # Time-based templates register shutdown cleanup after HA starts.
            # Leaving HA NOT_RUNNING means async_stop cannot clean these timers.
            await hass.async_start()
            try:
                yield clock
            finally:
                # Stop HA while its timer deadlines still use the same clock.
                # Restoring real time first leaves shutdown timers in the future.
                await hass.async_stop()


def pytest_ignore_collect(collection_path, config):
    """Select files before import so legacy collection errors cannot break the gate."""
    suite = config.getoption("--ha-suite")
    if suite is None or not collection_path.name.startswith("test_"):
        return None
    if collection_path.name in STANDALONE_TEST_FILES:
        return True
    legacy = collection_path.name in LEGACY_TEST_FILES
    return legacy if suite == "maintained" else not legacy


@pytest.fixture(autouse=True)
def auto_enable_custom_integrations(enable_custom_integrations):
    yield


@pytest.fixture(autouse=True)
def isolate_legacy_entity_capability_probes(request):
    """Entity refresh scripts describe polling, not the separate capability scan.

    Keep their endpoint side effects deterministic. The real probe is exercised
    by test_capability_detection.py rather than consuming these scripted polls.
    """
    if request.node.path.name not in {
        "test_binary_sensors.py", "test_button.py", "test_device_tracker.py",
        "test_light.py", "test_select.py", "test_sensor.py", "test_switch.py",
        "test_update.py",
        "test_updater_ap_mode.py", "test_updater_default_mode.py",
        "test_updater_mesh_mode.py", "test_updater_repeater_mode.py",
    }:
        yield
        return
    with patch(
        "custom_components.miwifi.compatibility.CompatibilityChecker.run",
        return_value={"device_list": True, "wifi_config": True, "portforward": False},
    ):
        yield
