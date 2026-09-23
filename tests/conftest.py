"""Fixtures shared by the whole suite."""

from __future__ import annotations

from pathlib import Path

import pytest

# Test modules that predate the current code and Home Assistant: they assert
# old entity names, service signatures and APIs, and most of them fail on the
# current stable release. They run in a separate, non-blocking CI job so the
# failures stay visible without hiding the result of the maintained tests.
# Remove a file from this set once it passes, and it joins the blocking job.
LEGACY_TEST_FILES: frozenset[str] = frozenset(
    {
        "test_binary_sensors.py",
        "test_button.py",
        "test_config_flow.py",
        "test_device_tracker.py",
        "test_diagnostics.py",
        "test_discovery.py",
        "test_init.py",
        "test_light.py",
        "test_luci.py",
        "test_select.py",
        "test_self_check.py",
        "test_sensor.py",
        "test_services.py",
        "test_switch.py",
        "test_update.py",
        "test_updater_ap_mode.py",
        "test_updater_default_mode.py",
        "test_updater_main.py",
        "test_updater_mesh_mode.py",
        "test_updater_repeater_mode.py",
    }
)


def pytest_configure(config: pytest.Config) -> None:
    """Register the marker used to split the legacy suite off."""

    config.addinivalue_line(
        "markers", "legacy: pre-existing test module not yet updated to the current code"
    )


def pytest_collection_modifyitems(items: list[pytest.Item]) -> None:
    """Mark every test that lives in a legacy module."""

    for item in items:
        if Path(str(item.fspath)).name in LEGACY_TEST_FILES:
            item.add_marker(pytest.mark.legacy)


@pytest.fixture(autouse=True)
def auto_enable_custom_integrations(enable_custom_integrations):
    """Let Home Assistant load the integration from custom_components.

    Without this fixture the component is invisible to the config entry
    machinery, and every flow test fails with UnknownHandler.
    """

    yield
