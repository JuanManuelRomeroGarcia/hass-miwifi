"""Fixtures shared by the whole suite."""

from __future__ import annotations

from unittest.mock import AsyncMock, patch

import pytest

from custom_components.miwifi.const import DEFAULT_PANEL_VERSION


@pytest.fixture(autouse=True)
def auto_enable_custom_integrations(enable_custom_integrations):
    """Let Home Assistant load the integration from custom_components.

    Without this fixture the component is invisible to the config entry
    machinery, and every flow test fails with UnknownHandler.
    """

    yield


@pytest.fixture(autouse=True)
def stub_panel_version():
    """Keep the frontend panel version check off the network.

    Every update cycle reads it, and on the empty config directory a test runs
    with that means downloading the panel from GitHub over an aiohttp session of
    its own - a real socket, which the harness blocks and then reports at
    teardown as "the test opens sockets".
    """

    with patch(
        "custom_components.miwifi.frontend.read_local_version",
        AsyncMock(return_value=DEFAULT_PANEL_VERSION),
    ), patch(
        "custom_components.miwifi.frontend.async_read_remote_version",
        AsyncMock(return_value=None),
    ):
        yield
