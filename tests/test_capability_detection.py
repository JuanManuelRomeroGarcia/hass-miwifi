"""Capability scans distinguish unsupported endpoints from temporary outages."""

from unittest.mock import AsyncMock, Mock, patch

import pytest

from custom_components.miwifi.compatibility import CompatibilityChecker
from custom_components.miwifi.enum import Mode
from custom_components.miwifi.exceptions import LuciConnectionError, LuciError


@pytest.mark.parametrize("raw_mode, skips_firmware", [(0, False), (1, True)])
async def test_scan_checks_endpoints_and_respects_router_mode(hass, raw_mode, skips_firmware):
    client = Mock()
    for method in (
        "macfilter_info", "qos_info", "rom_update", "flash_permission", "led",
        "wifi_diag_detail_all", "wifi_detail_all", "device_list", "topo_graph",
        "portforward",
    ):
        setattr(client, method, AsyncMock(return_value={"code": 0, "info": []}))
    client.mode = AsyncMock(return_value={"mode": raw_mode})
    client.init_info = AsyncMock(return_value={"hardware": "RA67"})
    checker = CompatibilityChecker(hass, client)
    checker._log = AsyncMock()

    with patch("custom_components.miwifi.compatibility.get_combined_unsupported", return_value={}):
        result = await checker.run()

    assert checker.mode == Mode(raw_mode)
    assert result["device_list"] is (None if skips_firmware else True)
    assert result["wifi_config"] is True
    assert result["topo_graph"] is (None if skips_firmware else True)
    assert client.device_list.await_count == (0 if skips_firmware else 1)
    assert client.rom_update.await_count == (0 if skips_firmware else 1)
    assert result["rom_update"] is (None if skips_firmware else True)


@pytest.mark.parametrize(
    "failure, expected",
    [(LuciConnectionError("offline"), None), (LuciError("404 not found"), False)],
    ids=["temporary-outage", "unsupported-endpoint"],
)
async def test_capability_scan_failure_classification(hass, failure, expected):
    client = Mock(device_list=AsyncMock(side_effect=failure))
    checker = CompatibilityChecker(hass, client, max_retries=1)
    checker._log = AsyncMock()

    result = await checker._safe_call(checker._check_device_list, "device_list")

    assert result is expected
    client.device_list.assert_awaited_once_with()
