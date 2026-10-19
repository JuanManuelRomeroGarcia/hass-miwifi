"""Optional NAT reads recover from LuCI transport failures without writes."""
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

import pytest

from custom_components.miwifi.exceptions import LuciConnectionError, LuciRequestError
from custom_components.miwifi.updater import LuciUpdater


@pytest.mark.parametrize("failed_call", [1, 2, "retry"])
async def test_nat_connection_error_keeps_snapshot_and_recovers(failed_call):
    snapshot = {"ftype_1": [{"name": "existing"}], "ftype_2": [], "total": 1}
    error = LuciConnectionError("synthetic connection failure")
    if failed_call == "retry":
        replies = [LuciRequestError("invalid token"), error]
    elif failed_call == 2:
        replies = [{"list": []}, error]
    else:
        replies = [error]
    router = SimpleNamespace(
        data={"nat_rules": snapshot}, ip="192.0.2.1",
        hass=SimpleNamespace(async_add_executor_job=AsyncMock()),
        luci=SimpleNamespace(portforward=AsyncMock(side_effect=replies), login=AsyncMock()),
    )
    now = datetime(2026, 10, 19, 12, tzinfo=UTC)
    with patch("custom_components.miwifi.updater.dt_util.utcnow", return_value=now):
        await LuciUpdater._async_prepare_nat_rules(router)
        assert router.data["nat_rules"] is snapshot
        router.luci.portforward.reset_mock()
        await LuciUpdater._async_prepare_nat_rules(router)
        router.luci.portforward.assert_not_awaited()
    router.luci.portforward.side_effect = [{"list": [{"name": "single"}]}, {"list": [{"name": "range"}]}]
    with patch("custom_components.miwifi.updater.dt_util.utcnow", return_value=now + timedelta(seconds=61)):
        await LuciUpdater._async_prepare_nat_rules(router)
    assert router.data["nat_rules"]["total"] == 2
    assert router.luci.portforward.await_count == 2
    assert router.luci.login.await_count == (1 if failed_call == "retry" else 0)
