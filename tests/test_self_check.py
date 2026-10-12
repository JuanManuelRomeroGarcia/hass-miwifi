"""Self-check reports current endpoints, versions and an actionable issue link."""

from urllib.parse import parse_qs, urlsplit
from unittest.mock import AsyncMock, patch
import re

import pytest

from custom_components.miwifi.self_check import async_self_check
from tests.setup import async_mock_luci_client


@pytest.mark.parametrize("failed", [False, True], ids=["supported", "unsupported"])
async def test_self_check(hass, failed):
    from custom_components.miwifi.exceptions import LuciError

    with patch("custom_components.miwifi.updater.LuciClient") as factory:
        await async_mock_luci_client(factory)
        client = factory.return_value
        if failed:
            client.mode = AsyncMock(side_effect=LuciError("unsupported mode"))
        translations = {"notifications": {
            "self_check_title": "Router not supported",
            "self_check_message": "Some methods failed in router ({model}).",
        }}
        with patch("custom_components.miwifi.self_check.MiWiFiNotifier.get_translations", return_value=translations), patch(
            "custom_components.miwifi.self_check.MiWiFiNotifier.notify", new_callable=AsyncMock
        ) as notify:
            await async_self_check(hass, client, "R3600")
    notify.assert_awaited_once()
    body = notify.call_args.args[0]
    assert notify.call_args.kwargs == {
        "title": "Router not supported", "notification_id": "miwifi_self_check",
    }
    assert "Some methods failed in router (R3600)." in body
    assert " * xqnetwork/mode: " + ("🔴" if failed else "🟢") in body
    assert " * xqnetwork/get_netmode: 🟢" in body
    assert " * misystem/status: 🟢" in body
    assert " * xqsystem/reboot: ⚪" in body
    assert "MiWiFi Integration:" in body
    assert "Frontend Panel:" in body
    assert "Home Assistant:" in body
    link = re.search(r'href="([^"]+)"', body).group(1)
    parsed = urlsplit(link)
    assert parsed.netloc == "github.com"
    assert parsed.path == "/JuanManuelRomeroGarcia/hass-miwifi/issues/new"
    query = parse_qs(parsed.query)
    assert query["title"] == ["Add support for R3600"]
    assert query["body"][0] == body.split('<a href=')[0]
