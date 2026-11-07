"""The WAN debug log masks every secret in xqnetwork/wan_info, not only PPPoE's."""

# pylint: disable=protected-access

from __future__ import annotations

from copy import deepcopy
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from custom_components.miwifi.const import ATTR_SENSOR_WAN_IP, ATTR_SENSOR_WAN_TYPE
from custom_components.miwifi.updater import LuciUpdater, _mask_log_secrets

# The shape of a wan_info answer: PPPoE credentials in `details`, the VPN
# client's in `vpnInfo`. All values are made up.
WAN_INFO = {
    "code": 0,
    "info": {
        "link": 1,
        "status": 1,
        "gateWay": "192.0.2.1",
        "ipv4": [{"ip": "192.0.2.10", "mask": "255.255.255.0"}],
        "details": {"wanType": "pppoe", "username": "isp-user", "password": "pppoe-secret"},
        "vpnInfo": {
            "proto": "l2tp",
            "server": "vpn.example.com",
            "username": "vpn-user",
            "password": "vpn-secret",
        },
    },
}


def _updater() -> LuciUpdater:
    """Build an updater shell with only the attributes the WAN step touches."""

    updater = LuciUpdater.__new__(LuciUpdater)
    updater.is_ap_mode = False
    updater.ip = "192.0.2.104"
    updater.data = {}
    updater._is_cb0401v2 = False
    updater.luci = MagicMock()

    hass = MagicMock()

    async def _run(func, *args):
        return func(*args)

    hass.async_add_executor_job = _run
    updater.hass = hass

    return updater


@pytest.mark.asyncio
async def test_wan_log_masks_the_vpn_and_pppoe_passwords() -> None:
    """Neither password reaches the debug log; the sensors still read the answer."""

    answer = deepcopy(WAN_INFO)
    updater = _updater()
    updater.luci.wan_info = AsyncMock(return_value=answer)
    logger = MagicMock()

    with patch("custom_components.miwifi.updater._LOGGER", logger):
        await updater._async_prepare_wan(updater.data)

    logged = [
        call.args[1]
        for call in logger.debug.call_args_list
        if call.args and call.args[0] == "WAN info response: %s"
    ]
    assert len(logged) == 1
    text = repr(logged[0])
    assert "vpn-secret" not in text
    assert "pppoe-secret" not in text
    assert logged[0]["info"]["vpnInfo"]["password"] == "***"
    assert logged[0]["info"]["details"]["password"] == "***"
    assert logged[0]["info"]["vpnInfo"]["server"] == "vpn.example.com"

    assert answer == WAN_INFO
    assert updater.data[ATTR_SENSOR_WAN_TYPE] == "pppoe"
    assert updater.data[ATTR_SENSOR_WAN_IP] == "192.0.2.10"


def test_masking_reaches_every_level_and_keeps_empty_values() -> None:
    """A secret is masked wherever it is; an unset one stays visibly unset."""

    answer = {
        "info": {
            "vpnInfo": {"password": "", "proto": ""},
            "list": [{"token": "abc", "name": "x"}],
        },
        "stok": "def",
    }
    original = deepcopy(answer)

    assert _mask_log_secrets(answer) == {
        "info": {
            "vpnInfo": {"password": "", "proto": ""},
            "list": [{"token": "***", "name": "x"}],
        },
        "stok": "***",
    }
    assert answer == original


@pytest.mark.parametrize("answer", [None, "", "text", 0, []])
def test_masking_returns_an_answer_that_is_not_a_dict_as_it_is(answer) -> None:
    """Whatever the router answered still reaches the log."""

    assert _mask_log_secrets(answer) == answer
