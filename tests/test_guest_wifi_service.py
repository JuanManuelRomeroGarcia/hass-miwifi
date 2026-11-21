"""Guest saves preserve unedited settings and never retry a write automatically."""
from types import SimpleNamespace
from unittest.mock import AsyncMock, Mock, patch

import pytest
import voluptuous as vol
from httpx import Response

from custom_components.miwifi.services import MiWifiSetGuestWifiServiceCall
from custom_components.miwifi.luci import LuciClient
from custom_components.miwifi.exceptions import LuciConnectionError, LuciRequestError


async def call_guest(hass, data, response=None, *, missing=False, details_only=False, diag_rows=None, detail_rows=None):
    rows = [] if missing else [{"iftype": 3, "ifname": "wl14", "device": "wifi3.network1",
                               "ssid": "Existing guest", "encryption": "psk2", "password": "Existing-secret"}]
    luci = SimpleNamespace(
        wifi_diag_detail_all=AsyncMock(return_value={"info": diag_rows if diag_rows is not None else ([] if details_only else rows)}),
        wifi_detail_all=AsyncMock(return_value={"info": detail_rows if detail_rows is not None else rows}),
        login=AsyncMock(), set_guest_wifi=AsyncMock(
            side_effect=response if isinstance(response, BaseException) else None, return_value=response),
        set_wifi=AsyncMock(return_value={"code": 0}),
    )
    updater = SimpleNamespace(luci=luci, ip="192.0.2.1", async_request_refresh=AsyncMock())
    handler = MiWifiSetGuestWifiServiceCall(hass)
    handler.get_updater = Mock(return_value=updater)
    notifier = SimpleNamespace(get_translations=AsyncMock(return_value={}), notify=AsyncMock())
    with patch("custom_components.miwifi.services.MiWiFiNotifier", return_value=notifier):
        try:
            await handler.async_call_service(SimpleNamespace(data=data))
        except vol.Invalid:
            return luci, updater, notifier, True
    return luci, updater, notifier, False


@pytest.mark.parametrize("enable", [True, False])
@pytest.mark.parametrize("password", [None, ""])
async def test_state_only_keeps_all_existing_configuration(hass, enable, password):
    data = {"enable": enable}
    if password is not None:
        data["password"] = password  # Empty means keep, even for an older panel.
    luci, updater, notifier, failed = await call_guest(hass, data, {"code": 0})
    assert not failed
    luci.set_guest_wifi.assert_awaited_once()
    assert luci.set_guest_wifi.call_args.kwargs == {"retry_auth": False}
    payload = luci.set_guest_wifi.call_args.args[0]
    assert payload == {"wifiIndex": 3, "ifname": "wl14", "on": int(enable),
                       "enable": int(enable), "enabled": int(enable)}
    luci.set_wifi.assert_not_awaited()
    updater.async_request_refresh.assert_awaited_once()
    notifier.notify.assert_not_awaited()  # The panel confirms readback before success.


@pytest.mark.parametrize("response", [{"code": 1}, None, {}, "invalid", [],
                                      LuciConnectionError("unanswered"), LuciRequestError("rejected")])
async def test_rejected_or_malformed_reply_does_not_retry_or_announce_success(hass, response):
    luci, updater, notifier, failed = await call_guest(hass, {"enable": True}, response)
    assert failed
    luci.set_guest_wifi.assert_awaited_once()
    luci.set_wifi.assert_not_awaited()
    updater.async_request_refresh.assert_not_awaited()
    notifier.notify.assert_not_awaited()


async def test_explicit_configuration_edits_are_forwarded(hass):
    luci, _, _, failed = await call_guest(hass, {
        "enable": True, "ssid": "Requested guest", "encryption": "psk2",
        "hidden": 1, "password": "Requested-secret",
    }, {"code": "0"})
    assert not failed
    payload = luci.set_guest_wifi.call_args.args[0]
    assert payload["ssid"] == "Requested guest"
    assert payload["hidden"] == 1
    assert payload["encryption"] == payload["enctype"] == "psk2"
    assert payload["password"] == payload["pwd"] == payload["passwd"] == "Requested-secret"


async def test_missing_guest_network_cannot_write_default_index(hass):
    luci, _, _, failed = await call_guest(hass, {"enable": True}, {"code": 0}, missing=True)
    assert failed
    luci.set_guest_wifi.assert_not_awaited()


async def test_guest_reported_only_by_details_can_still_be_saved(hass):
    luci, _, _, failed = await call_guest(hass, {"enable": True}, {"code": 0}, details_only=True)
    assert not failed
    luci.wifi_detail_all.assert_awaited_once()
    luci.set_guest_wifi.assert_awaited_once()


@pytest.mark.parametrize("single_write", [True, False])
async def test_guest_auth_retry_is_disabled_only_for_panel_saves(single_write):
    client = LuciClient(AsyncMock(), "192.0.2.1", "synthetic", "sha1", protocol="http")
    client._url = "http://192.0.2.1/cgi-bin/luci"
    client._token = "synthetic-token"
    client._request_with_retry = AsyncMock(side_effect=[
        Response(200, json={"code": 1, "msg": "invalid token"}),
        Response(200, json={"code": 0}),
    ])
    client.login = AsyncMock()
    if single_write:
        with pytest.raises(LuciRequestError):
            await client.set_guest_wifi({"on": 1, "wifiIndex": 3}, retry_auth=False)
        client._request_with_retry.assert_awaited_once()
        client.login.assert_not_awaited()
    else:
        assert await client.set_guest_wifi({"on": 1, "wifiIndex": 3}) == {"code": 0}
        assert client._request_with_retry.await_count == 2
        client.login.assert_awaited_once()

@pytest.mark.parametrize("enable", [True, False])
async def test_index_from_matching_detail_is_used(hass, enable):
    diag = [{"ifname": "wl14", "iftype": 3, "status": "0"}]
    detail = [{"ifname": "wl14", "device": "wifi7.network1", "ssid": "Guest"}]
    luci, _, _, failed = await call_guest(hass, {"enable": enable}, {"code": 0}, diag_rows=diag, detail_rows=detail)
    assert not failed
    assert luci.set_guest_wifi.call_args.args[0]["wifiIndex"] == 7
    assert luci.set_guest_wifi.call_args.args[0]["ifname"] == "wl14"

@pytest.mark.parametrize("diag,detail", [
    ([{"ifname": "wl14", "iftype": 3}], []),
    ([{"ifname": "wl14", "iftype": 3, "device": "wifi3.network1"}], [{"ifname": "wl14", "device": "wifi7.network1"}]),
    ([{"ifname": "wl14", "iftype": 3}], [{"ifname": "wl33", "device": "wifi7.network1"}]),
])
async def test_unverifiable_or_conflicting_index_never_writes(hass, diag, detail):
    luci, _, _, failed = await call_guest(hass, {"enable": True}, {"code": 0}, diag_rows=diag, detail_rows=detail)
    assert failed
    luci.login.assert_not_awaited()
    luci.set_guest_wifi.assert_not_awaited()
