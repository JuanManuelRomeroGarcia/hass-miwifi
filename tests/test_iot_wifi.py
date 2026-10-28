"""IoT role/firmware gating, secret handling and non-retried writes."""
from copy import deepcopy
from types import SimpleNamespace
from unittest.mock import AsyncMock

import httpx
import pytest
from homeassistant.components import websocket_api

from custom_components.miwifi.const import DOMAIN, UPDATER
from custom_components.miwifi.iot_wifi import IotError, manager
from custom_components.miwifi.luci import LuciClient
from custom_components.miwifi import ws_api


@pytest.fixture
def iot(hass):
    payload = {"code": 0, "advanceInfo": {"enable": 1, "wifi5mode": 1}, "basicInfo": [
        {"ssid": "IoT &amp; 2G", "ssidHtmlEncode": 1, "encryption": "psk2", "password": "kept-key-2g"},
        {"ssid": "IoT 5G", "ssidHtmlEncode": 1, "encryption": "psk2", "password": "kept-key-5g"},
    ]}
    api = SimpleNamespace(get=AsyncMock(side_effect=lambda *a, **kw: deepcopy(payload)), set_iot_wifi=AsyncMock())
    updater = SimpleNamespace(luci=api, data={"model": "rc01", "device_sw_version": "1.1.56 (CN)",
        "topo_graph": {"graph": {"is_main": True}}})
    hass.data[DOMAIN] = {"selected": {UPDATER: updater}}
    return manager(hass, "selected"), updater, payload


async def test_admin_view_includes_current_keys_for_masked_fields(iot):
    m, updater, _ = iot
    result = await m.read()
    assert result["bands"][0]["ssid"] == "IoT & 2G"
    assert result["bands"][0]["has_password"]
    assert result["bands"][0]["password"] == "kept-key-2g"
    assert result["bands"][1]["password"] == "kept-key-5g"
    updater.luci.set_iot_wifi.assert_not_awaited()


@pytest.mark.parametrize("changes", [{"model": "rc06"}, {"device_sw_version": "1.1.57"},
    {"topo_graph": {"graph": {"is_main": False}}}])
async def test_unknown_model_firmware_or_leaf_never_reads(iot, changes):
    m, updater, _ = iot
    updater.data.update(changes)
    with pytest.raises(IotError, match="unsupported"):
        await m.read()
    updater.luci.get.assert_not_awaited()


async def test_write_preserves_keys_and_mode_and_checks_result(iot):
    m, updater, payload = iot
    before = await m.read()
    async def apply(params, **kwargs):
        assert params["password2g"] == "kept-key-2g"
        assert params["password5g"] == "kept-key-5g"
        assert params["wifi5mode"] == 1
        payload["advanceInfo"]["enable"] = params["enable"]
        payload["basicInfo"][0]["ssid"] = params["ssid2g"]
    updater.luci.set_iot_wifi.side_effect = apply
    result = await m.write(before["revision"], False, [{"ssid": "New IoT"}, {"ssid": "IoT 5G"}])
    assert result["enabled"] is False
    assert result["bands"][0]["ssid"] == "New IoT"
    assert result["bands"][0]["password"] == "kept-key-2g"
    updater.luci.set_iot_wifi.assert_awaited_once()


async def test_stale_preflight_never_writes(iot):
    m, updater, payload = iot
    before = await m.read()
    payload["basicInfo"][0]["ssid"] = "Changed elsewhere"
    with pytest.raises(IotError, match="stale"):
        await m.write(before["revision"], False, [{"ssid": "New"}, {"ssid": "IoT 5G"}])
    updater.luci.set_iot_wifi.assert_not_awaited()


async def test_invalid_keys_and_non_wpa2_never_write(iot):
    m, updater, payload = iot
    before = await m.read()
    with pytest.raises(IotError, match="invalid"):
        await m.write(before["revision"], True, [{"ssid": "New", "password": "short"}, {"ssid": "IoT 5G"}])
    updater.luci.set_iot_wifi.assert_not_awaited()
    payload["basicInfo"][0]["encryption"] = "ccmp"
    before = await m.read()
    assert not before["writable"]
    with pytest.raises(IotError, match="unsupported"):
        await m.write(before["revision"], False, [{"ssid": "New"}, {"ssid": "IoT 5G"}])
    updater.luci.set_iot_wifi.assert_not_awaited()


async def test_unanswered_write_never_retries_and_reload_restores_revision(iot):
    m, updater, _ = iot
    before = await m.read()
    updater.luci.set_iot_wifi.side_effect = TimeoutError()
    with pytest.raises(IotError, match="unverified"):
        await m.write(before["revision"], False, [{"ssid": "IoT & 2G"}, {"ssid": "IoT 5G"}])
    updater.luci.set_iot_wifi.assert_awaited_once()
    with pytest.raises(IotError, match="stale"):
        await m.write(before["revision"], False, [{"ssid": "IoT & 2G"}, {"ssid": "IoT 5G"}])
    assert (await m.read())["revision"] is not None


async def test_luci_posts_keys_in_body_without_diagnostic_retention():
    requests = []
    def handle(request):
        requests.append(request)
        return httpx.Response(200, json={"code": 0})
    async with httpx.AsyncClient(transport=httpx.MockTransport(handle)) as transport:
        client = LuciClient(transport, ip="192.0.2.1", password="test", protocol="http")
        client._url = "http://192.0.2.1/cgi-bin/luci"
        client._token = "test-session"
        await client.set_iot_wifi({"password2g": "secret-test-key"})
        assert len(requests) == 1 and requests[0].method == "POST"
        assert "secret-test-key" not in str(requests[0].url)
        assert b"secret-test-key" in requests[0].content
        client._debug("Successful request", "url", '{"password":"secret"}', "xqnetwork/get_iotwifi_info")
        assert not client.diagnostics


async def test_iot_write_never_follows_a_redirect_with_passwords():
    requests = []
    def handle(request):
        requests.append(request)
        return httpx.Response(307, headers={"Location": "http://192.0.2.99/elsewhere"})
    async with httpx.AsyncClient(transport=httpx.MockTransport(handle), follow_redirects=True) as transport:
        client = LuciClient(transport, ip="192.0.2.1", password="test", protocol="http")
        client._url = "http://192.0.2.1/cgi-bin/luci"
        client._token = "test-session"
        with pytest.raises(httpx.HTTPStatusError):
            await client.set_iot_wifi({"password2g": "secret-test-key"})
        assert len(requests) == 1
        assert requests[0].url.host == "192.0.2.1"


@pytest.mark.parametrize("write", [False, True])
async def test_iot_websockets_require_admin(hass, hass_ws_client, hass_read_only_user, write):
    for handler in (ws_api.websocket_iot_read, ws_api.websocket_iot_write):
        websocket_api.async_register_command(hass, handler)
    token = await hass.auth.async_create_refresh_token(hass_read_only_user, client_id="https://test.example")
    client = await hass_ws_client(hass, hass.auth.async_create_access_token(token))
    message = {"id": 1, "type": "miwifi/iot_read", "router_mac": "02:00:00:00:00:01"}
    if write:
        message = {"id": 1, "type": "miwifi/iot_write", "entry_id": "selected", "revision": "test", "enabled": True, "bands": []}
    await client.send_json(message)
    assert (await client.receive_json())["error"]["code"] == "unauthorized"
