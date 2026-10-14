"""Validate DHCP API payloads, isolated writes and HA websocket authorization."""
import asyncio
import json
from copy import deepcopy
from types import SimpleNamespace
from unittest.mock import AsyncMock

import httpx
import pytest

from homeassistant.components import websocket_api
from custom_components.miwifi import ws_api
from custom_components.miwifi.const import DOMAIN, UPDATER
from custom_components.miwifi.dhcp import DhcpError, DhcpManager, get_manager
from custom_components.miwifi.exceptions import LuciRequestError
from custom_components.miwifi.luci import LuciClient

MAC = "02:00:00:00:00:51"
OTHER = {"mac": "02:00:00:00:00:52", "ip": "192.0.2.52", "name": "Other"}
NEW = {"mac": MAC, "ip": "192.0.2.51", "name": "Watch"}


@pytest.fixture
def router():
    rows = [deepcopy(OTHER)]

    async def bind(row):
        rows[:] = [item for item in rows if item["mac"] != row["mac"]] + [deepcopy(row)]
        return {"code": 0}

    async def unbind(mac):
        rows[:] = [item for item in rows if item["mac"] != mac]
        return {"code": 0}

    api = SimpleNamespace(
        rows=rows,
        dhcp_bindings=AsyncMock(side_effect=lambda: {"code": 0, "list": deepcopy(rows), "devicelist": []}),
        dhcp_settings=AsyncMock(return_value={"code": 0, "info": {"ignore": "0", "lanIp": [{"ip": "192.0.2.1", "mask": "255.255.255.0"}]}}),
        init_info=AsyncMock(return_value={"code": 0, "hardware": "RC01", "romversion": "1.1.56"}),
        dhcp_bind=AsyncMock(side_effect=bind), dhcp_unbind=AsyncMock(side_effect=unbind),
    )
    return api, DhcpManager(api)


async def test_incremental_crud_preserves_unrelated(router):
    api, manager = router
    before = await manager.async_read()
    added = await manager.async_write("add", before["revision"], **NEW)
    api.dhcp_bind.assert_awaited_once_with(NEW)
    assert OTHER in added["bindings"] and NEW in added["bindings"]
    edited_row = {**NEW, "ip": "192.0.2.53", "name": "Renamed"}
    edited = await manager.async_write("edit", added["revision"], **edited_row)
    assert OTHER in edited["bindings"] and edited_row in edited["bindings"]
    removed = await manager.async_write("delete", edited["revision"], MAC)
    assert removed["bindings"] == [OTHER]
    assert removed["revision"] == before["revision"]
    api.dhcp_unbind.assert_awaited_once_with(MAC)


@pytest.mark.parametrize("mac,ip,name,code", [
    ("00:00:00:00:00:00", NEW["ip"], "", "invalid_mac"),
    ("FF:FF:FF:FF:FF:FF", NEW["ip"], "", "invalid_mac"),
    ("01:00:00:00:00:51", NEW["ip"], "", "invalid_mac"),
    (MAC + ";" + OTHER["mac"], NEW["ip"], "", "invalid_mac"),
    (MAC, "192.0.2.1", "", "invalid_ip"),
    (MAC, "192.0.2.0", "", "invalid_ip"),
    (MAC, "192.0.2.255", "", "invalid_ip"),
    (MAC, "198.51.100.51", "", "invalid_ip"),
    (MAC, "::1", "", "invalid_ip"),
    (MAC, NEW["ip"], "bad\nname", "invalid_name"),
    (MAC, NEW["ip"], "á" * 65, "invalid_name"),
    (MAC, OTHER["ip"], "", "conflict"),
])
async def test_invalid_changes_never_write(router, mac, ip, name, code):
    api, manager = router
    before = await manager.async_read()
    with pytest.raises(DhcpError, match=code):
        await manager.async_write("add", before["revision"], mac, ip, name)
    api.dhcp_bind.assert_not_awaited()
    api.dhcp_unbind.assert_not_awaited()


@pytest.mark.parametrize("change,code", [("disabled", "disabled"), ("firmware", "unsupported"), ("model", "unsupported")])
async def test_read_only_profiles(router, change, code):
    api, manager = router
    if change == "disabled":
        api.dhcp_settings.return_value["info"]["ignore"] = "1"
    else:
        api.init_info.return_value["romversion" if change == "firmware" else "hardware"] = "unknown"
    before = await manager.async_read()
    assert not before["writable"]
    with pytest.raises(DhcpError, match=code):
        await manager.async_write("delete", before["revision"], OTHER["mac"])
    api.dhcp_unbind.assert_not_awaited()


async def test_stale_revision_and_new_client_conflict(router):
    api, manager = router
    before = await manager.async_read()
    api.rows.append({**NEW, "ip": "192.0.2.53"})
    with pytest.raises(DhcpError, match="stale"):
        await manager.async_write("delete", before["revision"], OTHER["mac"])
    before = await manager.async_read()
    api.dhcp_bindings.side_effect = lambda: {"code": 0, "list": deepcopy(api.rows), "devicelist": [{**OTHER, "ip": "192.0.2.54"}]}
    with pytest.raises(DhcpError, match="conflict"):
        await manager.async_write("edit", before["revision"], MAC, "192.0.2.54", "Watch")
    api.dhcp_bind.assert_not_awaited()
    api.dhcp_unbind.assert_not_awaited()


@pytest.mark.parametrize("response", [{"code": 0}, {"code": 1, "list": [], "devicelist": []},
    {"code": 0, "list": [OTHER, OTHER], "devicelist": []},
    {"code": 0, "list": [OTHER, {**NEW, "ip": OTHER["ip"]}], "devicelist": []},
    {"code": 0, "list": [{**OTHER, "mac": "invalid"}], "devicelist": []}])
async def test_failed_list_never_becomes_empty(router, response):
    api, manager = router
    api.dhcp_bindings.side_effect = None
    api.dhcp_bindings.return_value = response
    with pytest.raises(DhcpError, match="invalid_response"):
        await manager.async_read()


async def test_timeout_is_not_retried_even_when_applied(router):
    api, manager = router
    before = await manager.async_read()

    async def timeout(row):
        api.rows.append(row)
        raise TimeoutError()

    api.dhcp_bind.side_effect = timeout
    with pytest.raises(DhcpError, match="unverified"):
        await manager.async_write("add", before["revision"], **NEW)
    assert api.dhcp_bind.await_count == 1
    assert NEW in (await manager.async_read())["bindings"]


async def test_detects_unrelated_data_loss_no_rollback(router):
    api, manager = router
    before = await manager.async_read()
    api.dhcp_bind.side_effect = lambda row: api.rows.clear()
    with pytest.raises(DhcpError, match="unverified"):
        await manager.async_write("add", before["revision"], **NEW)
    assert api.dhcp_bind.await_count == 1
    api.dhcp_unbind.assert_not_awaited()


async def test_reload_during_read_prevents_write(router):
    api, _ = router
    current = [True]
    manager = DhcpManager(api, lambda: current[0])
    before = await manager.async_read()
    api.init_info.side_effect = lambda: current.__setitem__(0, False) or api.init_info.return_value
    with pytest.raises(DhcpError, match="router_changed"):
        await manager.async_write("delete", before["revision"], OTHER["mac"])
    api.dhcp_unbind.assert_not_awaited()


async def test_concurrent_writes_only_one_accepts_same_revision(router):
    api, manager = router
    before = await manager.async_read()
    results = await asyncio.gather(
        manager.async_write("add", before["revision"], **NEW),
        manager.async_write("add", before["revision"], **NEW), return_exceptions=True)
    assert sum(isinstance(value, dict) for value in results) == 1
    assert sum(isinstance(value, DhcpError) and str(value) == "stale" for value in results) == 1
    assert api.dhcp_bind.await_count == 1


async def test_exact_form_payload_and_no_post_retry():
    requests = []

    def handler(request):
        requests.append(request)
        return httpx.Response(200, json={"code": 0})

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as http:
        client = LuciClient(http)
        client._url, client._token = "http://192.0.2.1/cgi-bin/luci", "test-session"
        await client.dhcp_bind(NEW)
        await client.dhcp_unbind(MAC)
        from urllib.parse import parse_qs
        assert json.loads(parse_qs(requests[0].content.decode())["data"][0]) == [NEW]
        assert parse_qs(requests[1].content.decode()) == {"mac": [MAC]}
        assert requests[0].url.path.endswith("/api/xqnetwork/mac_bind")
        assert requests[1].url.path.endswith("/api/xqnetwork/mac_unbind")
        assert all(request.method == "POST" for request in requests)
        client._client.post = AsyncMock(side_effect=RuntimeError("client has been closed"))
        with pytest.raises(RuntimeError):
            await client.dhcp_bind(NEW)
        assert client._client.post.await_count == 1


async def test_luci_error_is_contained(router):
    api, manager = router
    api.dhcp_bindings.side_effect = LuciRequestError("private router response")
    with pytest.raises(DhcpError, match="^read_failed$"):
        await manager.async_read()


async def test_explicit_entry_manager_survives_reads_not_reload(hass, router):
    api, _ = router
    updater = SimpleNamespace(luci=api)
    hass.data[DOMAIN] = {"selected": {UPDATER: updater}}
    manager = get_manager(hass, "selected")
    assert manager is get_manager(hass, "selected")
    with pytest.raises(DhcpError, match="router_changed"):
        get_manager(hass, "missing")
    hass.data[DOMAIN]["selected"][UPDATER] = SimpleNamespace(luci=api)
    with pytest.raises(DhcpError, match="router_changed"):
        await manager.async_read()


@pytest.mark.parametrize("command", ["routers", "read", "write"])
async def test_websockets_require_admin(hass, hass_ws_client, hass_read_only_user, command):
    for handler in (ws_api.websocket_dhcp_routers, ws_api.websocket_dhcp_read, ws_api.websocket_dhcp_write):
        websocket_api.async_register_command(hass, handler)
    refresh_token = await hass.auth.async_create_refresh_token(hass_read_only_user, client_id="https://test.example")
    client = await hass_ws_client(hass, hass.auth.async_create_access_token(refresh_token))
    payload = {"id": 1, "type": f"miwifi/dhcp_{command}"}
    if command != "routers":
        payload["entry_id"] = "selected"
    if command == "write":
        payload.update(action="delete", revision="revision", mac=MAC)
    await client.send_json(payload)
    response = await client.receive_json()
    assert not response["success"]
    assert response["error"]["code"] == "unauthorized"


async def test_admin_websocket_reads_and_writes(hass, hass_ws_client, hass_admin_user, router):
    api, _ = router
    hass.data[DOMAIN] = {"selected": {UPDATER: SimpleNamespace(luci=api)}}
    for handler in (ws_api.websocket_dhcp_read, ws_api.websocket_dhcp_write):
        websocket_api.async_register_command(hass, handler)
    client = await hass_ws_client(hass)
    await client.send_json({"id": 1, "type": "miwifi/dhcp_read", "entry_id": "selected"})
    result = await client.receive_json()
    assert result["success"]
    await client.send_json({"id": 2, "type": "miwifi/dhcp_write", "entry_id": "selected", "action": "add", "revision": result["result"]["revision"], **NEW})
    result = await client.receive_json()
    assert result["success"]
    assert NEW in result["result"]["bindings"]
