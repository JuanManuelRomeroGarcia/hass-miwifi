"""Fresh read-only diagnostics, partial exports and credential isolation."""

import asyncio
import json
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch
import zipfile

import pytest
import voluptuous as vol

from homeassistant.core import Context
from homeassistant.exceptions import Unauthorized
from homeassistant.helpers.service import async_register_admin_service

from custom_components.miwifi.const import DOMAIN, UPDATER
from custom_components.miwifi.notifier import MiWiFiNotifier
from custom_components.miwifi.exceptions import LuciRequestError
from custom_components.miwifi.router_dump import DumpRedactor, READ_QUERIES, async_collect_reads
from custom_components.miwifi.services import MiWifiDumpRouterDataService


def router(*, main=True, model="rd08", ip="192.0.2.1"):
    async def get(path, parameters, **kwargs):
        if parameters.get("service") == "multiwan":
            return {"code": 0, "multiwan": {"enable": 1}}
        return {"code": 0, "info": {"mac": "AA:BB:CC:DD:EE:01", "ip": "192.0.2.20",
                "password": "synthetic-wifi-password", "token": "synthetic-response-token"}}
    return SimpleNamespace(
        data={"model": model, "mode": 0 if main else 3,
              "device_model": f"xiaomi.router.{model}", "wifi_adapter_length": 2,
              "topo_graph": {"graph": {"is_main": main}}}, ip=ip,
        luci=SimpleNamespace(get=AsyncMock(side_effect=get),
                             _password="synthetic-router-password", _token="synthetic-session-token"),
    )


async def test_full_capture_queries_main_and_nodes_without_control_calls():
    main, node = router(), router(main=False, ip="192.0.2.2")
    result = await async_collect_reads([main, node], {"api_diagnostics": True}, {})
    assert len(result["routers"]) == 2
    paths = [(call.args[0], call.args[1]) for call in main.luci.get.await_args_list]
    assert ("xqnetwork/wan_info", {"wan_name": "WAN2"}) in paths
    assert ("xqnetwork/macbind_info", {}) in paths
    assert ("xqnetwork/lan_dhcp", {}) in paths
    node_paths = [call.args[0] for call in node.luci.get.await_args_list]
    assert "misystem/devicelist" in node_paths
    assert "xqnetwork/wan_info" not in node_paths
    for query in READ_QUERIES:
        assert not any(word in query.path for word in ("/set_", "reboot", "upgrade", "/login", "/logout", "mac_bind", "mac_unbind", "qos_switch"))
    assert all(row["method"] == "GET" for item in result["routers"] for row in item["requests"])


async def test_wifi_dump_uses_readers_not_setters_and_selected_blocks_only():
    main = router()
    result = await async_collect_reads([main], {"wifi_config": True}, {})
    assert {row["path"] for row in result["routers"][0]["requests"]} == {
        "xqnetwork/wifi_detail_all", "xqnetwork/wifi_diag_detail_all"}
    assert main.luci.get.await_count == 2


async def test_verified_rc01_and_rc06_api_reads_are_scoped_by_model_and_role():
    main = router(model="rc01")
    node = router(model="rc06", main=False, ip="192.0.2.2")
    result = await async_collect_reads([main, node], {"api_diagnostics": True}, {})
    rows = [{read['id']: read for read in item['requests']} for item in result['routers']]
    assert rows[0]['thermal_control']['outcome'] == 'ok'
    assert rows[1]['thermal_control']['reason'] == 'unverified_model'
    assert rows[0]['mesh_steering']['reason'] == 'unverified_model'
    assert rows[1]['mesh_steering']['outcome'] == 'ok'
    assert all(row['port_map']['outcome'] == 'ok' for row in rows)
    assert rows[0]['wan_status']['outcome'] == 'ok'
    assert rows[1]['wan_status']['reason'] == 'main_router_only'


async def test_new_model_specific_reads_skip_unknown_hardware():
    unknown = router(model="unknown")
    result = await async_collect_reads([unknown], {"api_diagnostics": True}, {})
    rows = {read['id']: read for read in result['routers'][0]['requests']}
    for key in ('thermal_control', 'port_map', 'mesh_steering', 'wps_info', 'nfc_info'):
        assert rows[key]['reason'] == 'unverified_model'


async def test_vendor_error_body_is_retained_and_other_queries_continue():
    main = router()
    normal = main.luci.get.side_effect
    async def get(path, params, **kwargs):
        if path == "misystem/status":
            raise LuciRequestError("private message", response={"code": 999, "msg": "unsupported"})
        return await normal(path, params, **kwargs)
    main.luci.get.side_effect = get
    result = await async_collect_reads([main], {"system": True}, {})
    rows = {r["id"]: r for r in result["routers"][0]["requests"]}
    assert rows["status"]["response"]["code"] == 999
    assert rows["status"]["outcome"] == "error"
    assert rows["vpn_status"]["outcome"] == "ok"
    assert "private message" not in json.dumps(result)


async def test_timeout_is_partial_and_cancellation_is_not_swallowed():
    main = router()
    normal = main.luci.get.side_effect
    async def get(path, params, **kwargs):
        if path == "misystem/status":
            await asyncio.sleep(1)
        return await normal(path, params, **kwargs)
    main.luci.get.side_effect = get
    with patch("custom_components.miwifi.router_dump.REQUEST_SECONDS", 0.01):
        result = await async_collect_reads([main], {"system": True}, {})
    rows = {r["id"]: r for r in result["routers"][0]["requests"]}
    assert rows["status"]["outcome"] == "timeout"
    assert rows["vpn_status"]["outcome"] == "ok"
    main.luci.get.side_effect = asyncio.CancelledError()
    with pytest.raises(asyncio.CancelledError):
        await async_collect_reads([main], {"system": True}, {})


async def test_budgets_and_large_responses_are_explicit():
    main = router()
    with patch("custom_components.miwifi.router_dump.ROUTER_SECONDS", 0):
        result = await async_collect_reads([main], {"system": True}, {})
    main.luci.get.assert_not_awaited()
    assert all(r.get("error") == "capture_limit" for r in result["routers"][0]["requests"])
    with patch("custom_components.miwifi.router_dump.MAX_RESPONSE_BYTES", 10):
        result = await async_collect_reads([main], {"system": True}, {})
    assert all(r["outcome"] == "truncated" and r["response"] is None for r in result["routers"][0]["requests"])


async def test_unsupported_registry_skips_without_requests():
    main = router()
    result = await async_collect_reads([main], {"system": True}, {"status": ["rd08"]})
    assert "misystem/status" not in [c.args[0] for c in main.luci.get.await_args_list]
    row = next(r for r in result["routers"][0]["requests"] if r["id"] == "status")
    assert row["reason"] == "unsupported_by_registry"


@pytest.mark.parametrize("hide", [True, False])
def test_secrets_always_hidden_and_identifiers_correlate(hide):
    source = {"password": "synthetic-wifi-password", "key": "synthetic-psk-value",
              "token": "synthetic-token-value", "message": "synthetic-wifi-password repeated",
              "url": "http://192.0.2.1/;stok=synthetic-session-token/api?token=synthetic-token-value",
              "a": {"mac": "AA:BB:CC:DD:EE:01", "ip": "192.0.2.1", "ssid": "PrivateNetwork"},
              "b": {"parent": "aa:bb:cc:dd:ee:01", "mac": "AA:BB:CC:DD:EE:02", "ip": "192.0.2.2"},
              "parent_bare": "aabbccddee01", "netmask": "255.255.255.0", "lanmask": "255.255.255.0", "version": "1.2.3.4",
              "displayName": "PrivateRouter", "devname": "PrivateClient", "username": "PrivateAccount", "imei": "123456789012345",
              "ipv6": ["fd12:3456::1", "fd12:3456::2", "fd12:3456::1"]}
    result = DumpRedactor(hide, ("synthetic-session-token",)).redact(source)
    encoded = json.dumps(result)
    for value in ("synthetic-wifi-password", "synthetic-psk-value", "synthetic-token-value", "synthetic-session-token"):
        assert value not in encoded
    if hide:
        assert result["a"]["mac"] == result["b"]["parent"]
        assert result["a"]["mac"] == result["parent_bare"]
        assert result["a"]["mac"] != result["b"]["mac"]
        assert result["a"]["ip"] != result["b"]["ip"]
        assert result["ipv6"][0] == result["ipv6"][2] != result["ipv6"][1]
        for value in ("AA:BB:CC", "192.0.2.", "fd12:3456", "PrivateNetwork", "PrivateRouter", "PrivateClient", "PrivateAccount", "123456789012345"):
            assert value not in encoded
    else:
        assert result["a"]["mac"] == source["a"]["mac"]
        assert result["a"]["ssid"] == "PrivateNetwork"
    assert source["password"] == "synthetic-wifi-password"
    assert result["netmask"] == "255.255.255.0"
    assert result["version"] == "1.2.3.4"
    assert result["lanmask"] == "255.255.255.0"


def test_pseudonyms_never_retain_an_original_address():
    source = ["02:FE:00:00:00:01", "AA:BB:CC:DD:EE:01", "198.18.0.1", "192.0.2.1"]
    result = DumpRedactor().redact(source)
    assert not set(source).intersection(result)
    assert len(set(result)) == 4


async def test_service_writes_only_private_redacted_archive(hass, tmp_path):
    hass.config.config_dir = str(tmp_path)
    main, node = router(), router(main=False, ip="192.0.2.2")
    integrations = {"main": {UPDATER: main}, "node": {UPDATER: node}}
    translation_hass = SimpleNamespace(config=SimpleNamespace(language="es"), data={},
                                       async_add_executor_job=hass.async_add_executor_job)
    translations = await MiWiFiNotifier(translation_hass).get_translations()
    notifier = SimpleNamespace(get_translations=AsyncMock(return_value=translations), notify=AsyncMock())
    options = MiWifiDumpRouterDataService.schema({"api_diagnostics": True})
    with (patch("custom_components.miwifi.services.async_get_integrations", return_value=integrations),
          patch("custom_components.miwifi.services.get_combined_unsupported", new=AsyncMock(return_value={})),
          patch("custom_components.miwifi.services.async_get_integration", new=AsyncMock(return_value=SimpleNamespace(version="3.11.0"))),
          patch("custom_components.miwifi.services.MiWiFiNotifier", return_value=notifier)):
        service = MiWifiDumpRouterDataService(hass)
        await service.async_call_service(SimpleNamespace(data=options))
        archives = list((tmp_path / DOMAIN / "exports").glob("dump_*.zip"))
        assert len(archives) == 1
        with zipfile.ZipFile(archives[0]) as archive:
            content = archive.read(archive.namelist()[0]).decode()
        data = json.loads(content)
        assert len(data["api_diagnostics"]["routers"]) == 2
        assert "synthetic-wifi-password" not in content
        assert "synthetic-session-token" not in content
        assert not (tmp_path / "www").exists()
        assert data["status"] == "ok"
        assert "Los datos del router están listos" in notifier.notify.call_args.args[0]
        assert "Router data ready" not in notifier.notify.call_args.args[0]
        assert hass.data[DOMAIN]["last_dump_zip_url"].startswith("/api/miwifi/exports/")
        async with hass.data[DOMAIN]["dump_lock"]:
            with pytest.raises(vol.Invalid, match="already in progress"):
                await service.async_call_service(SimpleNamespace(data=options))


async def test_dump_requires_a_section_and_an_admin(hass):
    service = MiWifiDumpRouterDataService(hass)
    with pytest.raises(vol.Invalid, match="Select at least"):
        await service.async_call_service(SimpleNamespace(data={"hide_sensitive": True}))
    async_register_admin_service(hass, DOMAIN, "dump_router_data", service.async_call_service, service.schema)
    await hass.auth.async_create_user("Owner test")
    user = await hass.auth.async_create_user("Read only test", group_ids=[])
    assert not user.is_admin
    with pytest.raises(Unauthorized):
        await hass.services.async_call(DOMAIN, "dump_router_data", {"api_diagnostics": True},
                                       blocking=True, context=Context(user_id=user.id))


@pytest.mark.parametrize("hide", [True, False])
def test_init_info_serial_and_room_are_private_but_query_ids_remain_readable(hide):
    source = {"id": "init_info", "response": {
        "hardware": "RC01", "romversion": "1.1.56", "id": "12345/SYNTHETIC-SERIAL",
        "features": {"locale": "PrivateRoom"}, "routername": "PrivateRoom"}}
    result = DumpRedactor(hide).redact(source)
    assert result["id"] == "init_info"
    assert result["response"]["hardware"] == "RC01"
    assert result["response"]["romversion"] == "1.1.56"
    if hide:
        assert "SYNTHETIC-SERIAL" not in json.dumps(result)
        assert "PrivateRoom" not in json.dumps(result)
        assert result["response"]["features"]["locale"] == result["response"]["routername"]
    else:
        assert result == source
