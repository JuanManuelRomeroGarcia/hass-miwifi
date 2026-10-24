"""Credential rejection, recovery and secret-bearing request regressions."""
import json
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

import pytest
from httpx import RequestError, Response
from homeassistant import config_entries
from homeassistant.const import CONF_PASSWORD
from homeassistant.exceptions import ConfigEntryAuthFailed
from homeassistant.helpers.httpx_client import get_async_client
from pytest_homeassistant_custom_component.common import MockConfigEntry

from custom_components.miwifi.const import DOMAIN
from custom_components.miwifi.diagnostics import async_get_config_entry_diagnostics
from custom_components.miwifi.helper import async_verify_access
from custom_components.miwifi.exceptions import LuciAuthenticationError, LuciRequestError
from custom_components.miwifi.luci import LuciClient
from custom_components.miwifi.updater import LuciUpdater


def client(hass):
    c = LuciClient(get_async_client(hass, False), "192.0.2.1", "admin-secret", protocol="http")
    c._url = "http://192.0.2.1/cgi-bin/luci"
    c._token = "session-secret"
    return c


async def test_wifi_query_never_reaches_diagnostics_or_retry_log(hass, caplog):
    c = client(hass)
    secret = "wifi-secret&with spaces"
    replies = [Response(200, json={"code": 1, "msg": "invalid token"}), Response(200, json={"code": 0})]
    with patch.object(c, "_request_with_retry", AsyncMock(side_effect=replies)) as request, patch.object(c, "login", AsyncMock()), caplog.at_level("DEBUG", logger="miwifi"):
        assert await c.set_wifi({"pwd": secret, "ssid": "test"}) == {"code": 0}
    assert "pwd=" in request.await_args_list[0].args[1]
    assert all("?" not in key for key in c.diagnostics)
    assert "xqnetwork/set_wifi" in c.diagnostics
    serialized = json.dumps(c.diagnostics) + caplog.text
    assert secret not in serialized
    assert "wifi-secret" not in serialized
    assert "pwd=" not in serialized


async def test_exception_url_is_not_retained(hass):
    c = client(hass)
    c._debug("Connection error", "unused", RequestError("http://router/?pwd=secret"), "set_wifi?pwd=secret")
    assert "secret" not in json.dumps(c.diagnostics)


@pytest.mark.parametrize("status,payload", [(200, {"code": 401}), (200, {"code": "401"}), (401, None), (403, None)])
async def test_login_rejection_is_auth_error(hass, status, payload):
    c = client(hass)
    response = Response(status, json=payload) if payload else Response(status, text="denied")
    with patch.object(c, "_request_with_retry", AsyncMock(return_value=response)):
        with pytest.raises(LuciAuthenticationError):
            await c.login()
    assert c.authentication_failed
    assert c._token is None


async def test_unknown_login_failure_is_not_auth_error(hass):
    c = client(hass)
    with patch.object(c, "_request_with_retry", AsyncMock(return_value=Response(200, json={"code": 1}))):
        with pytest.raises(LuciRequestError):
            await c.login()
    assert not c.authentication_failed


async def test_updater_auth_failure_stops_cycle_without_retry(hass):
    u = LuciUpdater(hass, "192.0.2.1", "old", "sha1")
    with patch.object(u.luci, "logout", AsyncMock()), patch.object(u.luci, "login", AsyncMock(side_effect=LuciAuthenticationError("denied"))) as login, patch("custom_components.miwifi.updater.asyncio.sleep", AsyncMock()):
        with pytest.raises(ConfigEntryAuthFailed):
            await u.update()
        login.assert_awaited_once()


async def test_optional_handler_cannot_hide_failed_relogin(hass):
    u = LuciUpdater(hass, "192.0.2.1", "old", "sha1")
    async def swallowed(_retry):
        u.luci.authentication_failed = True
        return {}
    with patch.object(u, "_async_update", side_effect=swallowed):
        with pytest.raises(ConfigEntryAuthFailed):
            await u.update()


async def test_first_refresh_reports_auth_failure_to_ha(hass):
    entry = MockConfigEntry(domain=DOMAIN, data={"ip_address": "192.0.2.1", CONF_PASSWORD: "old"})
    entry.add_to_hass(hass)
    entry.mock_state(hass, config_entries.ConfigEntryState.SETUP_IN_PROGRESS)
    u = LuciUpdater(hass, "192.0.2.1", "old", "sha1", config_entry=entry)
    u._is_first_update = False
    u._is_reauthorization = True
    with patch.object(u.luci, "login", AsyncMock(side_effect=LuciAuthenticationError("denied"))) as login:
        with pytest.raises(ConfigEntryAuthFailed):
            await u.async_config_entry_first_refresh()
        login.assert_awaited_once()
    await u.async_shutdown()


async def test_polling_starts_reauth_and_cancels_next_poll(hass):
    entry = MockConfigEntry(domain=DOMAIN, data={"ip_address": "192.0.2.1", CONF_PASSWORD: "old"})
    entry.add_to_hass(hass)
    u = LuciUpdater(hass, "192.0.2.1", "old", "sha1", config_entry=entry)
    u._is_first_update = False
    u._is_reauthorization = True
    with patch.object(u.luci, "login", AsyncMock(side_effect=LuciAuthenticationError("denied"))) as login, patch.object(entry, "async_start_reauth_if_available") as start:
        await u.async_refresh()
        assert isinstance(u.last_exception, ConfigEntryAuthFailed)
        assert not u.last_update_success
        start.assert_called_once_with(hass)
        login.assert_awaited_once()
        assert u._unsub_refresh is None
    await u.async_shutdown()


async def test_verify_access_maps_auth_rejection_for_forms(hass):
    with patch("custom_components.miwifi.helper.LuciUpdater.async_request_refresh", side_effect=ConfigEntryAuthFailed), patch("custom_components.miwifi.helper.LuciUpdater.async_stop", AsyncMock()):
        code, _reason = await async_verify_access(hass, "192.0.2.1", "old", "sha1")
    assert code == 403


async def test_diagnostics_download_also_strips_legacy_query_keys(hass):
    entry = MockConfigEntry(domain=DOMAIN, data={CONF_PASSWORD: "admin-secret"})
    entry.add_to_hass(hass)
    c = client(hass)
    c.diagnostics = {"xqnetwork/set_wifi?pwd=wifi-secret": {"content": {"pwd": "wifi-secret"}}}
    u = SimpleNamespace(data={}, devices={}, luci=c)
    with patch("custom_components.miwifi.diagnostics.async_get_updater", return_value=u), patch("custom_components.miwifi.diagnostics.async_get_integrations", return_value={}), patch("custom_components.miwifi.diagnostics.build_mesh_support", return_value={}), patch("custom_components.miwifi.diagnostics.async_get_integration", AsyncMock(return_value=SimpleNamespace(version="test"))):
        result = await async_get_config_entry_diagnostics(hass, entry)
    assert "xqnetwork/set_wifi" in result["requests"]
    assert "wifi-secret" not in json.dumps(result)
    assert "admin-secret" not in json.dumps(result)


@pytest.mark.parametrize("override", [False, True])
async def test_reauth_preserves_identity_and_options(hass, override):
    options = {"is_ap_mode": True}
    if override:
        options[CONF_PASSWORD] = "old-option"
    entry = MockConfigEntry(domain=DOMAIN, unique_id="192.0.2.1", data={"ip_address": "192.0.2.1", CONF_PASSWORD: "old", "scan_interval": 30}, options=options)
    entry.add_to_hass(hass)
    with patch("custom_components.miwifi.config_flow.async_verify_access", AsyncMock(side_effect=[(403, "denied"), (504, "timeout"), (200, "")])) as verify, patch.object(hass.config_entries, "async_reload", AsyncMock(return_value=True)) as reload:
        result = await hass.config_entries.flow.async_init(DOMAIN, context={"source": config_entries.SOURCE_REAUTH, "entry_id": entry.entry_id}, data=entry.data)
        assert result["step_id"] == "reauth_confirm"
        for error in ("password.not_matched", "connection"):
            result = await hass.config_entries.flow.async_configure(result["flow_id"], {CONF_PASSWORD: "bad"})
            assert result["errors"] == {"base": error}
            assert entry.data[CONF_PASSWORD] == "old"
        result = await hass.config_entries.flow.async_configure(result["flow_id"], {CONF_PASSWORD: "new"})
        await hass.async_block_till_done()
    assert result["type"] == "abort"
    assert result["reason"] == "reauth_successful"
    assert entry.unique_id == "192.0.2.1"
    assert entry.data == {"ip_address": "192.0.2.1", CONF_PASSWORD: "new", "scan_interval": 30}
    assert entry.options == ({CONF_PASSWORD: "new", "is_ap_mode": True} if override else {"is_ap_mode": True})
    assert len(hass.config_entries.async_entries(DOMAIN)) == 1
    reload.assert_awaited_once_with(entry.entry_id)
    assert verify.await_args.args[1] == "192.0.2.1"
