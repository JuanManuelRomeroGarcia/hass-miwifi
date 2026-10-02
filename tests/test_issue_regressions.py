"""Regression tests for issues 309, 312, 313, 315-319 without a HA runtime.

Execute the actual class methods from their AST with API doubles, avoiding the
integration's HA-dependent imports. Live Home Assistant tests remain necessary.
Run: python -B tests/test_issue_regressions.py
"""
from __future__ import annotations

import ast
import asyncio
from enum import Enum
from pathlib import Path
import re
import sys
import time
from types import SimpleNamespace, ModuleType
import unittest
from unittest.mock import AsyncMock, Mock, patch

ROOT = Path(__file__).resolve().parents[1]
COMPONENT = ROOT/'custom_components/miwifi'


def load_class(filename, name, namespace, methods=None, drop_schema=False):
    tree = ast.parse((COMPONENT/filename).read_text(encoding='utf-8'))
    node = next(item for item in tree.body if isinstance(item, ast.ClassDef) and item.name == name)
    if methods is not None:
        node.body = [item for item in node.body if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef)) and item.name in methods]
    if drop_schema:
        node.body = [item for item in node.body if not (isinstance(item, ast.Assign) and any(isinstance(target, ast.Name) and target.id == 'schema' for target in item.targets))]
    module = ast.Module(body=[ast.ImportFrom(module='__future__', names=[ast.alias(name='annotations')], level=0), node], type_ignores=[])
    exec(compile(ast.fix_missing_locations(module), filename, 'exec'), namespace)
    return namespace[name]


def load_function(filename, name, namespace):
    tree = ast.parse((COMPONENT/filename).read_text(encoding='utf-8'))
    node = next(item for item in tree.body if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef)) and item.name == name)
    module = ast.Module(body=[ast.ImportFrom(module='__future__', names=[ast.alias(name='annotations')], level=0), node], type_ignores=[])
    exec(compile(ast.fix_missing_locations(module), filename, 'exec'), namespace)
    return namespace[name]


class LuciError(BaseException):
    pass


class ModeTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.logger = Mock()
        cls = load_class('luci.py', 'LuciClient', {'time': time, 'LuciError': LuciError, '_LOGGER': self.logger}, {'mode', 'netmode'})
        self.client = cls()
        self.client.ip = '192.0.2.1'
        self.client._api_paths = {'mode': 'xqnetwork/mode', 'netmode': 'xqnetwork/get_netmode'}
        self.client._mode_retry_at = 0.0
        self.client._mode_fallback_logged = False

    async def test_primary_success(self):
        self.client.get = AsyncMock(return_value={'mode': 2})
        self.assertEqual(await self.client.mode(), {'mode': 2})
        self.client.get.assert_awaited_once_with('xqnetwork/mode')
        self.logger.info.assert_not_called()

    async def test_fallback_cached_then_primary_recovers(self):
        original = {'netmode': 3}
        self.client.get = AsyncMock(side_effect=[LuciError('unsupported'), original, {'netmode': 4}, {'mode': 1}])
        with patch.object(time, 'monotonic', return_value=100):
            self.assertEqual(await self.client.mode(), {'netmode': 3, 'mode': 3})
        self.assertNotIn('mode', original)
        with patch.object(time, 'monotonic', return_value=120):
            self.assertEqual((await self.client.mode())['mode'], 4)
        with patch.object(time, 'monotonic', return_value=401):
            self.assertEqual(await self.client.mode(), {'mode': 1})
        self.assertEqual([call.args[0] for call in self.client.get.await_args_list], ['xqnetwork/mode', 'xqnetwork/get_netmode', 'xqnetwork/get_netmode', 'xqnetwork/mode'])
        self.logger.info.assert_called_once()

    async def test_repeated_failure_logs_info_once(self):
        self.client.get = AsyncMock(side_effect=[ValueError('bad response'), {'mode': 2, 'netmode': 8}, LuciError('unsupported'), {'netmode': 3}])
        with patch.object(time, 'monotonic', return_value=100):
            self.assertEqual((await self.client.mode())['mode'], 2)
        with patch.object(time, 'monotonic', return_value=401):
            await self.client.mode()
        self.logger.info.assert_called_once()
        self.logger.debug.assert_called_once()

    async def test_both_endpoints_fail_then_retry_primary(self):
        self.client.get = AsyncMock(side_effect=[LuciError('primary'), LuciError('fallback'), {'mode': 1}])
        self.assertEqual(await self.client.mode(), {'mode': 0})
        self.assertEqual(await self.client.mode(), {'mode': 1})
        self.logger.error.assert_called_once()

    async def test_cached_fallback_failure_resets_preference(self):
        self.client._mode_retry_at = float('inf')
        self.client.get = AsyncMock(side_effect=[LuciError('fallback'), {'mode': 1}])
        self.assertEqual(await self.client.mode(), {'mode': 0})
        self.assertEqual(await self.client.mode(), {'mode': 1})

    async def test_cancellation_propagates_from_both_endpoints(self):
        for calls in ([asyncio.CancelledError()], [LuciError('primary'), asyncio.CancelledError()]):
            self.client._mode_retry_at = 0.0
            self.client.get = AsyncMock(side_effect=calls)
            with self.assertRaises(asyncio.CancelledError):
                await self.client.mode()
        self.logger.error.assert_not_called()


class EntryCollection:
    """New HA API: iteration yields entries; mapping methods must not be used."""
    def __init__(self, entries):
        self.entries = entries
    def __iter__(self):
        return iter(self.entries)
    def values(self):
        raise AssertionError('Deprecated mapping lookup used')


class PurgeTests(unittest.IsolatedAsyncioTestCase):
    def make_service(self, entries, modern=True, entities=None):
        devices = {entry.id: entry for entry in entries}
        dev_reg = SimpleNamespace(devices=EntryCollection(entries) if modern else devices, async_get=Mock(side_effect=devices.get), async_remove_device=Mock())
        ent_reg = SimpleNamespace(entities={}, async_get=Mock(), async_remove=Mock())
        notifier = SimpleNamespace(get_translations=AsyncMock(return_value={}), notify=AsyncMock())
        env = {'time': time, 're': re, 'DOMAIN': 'miwifi', 'UPDATER': 'updater', 'ATTR_TRACKER_ENTRY_ID': 'entry_id', 'ATTR_TRACKER_LAST_ACTIVITY': 'last_activity', 'ATTR_TRACKER_MAC': 'mac', 'SIGNAL_PURGE_DEVICE': 'purge', 'async_get_integrations': lambda hass: {}, 'MiWiFiNotifier': lambda hass: notifier, 'async_dispatcher_send': Mock(), 'parse_last_activity': lambda value: int(value), 'dr': SimpleNamespace(async_get=lambda hass: dev_reg), 'er': SimpleNamespace(async_get=lambda hass: ent_reg, async_entries_for_device=lambda registry, device_id, **kwargs: (entities or {}).get(device_id, []))}
        load_function('services.py', '_all_device_entries', env)
        load_function('services.py', '_has_domain_identifier', env)
        cls = load_class('services.py', 'MiWifiPurgeInactiveDevicesServiceCall', env, drop_schema=True)
        return cls(SimpleNamespace(states=SimpleNamespace(get=lambda entity: None))), dev_reg, notifier

    @staticmethod
    def device(name, identifiers, config_entries=None):
        return SimpleNamespace(id=name, identifiers=identifiers, config_entries=config_entries or {'miwifi-entry'})

    async def test_long_identifiers_dry_run_and_apply_both_registry_apis(self):
        entries = [self.device('foreign', {('other', 'a', 'b', 'c'), ()}), self.device('miwifi', {('miwifi', '02:11:22:33:44:55', 'extra')}), self.device('short', {('other',)})]
        for modern in (True, False):
            for apply in (False, True):
                service, registry, notifier = self.make_service(entries, modern)
                result = await service.async_call_service(SimpleNamespace(data={'apply': apply, 'verbose': False}))
                self.assertEqual(result['applied'], apply)
                if apply:
                    registry.async_remove_device.assert_called_once_with('miwifi')
                else:
                    registry.async_remove_device.assert_not_called()
                self.assertIn('1 devices', notifier.notify.call_args.args[0])

    async def test_shared_devices_and_devices_with_entities_are_preserved(self):
        entries = [self.device('shared', {('miwifi', '02:11:22:33:44:55')}, {'miwifi-entry', 'other-entry'}), self.device('with-entity', {('miwifi', '02:11:22:33:44:66')})]
        service, registry, _ = self.make_service(entries, entities={'with-entity': [object()]})
        await service.async_call_service(SimpleNamespace(data={'apply': True, 'verbose': False}))
        registry.async_remove_device.assert_not_called()

    async def test_randomized_filter_preserves_known_nonrandom_mac(self):
        entries = [self.device('physical', {('miwifi', '00:11:22:33:44:55')})]
        service, registry, _ = self.make_service(entries)
        await service.async_call_service(SimpleNamespace(data={'apply': True, 'verbose': False}))
        registry.async_remove_device.assert_not_called()

    async def test_without_age_option_is_respected(self):
        service, registry, notifier = self.make_service([self.device('unknown', {('miwifi', 'unknown', 'extra')})])
        await service.async_call_service(SimpleNamespace(data={'apply': True, 'include_orphans_without_age': False, 'verbose': False}))
        registry.async_remove_device.assert_not_called()
        self.assertIn('0 devices', notifier.notify.call_args.args[0])


class RegistryOwnershipTests(unittest.TestCase):
    def test_unresolved_node_has_no_parent_link(self):
        env = {'DOMAIN': 'miwifi', '_LINKS_BY_VIA_DEVICE_ID': True}
        ensure = load_function('device_tracker.py', '_ensure_via_device_exists', env)
        via_info = load_function('device_tracker.py', '_via_device_info', env)

        self.assertIsNone(ensure(None, ''))
        self.assertEqual(via_info(ensure(None, '')), {})

    def test_empty_row_shared_with_another_integration_is_preserved(self):
        kept = SimpleNamespace(id='kept', config_entries={'new'})
        shared = SimpleNamespace(id='shared', config_entries={'old', 'foreign'})
        dev_reg = SimpleNamespace(async_remove_device=Mock())
        entity = SimpleNamespace(device_id='kept', config_entry_id='new')
        registry = SimpleNamespace(async_get_entity_id=Mock(return_value='device_tracker.client'), async_get=Mock(return_value=entity))
        hass = SimpleNamespace(config_entries=SimpleNamespace(async_entries=lambda domain: [SimpleNamespace(entry_id='old'), SimpleNamespace(entry_id='new')]))
        env = {
            'DOMAIN': 'miwifi',
            'dr': SimpleNamespace(async_get=lambda hass: dev_reg),
            'er': SimpleNamespace(async_get=lambda hass: registry, async_entries_for_device=lambda *args, **kwargs: []),
            'device_registry_rows': lambda *args, **kwargs: [kept, shared],
            '_ensure_via_device_exists': lambda *args: None,
        }
        reparent = load_function('device_tracker.py', '_reparent_client_device', env)

        self.assertFalse(reparent(hass, '02:00:00:00:00:01', 'new'))
        dev_reg.async_remove_device.assert_not_called()

    def test_roaming_keeps_tracker_and_all_sensors_on_one_device(self):
        mac = '02:00:00:00:00:01'
        old = SimpleNamespace(id='old-client', config_entries={'mesh'}, via_device_id='mesh-router')
        target = SimpleNamespace(id='target-client', config_entries={'main'}, via_device_id=None)
        parent = SimpleNamespace(id='main-router')
        rows = [old, target]
        tracker = SimpleNamespace(entity_id='device_tracker.client', platform='miwifi', config_entry_id='mesh', device_id=old.id)
        sensors = [
            SimpleNamespace(entity_id=f'sensor.client_{i}', platform='miwifi', config_entry_id='main', device_id=target.id)
            for i in range(12)
        ]
        entities = [tracker, *sensors]
        calls = []

        def update_entity(entity_id, **changes):
            entity = next(item for item in entities if item.entity_id == entity_id)
            for key, value in changes.items():
                setattr(entity, key, value)
            calls.append(('entity', entity_id))

        def update_device(device_id, **changes):
            row = next(item for item in rows if item.id == device_id)
            if 'new_config_entry_id' in changes:
                row.config_entries = {changes['new_config_entry_id']}
            if 'via_device_id' in changes:
                row.via_device_id = changes['via_device_id']
            calls.append(('device', device_id))

        dev_reg = SimpleNamespace(
            async_update_device=update_device,
            async_remove_device=lambda device_id: (rows.remove(next(row for row in rows if row.id == device_id)), calls.append(('remove', device_id))),
        )
        registry = SimpleNamespace(
            async_get_entity_id=lambda *args: tracker.entity_id,
            async_get=lambda entity_id: tracker,
            async_update_entity=update_entity,
        )
        env = {
            'DOMAIN': 'miwifi',
            'dr': SimpleNamespace(async_get=lambda hass: dev_reg),
            'er': SimpleNamespace(
                async_get=lambda hass: registry,
                async_entries_for_device=lambda reg, device_id, **kw: [
                    entity for entity in entities if entity.device_id == device_id
                ],
            ),
            'device_registry_rows': lambda *args, **kwargs: list(rows),
            '_ensure_via_device_exists': lambda *args: parent,
            '_MOVES_WITH_NEW_CONFIG_ENTRY_ID': True,
            '_LOGGER': Mock(),
        }
        load_function('device_tracker.py', '_move_device_row', env)
        reparent = load_function('device_tracker.py', '_reparent_client_device', env)
        hass = SimpleNamespace(config_entries=SimpleNamespace(async_entries=lambda domain: [SimpleNamespace(entry_id='mesh'), SimpleNamespace(entry_id='main')]))

        self.assertTrue(reparent(hass, mac, 'main', '02:00:00:00:00:02'))
        self.assertEqual(rows, [old])
        self.assertEqual(old.config_entries, {'main'})
        self.assertEqual(old.via_device_id, parent.id)
        self.assertTrue(all(entity.device_id == old.id and entity.config_entry_id == 'main' for entity in entities))
        self.assertEqual(len(entities), 13)
        self.assertLess(calls.index(('entity', tracker.entity_id)), calls.index(('device', old.id)))


class MeshSensorTests(unittest.TestCase):
    def test_main_router_setting_enables_sensors_for_leaf_clients(self):
        main = SimpleNamespace(options={'enable_device_sensors': True}, data={})
        leaf = SimpleNamespace(options={'enable_device_sensors': False}, data={})
        hass = SimpleNamespace(config_entries=SimpleNamespace(async_entries=lambda domain: [main, leaf]))
        env = {
            'DOMAIN': 'miwifi',
            'CONF_ENABLE_DEVICE_SENSORS': 'enable_device_sensors',
            'DEFAULT_ENABLE_DEVICE_SENSORS': False,
            'get_config_value': lambda entry, key, default: entry.options.get(key, entry.data.get(key, default)),
        }
        enabled = load_function('sensor.py', '_device_sensors_enabled', env)

        self.assertTrue(enabled(hass))
        main.options['enable_device_sensors'] = False
        self.assertFalse(enabled(hass))


class ClientSensorOwnerTests(unittest.TestCase):
    """#330: skip a client sensor only while another MiWiFi platform provides it."""

    def setUp(self):
        self.registry = {}
        self.platforms = []
        env = {
            'DOMAIN': 'miwifi',
            'er': SimpleNamespace(async_get=lambda hass: SimpleNamespace(
                async_get_entity_id=lambda domain, platform, uid: self.registry.get(uid))),
            'async_get_platforms': lambda hass, name: self.platforms,
        }
        self.keep = load_function('sensor.py', '_not_provided_elsewhere', env)

    @staticmethod
    def sensor(uid):
        return SimpleNamespace(unique_id=uid)

    def test_sensor_provided_by_another_platform_is_skipped(self):
        self.registry['miwifi-dev-a-ip'] = 'sensor.a_ip'
        self.platforms = [SimpleNamespace(domain='sensor', entities={'sensor.a_ip': object()})]
        self.assertEqual(self.keep(None, [self.sensor('miwifi-dev-a-ip')]), [])

    def test_registered_but_not_provided_sensor_is_added(self):
        # After a restart the registry row exists but no platform provides it.
        self.registry['miwifi-dev-a-ip'] = 'sensor.a_ip'
        self.platforms = [SimpleNamespace(domain='sensor', entities={})]
        sensor = self.sensor('miwifi-dev-a-ip')
        self.assertEqual(self.keep(None, [sensor]), [sensor])

    def test_new_sensor_is_added(self):
        sensor = self.sensor('miwifi-dev-b-ip')
        self.assertEqual(self.keep(None, [sensor]), [sensor])

    def test_only_sensor_platforms_count(self):
        self.registry['miwifi-dev-a-ip'] = 'sensor.a_ip'
        self.platforms = [SimpleNamespace(domain='device_tracker', entities={'sensor.a_ip': object()})]
        sensor = self.sensor('miwifi-dev-a-ip')
        self.assertEqual(self.keep(None, [sensor]), [sensor])

    def test_nothing_is_kept_between_calls(self):
        self.registry['miwifi-dev-a-ip'] = 'sensor.a_ip'
        live = SimpleNamespace(domain='sensor', entities={'sensor.a_ip': object()})
        self.platforms = [live]
        self.assertEqual(self.keep(None, [self.sensor('miwifi-dev-a-ip')]), [])
        live.entities.clear()  # the providing entry unloaded
        sensor = self.sensor('miwifi-dev-a-ip')
        self.assertEqual(self.keep(None, [sensor]), [sensor])


class RequestRoutingTests(unittest.IsolatedAsyncioTestCase):
    async def test_response_event_uses_the_requesting_node(self):
        foreign = SimpleNamespace(id='foreign-row', config_entry_id='other')
        node = SimpleNamespace(id='node-row', config_entry_id='node')
        updater = SimpleNamespace(
            _entry_id='node',
            data={'mac': '00:11:22:33:44:55'},
            ip='10.10.10.1',
            luci=SimpleNamespace(get=AsyncMock(return_value={'ok': 1})),
        )
        hass = SimpleNamespace(bus=SimpleNamespace(async_fire=Mock()))
        base = type('MiWifiServiceCall', (), {'__init__': lambda self, hass: setattr(self, 'hass', hass), 'get_updater': lambda self, service: updater})
        env = {
            'MiWifiServiceCall': base,
            'LuciError': Exception,
            'device_registry_rows': lambda *args, **kwargs: [foreign, node],
            'dr': SimpleNamespace(async_get=lambda hass: object(), CONNECTION_NETWORK_MAC='mac'),
            'ATTR_DEVICE_MAC_ADDRESS': 'mac',
            'CONF_URI': 'uri', 'CONF_BODY': 'body', 'CONF_DEVICE_ID': 'device_id',
            'CONF_TYPE': 'type', 'CONF_REQUEST': 'request', 'CONF_RESPONSE': 'response',
            'EVENT_LUCI': 'miwifi_luci', 'EVENT_TYPE_RESPONSE': 'response',
        }
        cls = load_class('services.py', 'MiWifiRequestServiceCall', env, drop_schema=True)

        await cls(hass).async_call_service(SimpleNamespace(data={'uri': 'status'}))

        self.assertEqual(hass.bus.async_fire.call_args.args[1]['device_id'], 'node-row')


class OptionsReloadTests(unittest.IsolatedAsyncioTestCase):
    """#333: saving one entry's options must not reload the whole mesh."""

    def listener(self, entries, sensors_before, sensors_now):
        reload = AsyncMock()
        domain = {e.entry_id: {} for e in entries}
        if sensors_before is not None:
            domain['device_sensors_mesh'] = sensors_before
        hass = SimpleNamespace(
            data={'miwifi': domain},
            config_entries=SimpleNamespace(async_entries=lambda domain: entries, async_reload=reload),
            async_add_executor_job=AsyncMock(),
        )
        env = {
            'asyncio': asyncio, 'DOMAIN': 'miwifi', 'DEVICE_SENSORS_MESH': 'device_sensors_mesh',
            '_LOGGER': Mock(), '_device_sensors_enabled': lambda hass: sensors_now,
            'get_global_panel_state': AsyncMock(return_value=False), 'async_remove_miwifi_panel': AsyncMock(),
            'read_local_version': AsyncMock(), 'async_register_panel': AsyncMock(),
        }
        return load_function('__init__.py', 'async_update_options', env), hass, reload

    async def test_reloads_only_the_changed_entry(self):
        entries = [SimpleNamespace(entry_id=f'e{i}') for i in range(4)]
        listener, hass, reload = self.listener(entries, sensors_before=True, sensors_now=True)
        await listener(hass, entries[2])
        self.assertEqual([c.args[0] for c in reload.await_args_list], ['e2'])

    async def test_mesh_wide_client_sensor_change_reloads_every_entry(self):
        entries = [SimpleNamespace(entry_id=f'e{i}') for i in range(4)]
        for before, now in ((False, True), (True, False)):
            listener, hass, reload = self.listener(entries, sensors_before=before, sensors_now=now)
            await listener(hass, entries[1])
            self.assertEqual(sorted(c.args[0] for c in reload.await_args_list), ['e0', 'e1', 'e2', 'e3'])
            self.assertEqual(hass.data['miwifi']['device_sensors_mesh'], now)

    async def test_unknown_previous_state_reloads_only_the_entry(self):
        entries = [SimpleNamespace(entry_id='e0'), SimpleNamespace(entry_id='e1')]
        listener, hass, reload = self.listener(entries, sensors_before=None, sensors_now=True)
        await listener(hass, entries[0])
        self.assertEqual([c.args[0] for c in reload.await_args_list], ['e0'])

    async def test_disabling_one_entry_keeps_sensors_when_another_enables_them(self):
        entries = [
            SimpleNamespace(entry_id='main', options={'enable_device_sensors': True}, data={}),
            SimpleNamespace(entry_id='leaf', options={'enable_device_sensors': False}, data={}),
        ]
        config_value = load_function('helper.py', 'get_config_value', {})
        enabled = load_function('sensor.py', '_device_sensors_enabled', {
            'get_config_value': config_value, 'DOMAIN': 'miwifi',
            'CONF_ENABLE_DEVICE_SENSORS': 'enable_device_sensors',
            'DEFAULT_ENABLE_DEVICE_SENSORS': False,
        })
        listener, hass, reload = self.listener(entries, sensors_before=True, sensors_now=True)
        listener.__globals__['_device_sensors_enabled'] = enabled
        await listener(hass, entries[1])
        self.assertEqual([c.args[0] for c in reload.await_args_list], ['leaf'])

        reload.reset_mock()
        entries[0].options['enable_device_sensors'] = False
        await listener(hass, entries[0])
        self.assertEqual(sorted(c.args[0] for c in reload.await_args_list), ['leaf', 'main'])

    async def test_unloaded_entry_does_not_reload_other_nodes(self):
        entries = [SimpleNamespace(entry_id='main'), SimpleNamespace(entry_id='leaf')]
        listener, hass, reload = self.listener(entries, sensors_before=False, sensors_now=True)
        del hass.data['miwifi']['leaf']
        await listener(hass, entries[1])
        reload.assert_not_awaited()

    async def test_options_flow_keeps_auto_purge_global(self):
        entry = SimpleNamespace(entry_id='e1', unique_id='192.0.2.2', options={'activity_days': 30})
        others = [SimpleNamespace(entry_id='e0', options={}), entry]
        update_entry = Mock()
        set_purge = AsyncMock()
        hass = SimpleNamespace(config_entries=SimpleNamespace(
            async_entries=lambda domain: others, async_update_entry=update_entry))

        class OptionsFlow:
            def async_create_entry(self, title, data):
                return {'type': 'create_entry', 'title': title, 'data': data}

        env = {
            'config_entries': SimpleNamespace(OptionsFlow=OptionsFlow), 'DOMAIN': 'miwifi', '_LOGGER': Mock(),
            'CONF_LOG_LEVEL': 'log_level', 'CONF_ENABLE_PANEL': 'enable_panel', 'CONF_IP_ADDRESS': 'ip_address',
            'CONF_PASSWORD': 'password', 'CONF_ENCRYPTION_ALGORITHM': 'encryption_algorithm',
            'CONF_TIMEOUT': 'timeout', 'CONF_PROTOCOL': 'protocol', 'DEFAULT_PROTOCOL': 'auto',
            'CONF_AUTO_PURGE_EVERY_DAYS': 'auto_purge_every_days', 'CONF_AUTO_PURGE_AT': 'auto_purge_at',
            'set_global_log_level': AsyncMock(), 'set_global_panel_state': AsyncMock(),
            'async_verify_access': AsyncMock(return_value=(200, None)),
            'codes': SimpleNamespace(is_success=lambda code: code == 200),
            'set_global_auto_purge': set_purge,
        }
        cls = load_class('config_flow.py', 'MiWifiOptionsFlow', env, {'__init__', 'async_step_init', 'async_update_unique_id'})
        flow = cls(entry)
        flow.hass = hass
        user_input = {
            'ip_address': '192.0.2.2', 'password': 'x', 'encryption_algorithm': 'sha1', 'timeout': 20,
            'protocol': 'auto', 'auto_purge_every_days': 8, 'auto_purge_at': '01:00:00',
        }

        result = await flow.async_step_init(user_input)

        self.assertEqual(result['type'], 'create_entry')
        set_purge.assert_awaited_once_with(hass, every_days=8, at='01:00')
        update_entry.assert_not_called()


class CompatibilityTests(unittest.TestCase):
    def test_model_identifiers(self):
        model = load_class('enum.py', 'Model', {'Enum': Enum})
        for code in ('RP01', 'RP03', 'RP04'):
            self.assertEqual(model(code.lower()).name, code)

    def test_scanner_import_new_and_legacy(self):
        tree = ast.parse((COMPONENT/'device_tracker.py').read_text(encoding='utf-8'))
        node = next(item for item in tree.body if isinstance(item, ast.Try) and any(isinstance(child, ast.ImportFrom) and any(alias.name == 'ScannerEntity' for alias in child.names) for child in item.body))
        for modern in (True, False):
            public = ModuleType('homeassistant.components.device_tracker')
            legacy = ModuleType('homeassistant.components.device_tracker.config_entry')
            expected = type('ScannerEntity', (), {})
            if modern:
                public.ScannerEntity = expected
            else:
                legacy.ScannerEntity = expected
            namespace = {}
            with patch.dict(sys.modules, {public.__name__: public, legacy.__name__: legacy}):
                exec(compile(ast.Module(body=[node], type_ignores=[]), 'device_tracker.py', 'exec'), namespace)
            self.assertIs(namespace['ScannerEntity'], expected)



def load_constants():
    """Plain literal constants from const.py, without importing Home Assistant."""
    tree = ast.parse((COMPONENT/'const.py').read_text(encoding='utf-8'))
    constants = {}
    for item in tree.body:
        if isinstance(item, ast.AnnAssign) and isinstance(item.target, ast.Name):
            target, value = item.target.id, item.value
        elif isinstance(item, ast.Assign) and len(item.targets) == 1 and isinstance(item.targets[0], ast.Name):
            target, value = item.targets[0].id, item.value
        else:
            continue
        if isinstance(value, ast.Constant):
            constants[target] = value.value
    return constants


class ClientValuesWithoutDataTests(unittest.TestCase):
    """A client that only a node's Wi-Fi list reports has no uptime or speeds."""

    MAC = '02:00:00:00:00:0A'

    def setUp(self):
        from datetime import datetime, timedelta
        env = {**load_constants(), 'DataUpdateCoordinator': object, 'datetime': datetime, 'timedelta': timedelta}
        tree = ast.parse((COMPONENT/'updater.py').read_text(encoding='utf-8'))
        skip_attrs = next(item for item in tree.body if isinstance(item, ast.AnnAssign)
                          and isinstance(item.target, ast.Name) and item.target.id == 'REPEATER_SKIP_ATTRS')
        env['REPEATER_SKIP_ATTRS'] = eval(compile(ast.Expression(skip_attrs.value), 'updater.py', 'eval'), env)
        cls = load_class('updater.py', 'LuciUpdater', env, {'_build_device', '_mass_update_device'})
        self.updater = cls.__new__(cls)
        self.updater._resolve_connection = lambda device: None
        self.updater.data = {'mac': '00:00:00:00:00:01'}
        self.updater.devices = {}
        self.updater._signals = {self.MAC: 90}
        self.c = env

    def build(self, **device):
        return self.updater._build_device({'mac': self.MAC, 'entry_id': 'entry', **device})

    def test_wifi_list_client_has_unknown_speeds(self):
        # xqnetwork/wifi_connect_devices gives only mac, wifiIndex and signal.
        device = self.build(wifiIndex=1, signal=90)
        self.assertIsNone(device[self.c['ATTR_TRACKER_DOWN_SPEED']])
        self.assertIsNone(device[self.c['ATTR_TRACKER_UP_SPEED']])
        self.assertEqual(device[self.c['ATTR_TRACKER_ONLINE']], '')
        self.assertIsNone(device[self.c['ATTR_TRACKER_IP']])

    def test_devicelist_client_keeps_its_values(self):
        device = self.build(online=1, ip=[{'ip': '192.0.2.5', 'online': '3600', 'downspeed': '10', 'upspeed': '5', 'active': 1}])
        self.assertEqual(device[self.c['ATTR_TRACKER_DOWN_SPEED']], 10.0)
        self.assertEqual(device[self.c['ATTR_TRACKER_UP_SPEED']], 5.0)
        self.assertEqual(device[self.c['ATTR_TRACKER_ONLINE']], '1:00:00')

    def test_offline_client_is_idle(self):
        device = self.build(online=0, ip=[{'ip': '192.0.2.5', 'online': '3600', 'downspeed': '10', 'upspeed': '5', 'active': 1}])
        self.assertEqual(device[self.c['ATTR_TRACKER_DOWN_SPEED']], 0.0)
        self.assertEqual(device[self.c['ATTR_TRACKER_UP_SPEED']], 0.0)
        self.assertEqual(device[self.c['ATTR_TRACKER_ONLINE']], '')

    def test_speed_recovers_when_router_starts_reporting_data(self):
        missing = self.build(wifiIndex=1)
        self.updater.devices[self.MAC] = missing
        reported = self.build(online=1, ip=[{'ip': '192.0.2.5', 'online': 60, 'downspeed': 20, 'upspeed': 10}])
        self.assertEqual(reported[self.c['ATTR_TRACKER_DOWN_SPEED']], 20.0)
        self.assertEqual(reported[self.c['ATTR_TRACKER_UP_SPEED']], 10.0)
        self.assertEqual(reported[self.c['ATTR_TRACKER_ONLINE']], '0:01:00')

    def test_force_load_leaf_does_not_replace_main_router_values(self):
        main_device = self.build(online=1, ip=[{'ip': '192.0.2.5', 'online': 60, 'downspeed': 20, 'upspeed': 10}])
        main = SimpleNamespace(data={}, devices={self.MAC: dict(main_device)})
        self.updater.ip = '192.0.2.2'
        self.updater.is_repeater = True
        self.updater.is_force_load = True
        integrations = {'192.0.2.1': {self.c['UPDATER']: main}}
        found = self.updater._mass_update_device({'mac': self.MAC, 'entry_id': 'leaf', 'wifiIndex': 1}, integrations)
        self.assertTrue(found)
        for key in ('ATTR_TRACKER_DOWN_SPEED', 'ATTR_TRACKER_UP_SPEED', 'ATTR_TRACKER_ONLINE', 'ATTR_TRACKER_IP'):
            self.assertEqual(main.devices[self.MAC][self.c[key]], main_device[self.c[key]])


class ClientSensorValueTests(unittest.TestCase):
    """The client sensors report a missing value as unknown."""

    def setUp(self):
        env = {**load_constants(), 'CoordinatorEntity': type('CoordinatorEntity', (), {}), 'SensorEntity': type('SensorEntity', (), {}), 'Connection': Enum('Connection', 'LAN'), 'KEY_SIGNAL_QUALITY': 'signal_quality'}
        cls = load_class('sensor.py', 'MiWifiDeviceAttributeSensor', env, {'native_value'})
        self.sensor = cls.__new__(cls)
        self.sensor.hass = SimpleNamespace(data={})
        self.sensor._mac = '02:00:00:00:00:0A'
        self.c = env

    def value(self, key, device):
        self.sensor._updater = SimpleNamespace(devices={self.sensor._mac: device})
        self.sensor.entity_description = SimpleNamespace(key=key)
        return self.sensor.native_value

    def test_empty_uptime_is_unknown(self):
        self.assertIsNone(self.value(self.c['ATTR_TRACKER_ONLINE'], {self.c['ATTR_TRACKER_ONLINE']: ''}))

    def test_uptime_is_reported(self):
        self.assertEqual(self.value(self.c['ATTR_TRACKER_ONLINE'], {self.c['ATTR_TRACKER_ONLINE']: '1:00:00'}), '1:00:00')

    def test_missing_speed_is_unknown(self):
        self.assertIsNone(self.value(self.c['ATTR_TRACKER_DOWN_SPEED'], {self.c['ATTR_TRACKER_DOWN_SPEED']: None}))


class TrackerSpeedAttributeTests(unittest.TestCase):
    def setUp(self):
        import math
        env = {**load_constants(), 'ScannerEntity': type('ScannerEntity', (), {}), 'CoordinatorEntity': type('CoordinatorEntity', (), {})}
        env['pretty_size'] = load_function('helper.py', 'pretty_size', {'math': math})
        self.cls = load_class('device_tracker.py', 'MiWifiDeviceTracker', env, {'_speed_attribute'})
        self.key = env['ATTR_TRACKER_DOWN_SPEED']

    def attribute(self, speed, connected=True):
        tracker = self.cls.__new__(self.cls)
        tracker._device = {self.key: speed}
        tracker.is_connected = connected
        return tracker._speed_attribute(self.key)

    def test_unknown_speed_is_empty(self):
        self.assertEqual(self.attribute(None), '')

    def test_speed_is_formatted(self):
        self.assertEqual(self.attribute(0.0), '0 B/s')
        self.assertEqual(self.attribute(2048.0), '2.0 KB/s')

    def test_disconnected_client_has_no_speed(self):
        self.assertEqual(self.attribute(2048.0, connected=False), '')

if __name__ == '__main__':
    unittest.main(verbosity=2)
