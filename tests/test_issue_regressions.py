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
    node = next(item for item in tree.body if isinstance(item, ast.FunctionDef) and item.name == name)
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


if __name__ == '__main__':
    unittest.main(verbosity=2)
