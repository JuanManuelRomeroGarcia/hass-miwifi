"""Standalone SSH inventory: discovery must never be mistaken for permission to call APIs."""
from __future__ import annotations

import argparse
import importlib.util
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

TOOL = Path(__file__).resolve().parents[1]/'tools/router_api_inventory.py'
spec = importlib.util.spec_from_file_location('router_api_inventory', TOOL)
inventory = importlib.util.module_from_spec(spec)
spec.loader.exec_module(inventory)

# Both stock luac and Xiaomi's opcode-remapped listings carry these comments.
LISTING = '''main <?:0,0> (20 instructions, 80 bytes at 0x100)
0+ params
1 [-] CLOSURE 0 0 ; 0x200
2 [-] SETGLOBAL 0 -1 ; index
3 [-] LOADK 1 1 ; 0x300
4 [-] (null) 1 -2 ; getClientList
5 [-] CLOSURE 1 2 ; 0x400
6 [-] SETGLOBAL 1 -3 ; startTest
7 [-] LOADK 1 3 ; 0x500
8 [-] (null) 1 -4 ; getCpuLoad

function <?:1,10> (40 instructions, 160 bytes at 0x200)
1 [-] GETGLOBAL 0 -1 ; entry
2 [-] LOADK 1 -2 ; "api"
3 [-] LOADK 2 -3 ; "misystem"
4 [-] LOADK 3 -4 ; "device_list"
5 [-] GETGLOBAL 4 -5 ; call
6 [-] LOADK 5 -6 ; "getClientList"
7 [-] (null) 0 -1 ; entry
8 [-] GETTABLE 1 -2 ; "api"
9 [-] GETTABLE 2 -3 ; "misystem"
10 [-] GETTABLE 3 -7 ; "start_test"
11 [-] (null) 4 -5 ; call
12 [-] GETTABLE 5 -8 ; "startTest"
13 [-] GETGLOBAL 0 -1 ; entry
14 [-] LOADK 1 -2 ; "api"
15 [-] LOADK 2 -9 ; "xqsystem"
16 [-] LOADK 3 -10 ; "get_cpu_load"
17 [-] GETGLOBAL 4 -5 ; call
18 [-] LOADK 5 -11 ; "getCpuLoad"

function <?:11,20> (9 instructions, 36 bytes at 0x300)
1 [-] GETTABLE 1 -1 ; "formvalue"
2 [-] LOADK 2 -2 ; "mac"
3 [-] SETTABLE 0 -3 1 ; "devices"
4 [-] LOADK 1 -4 ; "signal"

function <?:21,30> (5 instructions, 20 bytes at 0x400)
1 [-] LOADK 0 -1 ; "startDiagnostic"

function <?:31,40> (5 instructions, 20 bytes at 0x500)
1 [-] GETTABLE 0 -1 ; "setDetectionTimestamp"
2 [-] GETTABLE 1 -2 ; "loadavg"
'''

SOURCE = '''function index()
    entry({"api", "xqnetwork", "get_info"}, call("getInfo"), "", 1)
    entry({"api", "xqnetwork", "set_info"}, call("setInfo"), "", 2)
end
function getInfo()
    local mac = luci.http.formvalue("mac")
    luci.http.write_json({code=0})
end
function setInfo()
    cursor:commit("wireless")
end
'''


class InventoryTests(unittest.TestCase):
    def test_stock_and_remapped_listing_are_unverified_declarations(self):
        routes = {r['path']: r for r in inventory.parse_disassembly(LISTING)}
        self.assertEqual(set(routes), {'misystem/device_list', 'misystem/start_test', 'xqsystem/get_cpu_load'})
        read = routes['misystem/device_list']
        self.assertEqual(read['handler'], 'getClientList')
        self.assertTrue(read['handler_resolved'])
        self.assertEqual(read['parameter_hints'], ['mac'])
        self.assertEqual(read['classification'], 'read_candidate')
        self.assertEqual(routes['misystem/start_test']['classification'], 'mutation_or_action')
        self.assertEqual(routes['xqsystem/get_cpu_load']['classification'], 'needs_review')
        for route in routes.values():
            self.assertFalse(route['runtime_verified'])
            self.assertFalse(route['read_safety_verified'])
            self.assertTrue(route['conditional_registration_possible'])

    def test_source_fallback_does_not_claim_complete_analysis(self):
        routes = {r['path']: r for r in inventory.parse_source(SOURCE)}
        self.assertEqual(routes['xqnetwork/get_info']['parameter_hints'], ['mac'])
        self.assertFalse(routes['xqnetwork/get_info']['handler_resolved'])
        self.assertEqual(routes['xqnetwork/set_info']['classification'], 'mutation_or_action')

    def test_nested_static_paths_are_not_truncated(self):
        text = LISTING.replace('3 [-] LOADK 2 -3 ; "misystem"', '3 [-] LOADK 2 -3 ; "misystem"\n30 [-] LOADK 2 -3 ; "nested"')
        self.assertIn('misystem/nested/device_list', {r['path'] for r in inventory.parse_disassembly(text)})
        source = SOURCE.replace('"xqnetwork", "get_info"', '"xqnetwork", "nested", "get_info"')
        self.assertIn('xqnetwork/nested/get_info', {r['path'] for r in inventory.parse_source(source)})

    def test_metadata_services_failures_and_truncation_are_preserved(self):
        capture = '''__MIWIFI_META_BEGIN__
aarch64
config core 'version'
option ROM '1.1.38'
option HARDWARE 'RC06'
option password 'not-for-the-report'
__MIWIFI_META_END__
__MIWIFI_SERVICES_BEGIN__
trafficd present
mitempctrl not_listed
__MIWIFI_SERVICES_END__
__MIWIFI_CONTROLLER_BEGIN__ /usr/lib/lua/luci/controller/api/misystem.lua
'''+('a'*64)+'''  /usr/lib/lua/luci/controller/api/misystem.lua
__MIWIFI_FORMAT__ luac
'''+LISTING+'''
__MIWIFI_CONTROLLER_END__
__MIWIFI_CONTROLLER_BEGIN__ /usr/lib/lua/luci/controller/api/other.lua
__MIWIFI_ERROR__ bytecode_without_luac
__MIWIFI_CONTROLLER_END__
__MIWIFI_TRUNCATED__
'''
        report = inventory.parse_capture(capture)
        self.assertEqual(report['router']['hardware'], 'RC06')
        self.assertEqual(report['router']['rom'], '1.1.38')
        self.assertNotIn('password', report['router'])
        self.assertEqual(report['service_presence']['trafficd'], 'present')
        self.assertEqual(report['service_presence']['mitempctrl'], 'not_listed')
        self.assertTrue(report['truncated'])
        self.assertEqual(report['summary']['controllers_with_errors'], 1)
        self.assertEqual(report['summary']['declared_routes'], 3)
        self.assertEqual(report['controllers'][0]['sha256'], 'a'*64)

    def test_ssh_password_is_not_in_process_arguments_and_key_is_pinned(self):
        command = inventory.ssh_command('plink', 'plink', '192.0.2.1', 'root', 22,
                                         'SHA256:abc', '/private/password.tmp', None)
        self.assertIn('-pwfile', command)
        self.assertNotIn('-pw', command)
        self.assertIn('-batch', command)
        self.assertEqual(command[command.index('-hostkey')+1], 'SHA256:abc')
        self.assertEqual(command[-1], inventory.REMOTE_READ)
        self.assertIn('luac -p -l -l', command[-1])
        self.assertNotIn('client.get(', command[-1])

    def test_openssh_requires_existing_trust_and_keys(self):
        command = inventory.ssh_command('ssh', 'ssh', '192.0.2.1', 'root', 22, None, None, '/key')
        self.assertIn('StrictHostKeyChecking=yes', command)
        self.assertIn('BatchMode=yes', command)
        with self.assertRaises(ValueError):
            inventory.ssh_command('ssh', 'ssh', '192.0.2.1', 'root', 22, None, '/password', None)

    def test_option_injection_is_not_a_host(self):
        for value in ['-oProxyCommand=bad', 'host;touch bad', 'name with spaces', 'root@host']:
            with self.assertRaises(argparse.ArgumentTypeError):
                inventory.validate_host(value)
        for value in ['192.0.2.1', '2001:db8::1', 'router.example']:
            self.assertEqual(inventory.validate_host(value), value)

    def test_collection_failure_does_not_become_empty_success(self):
        result = subprocess.CompletedProcess([], 1, b'', b'Host key is not cached')
        with patch.object(inventory.subprocess, 'run', return_value=result):
            with self.assertRaisesRegex(ValueError, 'Host key'):
                inventory.collect(['ssh'], 10)
        with patch.object(inventory.subprocess, 'run', side_effect=subprocess.TimeoutExpired(['ssh'], 10)):
            with self.assertRaisesRegex(ValueError, 'agotado'):
                inventory.collect(['ssh'], 10)

    def test_comparison_uses_union_and_common_routes(self):
        report = inventory.parse_capture('__MIWIFI_META_BEGIN__\naarch64\n__MIWIFI_META_END__\n')
        one = {**report, 'connection': {'host': '192.0.2.1'}, 'controllers': [{'routes': [{'path': 'api/common'}, {'path': 'api/one'}]}]}
        two = {**report, 'connection': {'host': '192.0.2.2'}, 'controllers': [{'routes': [{'path': 'api/common'}, {'path': 'api/two'}]}]}
        with tempfile.TemporaryDirectory() as folder:
            output = Path(folder)
            inventory.write_comparison([one, two], output)
            text = (output/'comparacion.md').read_text(encoding='utf-8')
            self.assertIn('**1**', text)
            self.assertIn('api/one', text)
            self.assertIn('api/two', text)

    def test_prompted_password_temp_file_is_deleted_on_connection_failure(self):
        observed = []
        def fail(command, timeout):
            secret_file = Path(command[command.index('-pwfile')+1])
            self.assertEqual(secret_file.read_text(encoding='utf-8').strip(), 'synthetic-password')
            observed.append(secret_file)
            raise ValueError('synthetic SSH failure')
        with tempfile.TemporaryDirectory() as folder:
            with patch.object(inventory, 'client_path', return_value='plink'), patch.object(inventory.getpass, 'getpass', return_value='synthetic-password'), patch.object(inventory, 'collect', side_effect=fail):
                result = inventory.main(['--host', '192.0.2.1', '--backend', 'plink', '--password', '--output', folder])
            self.assertEqual(result, 1)
        self.assertTrue(observed)
        self.assertFalse(observed[0].exists())


if __name__ == '__main__':
    unittest.main()
