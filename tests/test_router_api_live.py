"""Read policy, credential isolation and bounded response regressions."""
import io
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import Mock, patch
import urllib.error

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
import router_api_live as live


class Reply(io.BytesIO):
    status = 200


class LiveReadTests(unittest.TestCase):
    def test_opt_in_unknown_model_probe_preserves_role_and_mac_restrictions(self):
        self.assertIsNone(list(live.read_plan(['thermal_control'], 'other', False,
                                            probe_model_specific=True))[0][3])
        self.assertEqual(list(live.read_plan(['wan_status'], 'other', True,
                                           probe_model_specific=True))[0][3], 'main_router_only')
        self.assertEqual(list(live.read_plan(['client_association'], 'other', False,
                                           probe_model_specific=True))[0][3], 'client_mac_required')

    def test_each_host_can_use_its_own_http_password(self):
        with tempfile.TemporaryDirectory() as folder:
            with patch.object(live.getpass, 'getpass', side_effect=['first-secret', 'second-secret']), patch.object(
                live, 'RouterClient'
            ) as client:
                client.return_value.login.side_effect = ValueError('failed')
                result = live.main(['--host', '192.0.2.1', '--host', '192.0.2.2',
                                    '--per-host-password', '--output', folder])
            self.assertEqual(result, 1)
            self.assertEqual([call.args[2] for call in client.call_args_list], ['first-secret', 'second-secret'])
            content = (Path(folder) / 'responses.json').read_text(encoding='utf-8')
            self.assertNotIn('first-secret', content)
            self.assertNotIn('second-secret', content)

    def test_separate_route_and_response_files_share_redaction(self):
        report = {'queries': ['client_association'], 'routers': [{
            'id': 'router_1', 'role': 'main_or_standalone',
            'identity': {'hardware': 'rc01', 'firmware': '1.1.56'},
            'samples': [{'reads': [{'id': 'client_association', 'path': 'xqnetwork/get_sta_bindinfo',
                'parameters': {'sta_mac': 'AA:BB:CC:DD:EE:FF'}, 'outcome': 'ok',
                'response': {'code': 0, 'mac': 'AA:BB:CC:DD:EE:FF', 'password': 'private-secret'}}]}],
        }]}
        with tempfile.TemporaryDirectory() as folder:
            output = Path(folder)
            live.write_report(report, live.dump.DumpRedactor(True), output)
            routes = json.loads((output / 'routes.json').read_text(encoding='utf-8'))
            responses = json.loads((output / 'responses.json').read_text(encoding='utf-8'))
            route = routes['routers'][0]['routes'][0]
            read = responses['routers'][0]['samples'][0]['reads'][0]
            self.assertNotIn('response', route)
            self.assertEqual(route['parameters']['sta_mac'], read['response']['mac'])
            for filename in ('routes.json', 'responses.json', 'samples.json'):
                content = (output / filename).read_text(encoding='utf-8')
                self.assertNotIn('private-secret', content)
                self.assertNotIn('AA:BB:CC:DD:EE:FF', content)

    def test_login_failure_still_exports_planned_routes(self):
        with tempfile.TemporaryDirectory() as folder:
            with patch.object(live.getpass, 'getpass', return_value='private-secret'), patch.object(
                live.RouterClient, 'login', side_effect=ValueError('failed')
            ):
                code = live.main(['--host', '192.0.2.1', '--query', 'status', '--output', folder])
            self.assertEqual(code, 1)
            routes = json.loads((Path(folder) / 'routes.json').read_text(encoding='utf-8'))
            self.assertEqual(routes['routers'][0]['routes'][0]['path'], 'misystem/status')
            self.assertEqual(routes['routers'][0]['error'], 'login_failed')

    def test_mesh_policy_uses_main_census_and_node_own_ports(self):
        plan = {key: (path, reason) for key, path, _, reason in live.read_plan(list(live.CATALOGUE), 'rc06', True)}
        for key in ('device_list', 'client_details', 'wifi_connect_devices'):
            self.assertEqual(plan[key][1], 'mesh_clients_read_from_main')
        self.assertIsNone(plan['port_map'][1])
        self.assertEqual(plan['thermal_control'][1], 'unverified_model')
        self.assertIsNone(plan['mesh_steering'][1])

    def test_unknown_hardware_does_not_enable_model_specific_read(self):
        plan = list(live.read_plan(['thermal_control', 'port_map'], 'unknown', False))
        self.assertTrue(all(row[3] == 'unverified_model' for row in plan))

    def test_targeted_association_requires_explicit_real_mac_and_main(self):
        self.assertEqual(list(live.read_plan(['client_association'], 'rc01', False))[0][3], 'client_mac_required')
        self.assertEqual(list(live.read_plan(['client_association'], 'rc06', True, '02:00:00:00:00:01'))[0][3], 'main_router_only')

    def test_redirect_is_never_followed(self):
        self.assertIsNone(live.NoRedirect().redirect_request(None, None, 302, '', {}, 'http://other/'))

    def test_oversize_response_is_discarded(self):
        client = live.RouterClient('192.0.2.1', 'sha1', 'synthetic-password')
        client.opener = Mock(open=Mock(return_value=Reply(b'x' * (live.MAX_BYTES + 1))))
        status, payload = client.request('misystem/status')
        self.assertEqual(status['outcome'], 'oversize')
        self.assertIsNone(payload)

    def test_auth_error_does_not_include_token_url_or_error_body(self):
        client = live.RouterClient('192.0.2.1', 'sha1', 'synthetic-password')
        client.token = 'synthetic-token'
        client.opener = Mock(open=Mock(side_effect=urllib.error.HTTPError('http://router/;stok=synthetic-token', 401, 'private', {}, None)))
        status, payload = client.request('misystem/status')
        self.assertEqual(status['outcome'], 'auth_error')
        self.assertNotIn('synthetic-token', json.dumps(status))
        self.assertIsNone(payload)

    def test_failed_login_is_not_retried_with_other_algorithm(self):
        client = live.RouterClient('192.0.2.1', 'sha1', 'synthetic-password')
        client.request = Mock(return_value=({'outcome': 'api_error'}, {'code': 401}))
        with self.assertRaises(ValueError):
            client.login()
        self.assertEqual(client.request.call_count, 1)

    def test_redaction_across_responses_and_schemas(self):
        source = {'routers': [{'secret': 'synthetic-password', 'url': '/;stok=synthetic-token/api',
                              'assoc_node': 'PrivateRoom', 'pppoeName': 'private-account',
                              'name': 'PrivateClient', 'mac': 'AA:BB:CC:DD:EE:FF'}]}
        result = live.safe_report(source, live.dump.DumpRedactor(True, ('synthetic-password', 'synthetic-token')))
        encoded = json.dumps(result)
        for secret in ('synthetic-password', 'synthetic-token', 'PrivateRoom', 'private-account', 'PrivateClient', 'AA:BB:CC:DD:EE:FF'):
            self.assertNotIn(secret, encoded)

    def test_empty_array_is_not_usable_telemetry_and_zero_is_real_data(self):
        self.assertFalse(live.has_data({'code': 0, 'devices': []}))
        self.assertTrue(live.has_data({'code': 0, 'speed': 0}))

    def test_cli_rejects_arbitrary_routes_before_password_or_network(self):
        with patch.object(live.getpass, 'getpass') as prompt:
            with self.assertRaises(SystemExit):
                live.main(['--host', '192.0.2.1', '--query', 'xqnetwork/set_wifi'])
            prompt.assert_not_called()


if __name__ == '__main__':
    unittest.main()
