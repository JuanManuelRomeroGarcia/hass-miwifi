#!/usr/bin/env python3
"""Bounded live samples from a fixed, reviewed Xiaomi read catalogue (Python 3.11+)."""
from __future__ import annotations

import argparse
import ast
from datetime import datetime, timezone
import getpass
import hashlib
import importlib
import json
from pathlib import Path
import re
import secrets
import socket
import sys
import time
import types
import urllib.error
import urllib.parse
import urllib.request

from router_api_inventory import validate_host

ROOT = Path(__file__).resolve().parents[1]
COMPONENT = ROOT / 'custom_components/miwifi'
# Import the pure-stdlib diagnostic/redaction module without integration setup.
PACKAGE = '_miwifi_live_reads'
if PACKAGE not in sys.modules:
    package = types.ModuleType(PACKAGE)
    package.__path__ = [str(COMPONENT)]
    sys.modules[PACKAGE] = package
dump = importlib.import_module(PACKAGE + '.router_dump')

CATALOGUE = {q.key: q for q in dump.READ_QUERIES if q.key in {
    'status', 'topo_graph', 'device_list', 'client_details', 'wifi_connect_devices',
    'wifi_diag_detail_all', 'port_map', 'thermal_control', 'multiwan_basic',
    'mesh_backhaul_preference', 'mesh_steering', 'wps_info', 'nfc_info', 'wan_status',
}}
NOTES = {
    'status': 'Estado general; comprobar unidades por campo.',
    'topo_graph': 'Topología informada; puede actualizarse con retraso.',
    'device_list': 'Censo antiguo del principal; no crear clientes con otras fuentes.',
    'client_details': 'RSSI, protocolo, enlaces y contadores; los enlaces no son tráfico de Internet.',
    'wifi_connect_devices': 'Lista parcial posible; señal antigua 0–100, no dBm.',
    'wifi_diag_detail_all': 'Configuración Wi-Fi. CCMP no identifica por sí solo WPA2/WPA3.',
    'port_map': 'Capacidad/asignación de puertos; no velocidad negociada.',
    'thermal_control': 'RC01 1.1.56: curr es el máximo de 7 entradas en °C; fan.speed son RPM medidas o estimadas por PWM. Cero no prueba parada.',
    'multiwan_basic': 'Configuración/políticas; bandwidth no es tráfico instantáneo.',
    'mesh_backhaul_preference': 'Preferencia configurada; no prueba el enlace actual.',
    'mesh_steering': 'Configuración de steering; no una medición de roaming.',
    'wps_info': 'wpa3_only se calcula desde encryption; no confirma SAE/PMF por radio.',
    'nfc_info': 'Configuración NFC; wpa3_only no confirma SAE/PMF por radio.',
    'wan_status': 'Estado WAN del principal, sin solicitar WAN2 ni cambiar políticas.',
    'client_association': 'Asociación actual y vínculo fijado son datos distintos.',
}
MAX_BYTES = 262144
MAX_REPORT_BYTES = 8_000_000
MAC = re.compile(r'(?:[0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}')


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def public_login_key():
    """Read the vendor protocol constant without importing HA or duplicating it."""
    for node in ast.parse((COMPONENT / 'const.py').read_text(encoding='utf-8')).body:
        if isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name) and node.target.id == 'CLIENT_PUBLIC_KEY':
            return ast.literal_eval(node.value)
    raise ValueError('Missing vendor public login constant')


def has_data(value):
    if isinstance(value, dict):
        return any(has_data(v) for k, v in value.items() if k not in ('code', 'msg', 'message'))
    if isinstance(value, list):
        return bool(value)  # Empty client arrays are not usable client telemetry.
    return value is not None and value != ''


class RouterClient:
    def __init__(self, host, algorithm, password, scheme='http', deadline=None):
        host = validate_host(host)
        address = '[' + host + ']' if ':' in host else host
        self.base = f'{scheme}://{address}/cgi-bin/luci'
        self.algorithm = algorithm
        self.password = password
        self.token = None
        self.deadline = deadline if deadline is not None else time.monotonic() + 180
        self.opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())

    def request(self, path, params=None, login=False):
        """One bounded request; no redirects, retries, proxy, or raw error text."""
        remaining = self.deadline - time.monotonic()
        if remaining <= 0:
            return {'outcome': 'skipped', 'error': 'capture_limit'}, None
        url = self.base + ('/api/' if login else f'/;stok={self.token}/api/') + path
        body = urllib.parse.urlencode(params).encode() if login else None
        if params and not login:
            url += '?' + urllib.parse.urlencode(params)
        started = time.monotonic()
        result = {'started_at': datetime.now(timezone.utc).isoformat()}
        try:
            req = urllib.request.Request(url, data=body)
            with self.opener.open(req, timeout=min(4, remaining)) as response:
                data = bytearray()
                while len(data) <= MAX_BYTES:
                    if time.monotonic() >= self.deadline:
                        result.update(outcome='timeout', error='capture_limit')
                        return result, None
                    chunk = response.read1(min(65536, MAX_BYTES + 1 - len(data)))
                    if not chunk:
                        break
                    data.extend(chunk)
                result['http_status'] = response.status
            result['bytes'] = len(data)
            if len(data) > MAX_BYTES:
                result.update(outcome='oversize', error='response_limit')
                return result, None
            try:
                payload = json.loads(data)
            except (ValueError, UnicodeError):
                result.update(outcome='invalid_json')
                return result, None
            if not isinstance(payload, dict):
                result.update(outcome='invalid_schema')
                return result, None
            code = payload.get('code')
            result['code'] = code
            if code not in (None, 0, '0'):
                result['outcome'] = 'api_error'
            elif not has_data(payload):
                result['outcome'] = 'ok_empty'
            else:
                result['outcome'] = 'ok' if code is not None else 'json_without_code'
            return result, payload
        except urllib.error.HTTPError as exc:
            result.update(http_status=exc.code, outcome='auth_error' if exc.code in (401, 403) else 'http_error')
            return result, None
        except (TimeoutError, socket.timeout):
            result.update(outcome='timeout')
            return result, None
        except (urllib.error.URLError, OSError):
            result.update(outcome='transport_error')
            return result, None
        finally:
            result['seconds'] = round(time.monotonic() - started, 3)

    def login(self):
        nonce = f'0_02:00:00:00:00:01_{int(time.time())}_{secrets.randbelow(1000)}'
        def digest(value):
            return hashlib.new(self.algorithm, value.encode()).hexdigest()
        params = {'username': 'admin', 'logtype': '2', 'nonce': nonce,
                  'password': digest(nonce + digest(self.password + public_login_key()))}
        result, payload = self.request('xqsystem/login', params, login=True)
        token = payload.get('token') if isinstance(payload, dict) else None
        if result['outcome'] not in ('ok', 'json_without_code') or not isinstance(token, str) or not re.fullmatch(r'[A-Za-z0-9_-]{1,128}', token):
            raise ValueError('Login failed; no alternate passwords or algorithms attempted')
        self.token = token


def read_plan(keys, model, node, client_mac=None, probe_model_specific=False):
    """Paths only come from the fixed catalogue, never firmware/user URL text."""
    for key in keys:
        if key == 'client_association':
            yield key, 'xqnetwork/get_sta_bindinfo', {'sta_mac': client_mac} if client_mac else {}, (
                'main_router_only' if node else 'unverified_model' if model not in ('rc01', 'rc06') and not probe_model_specific else 'client_mac_required' if not client_mac else None)
            continue
        query = CATALOGUE[key]
        reason = None
        if node and key in ('device_list', 'client_details', 'wifi_connect_devices'):
            reason = 'mesh_clients_read_from_main'
        elif node and query.main_only:
            reason = 'main_router_only'
        elif query.models and model not in query.models and not probe_model_specific:
            reason = 'unverified_model'
        yield key, query.path, dict(query.parameters), reason


def safe_report(report, redactor):
    # Extend masking for fields used by these additional API schemas.
    def scrub(value):
        if isinstance(value, dict):
            return {k: ('REDACTED' if re.sub('[^a-z]', '', k.lower()) in (
                'pppoename', 'account', 'email', 'location', 'assoclocation', 'assocnode') else scrub(v)) for k, v in value.items()}
        if isinstance(value, list):
            return [scrub(v) for v in value]
        return value
    return redactor.redact(scrub(report))


def write_report(report, redactor, output):
    safe = safe_report(report, redactor)
    encoded = json.dumps(safe, ensure_ascii=False, indent=2) + '\n'
    if len(encoded.encode()) > MAX_REPORT_BYTES:
        safe['error'] = 'report_limit'
        for router in safe['routers']:
            for sample in router.get('samples', []):
                for read in sample['reads']:
                    if 'response' in read:
                        read['response'] = None
                        read['response_omitted'] = 'report_limit'
        encoded = json.dumps(safe, ensure_ascii=False, indent=2) + '\n'
    (output / 'samples.json').write_text(encoded, encoding='utf-8')
    # Keep the historic filename and provide a stable two-file exchange format.
    (output / 'responses.json').write_text(encoded, encoding='utf-8')
    routes = {'schema_version': 1, 'kind': 'reviewed_http_read_plan', 'routers': []}
    for router in safe['routers']:
        entries = {r['id']: r for r in router.get('routes', [])}
        for sample in router.get('samples', []):
            for read in sample['reads']:
                entries.setdefault(read['id'], {
                    'id': read['id'], 'path': read['path'],
                    'parameters': read.get('parameters', {}),
                    'skip_reason': read.get('reason') if read['outcome'] == 'skipped' else None,
                })
        routes['routers'].append({
            'id': router['id'], 'role': router['role'],
            'identity': router.get('identity'), 'error': router.get('error'),
            'routes': list(entries.values()),
        })
    (output / 'routes.json').write_text(json.dumps(routes, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
    lines = ['# API: muestras de lectura', '',
             'Capturas puntuales: un valor distinto prueba un cambio observado, no garantiza la frescura de todos los campos.', '',
             '| Router | Consulta | Resultados por muestra | Cambios observados |', '|---|---|---|---|']
    for router in safe['routers']:
        if router.get('error'):
            lines.append(f"| {router['id']} | — | {router['error']} | — |")
            continue
        grouped = {}
        for sample in router['samples']:
            for read in sample['reads']:
                grouped.setdefault(read['id'], []).append(read)
        for key, rows in grouped.items():
            usable = [r['response'] for r in rows if r.get('outcome') in ('ok', 'ok_empty', 'json_without_code')]
            changed = len(usable) > 1 and any(p != usable[0] for p in usable[1:])
            states = ', '.join(r['outcome'] + (': ' + r['reason'] if r.get('reason') else '') for r in rows)
            lines.append(f"| {router['id']} | `{key}` | {states} | {'Sí' if changed else 'No / no comparable'} |")
    lines += ['', '## Interpretación de los campos', '']
    for key in report['queries']:
        lines.append(f'- `{key}`: {NOTES[key]}')
    lines += ['', 'Las respuestas completas están en samples.json, con secretos eliminados e identificadores seudonimizados. Un nodo con lista vacía no implica que no tenga clientes: la malla puede centralizarlos en el principal.', '']
    (output / 'comparacion.md').write_text('\n'.join(lines), encoding='utf-8')


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--host', action='append', required=True, type=validate_host)
    parser.add_argument('--sha256-host', action='append', default=[], help='Default for other hosts: sha1. No guessing/retries.')
    parser.add_argument('--mesh-node', action='append', default=[])
    parser.add_argument('--scheme', choices=('http', 'https'), default='http')
    parser.add_argument('--query', action='append', choices=sorted([*CATALOGUE, 'client_association']))
    parser.add_argument('--client-mac', type=str.upper)
    parser.add_argument('--samples', type=int, default=3)
    parser.add_argument('--interval', type=float, default=10, help='Pause between rounds, in seconds.')
    parser.add_argument('--budget', type=int, default=180)
    parser.add_argument('--password-file', type=Path, help='Admin HTTP password file, never SSH password; otherwise prompt.')
    parser.add_argument('--per-host-password', action='store_true', help='Pedir una contraseña web distinta para cada router.')
    parser.add_argument('--probe-model-specific', action='store_true', help='Probar también las rutas del catálogo limitadas por modelo; no confirma campos ni unidades en otros firmwares.')
    parser.add_argument('--output', type=Path, default=Path('.cache/router-api-live'))
    args = parser.parse_args(argv)
    hosts = list(dict.fromkeys(args.host))
    if len(hosts) > 4 or not 1 <= args.samples <= 6 or not 5 <= args.interval <= 60 or not 10 <= args.budget <= 600:
        parser.error('Limits: 4 hosts, 1–6 samples, 5–60 s interval, 10–600 s total budget')
    if not set(args.sha256_host + args.mesh_node) <= set(hosts):
        parser.error('Algorithm/mesh options must name an explicit --host')
    if args.client_mac and not MAC.fullmatch(args.client_mac):
        parser.error('Invalid client MAC')
    if args.per_host_password and args.password_file:
        parser.error('--per-host-password no se puede combinar con --password-file')
    password = '' if args.per_host_password else (args.password_file.read_text(encoding='utf-8-sig').strip() if args.password_file else getpass.getpass('Router admin HTTP password: '))
    if not args.per_host_password and (not password or '\n' in password or '\r' in password):
        parser.error('Password must be one non-empty line')
    keys = list(dict.fromkeys(args.query or CATALOGUE))
    report = {'schema_version': 1, 'captured_at': datetime.now(timezone.utc).isoformat(),
              'probe_model_specific': args.probe_model_specific, 'queries': keys, 'routers': [], 'limits': {
        'total_seconds': args.budget, 'response_bytes': MAX_BYTES, 'report_bytes': MAX_REPORT_BYTES}}
    redactor = dump.DumpRedactor(True, (password,))
    deadline = time.monotonic() + args.budget
    sessions = []
    args.output.mkdir(parents=True, exist_ok=True)
    for index, host in enumerate(hosts, 1):
        record = {'id': f'router_{index}', 'role': 'mesh_node' if host in args.mesh_node else 'main_or_standalone', 'samples': []}
        record['routes'] = [
            {'id': key, 'path': path, 'parameters': params, 'skip_reason': 'login_not_completed'}
            for key, path, params, _ in read_plan(keys, '', host in args.mesh_node, args.client_mac)
        ]
        report['routers'].append(record)
        if args.per_host_password:
            password = getpass.getpass(f'Contraseña web de {host}: ')
            if not password or '\n' in password or '\r' in password:
                record['error'] = 'invalid_password'
                continue
            redactor.secrets.append(password)
        client = RouterClient(host, 'sha256' if host in args.sha256_host else 'sha1', password, args.scheme, deadline)
        try:
            client.login()
        except (ValueError, OSError):
            record['error'] = 'login_failed'
            continue
        redactor.secrets.append(client.token)
        result, identity = client.request('xqsystem/init_info')
        model = str((identity or {}).get('hardware') or '').lower()
        record['identity'] = {'hardware': model, 'firmware': (identity or {}).get('romversion'), 'outcome': result['outcome']}
        plan = list(read_plan(keys, model, host in args.mesh_node, args.client_mac, args.probe_model_specific))
        record['routes'] = [{'id': key, 'path': path, 'parameters': params, 'skip_reason': reason}
                            for key, path, params, reason in plan]
        record['model_unverified_routes'] = [key for key, _, _, reason in
                                             read_plan(keys, model, host in args.mesh_node, args.client_mac)
                                             if reason == 'unverified_model']
        sessions.append((client, record, plan))
    if not sessions:
        write_report(report, redactor, args.output)
        return 1
    used_bytes = 0
    for number in range(args.samples):
        for client, record, plan in sessions:
            sample = {'number': number + 1, 'reads': []}
            record['samples'].append(sample)
            for key, path, params, reason in plan:
                read = {'id': key, 'path': path, 'parameters': params}
                sample['reads'].append(read)
                if reason or record.get('stopped') or used_bytes >= MAX_REPORT_BYTES:
                    read.update(outcome='skipped', reason=reason or ('router_stopped' if record.get('stopped') else 'response_budget'))
                    continue
                result, payload = client.request(path, params)
                used_bytes += result.get('bytes', 0)
                if result['outcome'] in ('ok', 'ok_empty') and key in ('client_details', 'device_list', 'wifi_connect_devices'):
                    rows = (payload or {}).get('devices' if key == 'client_details' else 'list')
                    if not isinstance(rows, list):
                        result['outcome'] = 'invalid_schema'
                    elif not rows:
                        result['outcome'] = 'ok_empty'
                read.update(result, response=payload)
                if result['outcome'] in ('auth_error', 'transport_error', 'timeout'):
                    record['consecutive_failures'] = record.get('consecutive_failures', 0) + 1
                    if result['outcome'] == 'auth_error' or record['consecutive_failures'] >= 3:
                        record['stopped'] = True
                else:
                    record['consecutive_failures'] = 0
                print(f"{record['id']} sample={number + 1} {key}: {read['outcome']}", flush=True)
                if time.monotonic() < deadline:
                    time.sleep(min(.2, max(0, deadline - time.monotonic())))
        write_report(report, redactor, args.output)
        if time.monotonic() >= deadline:
            break
        if number + 1 < args.samples:
            time.sleep(min(args.interval, max(0, deadline - time.monotonic())))
    print('Reports:', args.output.resolve())
    return 1 if any(r.get('error') or r.get('stopped') for r in report['routers']) else 0


if __name__ == '__main__':
    raise SystemExit(main())
