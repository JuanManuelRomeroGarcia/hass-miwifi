#!/usr/bin/env python3
"""Inventory Xiaomi LuCI declarations over SSH without running API handlers.

Standalone standard-library tool; it does not import Home Assistant or change
the integration. Optional --probe-http runs a separate fixed read catalogue.
Static declarations are NOT proof of runtime support or safety.
"""
from __future__ import annotations

import argparse
from collections import Counter
from datetime import datetime, timezone
import getpass
import ipaddress
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile


MAX_BYTES = 64 * 1024 * 1024
REMOTE_READ = r'''export LC_ALL=C
printf '__MIWIFI_META_BEGIN__\n'
uname -m
if [ -r /usr/share/xiaoqiang/xiaoqiang_version ]; then
    cat /usr/share/xiaoqiang/xiaoqiang_version
fi
printf '__MIWIFI_META_END__\n'
printf '__MIWIFI_SERVICES_BEGIN__\n'
ubus_ready=0
if command -v ubus >/dev/null 2>&1; then
    if service_list=$(ubus list 2>/dev/null); then ubus_ready=1; fi
fi
for service in trafficd mitempctrl; do
    if [ "$ubus_ready" -eq 1 ]; then
        if printf '%s\n' "$service_list" | grep -qx "$service"; then
            printf '%s present\n' "$service"
        else
            printf '%s not_listed\n' "$service"
        fi
    else
        printf '%s unknown\n' "$service"
    fi
done
printf '__MIWIFI_SERVICES_END__\n'
n=0
for f in /usr/lib/lua/luci/controller/api/*.lua; do
    [ -f "$f" ] || continue
    n=$((n + 1))
    if [ "$n" -gt 64 ]; then printf '__MIWIFI_TRUNCATED__\n'; break; fi
    printf '__MIWIFI_CONTROLLER_BEGIN__ %s\n' "$f"
    if command -v sha256sum >/dev/null 2>&1; then sha256sum "$f"; fi
    if command -v luac >/dev/null 2>&1; then
        printf '__MIWIFI_FORMAT__ luac\n'
        luac -p -l -l "$f" 2>/dev/null || printf '__MIWIFI_ERROR__ disassembly_failed\n'
    else
        magic=$(od -An -tx1 -N1 "$f" 2>/dev/null | tr -d ' \n')
        case "$magic" in
            1b) printf '__MIWIFI_ERROR__ bytecode_without_luac\n';;
            *) printf '__MIWIFI_FORMAT__ source\n'; cat "$f";;
        esac
    fi
    printf '\n__MIWIFI_CONTROLLER_END__\n'
done
'''

SYMBOL = re.compile(r'^[A-Za-z_][A-Za-z0-9_]*$')
FUNCTION = re.compile(r'^(?:main|function) [^\n]* at (0x[0-9a-fA-F]+)\)\s*$', re.M)
QUOTED = re.compile(r';\s*"([A-Za-z_][A-Za-z0-9_]*)"\s*$')
MUTATIONS = re.compile(
    r'(^|_)(set|add|delete|del|remove|reset|clear|clean|purge|start|stop|'
    r'enable|disable|switch|apply|reboot|shutdown|restart|reload|login|logout|'
    r'bind|unbind|upload|download|upgrade|update|format|repair|renew|release|'
    r'scan|test|write|save|flush|kill|install|uninstall|push|sync)(_|$)', re.I
)
READ_NAME = re.compile(r'^get_|(^|_)(info|status|list|statistics|detail|details|count|map)(_|$)', re.I)
SIDE_EFFECT = re.compile(
    r'^(?:set[A-Z_]|save[A-Z_]|commit$|reboot$|restart$|reload$|writefile$|'
    r'apply[A-Z_]|delete[A-Z_]|remove[A-Z_]|start[A-Z_]|stop[A-Z_]|sync[A-Z_])'
)


def _comments(lines: list[str]) -> list[str]:
    return [match[1] for line in lines if (match := QUOTED.search(line))]


def _classify(route: str, hints: list[str]) -> tuple[str, list[str]]:
    """Conservative hints for review, never an executable/read-safe allowlist."""
    name = route.rsplit('/', 1)[-1]
    if MUTATIONS.search(name):
        return 'mutation_or_action', ['El nombre indica una acción; no se ha ejecutado.']
    suspicious = sorted({hint for hint in hints if SIDE_EFFECT.search(hint)})
    if suspicious:
        return 'needs_review', ['Referencias que requieren revisar efectos: ' + ', '.join(suspicious[:8])]
    if READ_NAME.search(name):
        return 'read_candidate', ['Solo candidato por análisis estático; puede incluir credenciales o efectos indirectos.']
    return 'needs_review', ['No se ha determinado la semántica de la operación.']


def _record(parts: list[str], handler: str | None, hints: list[str], params: list[str]) -> dict:
    route = '/'.join(parts[1:])
    kind, notes = _classify(route, hints)
    return {'path': route, 'handler': handler, 'classification': kind,
            'parameter_hints': sorted(set(params)),
            'symbol_hints': sorted(set(hints))[:80], 'notes': notes,
            'evidence': 'static_declaration', 'runtime_verified': False,
            'read_safety_verified': False,
            'conditional_registration_possible': True}


def parse_disassembly(text: str) -> list[dict]:
    """Read comments/prototype links from stock and Xiaomi Fate/Z luac listings.

    Fate/Z remaps instruction names, so opcodes alone cannot identify calls.
    We only use annotated symbols and mark every result as unverified.
    """
    matches = list(FUNCTION.finditer(text))
    sections = {m[1]: text[m.end():matches[i+1].start() if i+1 < len(matches) else len(text)]
                for i, m in enumerate(matches)}
    main = next((text[m.end():matches[i+1].start() if i+1 < len(matches) else len(text)]
                 for i, m in enumerate(matches) if text[m.start():m.start()+4] == 'main'), '')
    prototypes = {}
    last_address = None
    for line in main.splitlines():
        if match := re.search(r';\s*(0x[0-9a-fA-F]+)\s*$', line):
            last_address = match[1]
        elif match := re.search(r';\s*([A-Za-z_][A-Za-z0-9_]*)\s*$', line):
            if last_address:
                prototypes[match[1]] = last_address
                last_address = None

    # Only instruction comments; exclude the duplicate constants-table entries.
    lines = [line for line in text.splitlines() if re.match(r'^\s*\d+\s+\[', line)]
    entries = [i for i, line in enumerate(lines) if re.search(r';\s*"?entry"?\s*$', line)]
    records = {}
    for number, start in enumerate(entries):
        block = lines[start+1:entries[number+1] if number+1 < len(entries) else min(start+45, len(lines))]
        call = next((i for i, line in enumerate(block) if re.search(r';\s*"?call"?\s*$', line)), None)
        if call is None:
            continue
        parts = _comments(block[:call])
        if len(parts) < 3 or parts[0] != 'api' or any(not SYMBOL.fullmatch(p) for p in parts):
            continue
        # Static path segments precede call(). Preserve nested paths too.
        handler = next(iter(_comments(block[call+1:call+4])), None)
        body = sections.get(prototypes.get(handler), '')
        hints = _comments(body.splitlines())
        params = []
        body_lines = body.splitlines()
        for i, line in enumerate(body_lines):
            if re.search(r';\s*"?formvalue"?\s*$', line):
                params.extend(_comments(body_lines[i+1:i+4])[:1])
        record = _record(parts, handler, hints, params)
        record['handler_resolved'] = bool(body)
        if not body:
            record['notes'].append('No se resolvió el cuerpo del manejador; análisis incompleto.')
        records[record['path']] = record
    return sorted(records.values(), key=lambda r: r['path'])


def parse_source(text: str) -> list[dict]:
    """Fallback for plain Lua; syntax hints only, not a Lua interpreter."""
    pattern = re.compile(r'\bentry\s*\(\s*\{([^}]+)\}\s*,\s*call\s*\(\s*[\'"]([A-Za-z_]\w*)[\'"]', re.S)
    records = {}
    for match in pattern.finditer(text):
        parts = re.findall(r'[\'"]([A-Za-z_]\w*)[\'"]', match[1])
        if len(parts) < 3 or parts[0] != 'api':
            continue
        handler = match[2]
        body = re.search(r'\bfunction\s+'+re.escape(handler)+r'\s*\([^)]*\)(.*?)\nend\b', text, re.S)
        hints = re.findall(r'[\'"]([A-Za-z_]\w*)[\'"]', body[1]) if body else []
        params = re.findall(r'formvalue\s*\(\s*[\'"]([A-Za-z_]\w*)[\'"]', body[1]) if body else []
        record = _record(parts, handler, hints, params)
        record['handler_resolved'] = False
        record['notes'].append('Lua en texto: análisis heurístico, sin resolver bloques ni llamadas indirectas.')
        records[record['path']] = record
    return sorted(records.values(), key=lambda r: r['path'])


def parse_capture(text: str) -> dict:
    metadata = re.search(r'__MIWIFI_META_BEGIN__\n(.*?)__MIWIFI_META_END__', text, re.S)
    router = {}
    if metadata:
        lines = metadata[1].strip().splitlines()
        if lines:
            router['architecture'] = lines[0].strip()
        allowed = {'ROM', 'CHANNEL', 'HARDWARE', 'LINUX', 'BUILDTIME', 'BUILDTS', 'GTAG'}
        for key, value in re.findall(r'option\s+(\w+)\s+[\'"]([^\r\n\'"]*)[\'"]', metadata[1]):
            if key in allowed:
                router[key.lower()] = value
    services = re.search(r'__MIWIFI_SERVICES_BEGIN__\n(.*?)__MIWIFI_SERVICES_END__', text, re.S)
    service_presence = dict(re.findall(r'^(trafficd|mitempctrl) (present|not_listed|unknown)$', services[1], re.M)) if services else {}
    controllers = []
    blocks = re.finditer(r'__MIWIFI_CONTROLLER_BEGIN__ ([^\n]+)\n(.*?)\n__MIWIFI_CONTROLLER_END__', text, re.S)
    for block in blocks:
        path, content = block[1].strip(), block[2]
        digest = re.search(r'^([0-9a-f]{64})\s+', content, re.M)
        errors = re.findall(r'^__MIWIFI_ERROR__ (\w+)', content, re.M)
        source = '__MIWIFI_FORMAT__ source' in content
        routes = parse_source(content) if source else parse_disassembly(content)
        controllers.append({'file': path, 'sha256': digest[1] if digest else None,
                            'format': 'source' if source else 'luac',
                            'errors': errors, 'routes': routes})
    routes = [r for c in controllers for r in c['routes']]
    return {'schema_version': 1, 'created_at': datetime.now(timezone.utc).isoformat(),
            'router': router, 'service_presence': service_presence, 'controllers': controllers,
            'truncated': '__MIWIFI_TRUNCATED__' in text,
            'summary': {'controllers': len(controllers), 'declared_routes': len(routes),
                        'classification_counts': dict(Counter(r['classification'] for r in routes)),
                        'controllers_with_errors': sum(bool(c['errors']) for c in controllers)},
            'limitations': ['Declaraciones estáticas: no prueban registro activo, seguridad ni respuesta HTTP.',
                            'No se ejecutó ningún manejador de API ni se consultaron credenciales del router.',
                            'El análisis no descubre rutas dinámicas, servicios binarios ni todas las llamadas indirectas.']}


def validate_host(value: str) -> str:
    try:
        ipaddress.ip_address(value)
        return value
    except ValueError:
        if len(value) <= 253 and re.fullmatch(r'[A-Za-z0-9](?:[A-Za-z0-9.-]*[A-Za-z0-9])?', value):
            return value
        raise argparse.ArgumentTypeError('Host inválido: usa una IP o nombre DNS, sin opciones SSH.')


def client_path(backend: str) -> str:
    if found := shutil.which(backend):
        return found
    if backend == 'plink':
        for env in ('ProgramFiles', 'ProgramFiles(x86)'):
            candidate = Path(os.environ.get(env, ''))/'PuTTY/plink.exe'
            if candidate.is_file():
                return str(candidate)
    raise ValueError(f'No se encuentra {backend}; instala/configura un cliente SSH de confianza.')


def ssh_command(backend: str, executable: str, host: str, user: str, port: int,
                hostkey: str | None, password_file: str | None, identity: str | None) -> list[str]:
    if backend == 'plink':
        command = [executable, '-batch', '-ssh', '-P', str(port), '-l', user]
        if hostkey:
            command += ['-hostkey', hostkey]
        if password_file:
            command += ['-pwfile', password_file]
        if identity:
            command += ['-i', identity]
        return command + [host, REMOTE_READ]
    if password_file or hostkey:
        raise ValueError('Con OpenSSH usa clave/agente y known_hosts; contraseña y --host-key requieren Plink.')
    command = [executable, '-T', '-o', 'BatchMode=yes', '-o', 'StrictHostKeyChecking=yes',
               '-o', 'ConnectTimeout=10', '-p', str(port), '-l', user]
    if identity:
        command += ['-i', identity]
    return command + [host, REMOTE_READ]


def collect(command: list[str], timeout: int) -> str:
    try:
        result = subprocess.run(command, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE, timeout=timeout, check=False)
    except subprocess.TimeoutExpired:
        raise ValueError('Tiempo de inspección SSH agotado; no se cambia el router.') from None
    if result.returncode:
        # Authentication/host-key errors help the user; no command or credential
        # is logged. Bound error output and never auto-accept a changed key.
        error = result.stderr.decode('utf-8', errors='replace')[:3000]
        raise ValueError('SSH rechazó la lectura:\n'+error)
    if len(result.stdout) > MAX_BYTES:
        raise ValueError('El listado excede el límite de 64 MiB; no se genera un inventario parcial.')
    return result.stdout.decode('utf-8', errors='replace').replace('\r\n', '\n')


def write_comparison(reports: list[dict], output: Path) -> None:
    lines = ['# Inventarios estáticos de APIs', '',
             'Las diferencias son declaraciones del firmware, no una prueba de funciones activas.', '',
             '| Router | Hardware | Firmware | Controladores | Rutas declaradas | trafficd | mitempctrl |',
             '| --- | --- | --- | ---: | ---: | --- | --- |']
    sets = {}
    for report in reports:
        host = report['connection']['host']
        router, summary = report['router'], report['summary']
        services = report.get('service_presence', {})
        lines.append(f"| {host} | {router.get('hardware','?')} | {router.get('rom','?')} | {summary['controllers']} | {summary['declared_routes']} | {services.get('trafficd','unknown')} | {services.get('mitempctrl','unknown')} |")
        sets[host] = {r['path'] for c in report['controllers'] for r in c['routes']}
    if len(sets) > 1:
        common = set.intersection(*sets.values())
        lines += ['', f'Rutas declaradas en todos: **{len(common)}**.', '',
                  '`present`: objeto visible en ubus; `not_listed`: no se lista en esta captura;',
                  '`unknown`: no se pudo consultar ubus. Ninguno verifica por sí solo la API HTTP.', '']
        for host, routes in sets.items():
            different = sorted(routes-common)
            lines += [f'## Declaradas en {host} y ausentes en algún otro inventario', '']
            lines += ['- `'+route+'`' for route in different] or ['Ninguna.']
            lines.append('')
    (output/'comparacion.md').write_text('\n'.join(lines)+'\n', encoding='utf-8')


def write_exchange_reports(reports: list[dict], output: Path, http: dict | None = None,
                           failed_inventories: int = 0) -> None:
    """Share route declarations separately from actual, redacted HTTP results.

    SSH output and host addresses remain in the legacy local files, never in
    these exchange files. Missing HTTP execution is explicitly not_queried.
    """
    routes = {'schema_version': 1, 'kind': 'ssh_static_declarations', 'routers': []}
    responses = {'schema_version': 1, 'kind': 'http_read_results',
                 'captured_at': datetime.now(timezone.utc).isoformat(), 'routers': []}
    routes['failed_inventories'] = responses['failed_inventories'] = failed_inventories
    if http:
        responses['limits'] = http.get('limits')
        responses['error'] = http.get('error')
    for index, report in enumerate(reports, 1):
        router_id = f'router_{index}'
        identity = {k: report['router'].get(k) for k in ('hardware', 'rom', 'architecture')}
        declarations = []
        for controller in report['controllers']:
            for route in controller['routes']:
                declarations.append({
                    'path': route['path'], 'classification': route['classification'],
                    'runtime_verified': False, 'read_safety_verified': False,
                })
        routes['routers'].append({'id': router_id, 'identity': identity, 'captured_at': report.get('created_at'),
                                  'summary': report['summary'], 'routes': declarations})
        actual = next((r for r in (http or {}).get('routers', []) if r['id'] == router_id), {})
        queried = {read['path'] for sample in actual.get('samples', [])
                   for read in sample['reads'] if read['outcome'] != 'skipped'}
        responses['routers'].append({
            'id': router_id, 'identity': identity,
            'http_identity': actual.get('identity'),
            'role': actual.get('role', 'not_specified'),
            'http_state': actual.get('error') or ('stopped' if actual.get('stopped') else
                                                 'captured' if actual.get('samples') else 'not_queried'),
            'samples': actual.get('samples', []),
            'not_queried_routes': sorted({r['path'] for r in declarations} - queried),
            'stopped': actual.get('stopped', False),
        })
    for name, payload in (('routes.json', routes), ('responses.json', responses)):
        (output / name).write_text(json.dumps(payload, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--host', action='append', required=True, type=validate_host)
    parser.add_argument('--user', default='root')
    parser.add_argument('--port', type=int, default=22)
    parser.add_argument('--backend', choices=('plink', 'ssh'), default='plink' if os.name == 'nt' else 'ssh')
    parser.add_argument('--host-key', action='append', default=[], metavar='HOST=SHA256:HUELLA')
    parser.add_argument('--identity', help='Clave SSH: PPK para Plink; clave OpenSSH para ssh.')
    passwords = parser.add_mutually_exclusive_group()
    passwords.add_argument('--password', action='store_true', help='Pedir contraseña sin mostrarla; solo Plink.')
    passwords.add_argument('--password-file', type=Path, help='Archivo privado de contraseña existente; solo Plink.')
    parser.add_argument('--output', type=Path, default=Path('.cache/router-api-inventory'))
    parser.add_argument('--timeout', type=int, default=120)
    parser.add_argument('--save-raw', action='store_true', help='Guardar también los listados estáticos privados.')
    parser.add_argument('--probe-http', action='store_true', help='Tras SSH, pedir contraseña web y consultar solo el catálogo fijo de lecturas revisadas (Python 3.11+).')
    parser.add_argument('--sha256-host', action='append', default=[], help='Host HTTP con SHA-256; los demás usan SHA-1. Solo con --probe-http.')
    parser.add_argument('--mesh-node', action='append', default=[], help='Host que es nodo mesh. Solo con --probe-http.')
    parser.add_argument('--probe-model-specific', action='store_true', help='Con --probe-http, probar rutas del catálogo en modelos todavía no verificados.')
    args = parser.parse_args(argv)
    if (args.sha256_host or args.mesh_node or args.probe_model_specific) and not args.probe_http:
        parser.error('Las opciones de comprobación HTTP requieren --probe-http.')
    if not set(args.sha256_host + args.mesh_node) <= set(args.host):
        parser.error('Las opciones HTTP deben indicar un --host solicitado.')
    if args.probe_http and (sys.version_info < (3, 11) or len(set(args.host)) > 4):
        parser.error('--probe-http requiere Python 3.11+ y como máximo cuatro routers.')
    if not re.fullmatch(r'[A-Za-z_][A-Za-z0-9_-]*', args.user) or not 1 <= args.port <= 65535:
        parser.error('Usuario o puerto SSH inválido.')
    if not 1 <= args.timeout <= 600:
        parser.error('El límite de tiempo debe estar entre 1 y 600 segundos.')
    hostkeys = {}
    for item in args.host_key:
        host, sep, key = item.partition('=')
        if not sep or host not in args.host or not re.fullmatch(r'SHA256:[A-Za-z0-9+/]+={0,2}', key):
            parser.error('--host-key requiere HOST=SHA256:HUELLA para un host solicitado.')
        hostkeys[host] = key
    if args.backend == 'ssh' and (hostkeys or args.password or args.password_file):
        parser.error('Para OpenSSH usa known_hosts y autenticación por clave/agente.')
    temporary = None
    reports = []
    failed_inventories = 0
    failed = False
    try:
        executable = client_path(args.backend)
        password_file = str(args.password_file.resolve()) if args.password_file else None
        if args.password:
            password = getpass.getpass('Contraseña SSH (no se guarda en el informe): ')
            if '\n' in password or '\r' in password:
                raise ValueError('La contraseña no puede contener saltos de línea con -pwfile.')
            fd, temporary = tempfile.mkstemp(prefix='miwifi-ssh-', suffix='.tmp')
            with os.fdopen(fd, 'w', encoding='utf-8') as stream:
                stream.write(password+'\n')
            del password
            password_file = temporary
        args.output.mkdir(parents=True, exist_ok=True)
        for host in dict.fromkeys(args.host):
            try:
                command = ssh_command(args.backend, executable, host, args.user, args.port,
                                      hostkeys.get(host), password_file, args.identity)
                capture = collect(command, args.timeout)
                report = parse_capture(capture)
                report['connection'] = {'host': host, 'port': args.port, 'user': args.user}
                if not report['controllers'] or not report['summary']['declared_routes']:
                    raise ValueError('No se han podido resolver rutas: formato/rutas del firmware no compatibles.')
                safe_host = host.replace(':', '_')
                (args.output/(safe_host+'.json')).write_text(json.dumps(report, ensure_ascii=False, indent=2)+'\n', encoding='utf-8')
                if args.save_raw:
                    (args.output/(safe_host+'-listing.txt')).write_text(capture, encoding='utf-8')
                reports.append(report)
                summary = report['summary']
                print(f"{host}: {report['router'].get('hardware','?')} {report['router'].get('rom','?')}; {summary['declared_routes']} rutas declaradas, {summary['controllers_with_errors']} controladores con error.")
                if report['truncated'] or summary['controllers_with_errors']:
                    failed = True
            except (OSError, ValueError) as error:
                failed = True
                failed_inventories += 1
                print(f'{host}: {error}', file=sys.stderr)
        if reports:
            write_comparison(reports, args.output)
            print('Informes:', args.output.resolve())
    except (OSError, ValueError) as error:
        print(str(error), file=sys.stderr)
        failed = True
        failed_inventories += 1
    finally:
        if temporary:
            Path(temporary).unlink(missing_ok=True)
    if args.output.is_dir():
        write_exchange_reports(reports, args.output, failed_inventories=failed_inventories)
    if reports:
        if args.probe_http:
            # Discovery never grants permission to execute arbitrary handlers.
            # A second, independent prompt obtains the HTTP admin credential.
            import router_api_live
            http_args = ['--output', str(args.output / 'http')]
            if args.probe_model_specific:
                http_args += ['--probe-model-specific']
            for report in reports:
                host = report['connection']['host']
                http_args += ['--host', host]
                if host in args.sha256_host:
                    http_args += ['--sha256-host', host]
                if host in args.mesh_node:
                    http_args += ['--mesh-node', host]
            try:
                failed = bool(router_api_live.main(http_args)) or failed
                payload = json.loads((args.output / 'http' / 'responses.json').read_text(encoding='utf-8'))
                write_exchange_reports(reports, args.output, payload, failed_inventories)
            except (OSError, ValueError):
                print('No se completó la comprobación HTTP; consulta responses.json.', file=sys.stderr)
                failed = True
    return 1 if failed else 0


if __name__ == '__main__':
    raise SystemExit(main())
