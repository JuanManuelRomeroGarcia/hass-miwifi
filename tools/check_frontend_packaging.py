"""Standalone packaging checks; HA API doubles do not replace a live HA test."""
import ast, asyncio, importlib.util, json, re, subprocess, sys, types
from pathlib import Path
from unittest.mock import AsyncMock, Mock

root = Path(sys.argv[1]) if len(sys.argv) > 1 else Path(__file__).resolve().parents[1]
component = root/'custom_components/miwifi'
for path in component.glob('*.py'):
    ast.parse(path.read_text(encoding='utf-8'), filename=str(path))
for path in component.rglob('*.json'):
    json.loads(path.read_text(encoding='utf-8'))
assets = component/'www'
assert json.loads((component/'manifest.json').read_text())['version'] == json.loads((assets/'version.json').read_text())['version']
for path in assets.rglob('*.js'):
    text = path.read_text(encoding='utf-8')
    assert '__MIWIFI_VERSION__' not in text and '/local/miwifi' not in text, path
    assert not re.search(r'(?:from\s*|import\s*|import\s*\()\s*[\"\']https?://', text), path
    assert 'miwifi-panel-frontend' not in text and 'cdn-icons-png.flaticon.com' not in text, path
    for ref in re.findall(r'(?:from\s*|import\s*|import\s*\()\s*[\"\'](\.[^\"\']+)', text):
        assert (path.parent/ref.split('?')[0]).is_file(), (path, ref)
    result = subprocess.run(['node', '--input-type=module', '--check'], input=text, text=True, encoding='utf-8', capture_output=True)
    assert result.returncode == 0, (path, result.stderr)
    for ref in re.findall(r'/miwifi_static/([\w./-]+)', text):
        if ref.endswith('/'):
            continue
        assert (assets/ref).exists(), (path, ref)

for name in ['homeassistant', 'homeassistant.components', 'homeassistant.components.frontend', 'homeassistant.components.http', 'homeassistant.components.panel_custom', 'homeassistant.core', 'packaged', 'packaged.const', 'packaged.logger']:
    sys.modules[name] = types.ModuleType(name)
front = sys.modules['homeassistant.components.frontend']
front.DATA_PANELS = 'panels'
def remove(hass, name):
    hass.data['panels'].pop(name)
front.async_remove_panel = Mock(side_effect=remove)
sys.modules['homeassistant.components.http'].StaticPathConfig = lambda *args: args
sys.modules['homeassistant.core'].HomeAssistant = object
sys.modules['packaged.const'].MAIN_ROUTER_STORE_FILE = 'unused'
sys.modules['packaged.logger']._LOGGER = Mock()
async def register(hass, **kwargs):
    hass.data.setdefault('panels', {})['miwifi'] = types.SimpleNamespace(config={'_panel_custom': {'module_url':kwargs['module_url']}})
custom = sys.modules['homeassistant.components.panel_custom']
custom.async_register_panel = AsyncMock(side_effect=register)
spec = importlib.util.spec_from_file_location('packaged.frontend', component/'frontend.py')
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)

async def check():
    async def executor(fn, *args):
        return fn(*args)
    hass = types.SimpleNamespace(data={}, http=types.SimpleNamespace(async_register_static_paths=AsyncMock()), async_add_executor_job=executor)
    version = await mod.read_local_version(hass)
    assert version == json.loads((assets/'version.json').read_text())['version']
    await asyncio.gather(*(mod.async_register_panel(hass, version) for _ in range(8)))
    assert hass.http.async_register_static_paths.await_count == 1
    assert custom.async_register_panel.await_count == 1
    assert custom.async_register_panel.call_args.kwargs['require_admin'] is True
    await mod.async_remove_miwifi_panel(hass)
    await mod.async_remove_miwifi_panel(hass)
    assert front.async_remove_panel.call_count == 1
    await mod.async_register_panel(hass, version)
    assert hass.http.async_register_static_paths.await_count == 1
    await mod.async_register_panel(hass, version+'-next')
    assert front.async_remove_panel.call_count == 2
    assert custom.async_register_panel.await_count == 3
    # Retry a failed static registration instead of caching the failed attempt.
    hass.data = {}
    hass.http.async_register_static_paths = AsyncMock(side_effect=[RuntimeError('test'), None])
    try:
        await mod.async_register_panel(hass, version)
    except RuntimeError:
        pass
    else:
        raise AssertionError('Failure was swallowed')
    await mod.async_register_panel(hass, version)
    assert hass.http.async_register_static_paths.await_count == 2

asyncio.run(check())
print('PASS: Python/JSON syntax, JavaScript syntax, relative imports, local assets, bundled version, concurrent setup, reload, removal, version replacement and retry after registration failure.')
