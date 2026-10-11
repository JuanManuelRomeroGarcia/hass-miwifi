"""Print the frontend dependency pinned by the installed HA Core."""

import json
from importlib.util import find_spec
from pathlib import Path

spec = find_spec("homeassistant")
if spec is None or not spec.submodule_search_locations:
    raise SystemExit("homeassistant is not installed")
manifest = Path(spec.submodule_search_locations[0]) / "components/frontend/manifest.json"
requirements = json.loads(manifest.read_text(encoding="utf-8"))["requirements"]
print(next(item for item in requirements if item.startswith("home-assistant-frontend")))
