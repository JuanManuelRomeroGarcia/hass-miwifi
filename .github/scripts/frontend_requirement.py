"""Print the home-assistant-frontend requirement of the installed Home Assistant.

Reads the frontend manifest from disk instead of importing the component, which
would pull in half of Home Assistant just to learn one version string.
"""

import json
from importlib.util import find_spec
from pathlib import Path

spec = find_spec("homeassistant")
if spec is None or not spec.submodule_search_locations:
    raise SystemExit("homeassistant is not installed")

manifest = Path(spec.submodule_search_locations[0]) / "components" / "frontend" / "manifest.json"
requirements = json.loads(manifest.read_text(encoding="utf-8"))["requirements"]
print(next(r for r in requirements if r.startswith("home-assistant-frontend")))
