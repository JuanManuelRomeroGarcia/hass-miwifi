# Home Assistant test suites

Use Python 3.14 in an isolated environment. CI pins
`pytest-homeassistant-custom-component==0.13.371` for Core 2026.10.0 and
`==0.13.366` for Core 2026.9.3. Install `requirements_test.txt` together with
that pin, then install the requirement printed by
`python .github/scripts/frontend_requirement.py`.

Run maintained tests with:

```sh
python -m pytest -q --ha-suite=maintained --continue-on-collection-errors
```

Run legacy integration tests separately with:

```sh
python -m pytest -q --ha-suite=legacy --continue-on-collection-errors
```

A client's last activity is written and read in Home Assistant's time zone,
which the test harness sets, so neither suite depends on the time zone of the
host.

`tests/conftest.py` lists the legacy modules inherited from PR #325. Selection
happens before import: broken legacy imports do not block collection of the
maintained suite. New test modules join the maintained suite by default. Remove
an old module from the legacy list only after reviewing its expectations and
getting it to pass. Running pytest without `--ha-suite` still collects both
suites normally.

Both maintained CI jobs and the legacy job must pass. Each job publishes its
JUnit report even on failure; the legacy job does not use `continue-on-error`.
The three standalone test modules are excluded only when
`--ha-suite` is selected because `validate.yml` already runs them directly,
together with frontend packaging, HACS and hassfest checks.

The MiWiFi classic device trigger is tested through the device automation
loader and with real HA event filtering and unsubscribe behavior. Manual YAML
automation testing used a simulated response event, not a router request. The
new target-based trigger picker uses a different API and is outside this change.
