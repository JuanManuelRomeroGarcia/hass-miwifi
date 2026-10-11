# Archived pre-release reply to #325

Posted on 2026-10-11 before v3.9.0 was published. The text below records that earlier state.

@brembygit, thank you for the test harness and the coordinator/device-trigger compatibility work. We have adapted the core of #325 locally for the upcoming release, preserving the changes already on main rather than applying the whole older branch unchanged.

The maintained CI matrix now covers HA Core 2026.10.0 and 2026.9.3 with the corresponding pytest-homeassistant-custom-component and exact HA frontend dependency. Suite selection happens before importing the legacy modules; inherited failures remain in a separate non-blocking job with reports. HACS/hassfest and the standalone/frontend checks remain separate.

The coordinator receives its owning config entry explicitly while keeping login/ambient fallbacks, and the classic device trigger imports TriggerActionType/TriggerInfo from the supported HA helper. Tests cover first refresh, login, trigger discovery, filtering, execution and unsubscribe. A manual YAML automation also received a simulated miwifi_luci response and created its notification. This does not add the classic device trigger to the newer target-based picker or test an actual router response.

Current local validation: **135 maintained tests + 65 standalone tests pass on HA 2026.10.0**; **134 maintained tests pass and 1 newer-registry-API test is skipped on HA 2026.9.3**. Frontend packaging and panel behavior checks pass. The inherited legacy suite has not been repaired (the earlier HA 2026.10.0 run had 185 failures, 7 passes and 40 errors).

The adaptation is still in the local development checkout, not yet committed/published on main; remote CI has not run for it. I am keeping this PR open until the published update supersedes it, and will credit your contribution in the changelog. The separate work in #324, #326, #327 and #331 remains pending and is not claimed included here.
