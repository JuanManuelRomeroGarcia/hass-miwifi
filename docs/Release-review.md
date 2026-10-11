# v3.9.0 release review

This review records the pre-release audit and preparation of **v3.9.0** on 2026-10-11. The preceding published version was v3.8.4; publication links and GitHub CI remain the authority for release status.

## Included local changes

See [v3.9.0 changelog](../CHANGELOG.md) for automatic private-MAC replacement and panel configuration, persistent selective purge, parent-census counter stability, mesh support capture, obsolete panel update cleanup, coordinator/device-trigger compatibility and the test harness adapted from #325.

The [private MAC guide](Random-MAC-addresses.md), [Spanish guide](Random-MAC-addresses-es.md), [diagnostics guide](Diagnostics.md) and [Spanish diagnostics guide](Diagnostics-es.md) document behavior and limits. Panel MAC settings are translated in all eight supported languages.

## Issues and PRs checked on 2026-10-11

| Item | Verified status | Next action |
| --- | --- | --- |
| [#325](https://github.com/JuanManuelRomeroGarcia/hass-miwifi/pull/325) — CI/coordinator/device trigger | Core work adapted locally; current HA 2026.10.0 and 2026.9.3 maintained suites pass. Legacy suite remains reported separately. Original PR is open; local adaptation is not yet on main. | Thank author and explain adaptation/validation. Keep open until published changes supersede it; do not claim merged. |
| [#329](https://github.com/JuanManuelRomeroGarcia/hass-miwifi/issues/329) — leaf clients count drops | Parent-census and returning-client changes tested locally and on maintainer's routers. Reporter still sees failure on HA 2026.10.1 / MiWiFi 3.8.4. | Give progress and support-capture instructions for the forthcoming build; keep open for reporter verification. |
| [#324](https://github.com/JuanManuelRomeroGarcia/hass-miwifi/pull/324) — resilience/topology role | PR-specific topology-role and shutdown/step guards are absent locally. Related counter work does not replace its implementation. | Separate review still needed; not finished. |
| [#326](https://github.com/JuanManuelRomeroGarcia/hass-miwifi/pull/326) — manual role override | Manual AP/mesh override absent locally; stacked on #324. | Separate implementation and cross-model validation needed. |
| [#327](https://github.com/JuanManuelRomeroGarcia/hass-miwifi/pull/327) — Wi-Fi selectors/write feedback | PR-specific selector options, requested_option and write-refusal handling absent locally. | Separate review needed; not finished. |
| [#331](https://github.com/JuanManuelRomeroGarcia/hass-miwifi/pull/331) — mesh nodes as clients | Current code skips live isap rows, but the PR's remembered-node filter and restore cleanup are absent locally. Retiring a private client MAC does not fix this case. | Separate review needed; not finished. |
| [#333](https://github.com/JuanManuelRomeroGarcia/hass-miwifi/issues/333) — reload fan-out/router sensors | Confirmed fan-out already fixed in #336 / v3.8.2. Remaining setup/deferred-router-sensor race is unproven and not fixed by this release. | Leave open; existing request for a timestamped setup/unload trace remains valid. |
| [#334](https://github.com/JuanManuelRomeroGarcia/hass-miwifi/issues/334) — force-load wireless satellite | No new wireless-backhaul evidence or implementation. | Leave open; needs actual wifi_connect_devices/node records. |
| [#311](https://github.com/JuanManuelRomeroGarcia/hass-miwifi/issues/311) — NOT_KNOWN CPE capability | Hardware confirmation still missing. | Do not add a blanket unsupported rule or claim resolved. |
| [#314](https://github.com/JuanManuelRomeroGarcia/hass-miwifi/issues/314) — DHCP reservations | DHCP reservation management is not implemented. Private-MAC replacement does not reserve IP addresses. | Leave as a separate feature request. |

## Verification

- HA 2026.10.0: 135 maintained tests and 65 standalone tests pass, plus frontend packaging and panel behavior checks.
- HA 2026.9.3: 134 maintained tests pass; one test for the newer device-registry API is skipped.
- Panel language dictionaries contain every English reference key in all eight supported languages. New MAC labels are translated and Spanish panel rendering was verified by user screenshots.
- Real installation: obsolete update entity removed; node counts remain stable over reloads; selective purge removed 24 entities and 2 old devices; removed clients remained absent after node reload; automatic replacement removed old Redmi and renamed watch registry-only records.
- The maintainer confirmed correct behavior after the final full HA restart. Remote CI and release publication are checked during publication. Legacy HA 2026.10.0 suite previously reported 185 failures, 7 passes and 40 errors and has not been repaired.

## Before publication

The final restart is confirmed. Version 3.9.0 is consistent across the integration and frontend, and local checks pass. Publish the signed code commit, check remote CI, then publish the tag/release and update wiki availability. Do not close another user's router issue on the basis of the maintainer's setup alone.

## Documentation and notification publication

- Project wiki commit `9e7200b3c8b2730bc6243186568cd288a701ef33` is published and its remote HEAD verified. English/Spanish MAC and diagnostics guides are linked from Home, Config, Services, FAQ and the sidebar. Pages explicitly identify the features as upcoming after v3.8.4. The documentation commit was unsigned with explicit user authorization after the configured GPG store failed; Git signing settings were not changed.
- [Reply to #329](https://github.com/JuanManuelRomeroGarcia/hass-miwifi/issues/329#issuecomment-6110913288) published and body verified through GitHub's API. Issue remains open for reporter verification.
- [Reply to #325](https://github.com/JuanManuelRomeroGarcia/hass-miwifi/pull/325#issuecomment-6110907366) published and body verified through GitHub's API. PR remains open until the unpublished local adaptation is available in the repository.
- No unrelated issue or PR was closed, merged or presented as fixed. This section records the documentation publication before v3.9.0; the code release follows separately.
