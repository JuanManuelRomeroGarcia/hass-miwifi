# Changelog

## Unreleased

- Standardize defaults at 60 seconds presence grace, 30 seconds polling and 20 seconds request timeout, including missing-setting fallbacks. Preserve explicitly saved user values.
- Explain scan interval, request timeout and presence grace in all eight form languages. New entries suggest 60 seconds; tracked-entry saves require at least scan interval plus timeout. Preserve existing values without silent adjustment, retain invalid submissions for correction, and document mesh latency limits.
- Integrate the local trial of #364 (empty leaf counters), #366 (persistent auto-purge deadlines and failure history), #368 (force-load client restoration and saved tracker state), and #370 (first-refresh topology role). Preserve contributor commits; no release or public merge yet.
- Reserve global scheduler ownership before asynchronous setup and cancel pending initialization on unload/reschedule, preventing multiple entries from arming duplicate purge timers.
- Handle LuCI connection failures in optional NAT reads, including the authentication retry; keep the last successful snapshot during transport failure and retry after one minute instead of aborting the coordinator refresh.
- Focused combined HA 2026.10.0 validation: 98 passed. Full legacy and compatibility batteries are deferred to the eventual GitHub PR. Keep integration/frontend version 3.12.0 during the hardware trial.

## 3.12.0 — 2026-10-17

- Translate the optional purge MAC-address filter in all eight languages and use a language-neutral day unit; preserve selection, preview defaults and deletion safeguards.
- Exclude positively identified mesh nodes from client tracking/restoration, clean up legacy client entities across MiWiFi entries while preserving router/foreign entities, and retry freed backhaul aliases across loaded nodes (#331, thanks to @brembygit and the maintainer follow-up). IP-only matches do not authorize registry deletion.
- Separate global mesh settings from per-device options, preserve legacy client-sensor behavior until explicitly saving the global setting, and keep force-load visible when enabled (#359, thanks to @brembygit).
- Add an opt-in manual AP/mesh role for nodes behind another gateway, skipping gateway mode/WAN/MAC-filter reads while retaining client updates and status-provided WAN speeds (#326, thanks to @brembygit). Keep the option off by default and translate it in the new per-device form in all eight languages.
- Add an opt-in fresh router API diagnostic export for all loaded main/mesh entries. Include request paths, parameters, timings, responses, errors and explicit skips from a fixed read-only catalogue, with time/size limits and partial results. Keep administrator-only private ZIP downloads and reject concurrent dumps.
- Always hide passwords, keys and known tokens. Optionally replace IP/MAC addresses and identifying names with distinct, consistent aliases across an archive. Use verified Wi-Fi readers instead of calling setters with empty parameters.
- Translate private dump/log download notices, automatic MAC replacement configuration and the purge preview title into all eight languages. Add notification and export regressions.
- Document the diagnostic catalogue, limits and privacy in English and Spanish. Confirm two-router captures and Spanish notifications on real HA 2026.10.1; retain the main NAT/node mode request failures in partial exports rather than hiding them.
- Add discreet optional PayPal/Wise support links at the bottom of Settings and the README. Keep every feature available without contributing and translate the panel invitation into all eight languages.
- Update integration, bundled frontend and translation cache references together to 3.12.0. Restart HA and refresh the panel after updating. The HACS minimum remains HA 2025.8.0.
- Also anonymize init_info hardware serials and room labels while preserving diagnostic query IDs.
- Real-device coverage includes the maintainer's RC01/RC06 wired mesh on HA 2026.10.1 and the contributor's four-node RD28/RA82 wired mesh. The intermittent router-sensor race (#333) and unconfirmed wireless-backhaul case (#334) have no confirmed hardware reproduction; this release does not claim to prove those cases fixed.

## 3.11.0 — 2026-10-16

### Panel views and mobile layout

- Add optional Cards / Table views for the device list (#357). Search by name, IP, MAC, serving node or connection, sort columns, choose visible columns and keep the name column visible while scrolling horizontally on mobile. Preserve administrator-only Internet access controls in Cards, with pending/error feedback.
- Add Cards / List views for system, Internet/WAN and main/mesh client counters. Both views show the same live values; long IP addresses and text wrap within their cards or table cells. Store view/column/sort preferences in the browser, without storing device readings or search text.
- Improve narrow-screen navigation, controls, topology wrapping, DHCP/private-MAC settings and port-forwarding dialogs. Support keyboard focus, Cancel/Escape and scrolling within small dialogs. Translate the added controls into all eight panel languages.

### Router compatibility and Wi-Fi

- Correct BE6500 Pro / RD08 firmware 1.1.96 connection codes: LAN=1, 2.4 GHz=2, 5 GHz=3, Guest=7 and IoT=9. Preserve the reporting router's interpretation across mixed-model mesh nodes and keep other models' existing schemas (#358, resolves #356).
- Read RD08 main-router WAN2 configuration, IP, type, physical link and connection status. Expose a separate WAN2 IP address sensor with status attributes and show WAN2 in the panel when enabled. Cache capability checks for five minutes, bound requests and clear stale WAN2 values on failures without changing WAN1 status or stopping client polling (#358, resolves the dual-WAN part of #355).
- Do not infer WAN2 traffic from configured bandwidth/weights or change WAN policies. RAM continues to display the firmware's reported 256 MB; no verified alternate physical-memory API was supplied.
- Recover Wi-Fi channel options after transient failures with bounded retry backoff. Preserve router-reported selections, verify writes, distinguish refused writes from unanswered requests, and expose later mesh-controller reversions through the pending requested option (#327, thanks to @brembygit).
- Resolve mesh nodes through their backhaul MAC aliases and expose `connected_via_router_device_mac` / `connected_via_router_name` for dashboard filtering while retaining the existing router MAC attribute (#354, thanks to @brembygit).

### Maintenance, validation and upgrade

- Restore CodeQL scanning for Python and frontend code, remove private client identifiers from roaming logs, document vendor authentication constraints and update CI actions to Node 24 releases (#351, #352, #353). Complete the README gallery of all 74 recognized model codes without claiming universal firmware/feature support.
- Build the local preview iframe URL from predefined route/language choices and encoded query parameters instead of DOM text; add a regression check for invalid selections and injected parameters.
- Keep the HACS Home Assistant minimum at 2025.8.0. Validate with maintained suites on HA 2026.10.0 and 2026.9.3, the full 2026.10.0 legacy suite, standalone regressions and frontend behavior/packaging checks. The existing registry-version skip remains on 2026.9.3.
- The maintainer confirmed the combined panel on real HA in desktop and mobile views. @MaximSN confirmed corrected RD08 network labels and WAN2 display after refreshing the frontend session. #333's router-sensor setup race, #334's wireless force-load case and the unmerged role/mesh-cleanup proposals are not claimed resolved.
- Update through HACS, restart HA and refresh the panel. Integration, bundled assets and translation cache references now use 3.11.0; no separate frontend install is needed. Existing private-MAC rules, DHCP safeguards and client/purge behavior are preserved.

## 3.10.0 — 2026-10-14

- Add an administrator-only DHCP panel page with explicit router selection, reservation reads and verified incremental add/edit/delete. Initial writes are limited to the tested BE10000 / RC01 firmware 1.1.56 profile; other compatible responses remain read-only (#314).
- Validate LAN host addresses and known IP conflicts, serialize writes, reject stale editors and verify unrelated reservations. Require a refresh after an ambiguous write failure without automatic retries or rollback. Keep DHCP reservations independent of private-MAC entity cleanup.
- Translate DHCP controls and errors into all eight panel languages and document the combined local #346/DHCP hardware test.
- Show router names rather than repeated IP titles in the DHCP selector. Include only confirmed main routers and reject node-targeted requests or a main-role change during an operation.
- Automatically load the sole main router's DHCP reservations without a redundant selector. Look up its HA name through the config-entry-scoped registry API, avoiding the deprecated device lookup and names from another entry.

- Adapt @brembygit's topology-role and updater resilience contribution (#324) on the v3.9.1 baseline (#346). Use positive mesh/AP topology roles while preserving main-router, CB0401V2 and existing mesh-mode precedence; fall back to the mode endpoint when local or parent topology is malformed.
- Normalize whitespace in topology leaf addresses before matching configured nodes, preserving both role detection and the parent topology's client-count fallback.
- Contain optional WAN, channel, client-list, upstream signal and force-load counter endpoint failures so later preparation steps can continue. Retry them on later refreshes; critical login/status failures retain their existing error behavior.
- Cancel coordinator polling before saving history or logging out, including a failed logout. Access verification uses this stop path once on every exit.

## 3.9.1 — 2026-10-13

Maintenance release for client counters, private-MAC configuration and current Home Assistant compatibility. Includes #345, #347 and #348.

- Preserve a force-load leaf's own client counters when the parent router pushes client records to it (#348).
- Resolve a known router's backhaul connection alias when linking clients to their serving node, requiring the registered router identity and loaded entry to match.
- Request force-load client counters once per polling cycle. Handle endpoint failures through the existing update error path instead of repeating the request outside it.
- Cancel the pending automatic purge deadline before its startup kickoff or scheduled run replaces it, preventing duplicate runs and timers left behind after cancellation.
- Preserve nested Wi-Fi channel and bandwidth values in write snapshots, with top-level provider fields as fallbacks when nested values are missing.
- Restore the legacy Home Assistant integration tests and make their CI job required alongside the maintained compatibility suites. Isolate router delay mocks, wait for background jobs and validate current registry, polling and client ownership behavior.
- Read device entries through the supported registry iterator when saving private-MAC replacement rules, including registry-only historical clients. Retain compatibility with older mapping-based registries (#347, thanks to @brembygit).
- Use the coordinator's supported refresh callback, wait for topology data before provisioning client sensors, and shut down temporary login coordinators on success and failure.
- Cancel discovery timers at Home Assistant shutdown and remove per-router stored history when an already unloaded integration entry is deleted.
- Redact device data in downloaded diagnostics and restore entity-description icons for Wi-Fi selectors and binary sensors.
- Refresh the integration and bundled panel cache version to 3.9.1.

### Validation and upgrade

- The combined release is checked with the complete legacy suite on HA Core 2026.10.0, maintained compatibility suites on 2026.10.0 and 2026.9.3, and HACS, hassfest, standalone regression and frontend checks. The newer device-registry ownership test retains its version-specific skip on 2026.9.3.
- Update through HACS, restart Home Assistant and refresh the browser. Existing private-MAC rules remain configured; automatic replacement is still opt-in for individually configured clients with unique router names.
- This release does not claim to resolve every router-specific report. #329 still needs its reporter's diagnostic validation; topology-role overrides, Wi-Fi write verification and the remaining mesh-node cleanup proposals stay in their separate PRs.

## 3.9.0 — 2026-10-11

Private MAC management, persistent client cleanup, mesh diagnostics and compatibility with current Home Assistant.

### Private MAC addresses and cleanup

- Add opt-in automatic replacement for individually configured clients with unique router names. Support previous/current aliases and learning a rename on a known connected MAC. Require fresh complete client lists from every loaded node and exactly one associated online MAC; protect ambiguous, unknown or stale observations.
- Remove older associated MiWiFi trackers and client sensors across nodes without waiting for the inactivity age limit. Preserve current clients and unrelated integration entities. Do not migrate entity/device IDs, custom labels, areas, persons or automation references.
- Match unavailable historical clients retained only in HA's registries when saving a rule. Use integration-provided names and MiWiFi tracker/MAC identifiers, not user display-name overrides.
- Add a compact client list in the main router's panel settings, with known-client selection, expandable aliases, removal, refresh and save. Read and write rules only as an administrator; preserve other saved rules and block saving after a failed load. Use device names in configuration notifications. Saving rules requires no reload or restart.
- Persist rules and suppression of retired/purged MACs across reloads and restarts. Clear client copies from all loaded nodes and stores, including empty and non-force-load leaf stores. Stale restored/offline records do not recreate removed clients; a genuinely connected old MAC can return.
- Add an optional explicit MAC allowlist to inactivity purging. Preserve activity seen on any loaded node. Clean matching client sensors, including disabled sensors, when explicitly selected with orphan cleanup; preserve unrelated/recent entities and recently changed states without known activity dates.
- Make purge previews include all selected entities and resulting empty devices. Count devices removed by signal handlers as well as the service and return the device count in the action response. Simulation does not change suppression state.

### Mesh counters and diagnostics

- Keep a recent completed parent census authoritative across later leaf refreshes instead of replacing its count with a different topology total after one cycle. Fall back when the source is unloaded/replaced or expires after three scan intervals plus the request timeout (minimum 60 seconds). Use the updater's supported timeout property.
- Clear stale moved-client markers when the parent census assigns a returning client to a node again, so it contributes to the counters once.
- Add bounded, in-memory mesh support capture to integration diagnostics for #329. Include all loaded nodes, startup/recent censuses, parent/client ownership, moved markers, counter transitions and topology address-whitespace flags without extra router requests.
- Anonymize MAC/IP/entry relationships consistently within one HA runtime and exclude names, SSIDs, credentials and raw payloads from mesh_support. Earlier diagnostic sections retain their original format and may contain private data; publish only mesh_support.

### Compatibility, bundled frontend and documentation

- Adapt the CI and coordinator/device-trigger compatibility work from #325, with thanks to @brembygit. Pass the owning config entry explicitly while preserving login/ambient fallbacks. Import TriggerActionType and TriggerInfo from the supported HA helper.
- Validate classic device-trigger discovery, event filtering, execution and unsubscribe. Manual YAML automation testing confirmed a simulated miwifi_luci response creates its notification; this does not add classic triggers to the newer target-based picker or verify a real router response.
- Add maintained CI rows for HA Core 2026.10.0 and 2026.9.3 with their exact frontend dependency. Separate inherited legacy tests into a non-blocking reported job and select suites before importing incompatible modules. Keep HACS/hassfest and standalone/frontend checks.
- Remove the obsolete separate panel frontend update entity and clean existing integration-owned entries on setup, including renamed/disabled entries. Router firmware update entities remain. Remove unused legacy panel-version fields/state constants while retaining the bundled version helper.
- Translate the MAC settings into all eight panel languages: English, Spanish, German, French, Brazilian Portuguese, Russian, Turkish and Simplified Chinese. Check full key coverage.
- Document configuration, aliases, safeguards, deletion effects, persistence, diagnostics and troubleshooting in README and English/Spanish project wiki guides. Distinguish automatic replacement from ordinary inactivity purging and DHCP reservations.

### Validation and remaining limits

- HA Core 2026.10.0: 135 maintained pytest tests and 65 standalone tests pass (200 total), plus frontend packaging and panel behavior checks.
- HA Core 2026.9.3: 134 maintained tests pass; one test for the newer device-registry API is skipped.
- Real-router testing confirmed stable leaf counts across refresh/reload, returning clients counted again, obsolete panel update removal, selective purge removing 24 entities and 2 old devices, and removed clients staying absent after node reloads. Automatic replacement removed an older Redmi MAC and a registry-only old watch after a router rename.
- The maintainer confirmed the final full HA restart is correct; removed clients and saved rules remain as expected. #329 remains open until its reporter verifies their own router setup. #333's remaining router-sensor setup race and #334's potential force-load wireless-backhaul case are not claimed fixed.
- The inherited legacy suite is not repaired: the previous HA 2026.10.0 run reported 185 failures, 7 passes and 40 errors. Remote CI is checked before publishing this release.

## 3.8.4

- Recognize RN12 (Xiaomi Range Extender AX1500) during setup and add its bundled image to the panel and README gallery (#343). The reporter confirmed setup over HTTPS with firmware 1.0.63; individual features remain subject to the router's API capabilities.
- Accept the panel settings payload in `miwifi.apply_config`, validate its three supported fields, retain administrator-only access, and document the action in `services.yaml` (#337).
- Re-create a known client's tracker when its original platform unloads after the client moves to another mesh entry. Preserve the entity ID and keep new-device notifications restricted to actual discoveries (#332).
- Read single-owner device rows through `config_entry_id` to avoid Home Assistant 2026.10 deprecation reports. Preserve multiple owners on composite devices and older cores, including inactive-device purge safeguards (related to #344).
- Prevent a tracker from linking its device row to itself when a stored parent MAC, an alternate MAC, or merged identifiers resolve to the client's own row. Keep the client and omit only the invalid parent link.
- Refresh the integration and bundled panel cache version to 3.8.4 and add regression coverage for settings validation, tracker recovery, parent links and device ownership.

Thanks to [@brembygit](https://github.com/brembygit) for the #332 reproduction, independent router testing, and the composite-device coverage in #344, and to the #343 reporter for verifying RN12 setup.

### Validation

126 tests pass: 69 targeted tests on Home Assistant Core 2026.10.0 and 57 standalone regression, client-counter and private-export security tests. Frontend packaging and syntax checks also pass. Coverage includes the real service registry and entity platforms, tracker reload/disable recovery with force load enabled and disabled, preserved entity IDs, duplicate prevention, disabled entities, valid parent links, and legacy/composite device ownership.

Manual testing confirmed panel settings save successfully and clients continue updating after reload. A disconnected laptop's tracker previously failed to load because of a self-parent link; after the guard, startup and reconnect/reload worked without that error. Independent tests on an RD28/RA82 wired mesh confirmed the #332 fix: affected trackers recovered within 30 seconds after origin reload or disable, retained their IDs and serving-node ownership, and remained live after the origin was re-enabled.

### Upgrade and remaining work

Update through HACS, restart Home Assistant, and refresh the browser. The panel is bundled with the integration. This release does not repair incorrect parent data already reported by a router or shown in the panel; the observed self-parent label remains under investigation. The separate NAT connection-error handling and router-sensor duplication race (#333) are not fixed here. PRs #324-#327 and #331 remain separate work.

## 3.8.3

- Prevent duplicate client sensor creation when several routers hold the same client at startup or during roaming. Skip a sensor only while a live MiWiFi sensor platform provides it; existing registry rows do not block sensor recovery after restart or reconnect (#330).
- Reset self-counted client counters once per polling cycle on access points and other repeater roles without force load. Preserve counters pushed to leaf nodes by their parent and the existing gateway/force-load behavior (#341, fixes #340).
- Add a real Home Assistant regression test for one disconnected client restored by two routers. The control reproduces duplicate IDs without the live-platform filter; the corrected path provides every client sensor once.
- Refresh the integration and bundled panel cache version to 3.8.3.

Thanks to [@brembygit](https://github.com/brembygit) for #330 and #341.

### Validation

39 standalone regression tests, 7 client-counter tests, 8 tests on Home Assistant 2026.9.3, 5 export security tests, and frontend packaging checks pass. Manual testing confirmed startup without duplicate IDs with a disconnected client, sensor recovery on reconnect, working mesh client sensors and roaming, and stable client counts during node changes. The access-point accumulation case was reproduced in automated tests (4 clients became 12 after three cycles before the fix; they remain 4 after it).

The separate tracker loss after reloading its origin entry (#332) and the unconfirmed router-sensor duplication race (#333) remain outside this release.

### Upgrade

Update through HACS, restart Home Assistant, and refresh the browser. The panel remains bundled with the integration. This release does not repair historical client-count statistics recorded before the fix.

## 3.8.2

- Reload only the router whose options changed. Reload all MiWiFi entries only when the effective mesh-wide client-sensor setting changes (#336, related to #333).
- Keep the automatic purge schedule in the global store instead of copying it into every router's options and triggering repeated reloads (#336).
- Report missing client speeds as unknown when a client is detected only through a node's Wi-Fi list. Report empty client uptime as unknown, while preserving available router values and numeric zero speeds for offline clients (#338).
- Restore the router photo gallery in the README, use bundled router images in the updater, and remove duplicate root images (#335).
- Refresh the bundled panel cache version to 3.8.2 and add regression coverage for mesh value preservation, speed recovery, effective sensor settings, and unloaded entries.

Thanks to [@brembygit](https://github.com/brembygit) for #336 and #338.

### Validation

34 standalone regression tests, 5 export security tests, and frontend packaging checks pass. Manual RC01 + RC06 wired-mesh tests confirmed client sensors and speeds, restart recovery, roaming in both directions, per-node options reloads, and automatic sensor removal/restoration when the effective mesh-wide setting changes. The Wi-Fi-list-only missing-data case is covered by automated tests; it was not reproduced on this wired-mesh setup.

The duplicate router-sensor race also reported in #333 remains unconfirmed. This release fixes its confirmed reload fan-out, without claiming to resolve that race or the separate tracker-reload issue #332.

### Upgrade

Update through HACS, restart Home Assistant, and refresh the browser. The panel remains bundled with the integration. Client sensors remain enabled across the mesh while any router entry enables them.

## 3.8.0

- Make scheduled automatic device purging conservative and allow disabling it with a zero-day interval. Undated devices are preserved by default; the manual dry-run service remains available (#321).
- Correct Mesh client counts and attribute clients to the serving node, including nodes that use a different backhaul MAC (#322).
- Keep each roaming client, its device tracker, and its sensors together under the currently serving router in Home Assistant. Update the parent link without reloading and remove stale MiWiFi-only device rows (#323).
- Adapt device registry and targeted service lookups for current Home Assistant APIs while retaining compatibility with older versions (#323).
- Refresh the bundled panel cache version to 3.8.0.

Thanks to [@brembygit](https://github.com/brembygit) for contributing the fixes in #321, #322, and #323.

### Upgrade

Update the integration through HACS, restart Home Assistant, and refresh the browser. The panel remains bundled with the integration.

## 3.7.0

- Ship the frontend, Lit, translations and images inside the integration; update them together through HACS.
- Remove independent panel downloads and monitoring; use Home Assistant's asynchronous static resources API.
- Point panel feedback to this repository and use local fallback icons for unknown models.
- Fix unsupported-language fallback and align frontend cache versions with the integration.
- Fix device purge crashes with longer registry identifiers (#313) and adapt registry iteration (#318).
- Prefer the public ScannerEntity import with backwards compatibility (#309).
- Reduce repeated mode endpoint requests and log messages, while preserving cancellation and recovery (#312, #319).
- Recognize RP01 and RP03 based on reported read API compatibility (#315, #316, #317).
- Include the existing local sensor setup and mesh device tracking fixes.

### Upgrade

Update the integration through HACS, restart Home Assistant and refresh the browser.
No separate frontend repository, Lovelace resource or panel_custom YAML is required.
Legacy /config/www/miwifi files are preserved but are not used for the panel.
The /local/miwifi/exports/ path remains in use for generated diagnostic downloads.
The panel's old update entity reports the bundled version; updates are managed by HACS.
