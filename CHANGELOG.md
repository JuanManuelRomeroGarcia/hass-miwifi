# Changelog

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
