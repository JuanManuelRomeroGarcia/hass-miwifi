# Changelog

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
