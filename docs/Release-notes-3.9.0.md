# MiWiFi v3.9.0

## Private MAC management

Add opt-in automatic replacement for clients whose router names uniquely identify the same physical device. In the main router's panel settings, select clients, enter previous/current aliases, remove rules and save. The compact list is translated into all eight panel languages.

Replacement waits for fresh complete client lists from every loaded MiWiFi node and exactly one connected MAC. It removes older associated MiWiFi trackers and client sensors across nodes, including unavailable historical clients retained only in HA's registry. Rules and suppression of retired MACs survive reloads and restarts; a real reconnection can admit an old MAC again.

**This feature is disabled by default. Enable it only for unique physical clients. It deletes the old MAC's MiWiFi entities; entity/device IDs, areas, custom names, person assignments and automation references are not transferred.** Review anything that referenced an old tracker. It does not manage DHCP reservations or change client privacy settings.

[English guide](https://github.com/JuanManuelRomeroGarcia/hass-miwifi/wiki/Random-MAC-addresses) · [Guía en español](https://github.com/JuanManuelRomeroGarcia/hass-miwifi/wiki/Random-MAC-addresses-es)

## Cleanup and mesh reliability

- Restrict inactivity purge to explicit MACs, clean associated client sensors, and report accurate entity/device totals in previews and apply responses. Recent activity on any loaded node protects a client.
- Persist suppression of purged records and clear saved client copies across nodes, preventing stale/offline records from recreating them after reloads or restarts.
- Keep a recent completed parent client census authoritative on mesh leaves; clear stale moved-client markers when clients return.
- Add bounded mesh_support diagnostics for all loaded nodes, with consistent anonymized MAC/IP/entry relationships and counter history, without extra router requests. **Only mesh_support is anonymized for public sharing; other diagnostic sections may contain private data.** [Diagnostics guide](https://github.com/JuanManuelRomeroGarcia/hass-miwifi/wiki/Diagnostics).
- Remove the obsolete separate panel frontend update entity. The panel continues updating with the integration; router firmware update entities remain available.

## Home Assistant compatibility and validation

Adapt the test harness, explicit coordinator config-entry ownership and classic device-trigger compatibility work from #325, with thanks to @brembygit. This restores the classic trigger API/YAML behavior on current HA; it does not add those triggers to the newer target-based picker.

Local validation: 135 maintained tests plus 65 standalone tests pass on HA 2026.10.0; 134 maintained tests pass and one newer-registry test is skipped on HA 2026.9.3. Frontend packaging, panel behavior and all eight language dictionaries are checked. Real-router testing confirmed cleanup, renamed-watch replacement and correct behavior after a full HA restart.

The inherited legacy tests remain reported separately and have not been repaired. Issue #329 stays open for verification on its reporter's routers. This release does not claim the remaining router-sensor race in #333, wireless force-load case in #334, DHCP reservations in #314 or the separate changes in PRs #324, #326, #327 and #331.

## Install

Update the integration to v3.9.0 through HACS, restart Home Assistant, then refresh the panel. The panel and translations are bundled; no separate frontend installation is needed. Private-MAC rules are configured once per client and remain saved across restarts.
