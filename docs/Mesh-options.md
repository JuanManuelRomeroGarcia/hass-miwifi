# Mesh and device settings (v3.12.0)

Open Configure on a MiWiFi entry in Home Assistant.

- **Global mesh settings** controls the panel, log level, auto-purge schedule and client sensors. It is offered on the main router, or on every entry when no main is identified yet. The latest explicit global save determines the shared sensor setting. Until that first save, existing behavior is preserved.
- **Settings for this device** controls connection, credentials, intervals, tracking, WAN units, port probing, AP role and force-load. Saving preserves the shared options and normally reloads only that entry. Changing the effective shared client-sensor setting reloads every entry.

Disabling client sensors removes them across all entries. Keep a backup first if you customized those entities.

## Manual AP / mesh-node role

This option is off by default. Enable it for a device behind another gateway when its firmware does not support the usual gateway mode, WAN or MAC-filter queries in that role. It can also apply to a mesh main running as an AP behind another manufacturer's gateway. Do not enable it on your Internet gateway merely to hide a WAN error.

It changes integration behavior, not router configuration, Wi-Fi, DHCP or NAT. The mode becomes `access_point`; client tracking, counters and speeds reported by `misystem/status` remain available. WAN state, link, IP and type can become unknown because their requests are skipped. No WAN2 values are invented.

## Nodes previously tracked as clients

Known mesh nodes are excluded from client tracking and restoration. Only positive firmware identification (`isap > 0`) authorizes cleanup of their old client entities, including disabled entities and other MiWiFi entries. An IP match alone never authorizes deletion. Router entities and other integrations are preserved.

Review automations using an old client tracker for a node; those references are not migrated automatically. Do not manually delete an empty device row that still serves as a parent for clients.

Physical testing covers wired meshes. If duplicate entities or a wireless satellite tracked as a client recur, open a new issue with model, firmware, HA version, reproduction steps and anonymized diagnostics.

## Presence timing

See [timing, minimums and examples](Presence-timing.md) before changing polling, timeout or presence grace. Save validation is prepared locally for the next update.
