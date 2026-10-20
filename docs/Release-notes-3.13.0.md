# MiWiFi v3.13.0

Mesh recovery, persistent purge scheduling, translated client diagnostics and
optional real Wi-Fi signal/link metrics.

- Fix leaf counters when the last parent-reported client leaves (#364).
- Keep auto-purge deadlines across restarts, record failures and prevent duplicate
  scheduled timers (#366 and maintainer follow-up).
- Restore force-load node clients and saved tracker states, and identify wired
  mesh nodes from their topology on the first refresh (#368 and #370 together).
- Recover optional NAT reads after transport failures without aborting polling.
- Use consistent 60/30/20-second presence/scan/request defaults, validate timing
  changes and explain them in all eight supported languages. Saved settings stay.
- Translate client diagnostics and add optional Wi-Fi protocol and TX/RX link-rate
  sensors. Use real negative RSSI when available; hide Wi-Fi-only fields on LAN.
  Support depends on the router's firmware. Link rates are not Internet throughput.
- Add a standalone SSH API inventory tool; it does not run in normal HA polling
  and never calls discovered API handlers automatically.
- Remove internal notes and obsolete workflow copies from repository tracking.

Thanks to @brembygit for the four mesh/scheduler contributions.

## Update

Update through HACS, restart Home Assistant and refresh the panel cache. The
integration and frontend both use 3.13.0. The minimum remains HA 2025.8.0.
New diagnostic sensors can be enabled from the device's disabled entities.
Review purge candidates in simulation before enabling automatic deletion.

The maintainer verified stable presence, return/departure, RSSI against the app,
mesh client metrics, LAN field hiding, reloads and a selective deletion on RC01/RC06,
without reported errors. Scheduler deadlines, empty-leaf and force-load startup
edge cases retain automated coverage; not every case was reproduced on hardware.
The existing unknown client total-usage reading is not claimed fixed.

## Español

Esta versión reúne las correcciones de malla y autopurga, las traducciones de
diagnóstico y las nuevas métricas Wi-Fi disponibles en firmwares compatibles.
Mantiene los ajustes guardados y propone 60/30/20 segundos por defecto.
Actualiza desde HACS, reinicia Home Assistant y refresca el panel. Los tres
sensores nuevos son opcionales; las velocidades de enlace no equivalen al tráfico
de Internet. Revisa una simulación antes de activar la autopurga.
