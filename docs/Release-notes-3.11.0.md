# MiWiFi v3.11.0

Optional panel tables/lists, a mobile layout refresh, verified BE6500 Pro dual-WAN
and connection-category support, Wi-Fi write recovery and mesh node identities.

## Choose the view that suits your screen

- **Devices → Cards / Table**: search by name, IP, MAC, node or connection; select
  columns and sort headings. On mobile the table scrolls sideways while names stay
  visible. Cards retain administrator-only Internet access controls and now show
  pending operations and failures.
- **Status → Cards / List**: system information, Internet/WAN and main/mesh client
  counters share the same live data in both layouts. IP addresses and long values
  wrap within the available width.
- View, column and sorting preferences stay in that browser. Device readings and
  search text are not persisted. Restricted browser storage does not prevent use.
- Improve mobile navigation, topology wrapping, DHCP/private-MAC controls and port
  dialogs, including keyboard focus, Cancel/Escape and small-screen scrolling.
- New controls are translated into English, Spanish, German, French, Brazilian
  Portuguese, Russian, Turkish and Simplified Chinese.

[Panel guide](https://github.com/JuanManuelRomeroGarcia/hass-miwifi/wiki/Panel-device-view)
· [Guía en español](https://github.com/JuanManuelRomeroGarcia/hass-miwifi/wiki/Panel-device-view-es)

## BE6500 Pro / RD08

PR #358 corrects firmware 1.1.96 client types, including **LAN, 2.4 GHz, 5 GHz,
Guest and IoT**, and preserves the source router's schema through mixed-model mesh
forwarding. Other models retain their existing connection codes (#356).

An RD08 main router with dual WAN enabled gains a **WAN2 IP address** sensor with
type, link and connection attributes. The status panel shows WAN2 separately.
Capability checks run at most every five minutes; WAN2 readings refresh with
normal polling. Failed reads clear stale secondary data without marking WAN1
offline or stopping the client census (#355).

This is read-only: it does not alter WAN policies or invent WAN2 speed readings
from configured bandwidth/weights. The supplied firmware still reports 256 MB RAM;
that API value remains displayed rather than hardcoding an assumed total.

[RD08 guide](https://github.com/JuanManuelRomeroGarcia/hass-miwifi/wiki/BE6500-Pro)
· [Guía en español](https://github.com/JuanManuelRomeroGarcia/hass-miwifi/wiki/BE6500-Pro-es)

## Wi-Fi, mesh and maintenance since v3.10.0

- #327: recover channel lists after transient errors using bounded retry backoff;
  preserve observed selections, verify writes and distinguish refused writes from
  unanswered requests. Later mesh-controller reversions retain the requested option.
- #354: resolve backhaul MAC aliases and expose serving-node identity/name
  attributes for dashboard filters, retaining the original router MAC attribute.
- #351–#353: restore Python/frontend CodeQL scanning, remove private client data
  from roaming logs, document authentication constraints and refresh CI actions.
- Complete the README gallery of 74 recognized models. Recognition does not imply
  that every firmware implements every feature.

Thanks to **@brembygit** for Wi-Fi/mesh contributions and cross-model evidence,
**@MaximSN** for the RD08 diagnostic and hardware verification, and everyone who
reported and tested these changes. The device-table proposal comes from #357.

## Validation and installation

The final build is validated with both maintained HA compatibility suites, the
complete legacy suite, standalone regression/security/counter checks and all five
frontend behavior scripts plus packaging validation. The maintainer confirmed
the combined panel in real HA on desktop and mobile; Maxim confirmed the RD08
category and WAN2 fixes. CI results on the release commit remain the authority.

Update through HACS, **restart Home Assistant**, then refresh the panel. If an old
layout remains, try a fresh private window or clear the browser's site cache.
The integration and all bundled frontend cache references are 3.11.0; there is no
separate panel installation. The HACS minimum stays HA 2025.8.0; current compatibility
tests cover 2026.9.3 and 2026.10.0, not every intervening HA release.

Existing private-MAC rules, DHCP safeguards and cleanup remain configured. Do not
expect private-MAC replacement to migrate DHCP reservations or automation references.
Manual role overrides and the separate mesh cleanup proposal are not included;
#333 and #334 remain open for evidence/verification. Report new regressions with
the installed version and redacted evidence; never post credentials or session URLs.
