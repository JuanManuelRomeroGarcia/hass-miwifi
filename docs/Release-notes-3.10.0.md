# MiWiFi v3.10.0

DHCP reservations in the bundled panel, topology-based mesh roles and resilience to optional router API failures. Includes the #346 adaptation of @brembygit's #324 contribution, on the v3.9.1 baseline.

## DHCP reservations

- Open **MiWiFi → DHCP**. The confirmed main router loads automatically, showing its name and IP. Mesh nodes are excluded. Multiple independent main routers require choosing the corresponding network.
- Administrators can list reservations, choose a known client or enter MAC/IPv4/name manually, edit a reservation's IP/name, and confirm its removal.
- **Initial write support is limited to BE10000 / RC01 firmware 1.1.56 with DHCP enabled.** Other compatible main-router responses are read-only. AX1800 stock 3.0.34 (#314) still needs its native API format and mutation behavior verified.
- Validate host addresses against the actual LAN subnet and known IP conflicts, reject stale editors, serialize operations and verify the resulting list, including unrelated reservations. Send one incremental reservation, never the whole list. A failed or unverified write requires a fresh read before retrying; there is no automatic mutation retry or rollback.
- Reservations remain tied to a specific MAC. Automatic private-MAC entity replacement does not migrate DHCP reservations. Saving does not force renewal of an existing client lease.
- Controls and errors are translated into all eight panel languages. Router-name lookup uses the config-entry-scoped device registry API, avoiding the deprecated ambiguous lookup.

[English guide](https://github.com/JuanManuelRomeroGarcia/hass-miwifi/wiki/DHCP-reservations) · [Guía en español](https://github.com/JuanManuelRomeroGarcia/hass-miwifi/wiki/DHCP-reservations-es)

## Mesh roles and recovery

- Use positive topology evidence for AP/mesh roles, including wired leaves whose gateway-mode endpoint reports `default`. Preserve main-router, CB0401V2 and existing mesh-mode precedence; malformed topology falls back to the endpoint.
- Normalize whitespace in leaf IPs before matching configured nodes and applying the parent's counter fallback.
- Contain optional WAN, channel, client-list, upstream signal and force-load counter endpoint failures so later preparation can continue. Subsequent polls retry these reads. Critical login/status failures retain their existing error handling.
- Cancel coordinator polling before saving history or logging out, including a failed logout. Temporary access verification uses the same stop path once.
- Preserve the v3.9.1 counter, private-MAC and purge corrections. These changes do not claim to resolve the reporter-specific count regression in #329 or implement the separate role override, Wi-Fi and mesh cleanup proposals in #326, #327 or #331.

## Validation and installation

The combined build is checked with the complete legacy suite on HA 2026.10.0, maintained suites on HA 2026.10.0 and 2026.9.3, standalone regressions, frontend behavior, eight-language coverage and packaging checks. The 2026.9.3 suite retains the existing version-specific registry test skip.

The maintainer confirmed successful HA startup and correct panel behavior with both changes installed. A controlled temporary native-API reservation on BE10000 verified add/edit/delete and preservation of all original bindings. Real-client lease renewal and persistence after a router reboot are not claimed tested.

Update through HACS, restart Home Assistant and refresh the browser. The panel and translations update with the integration; no separate frontend installation is required.
