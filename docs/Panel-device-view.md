# Device table and mobile panel review

The Status page offers **Cards / List** for system, Internet (including WAN2 when
enabled) and main/mesh client counters. The list uses Field/Value columns that wrap
on mobile. Long addresses also wrap inside cards. This browser-only preference is
separate from the device table preference and stores no readings. WAN2 comes from
merged PR #358, included in the same release. Both views use the same data and
preserve the selected presentation when readings change.
Available from **v3.11.0**. Automated data/preference checks pass and the maintainer
confirmed the combined status and device views in real HA on desktop and mobile.
Earlier viewport checks covered the prior panel layout; these confirmations do not
establish every browser/theme/phone combination.
If HA does not yet run main with #358, back up and copy the complete
`custom_components/miwifi` folder and restart HA; copying `www` alone only updates
the frontend and cannot install WAN2 backend support.

Implements the device-table proposal in #357 without adding router queries for
these views. Upgrade through HACS, restart HA and refresh the panel; no separate
frontend installation is required. Bundled cache references use 3.11.0.

The Devices page offers Cards and Table views, search by name/IP/MAC/node/connection,
sortable headings and selectable columns. The name column stays visible while the
table scrolls horizontally on a phone. WAN controls remain available in Cards.
View, columns and sort order are stored in the browser; searches and client data
are not. Blocked browser storage does not prevent using the view. Offline devices
include unavailable trackers, and totals remain global while searching.

The panel review also adjusts navigation, grids, long names and controls across
Status, Mesh, Settings, DHCP and port forwarding. Topology nodes wrap on phones.
The port dialog fits small windows and supports vertical scrolling, Cancel,
Escape and Tab navigation. New labels cover all eight panel languages.

## Validation and HA trial

Run `node tools/test_devices_ui.mjs`, the existing MAC replacement and DHCP UI
checks, and `python tools/check_frontend_packaging.py`. The device checks cover
search, numeric name/IP and transfer-rate sorting, preference restore, blocked
storage, unavailable state, WAN permissions/duplicate writes/errors and translations.

Run `python tools/preview_panel.py` and open `http://127.0.0.1:8767` to inspect the
actual pages with synthetic responses. Its writes never reach HA or a router.
The preview covers widths 320, 390, 768 and 1280, themes, languages and permissions;
it does not replace a real HA companion-app/phone check.

Back up the installed `custom_components/miwifi/www` folder and copy the complete
local `www` folder over SFTP. Do not copy preview tools into HA. Force-refresh the
frontend cache after copying; the release's integration and frontend use 3.11.0.
Check all pages, long names, multiple nodes, table scrolling, column selection,
search, sorting, offline devices, preference restore and a non-admin user. Confirm
that real state/IP/connection changes are reflected during normal HA use and after
navigating back. Open and cancel the port dialog without saving. Only use an agreed
test client if validating WAN access changes, and restore its original setting.

See the [Spanish trial guide](Panel-device-view-es.md) for the full checklist.
