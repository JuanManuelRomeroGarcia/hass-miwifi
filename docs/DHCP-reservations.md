# DHCP reservations (local testing)

Open MiWiFi → **DHCP** to inspect the main router's reservations. Only loaded entries with a confirmed `is_main` role are eligible. Mesh nodes are excluded, and the backend rejects both reads and writes targeting them. For multiple independent networks, choose the corresponding main router. Administrators can add a known client or enter a MAC, IPv4 address and name manually, edit a reservation's IP/name, or confirm its removal. Operations never fall back to another mesh node.

## Initial support

Read and incremental add/edit/delete API behavior was verified on **BE10000 / RC01 firmware 1.1.56**. Writes are enabled only for this profile with DHCP enabled. Other firmware is read-only when its responses are compatible. AX1800 stock 3.0.34 (#314) still needs request/response and mutation verification.

When there is one main router, its name/IP and reservations load automatically with no router dropdown. Only multiple main routers from independent networks require choosing one. Refresh rechecks the loaded main entries before reading their reservations.

The feature does not modify LAN addresses, the DHCP pool, DNS or lease durations. Reads run on demand and do not add DHCP queries to coordinator polling.

Before saving, the integration re-reads configuration, rejects a stale editor, validates the subnet's usable host addresses, and checks conflicts with other reservations or the router's known candidates. It sends one incremental MAC operation and verifies the resulting list, including unrelated reservations. It never rewrites the whole list. The router does not provide atomic compare-and-set against external apps or sessions.

An ambiguous write failure may mean the operation already applied. **Refresh and inspect the list before retrying.** Further writes remain blocked until a successful read. No automatic mutation retry or rollback can overwrite external changes.

## Private MACs and leases

A reservation belongs to one specific MAC. Automatic private-MAC replacement in HA does not migrate or delete router DHCP reservations. Use a stable MAC for that network, or explicitly manage a new reservation when its MAC changes. Saving a reservation does not force renewal of a client's existing lease.

## Combined #346 + DHCP testing

The local integration folder contains v3.9.1, the prepared #346 adaptation and this DHCP development. No new release is published.

Back up the installed integration folder, copy the complete local `custom_components/miwifi` folder, restart HA and refresh the panel without cache. Verify mesh roles, counters over several polls/reloads and logs. Compare the DHCP list with the router's native UI. Use an agreed spare reservation and free IP for add/edit/delete tests, check unrelated entries remain unchanged, and remove the temporary record afterwards. If using a real client, verify its address after lease renewal. Recheck topology, counters, purged clients and private-MAC rules.

Automated HA tests use router API doubles. Real-client lease acquisition and persistence across a router reboot remain hardware checks.

For a visual preview without HA or router access, run `python tools/preview_dhcp.py` and open `http://127.0.0.1:8766`. It uses fictitious records only. Run legacy tests under `TZ=UTC` in WSL, matching CI, to keep the tests' simulated clock consistent.
