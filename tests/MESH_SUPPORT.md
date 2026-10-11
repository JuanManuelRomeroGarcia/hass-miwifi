# Mesh support capture

The integration diagnostics contain a `mesh_support` section for client routing
and counter investigations, including issue #329. It covers every currently
loaded MiWiFi entry in a single download. No additional API requests are made.

After installing the modified integration files, restart Home Assistant, wait for
the affected nodes to refresh and reproduce the problem. Download integration
diagnostics from the MiWiFi entry's menu. Share **only the `mesh_support` section**
publicly: the older sections in the same diagnostics download still contain
ordinary device/network data and are not covered by this section's anonymization.

The report includes HA/integration versions, router model/firmware, numeric and
boolean effective entry settings, topology, stored client ownership, and recent
observations from `misystem/devicelist` and `wifi_connect_devices`. Parent-to-node
matches retain consistent aliases. A whitespace flag preserves malformed topology
addresses without disclosing the address itself. An unmatched parent or absence
of an active address is evidence, not a conclusive explanation of the failure.

Counter events record values before resets, after parent pushes, after
`new_status`/topology counts are applied and at refresh completion. The first
census for each source and first 12 counter events survive rotation of the recent
12 censuses and 60 events per entry. Each census and stored-client export is
limited to 512 clients and explicitly reports truncation.

Names, SSIDs, credentials and arbitrary raw API payloads are excluded from the
support section. MAC/IP/entry identifiers use keyed aliases that remain stable
across all entries and downloads in one HA runtime. Restarting HA changes the
aliases and clears history; reloading an entry starts its history again. Entries
that are not loaded cannot contribute live information. This report does not
alter client routing, counters or router settings.
