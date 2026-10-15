# Mesh node identities and dashboard filters

Available in source builds incorporating PR #354; not included in the published
v3.10.0 release.

Some nodes have two MAC addresses: their own device MAC and the MAC the main
router uses in a client's `parent` field. These addresses can differ on an RA82
and may explain the AX6S dashboard report in #329; that specific installation
still needs confirmation.

Client trackers and client sensors expose:

| Attribute | Meaning |
| --- | --- |
| `router_mac` / `connected_via_router_mac` | Parent MAC reported by the mesh. Existing behavior is preserved. |
| `connected_via_router_device_mac` | Serving node's own device MAC, resolved from a loaded node. |
| `connected_via_router_name` | Serving node's Home Assistant device name override, otherwise its router name. |
| `connected_via_entry_id` | Integration entry currently serving the client. |

In Developer Tools → States, inspect a client connected to the affected node.
For a table that filters by the node's own MAC, use
`connected_via_router_device_mac` and copy its exact value, including case.
Alternatively, filter by `connected_via_entry_id`. Keeping a filter on the old
`router_mac` still requires the parent MAC shown on the client; the integration
does not rewrite existing dashboard YAML. Use a MAC or entry ID for a stable
filter because a display name can be changed or shared by several nodes.

Wait for the main and node entries to load and complete a refresh. The new
identity/name attributes may be empty until the serving node is known. The node
alias also lets Home Assistant's “Connected via” link identify the correct node.
An occupied alias does not cause another device row to be merged or deleted;
resolution can still use the loaded updater. Cleanup of old mesh-node client
records is separate work tracked in #331.
