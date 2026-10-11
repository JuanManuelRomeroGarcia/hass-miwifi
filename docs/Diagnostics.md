# Diagnostics and mesh support

> Availability: **v3.9.0 and later** for the `mesh_support` capture described below.

## Download the Home Assistant diagnostics

Open **Settings → Devices & services → MiWiFi**, use the menu of a configured integration entry and select **Download diagnostics**. Wait for successful refreshes first and download immediately after reproducing the problem. No reinstall, factory reset or deletion of integration entries is required.

The file contains the entry's ordinary diagnostics and a `mesh_support` section covering **all currently loaded MiWiFi nodes**. Entries that are unloaded cannot contribute live observations. A router-data dump is a different file: it contains raw router responses and is not a substitute for this capture.

## What `mesh_support` contains

- Home Assistant/integration versions, router models and firmware, effective numeric/boolean settings.
- Topology, anonymized client ownership, parent-to-node relationships and moved-client markers.
- Recent client observations from existing `misystem/devicelist` and `wifi_connect_devices` responses, with active flags preserved.
- Counter snapshots before reset, after parent pushes, after other count sources and at refresh completion.
- First startup events and initial source censuses, retained alongside bounded recent history. Capture is limited to 60 recent events and 12 recent censuses per entry, with up to 512 client rows and explicit truncation flags.

Capture is in memory and adds no API requests. A node reload starts that node's history again; a full HA restart clears history and changes anonymized aliases. MAC/IP/entry aliases are consistent across the loaded nodes and downloads in the same HA runtime. Reproduce the issue and download again after restarting.

## Share safely and make the report useful

**Share only the `mesh_support` section publicly.** It excludes names, SSIDs, credentials and arbitrary raw payloads. The older `data`, `devices` and request sections retain ordinary device/network data; the entire file is not covered by the support section's anonymization.

Include the time of the problem, expected and displayed counts, whether HA entities or only panel cards are affected, and the role/force-load/tracking/client-sensor settings of each configured node. State whether the issue begins at startup, after a refresh, reload, roaming or client rename.

For private-MAC replacement, also describe the configured router-name aliases and whether exactly one MAC is connected; replacement rules are not exported in `mesh_support`. Do not post identifying names or raw dumps unnecessarily. If additional raw responses are needed, redact each MAC consistently across every file and parent reference rather than replacing all devices with the same placeholder.

## Interpretation limits

A missing parent match, a trailing-whitespace flag or an absent active IP is evidence to investigate, not proof of the entire cause. A download made halfway through an update can contain a transient pre-completion count; compare the completed-refresh events. Successful results on one router setup do not close a report from another model or firmware without its user's verification.

For the implementation and collection details, see [mesh support capture](../tests/MESH_SUPPORT.md). For duplicate clients, see [private MAC addresses](Random-MAC-addresses.md).
