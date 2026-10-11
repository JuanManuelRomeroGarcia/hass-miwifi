# Private MAC addresses and automatic replacement

> Availability: **v3.9.0 and later**. Earlier releases do not include automatic private-MAC replacement.

## Why a phone or watch appears more than once

A client can use a private MAC address for each Wi-Fi network, or change that address later. MiWiFi identifies clients by their MAC address, so an old address can leave an inactive device beside the currently connected one. Moving between mesh nodes with the **same** MAC is a different case: it does not establish a new physical identity.

Two clients with the same name are not necessarily the same physical device. Automatic replacement is **disabled by default** and works only for the unique names and aliases you explicitly associate. It does not change the client's Wi-Fi privacy settings, configure the router's DHCP leases, or merge every same-named device.

## Configure a client in the panel

1. Sign in with a Home Assistant administrator account.
2. Open **MiWiFi → Settings → Integration options → Automatic MAC replacement** on the main router's settings page. The configuration covers all loaded MiWiFi entries, not just that router.
3. Select **Add a known client**, or use **Add manually** if its name is missing. A client already included as an alias is not offered again.
4. Expand the client's row. Enter one **router/app Xiaomi name** per line, including previous names. Names are case-insensitive and surrounding whitespace is ignored. Renaming a Home Assistant display label alone does not establish a router-name alias.
5. Press **Save**. Adding, editing or removing a row only takes effect after saving. No integration reload or HA restart is required for a configuration change.
6. Connect the client to Wi-Fi and allow the configured nodes to refresh. Keep the current and previous names in one rule, rather than creating one rule per alias.

Example for one watch renamed in the router:

```text
Reloj JuanMa
SM-L315F
```

Use this only when both names refer to the same physical watch and are unique in your network. Give separate physical devices different names in the router before configuring replacement.

## When an old address is removed

The integration must have fresh, successful, complete client lists from **every loaded MiWiFi node**, and exactly one associated MAC must be confirmed connected. An old associated MAC must be absent from those lists or explicitly inactive. A record with unknown/invalid activity flags is protected. Freshness expires after three scan intervals plus one request timeout for that node, with a minimum of 60 seconds.

Old MACs can be discovered in current router data, saved per-node client data, or MiWiFi tracker/device registry entries when the rule is saved. This covers unavailable historical clients left only in Home Assistant. Matching registry names come from the integration, not user display-name overrides.

Replacement removes the old MAC's **MiWiFi tracker and client sensors**, including disabled sensors, from all loaded nodes and their saved caches. It removes the device row only if no unrelated entities remain and it has one config-entry owner. The currently connected MAC stays. Unlike inactivity purging, verified replacement does not wait a minimum number of days.

**It does not transfer entity IDs, device IDs, areas, custom names, person assignments or automation references from the old MAC to the current MAC.** Check any automations, dashboards and persons that referenced the deleted tracker. Recorder history is not migrated or explicitly erased by this action; normal Home Assistant retention still applies.

## Renaming, persistence and disabling

- A rename reported on a known, connected MAC can be learned as another alias. If the name and MAC change together, explicitly add the old and new router names to the same rule; a new name alone cannot prove identity.
- Saved rules, learned MACs and suppression of retired addresses survive reloads and HA restarts. Stale stored or offline router records must not recreate a retired address.
- A retired MAC is accepted again if fresh router data explicitly reports a real connection. Suppression is not a permanent blacklist.
- Use **Remove rule**, then **Save**, to stop future replacement for that client. Remove all rules and save to disable the feature. Previously deleted entities are not restored, and suppression remains until a genuine reconnection.
- The ordinary purge action remains useful for clients without a configured identity. Preview before applying it; MAC selection and inactivity age still govern that action.

## If a duplicate remains

| Observation | What to check |
| --- | --- |
| The current tracker is away/offline | Connect the current client and wait for fresh node scans. |
| The name changed | Expand the rule and save both names, one per line. |
| The old client is unavailable and not in router lists | Save the rule again so registry-only MiWiFi clients can be associated. |
| Two associated MACs are connected | Replacement deliberately waits. Confirm whether these are actually two devices. |
| A node is not refreshing or returns incomplete data | Restore successful node updates first; do not delete HA entries as a workaround. |
| Other integration entities remain on the old device | Their device row is preserved; only MiWiFi-owned client entities are removed. |
| Changes vanish after navigating away | Press Save before leaving the page. |

For unresolved cases, report versions, router models/firmware, configured name aliases and whether each node is refreshing. Download integration diagnostics after reproducing the problem. Share **only `mesh_support`** publicly for mesh routing/counter investigation: it anonymizes MAC/IP/entry identifiers across the loaded nodes. It deliberately omits client names and does not contain replacement rules. The older diagnostic sections can contain ordinary private device/network data; do not publish the entire JSON unreviewed. See [mesh support capture](../tests/MESH_SUPPORT.md).

## YAML action

The panel is the recommended configuration interface. Administrators can also call:

```yaml
action: miwifi.configure_mac_replacement
data:
  clients:
    watch:
      - Reloj JuanMa
      - SM-L315F
    phone:
      - Redmi-Note-14-Pro-5G
```

`clients` replaces the **whole saved rule set**, so include every client you want to keep. The keys (`watch`, `phone`) identify rules and are not router names. Use `clients: {}` to disable all rules. The panel loads the full saved configuration before editing and refuses to save after a failed load.

## Validation so far

Local tests cover rules and aliases, registry-only historical clients, all-node freshness, concurrent connected MACs, unknown activity flags, persistence, removal across nodes and protection of unrelated entities. A real Home Assistant installation confirmed removal of an older Redmi address and a renamed watch's unavailable old device. The maintainer confirmed correct behavior after the final full HA restart. This does not establish identical behavior on every router model or firmware.
