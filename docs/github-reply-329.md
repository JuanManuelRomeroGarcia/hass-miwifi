# Archived pre-release reply to #329

Posted on 2026-10-11 before v3.9.0 was published. The text below records that earlier state.

@Daottuan, thank you for confirming that v3.8.4 on Home Assistant 2026.10.1 still shows the count at startup and then drops it to zero.

We have prepared changes for the next release to keep a recent completed parent-router client census authoritative on a mesh leaf, and to clear stale moved-client markers when clients return. On our test installation the leaf count remains stable across subsequent refreshes and node reloads. This is progress, not confirmation that your RC01/RA70/RB03 setup is fixed; this issue stays open.

We also added a bounded `mesh_support` capture to Home Assistant integration diagnostics. It records initial and recent client censuses, parent-to-node mapping and counter transitions across all loaded MiWiFi entries, without extra router requests. MAC/IP/entry aliases stay consistent within one HA runtime. The new [diagnostics guide](https://github.com/JuanManuelRomeroGarcia/hass-miwifi/wiki/Diagnostics) explains collection and privacy.

These changes are currently in the development build, **not in the published v3.8.4**. Once the next build is available, please reproduce the startup/count-drop behavior and immediately download integration diagnostics from a configured MiWiFi entry. Share only the `mesh_support` section publicly; the older sections of the JSON can still contain private network data. A full HA restart resets capture history, so reproduce and download after it.

The remaining configuration details would also help: are all three routers configured as separate integration entries, what are the RA70/RB03 firmware versions, and which entries have force load, device tracking and client sensors enabled? We will compare your observations with the completed-refresh counter events rather than assume the same cause across router models. Thank you for helping us verify this properly.
