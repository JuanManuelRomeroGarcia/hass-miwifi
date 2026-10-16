# BE6500 Pro / RD08 compatibility (PR #358)

These changes are under review and are not included in v3.10.0.
They use the responses supplied for RD08 firmware 1.1.96 in issues
[#355](https://github.com/JuanManuelRomeroGarcia/hass-miwifi/issues/355) and
[#356](https://github.com/JuanManuelRomeroGarcia/hass-miwifi/issues/356).
Hardware confirmation of the revised integration is still required.

## Client connections

RD08 reports LAN=1, 2.4 GHz=2, 5 GHz=3, Guest=7 and IoT=9 in
`misystem/devicelist`. These codes are decoded for RD08 only, including when
its client census is forwarded to another mesh node. Other router models
retain their existing connection codes. Unknown codes remain unknown.

## Dual WAN (read only)

On an RD08 acting as the main router, the integration checks
`misystem/get_ps_service?service=multiwan`. When enabled, it reads
`xqnetwork/wan_info?wan_name=WAN2`. Capability discovery is cached for five
minutes, including failed requests; WAN2 information refreshes with normal
polling. Each request has a six-second timeout. Other models and mesh nodes
are not probed with these additional requests.

The existing primary WAN entity IDs and readings remain unchanged.
The new **WAN2 IP address** sensor includes `enabled`, `type`, `link` and
`connected` attributes. The status panel shows WAN2 separately when enabled,
with labels in all eight supported panel languages. A confirmed disconnected
WAN2 has no current address. A failed or incomplete request makes its data
unavailable rather than retaining an old address or marking WAN1 offline.
Enabling or disabling dual WAN may take up to five minutes to appear.

No WAN policy or port configuration is changed. Configured bandwidth and
weights are not transfer rates, so no WAN2 upload/download speed is invented.
Failover and load-balancing behavior are not inferred from the policy's
numeric mode. Test enabled, disconnected, disabled and reconnected states on
real hardware before merging; confirm ordinary WAN1 and mesh client updates.

## Memory

`misystem/status.mem.total` reports 256 MB in the supplied diagnostic.
The integration displays this firmware value; it does not replace it with a
model-based assumption. A different total needs a verified router response.

When sharing evidence, remove passwords, session tokens and private network
details. Never include a browser URL containing `stok`.
