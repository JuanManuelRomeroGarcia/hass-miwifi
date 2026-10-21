# Fresh router API diagnostic export

Available from v3.12.0.
The first real HA 2026.10.1 trial completed on 16 October 2026 with an RC01 main
and RC06 node, with no HA log errors reported. The archive records three failed
queries (main NAT and node mode), while the remaining capture continued.
A second real trial on 17 October confirmed Spanish notifications and additional
identifier masking in the exported archive. Optional support links were also
checked on the panel and confirmed to work without being intrusive.

In **MiWiFi → Settings → Dump router data**, enable **Fresh API queries and
responses (main and nodes)** and generate the archive. This option is off by
default. It queries every loaded router using the full known diagnostic
catalogue; the individual section checkboxes do not restrict this mode.
The diagnostic dialog is also available when no main router is recognized.

These are fresh requests, not a replay of previous calls. Each router has model,
firmware, role and address metadata. Cached counters are clearly separated from
fresh responses. Each request records its API path without authentication,
parameters, timestamp, duration, response and outcome. Firmware errors retain
their JSON response; transport failures may have no response. Skipped requests
identify role/model restrictions, inactive WAN2 or capture limits.

The catalogue covers system information, modes, topology, WAN1, Wi-Fi, clients,
MAC filters, NAT, QoS, DHCP, VPN, update checks, flash permissions and LED status.
It includes RD08 WAN2/port reads where applicable, channels for up to four
adapters, and known CB0401 mobile reads. It does not discover every possible
firmware endpoint. An error on one model does not establish that an endpoint is
unavailable on all models.

The local post-3.13.0 preparation adds model/role-scoped RC01/RC06 port maps,
RC01 thermal-control data, mesh preferences, RC06 steering, Multi-WAN configuration
and WPS/NFC reads. These do not add sensors or change normal polling. RC01 1.1.56
reports the hottest of seven Celsius inputs and measured-or-estimated fan RPM;
do not label them exclusive CPU temperature or always-measured fan speed. These
WPS/NFC fields do not establish per-radio SAE/PMF. A standalone
live-sampling tool and its [Spanish guide](Router-API-live-es.md) help compare data.

Only a fixed read-only catalogue is used. It does not reboot, update firmware or
change Wi-Fi, DHCP reservations or NAT rules. Wi-Fi setters are not called with
empty parameters as a substitute for readers. Requests reuse the integration's
existing client session; normal authentication recovery may still occur if the
router reports an expired token.

## Limits and privacy

- Up to 4 seconds per request, 45 seconds per router and 120 seconds per capture,
  with at most 32 routers. Failed requests do not stop later reads. Cancelling
  the task cancels its active request. Concurrent dumps are rejected.
- Up to 1 MB of retained response data per request and 8 MB per capture. Omitted
  oversized responses have an explicit marker. Non-JSON bodies are not exported.
  These are retention/export limits, not HTTP download or peak-memory limits.
- Passwords, keys and known tokens are always hidden, even when identifier
  anonymization is off. With anonymization enabled, IP addresses, MAC addresses
  and names have distinct, consistent aliases across this archive. Client and
  parent references remain comparable. IP aliases do not preserve original
  subnets or address scope.
- Alias maps are neither exported nor saved for later captures. Review the
  archive before sharing: new firmware-specific sensitive fields may not yet
  be recognized.
- The ZIP stays in Home Assistant's private export directory and downloads use
  an administrator-only signed link. Nothing is sent to GitHub or another
  external service. The previous export is removed only after creating the new
  archive successfully.

## Real Home Assistant trial

Keep a backup, copy the complete `custom_components/miwifi` directory through
SFTP, and restart Home Assistant. Refresh the panel while bypassing its cache.
Generate a full archive, check main/node entries, errors and omissions, and
verify that passwords and tokens are absent. Compare a normal section-based
dump as well. Confirm Wi-Fi, reservations, rules and normal client updates remain
unchanged. This trial does not publish another version.
