# MiWiFi #396: voluntary mesh observation guide

This guide is for a router owner who chooses to help investigate client
ownership. Please review the script before using it and only run it on routers
you own or are authorized to access. The diagnostic logs in to each router
and reads three client endpoints. It does not change Wi-Fi settings, restart
routers or run setters. Login creates a LuCI session. This script has not yet
been verified on physical routers.

**LuCI uses unencrypted HTTP here.** Session tokens and responses travel over
the local network without transport encryption. Run the diagnostic only on a
trusted local network, and do not expose the routers or this traffic to the
internet. The script allows only a configured RFC 1918 IPv4 address and the
specific login and read URLs; it does not follow redirects.

## Requirements and preparation

- Extract this ZIP to a new, separate directory, outside your Home Assistant
  configuration and installed integrations. Python 3.11 or newer is required;
  this bundle has been tested only with Python 3.14.4. Home Assistant is not
  required. The four LuCI modules in the bundle are unchanged copies from the
  stated commit; the script does not start the integration.
- Create and activate a virtual environment, then install the declared dependency:

  Windows PowerShell:
  ```powershell
  py -3 -m venv .venv
  .\.venv\Scripts\Activate.ps1
  python -m pip install -r requirements.txt
  ```

  Linux/macOS:
  ```sh
  python3 -m venv .venv
  . .venv/bin/activate
  python -m pip install -r requirements.txt
  ```

  Installation normally contacts the configured Python package index; it is a
  separate step from the diagnostic. Alternatively install from a trusted local
  wheelhouse using `python -m pip install --no-index --find-links PATH -r requirements.txt`.
  The diagnostic itself sends only the documented local router requests.
- An interactive terminal that can hide password input. Keep the terminal,
  credentials, local IPs and any original router information private. Do not
  put passwords on the command line or share terminal transcripts.
- The local IPv4 address and router administrator password for each router.
  For the reported setup, select **`sha256` for RC06/BE7000 firmware 1.1.38**
  and **`sha1` for R3 and R4**. These algorithms have been tested with mock
  responses; the actual firmware login still needs physical validation.
- If known, note the client MACs for a fixed Ethernet device, a stationary
  Wi-Fi device and a device used for roaming. Optionally note router and
  backhaul MAC aliases: they help relate an observed `parent` to a node. MACs
  are entered locally and replaced with per-run pseudonyms in the report.
  Unknown aliases can be left blank; do not guess them.

## Run the capture

From the extracted package directory, with the virtual environment active:

```text
python tools/mesh_ownership_capture.py
```

The prompts are in Spanish: `Archivo de salida` means output file, `IP privada`
means private IP, `MAC conocidas` means known MAC aliases, `Algoritmo` means
algorithm, `Contraseña` means password, `Antes`, `Durante`, and `Después` mean
before, during, and after. Leave optional fields blank when unknown.

Enter a **new** JSON output path, then the details for `main` (RC06), `r3`
and `r4` when prompted. The script rejects an existing output file and asks
for each password without echo. Optionally enter the known MAC aliases and
client MACs. It does not store raw router responses, passwords or tokens in the
report. Its three phases are started by pressing Enter at each prompt:

1. **Before:** keep the Ethernet and stationary Wi-Fi clients unchanged.
   Verify independently that the roaming device is associated with RC06, then
   press Enter to record all three routers.
2. **During:** move the roaming device until it associates with R4. Verify the
   association independently, then press Enter to record all three routers.
3. **After:** move it back until it associates with RC06. Verify the association
   independently, then press Enter for the final three-router sample.

Do not change router or Wi-Fi configuration to force a handover. Association
is not guaranteed: a device can stay on the old access point. To verify it,
use a read-only client association/BSSID view on the device or router and
compare the BSSID with a known, independently verified node-radio identifier.
A router label, signal strength, physical proximity, or an empty `parent`
alone is not proof. If the node cannot be verified, record that fact privately
and do not describe that phase as confirmed roaming. The readings are taken
concurrently across routers, but individual endpoint times differ.

## Output and privacy review

The script creates only the JSON file at the chosen output path; it will not
overwrite an existing file. The report includes the observation router, phase,
endpoint, timestamps, outcome and allowlisted client fields. MAC addresses and
text interface identifiers use keyed pseudonyms consistent across routers and
phases in this run; a new run uses a new random key. The key is not exported.
The report does not contain original IPs, SSIDs, client names, passwords or
session tokens. `parent` may be missing, null, empty, an identified value, or
invalid; none of these alone proves the physical association.

Before sharing, **open and inspect the entire JSON**. Check that no real MAC,
IP address, SSID, personal name, password, token or other private value is
present, including fields you did not expect. Do not share it if anything
looks sensitive; ask the maintainers to review the tool first. Keep any local
mapping between devices and pseudonyms private. This capture does not measure
Home Assistant registry events or Recorder writes.

## Stop or recover

Press Ctrl+C to stop. If authentication fails, that router is marked
`authentication_failed` and other routers can still be sampled. Failed reads
are marked `error`; the script does not automatically log in again after token
expiry. Unknown or unavailable endpoints are not proof that the router cannot
support them. If an error occurs, stop rather than changing router settings;
check the output location and prerequisites, then use a new output filename if
you choose to repeat the capture. A failed or interrupted save could leave a
partial file: inspect it before keeping, deleting or sharing it. No router
configuration restoration is needed because the diagnostic does not modify it.
