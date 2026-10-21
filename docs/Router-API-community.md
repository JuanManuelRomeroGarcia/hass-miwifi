# Check compatibility with a Xiaomi router

[Español](Router-API-community-es.md) | English

These optional tools run on your PC and do not require Home Assistant.
Keep a complete copy of the repository: the HTTP script uses the integration's
catalogue and redactor. You need Python 3.11 or later. SSH is optional and must
already be enabled; the scripts do not unlock it.

Download the [ZIP of the `api-live-trial` testing branch](https://github.com/JuanManuelRomeroGarcia/hass-miwifi/archive/refs/heads/api-live-trial.zip)
and extract it. Open a terminal inside the extracted folder to run the commands
below. Run the tools on your PC; installing this branch's integration in HA is
not required. The published stable release does not yet include these options.

## Basic option: HTTP queries

From the repository folder, replace the example IP with your router's address:

```powershell
python tools/router_api_live.py --host 192.0.2.1 --sha256-host 192.0.2.1 --probe-model-specific --output .cache/informe-router
```

The script prompts for the web administration password without displaying it.
`--sha256-host` must match the router's authentication algorithm: our BE10000
uses SHA-256; our BE7000 uses SHA-1 and does not need this option. This is not a
universal rule for each model. If unsure, check your existing MiWiFi settings;
do not try different passwords. For a mesh node, add `--mesh-node 192.0.2.1`.

It takes three samples, with ten seconds between rounds. The catalogue is
limited: it does not test every API in the firmware. The model-specific probe
option lets us check routes for features such as the fan on other models,
without creating sensors or assuming their units. A query skipped because of
the router's role or a missing client MAC does not mean the API is unavailable.

## Advanced option: discover routes over SSH and query them over HTTP

On Windows, also install PuTTY/Plink. Connect over SSH beforehand and verify the
router's host key; the tool does not automatically accept unknown keys.

```powershell
python tools/router_api_inventory.py --host 192.0.2.1 --password --probe-http --sha256-host 192.0.2.1 --probe-model-specific --output .cache/informe-router
```

It prompts for two independent passwords: SSH and web administration. The default
SSH user is `root`; change it with `--user USERNAME` if needed. The scripts have
no fixed passwords. On Linux/macOS, OpenSSH with a key or agent can be used
without `--password`; see the [SSH inventory guide (Spanish)](Inventario-APIs-SSH-es.md).

The inventory finds route declarations without executing their handlers. The
HTTP phase only queries a fixed, reviewed list: discovering a route does not
automatically turn it into a request. Without `--probe-http`, both JSON files
are still generated, but the response file explicitly states that HTTP queries
were not performed.

## What to share

Share only these two files from your chosen output folder:

- **`routes.json`**: routes, model/firmware identity and the scope of the plan
  or inventory. It contains no HTTP responses.
- **`responses.json`**: redacted HTTP responses, errors and skipped queries;
  the SSH workflow also lists declarations that were not queried.

State whether the router is the main router, an access point or a mesh node.
The HTTP tool's `main_or_standalone` label does not automatically distinguish
AP mode, so please provide that context. Use a separate output folder for each
router when running tests separately, because the files are overwritten.

HTTP reports remove credentials and pseudonymize known identifiers. Review them
before publishing: other firmware may introduce fields we do not yet recognize.
Local `IP.json` files, SSH listings and the inventory's `comparacion.md` may
contain network information and are not needed for a contribution. Do not share
password files.

A successful response, an empty list, an unavailable route and an authentication
error are different results. We will use model, firmware, role and field
validation to decide which functions to enable in MiWiFi.

## Short announcement

> We are looking for users of different Xiaomi routers to help improve MiWiFi
> compatibility with Home Assistant. We have prepared an optional tool that
> reads router information from your PC without changing its settings.
>
> The basic test only needs web access to the router. SSH is optional for
> discovering the routes declared by each firmware. Each user supplies their
> own credentials, which are not included in the reports.
>
> Share `routes.json` and `responses.json` after reviewing them, and include
> your model, firmware and whether it runs as the main router, an AP or a mesh
> node. We want to check which features each router provides, such as
> temperature, fan, ports and Wi-Fi metrics. An unavailable feature or an empty
> list is useful information too.
>
> Follow this guide using the repository version that includes both scripts
> and these options. You do not need to install a test version in HA.

When publishing the announcement, link to this guide on the branch or version
that includes the changes. Do not say the new options are available in v3.13.0:
they were prepared after that release. Do not attach the maintainer's private
captures used to verify the tools.
