# CITADEL

> **Type:** standalone service dashboard with an optional OpenClaw plugin.
>
> The FastAPI dashboard and scanner run on bare metal. The release ZIP is an
> OpenClaw plugin package, not a generic bare-metal installer.

[![OpenClaw plugin](https://github.com/safrano9999/CITADEL/actions/workflows/openclaw-plugin-release.yml/badge.svg)](https://github.com/safrano9999/CITADEL/actions/workflows/openclaw-plugin-release.yml)

![CITADEL dashboard](CITADEL.png)

CITADEL discovers listening TCP services, identifies HTTP endpoints, and builds
one dashboard for local, subnet, Tailscale, and Cloudflare routes. Providers are
reconciled independently, so local discovery remains useful even when a remote
provider is disabled or unavailable.

## Features

- Discovers listeners with `ss` and probes HTTPS before HTTP.
- Recognizes HTML services, generic HTTP services, and OpenAI-compatible
  `/v1/models` endpoints.
- Produces deterministic service metadata in `services.json`.
- Presents discovered services in a FastAPI dashboard.
- Supports localhost, subnet, Tailscale Serve, and Cloudflare providers.
- Preserves unrelated Tailscale listeners and unrelated Cloudflare resources.
- Supports port allowlists, blocklists, Cloudflare hostnames, and Access email
  policies.
- Exposes the same route data through the `/citadel` OpenClaw command.

## Supported deployment modes

| Mode | Status | What is provided |
|---|---|---|
| Bare metal | **Supported** | Scanner, FastAPI dashboard, configuration scripts, and a user-systemd installer |
| OpenClaw | **Supported** | Optional release ZIP with the `/citadel` command and scan integration |
| Hermes | **Not provided** | This repository contains no Hermes plugin, hook, or manifest |

CITADEL can discover a running Hermes service like any other listener. That is
service discovery, not a native Hermes integration.

## Releases

The [latest release](https://github.com/safrano9999/CITADEL/releases/latest)
contains:

- [`citadel-latest.zip`](https://github.com/safrano9999/CITADEL/releases/download/latest/citadel-latest.zip)
  · [SHA-256](https://github.com/safrano9999/CITADEL/releases/download/latest/citadel-latest.zip.sha256)

This ZIP is assembled and validated as an **OpenClaw plugin package**. For a
bare-metal installation, clone the source repository instead.

## Bare-metal installation

Requirements:

- Python 3 with `venv`
- `curl`
- `ss` from `iproute2`
- `flock` from `util-linux`
- Tailscale CLI only when the Tailscale provider is enabled
- Nmap only when the optional Tailscale Discovery scan is used

Clone the source and create an isolated Python environment:

```bash
git clone https://github.com/safrano9999/CITADEL.git
cd CITADEL
python3 -m venv .venv
.venv/bin/python -m pip install -r requirements.txt
./config.sh --no-container
```

Run one scan, then start the dashboard:

```bash
./scan.sh
.venv/bin/python webui.py
```

The default example binds the dashboard to `127.0.0.1:11000`.

### User systemd service

`set_daemon.sh` writes, links, enables, and starts `citadel.service`. Point it
at the virtual-environment interpreter:

```bash
PYTHON_BIN="$PWD/.venv/bin/python" ./set_daemon.sh
systemctl --user status citadel.service
```

The installer also attempts to enable user lingering when it is available.

## OpenClaw installation

Download and verify the public release package:

```bash
curl -fL \
  -o citadel-latest.zip \
  https://github.com/safrano9999/CITADEL/releases/download/latest/citadel-latest.zip
curl -fL \
  -o citadel-latest.zip.sha256 \
  https://github.com/safrano9999/CITADEL/releases/download/latest/citadel-latest.zip.sha256
sha256sum -c citadel-latest.zip.sha256
openclaw plugins install ./citadel-latest.zip \
  --force \
  --dangerously-force-unsafe-install
openclaw gateway restart
```

The plugin can use its packaged scanner and state, or it can point to an
existing bare-metal CITADEL checkout:

```json
{
  "plugins": {
    "entries": {
      "citadel": {
        "enabled": true,
        "config": {
          "servicesPath": "/opt/citadel/services.json",
          "scanScript": "/opt/citadel/scan.sh"
        }
      }
    }
  }
}
```

Available commands:

```text
/citadel
/citadel localhost
/citadel subnet
/citadel tailscale-default
/citadel tailscale-http
/citadel tailscale-https
/citadel cloudflare
/citadel other
/citadel scan
```

The plugin does not launch the FastAPI dashboard. It reads CITADEL state,
renders provider buttons, and can run the configured scanner.

## Configuration

`config.sh --no-container` renders local configuration from
`config.conf_example` and `env.example`.

| Setting | Example default | Purpose |
|---|---:|---|
| `FASTAPI_HOST` | `127.0.0.1` | Dashboard bind address |
| `CITADEL_WEBUI_PORT` | `11000` | Dashboard port |
| `CITADEL_TOKEN` | generated | Optional token protecting Cloudflare edits in the dashboard |
| `CITADEL_CONTAINER` | `0` | Discover container-host listeners with Nmap through `host.containers.internal` |
| `CITADEL_CONTAINER_MAP` | `0` | Route discovered host HTTP services through Tailscale and Cloudflare |
| `CITADEL_DEDUPE_PORT` | `65100` | First replacement port when a mapped host service duplicates a container port |
| `CITADEL_SUBNET_IP` | empty | Address used for subnet routes and the Cloudflare origin |
| `CITADEL_HTTPS_ONLY` | `0` | When enabled, route only services that already speak HTTPS on localhost; HTTP services remain visible |
| `CITADEL_CLEAR_TAILSCALE` | `0` | At exactly `1`, delete all Tailscale Serve/Funnel routes and all saved CITADEL assignments before every scan, then rebuild them |
| `CITADEL_TAILSCALE` | `true` | Enable Tailscale route reconciliation |
| `CITADEL_TAILSCALE_DEFAULT` | `1` | Enable (`1`) or disable (`0`) the `Tailscale Default` Serve route, which keeps the discovered service port unchanged |
| `CITADEL_TAILSCALE_HTTP_START` | empty | First public port for stable Tailscale HTTP Serve assignments; empty or `0` disables this dropdown |
| `CITADEL_TAILSCALE_HTTPS_START` | `0` | First public port for stable Tailscale HTTPS Serve assignments; empty or `0` disables this dropdown |
| `CITADEL_TAILSCALE_RANGE` | `10` | Initial spacing between sorted Tailscale assignments |
| `CITADEL_CADDY_HTTPS_START` | `0` | First HTTPS port in the generated central-Caddy export; `0` disables it |
| `CITADEL_CADDY_RANGE` | `1` | Increment between generated central-Caddy ports |
| `CITADEL_CADDY_BACKEND` | empty | Container DNS name used as the reverse-proxy backend |
| `CITADEL_CADDY_HOST` | empty | Central Tailscale hostname included beside localhost and `127.0.0.1` |
| `CITADEL_TS_DISCOVERY` | `0` | Show manually generated Tailnet discovery data in a separate view |
| `CITADEL_CLOUDFLARE` | `1` | Enable Cloudflare reconciliation when all required values exist |
| `CITADEL_CLOUDFLARE_DOMAIN` | empty | DNS suffix used for generated hostnames |
| `CITADEL_CLOUDFLARE_ACCOUNT_ID` | empty | Existing Cloudflare account ID |
| `CITADEL_CLOUDFLARE_ZONE_ID` | empty | Existing Cloudflare zone ID |
| `CITADEL_CLOUDFLARE_TUNNEL_ID` | empty | Existing named Tunnel ID |
| `CLOUDFLARE_API_TOKEN` | empty | Scoped Cloudflare API token |
| `CLOUDFLARE_EMAIL` | empty | Default Access email allowlist |
| `TUNNEL_TOKEN` | empty | Token consumed by the separately managed connector |

Non-secret service settings belong in `config.conf`. Secrets belong in `.env`,
which is ignored by Git.

During interactive configuration, `CITADEL_TOKEN` offers three choices: no
token, enter a token, or generate one with `openssl rand -hex 32` (the default).
An empty or `blank` value disables the prompt in the dashboard. When configured,
the token is required to enter Cloudflare edit mode and to save Cloudflare
rules. Five invalid attempts within five minutes lock that client out for
15 minutes.

With `CITADEL_CONTAINER=0`, discovery and routing behave exactly like the
bare-metal mode. With `CITADEL_CONTAINER=1`, host listeners are additionally
written to `host_services.json` and shown in a separate dashboard list.
`CITADEL_CONTAINER_MAP=0` keeps them list-only. When mapping is enabled, only
HTTP/HTTPS host listeners are added to Tailscale and Cloudflare; subnet routes
continue to use only the container-local services. A collision between a local
and host origin port is assigned from `CITADEL_DEDUPE_PORT` upward and recorded
in `host_services.json`.

### Tailscale Discovery

Set `CITADEL_TS_DISCOVERY=1` to show the separate Tailscale button in the
dashboard. Discovery remains independent from the normal scan and is started
manually:

```bash
./Scan_TS.sh
```

The script reads online peers from `tailscale status --json`, excludes the
local host, scans every TCP port with Nmap, identifies HTTP/HTTPS endpoints,
and writes the result atomically to the ignored `ts.json` runtime file. It
never invokes `scan.sh`, creates mappings, or changes remote hosts. The
dashboard groups all discovered services by host.

An optional `config.ini` selects a custom CA:

```ini
[CITADEL]
ca_cert = /path/to/certs/ca.pem
```

### Port policy

`ports.filter.json` is created during the first scan. Start from
`ports.filter.json.example` when a policy should be prepared in advance:

```json
{
  "whitelist": [],
  "blacklist": [4000, "5000-5010"],
  "cloudflare": {
    "11000": {
      "subdomains": ["citadel"],
      "whitelist": true,
      "emails": ["operator@example.net"]
    }
  }
}
```

A non-empty whitelist takes precedence. Otherwise the blacklist is applied.

### Persistent Fedora container state

The merged Fedora container setup asks for `CITADEL_PERSISTENT` and enables it
by default. When enabled, the generated container mounts the instance-specific
named volume `<container>-citadel` at `/named_volumes/CITADEL`.

The volume stores only mutable runtime state. Provider code and configuration
remain in the installed plugin directory, so image updates are never hidden by
the volume. Links generated during container initialization migrate existing
files once where present and are safe to recreate. The initially absent
`tailscale.json` uses a direct link so its first atomic write creates valid JSON
instead of an empty placeholder:

```text
ports.filter.json
extensions/providers_state.json
extensions/enabled/cloudflare/routes.json
tailscale.json
```

Without persistence, CITADEL reads and writes these paths directly below its
own plugin directory. With persistence, atomic replacements resolve the link
target and stay inside the named volume.

## Providers

Provider activation is directory based:

```text
extensions/enabled/<provider>/
extensions/disabled/<provider>/
```

`extension.json` describes a provider; directory placement controls whether it
is active.

### Localhost and subnet

- `localhost` maps services to `127.0.0.1:<port>`.
- `subnet` maps services to `CITADEL_SUBNET_IP:<port>`.

### Tailscale

CITADEL never installs, authenticates, or starts Tailscale. For every
discovered HTTP service it can publish a one-to-one Serve route plus two
independently allocated variants:

- `Tailscale Default`, enabled with `CITADEL_TAILSCALE_DEFAULT=1`, keeps the
  discovered service port unchanged;
- `Tailscale HTTP`, beginning at `CITADEL_TAILSCALE_HTTP_START`;
- `Tailscale HTTPS`, beginning at `CITADEL_TAILSCALE_HTTPS_START`.

The example configuration enables `Tailscale Default` and disables both
allocated variants with an empty or `0` start.
Set `CITADEL_TAILSCALE_DEFAULT=0` to disable only the one-to-one variant. An
empty or `0` start value disables only the corresponding allocated variant.
Direct Tailnet access to applications bound to a wildcard or Tailscale address
remains technically available, but CITADEL neither creates, removes, nor
displays a separate Tailscale Direct route.

On the first allocation, services are sorted by their origin port and spaced
by `CITADEL_TAILSCALE_RANGE`, for example `35000`, `35010`, `35020`. A service
discovered later is inserted into the available numeric gap without changing
existing public ports. A collision during a new assignment advances the
candidate by one until a free port inside that gap is found. Existing
assignments never move automatically: if another listener later occupies a
persisted port, the scan reports its address, process/PID or Tailscale handler
and leaves both the foreign listener and the stored assignment untouched.

Choose dedicated non-overlapping HTTP and HTTPS port blocks that do not overlap
application, container-publish, or raw-TCP ranges. CITADEL also checks current
local sockets, every live Tailscale listener, and all stored assignments before
claiming a new port. Missing services retain their assignments so that an old
URL is never silently reused for a different service. Raw TCP services such as
PostgreSQL participate only in collision detection; they do not receive HTTP or
HTTPS tiles.

`scan.sh --provider tailscale` performs the same listener discovery while
reconciling only the enabled Tailscale provider and its configured Default,
HTTP, and HTTPS variants. It does not call the Cloudflare or subnet providers.
The Fedora container runs one complete scan during initialization. Further
scans run only when explicitly requested through the CLI.

Route decisions and stable port assignments are persisted in `tailscale.json`,
so unchanged services are not reconfigured on every scan. In the Fedora setup
this file uses the existing CITADEL named volume; no additional volume is
created. Foreign or manually changed listeners are never claimed.

### Central Caddy export

Set `CITADEL_CADDY_HTTPS_START`, `CITADEL_CADDY_RANGE`,
`CITADEL_CADDY_BACKEND`, and `CITADEL_CADDY_HOST` to export the latest detected
container services as one deterministic `CADDYFILES/Caddyfile`. CITADEL is
placed first; the remaining services follow by internal port. Every frontend
contains only the configured Tailscale hostname, `localhost`, and `127.0.0.1`.
The generated routes never include `CITADEL_SUBNET_IP` and never open a port by
themselves.

With `CITADEL_PERSISTENT=1`, `CADDYFILES` is stored in the existing CITADEL
named volume. Mount that volume read-only at `/etc/caddy/<instance>` in the
central Caddy container and add one import to the main Caddyfile, for example:

```text
import fedora44-ai-safrano9999-ucore/CADDYFILES/Caddyfile
```

The central Caddy Quadlet remains responsible for publishing the generated
HTTPS range. A start value of `0` writes a valid disabled file and creates no
routes. Reload or restart central Caddy after a successful scan changes the
imported file; Caddy does not watch imported files automatically.

Allow the scanning user to manage Tailscale without running every scan as root:

```bash
sudo tailscale set --operator="$USER"
./scan.sh
```

Release selected CITADEL-managed ports with:

```bash
sudo ./unroute.sh 11000
```

With no port arguments, `unroute.sh` uses `CITADEL_WEBUI_PORT`. It never runs a
global Tailscale Serve reset.

### Cloudflare

Cloudflare reconciliation runs only when it is enabled and its API token,
account, zone, Tunnel, and domain settings are complete. It manages:

- DNS records for discovered services;
- ingress entries on an existing named Tunnel;
- optional Cloudflare Access email policies.

It preserves unrelated DNS records, Access resources, and Tunnel ingress
rules. See [CITADEL_CLOUDFLARE.md](CITADEL_CLOUDFLARE.md) for the required API
permissions and provider-specific setup.

## Operations

Run or repeat discovery:

```bash
./scan.sh
```

The scan updates:

```text
ss.json
services.json
cache/<port>.json
extensions/providers_state.json
extensions/enabled/<provider>/routes.json
tailscale.json
last_scan.txt
```

The dashboard does not execute scans. Cloudflare edits made in the dashboard
are saved immediately and applied by the next `./scan.sh` CLI run.

Inspect the user service:

```bash
systemctl --user status citadel.service
journalctl --user -u citadel.service
```

## Security and storage

- Keep the dashboard bound to `127.0.0.1` unless remote exposure is deliberate.
- Treat `.env`, Cloudflare tokens, Tunnel tokens, and private CA material as
  secrets.
- Give the Cloudflare token only the account- and zone-scoped permissions
  described in `CITADEL_CLOUDFLARE.md`.
- The scanner records listener metadata and service titles. Protect the
  repository directory if that inventory is sensitive.
- Downloaded service icons are limited to 1 MiB, passive image formats, and
  the same host and port as the discovered service.
- Dashboard templates use automatic HTML escaping.
- Runtime JSON is written through durable temporary files and atomically
  replaced so readers never observe a partial update.
- Runtime state, caches, generated routes, local configuration, and release
  archives are excluded by `.gitignore`.
- Without Fedora container persistence, back up `ports.filter.json` and
  provider state when custom routes must survive a fresh checkout.

## Development and checks

Install dependencies, then run the same source checks used by the release
workflow:

```bash
.venv/bin/python -m unittest discover -s tests
node --check index.js
bash -n scan.sh
bash -n unroute.sh
```

The release workflow builds `citadel-latest.zip`, writes its SHA-256 file, and
publishes both only for a version tag.
