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
/citadel tailscale
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
| `CITADEL_CONTAINER` | `0` | Also discover listeners on the container host through `host.containers.internal` |
| `CITADEL_CONTAINER_MAP` | `0` | Route discovered host HTTP services through Tailscale and Cloudflare |
| `CITADEL_DEDUPE_PORT` | `65100` | First replacement port when a mapped host service duplicates a container port |
| `CITADEL_SUBNET_IP` | empty | Address used for subnet routes and the Cloudflare origin |
| `CITADEL_TAILSCALE` | `true` | Enable Tailscale route reconciliation |
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

CITADEL never installs, authenticates, or starts Tailscale. For every new or
changed web service, automatic mode:

1. tries an HTTPS Tailscale Serve listener;
2. falls back to HTTP Serve;
3. uses a direct Tailnet URL only when the service already listens on a
   wildcard or Tailscale address.

`scan.sh --provider tailscale` performs the same listener discovery and
HTTPS-before-HTTP probing while reconciling only the enabled Tailscale
provider. It does not call the Cloudflare or subnet providers. The Fedora
container runs one complete scan during initialization. Further scans run
only when explicitly requested through the CLI.

Route decisions are persisted in `tailscale.json`, so unchanged services are
not reconfigured on every scan. Foreign or manually changed listeners are not
claimed.

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
- Back up `ports.filter.json` and provider state when custom routes must survive
  a fresh checkout.

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
