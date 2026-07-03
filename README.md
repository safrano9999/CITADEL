# CITADEL

## OpenClaw plugin

The same repository can be linked as an OpenClaw plugin. It reads the existing
`services.json`; the FastAPI dashboard remains an independent service.

```text
/citadel
/citadel localhost
/citadel subnet
/citadel tailscale
/citadel cloudflare
/citadel other
/citadel scan
```

![CITADEL](CITADEL.png)

Self-hosted service dashboard for local/remote routes with a modular provider system.

## Why CITADEL?

CITADEL is built for the real-world homelab/dev workflow:

- You run multiple services, each on a different port.
- You want one clean dashboard to discover and open them.
- You want flexible routing targets (localhost, subnet, Tailscale, Cloudflare).
- You want Tailscale links when Tailscale is already running and logged in.

## How it works

CITADEL scans listening ports, probes HTTP services, and maps every discovered service to the active providers. Tailscale integration is reconciliation only. For Cloudflare, CITADEL can start an installed `cloudflared.service` when Cloudflare is enabled and the Tunnel token is present; it never installs or authenticates Tailscale and never launches an ad-hoc connector.

Example: you start a new service on port 3000. Next scan, it shows up on the dashboard with working links for every provider:

| Provider | Generated URL |
|---|---|
| localhost | `http://127.0.0.1:3000` |
| subnet | `http://192.168.1.50:3000` |
| tailscale | `https://citadel-bold-falcon.tailnet.ts.net:3000` |
| cloudflare | `https://3000.services.example.net` |

Start a service, scan, done. Every discovered HTTP service is mapped to every enabled provider. The Tailscale provider uses HTTPS Serve for loopback-only listeners and direct Tailnet URLs for wildcard or Tailscale-bound listeners, preventing both processes from claiming the same port.

## Quick Start

```bash
cp config.conf_example config.conf
python3 -m pip install -r requirements.txt
python3 webui.py
```

Cloudflare secrets are optional. When Cloudflare is used, create `.env` from `env.example`; `.env` is ignored by Git.

### Baremetal Systemd

```bash
./set_daemon.sh
```

The script writes a local systemd unit, symlinks it into `~/.config/systemd/user/`, reloads user systemd, and enables `citadel.service`.

### Runtime Config

| Variable | Default | Description |
|---|---|---|
| `FASTAPI_HOST` | `127.0.0.1` | Web UI bind host |
| `CITADEL_WEBUI_PORT` | `10999` | Web UI port |
| `CITADEL_SUBNET_IP` | empty | IP used by the subnet provider |
| `CITADEL_TAILSCALE` | `true` | Reconcile native Tailscale Serve routes when Tailscale is logged in |
| `CITADEL_CLOUDFLARE` | `false` | Reconcile Cloudflare resources when enabled and required values exist |
| `CITADEL_CLOUDFLARE_DOMAIN` | empty | Hostname suffix, including a subdomain such as `services.example.net` |
| `CITADEL_CLOUDFLARE_ACCOUNT_ID` | empty | Cloudflare account ID |
| `CITADEL_CLOUDFLARE_ZONE_ID` | empty | Cloudflare zone ID |
| `CITADEL_CLOUDFLARE_TUNNEL_ID` | empty | Existing named Tunnel ID |
| `CITADEL_CLOUDFLARE_ORIGIN_HOST` | `127.0.0.1` | Origin address as seen by cloudflared |
| `CLOUDFLARE_EMAIL` | empty | Default Access email whitelist for new Cloudflare routes; Cloudflare is skipped when missing |

These non-secret values live in `config.conf`. `CLOUDFLARE_API_TOKEN`, `CLOUDFLARE_EMAIL`, and the separately consumed `TUNNEL_TOKEN` live in `.env`.

## Core Idea

- Port discovery and metadata stay generic.
- Route generation is delegated to providers.
- Provider activation is controlled by folder placement:
  - `extensions/enabled/<provider>/`
  - `extensions/disabled/<provider>/`

`extension.json` is metadata only (id/label/version), not an activation switch.

## Providers

Enabled by default:
- `localhost` — routes to `127.0.0.1:<port>`
- `subnet` — routes to `CITADEL_SUBNET_IP:<port>`
- `tailscale` — HTTPS routes to `<tailnet-domain>:<port>`
- `cloudflare` — DNS, named Tunnel ingress, and optional Access policies; inactive until `CITADEL_CLOUDFLARE=true`

Provider scripts live in `functions/providers/`. `dispatch.py` runs all enabled providers and aggregates state.

### Provider Config

- `localhost` and `tailscale` work out of the box (no config required).
- `subnet` reads `CITADEL_SUBNET_IP` from `config.conf`.
- `cloudflare` reads non-secrets from `config.conf` and its scoped API token from `.env`.

### Tailscale Provider

- Checks runtime via `tailscale status`; never starts Tailscale
- Resolves `route_mode = auto` from the discovered listener addresses
- Uses native, persistent Tailscale Serve routes for loopback-only services
- Removes managed Serve routes and uses direct Tailnet URLs for wildcard or Tailscale-bound services
- Stores URLs, backend targets, status, and managed ports in `tailscale.json`
- Generates URLs like `https://<tailnet-domain>:<port>`
- Set the scanning user as Tailscale operator once, then run scans without sudo:

  ```sh
  sudo tailscale set --operator="$USER"
  ./scan.sh
  ```

### Cloudflare Provider

Cloudflare reconciliation runs when `CITADEL_CLOUDFLARE=1`, the API token is valid, and the configured account, zone, and Tunnel identifiers are present. Mapping is performed through the API and does not depend on where or how `cloudflared` runs. CITADEL preserves unrelated DNS records, Access resources, and Tunnel ingress rules.

Every discovered service receives `<port>.<CITADEL_CLOUDFLARE_DOMAIN>` by default. In the Cloudflare WebUI tab, select **EDIT** to assign either a short label or a complete hostname:

- `citadel` becomes `citadel.services.example.net`.
- `citadel.internal.example.net` is used directly, provided it belongs to the configured zone.
- Empty remains the port-based hostname.

Enable **Whitelist** to create a Cloudflare Access email allow policy. At least one email is required, and the Cloudflare One-time PIN identity provider must be enabled. Select **SAVE & SCAN** to write `ports.filter.json` and immediately perform the deterministic Cloudflare API changes.

The API token needs Tunnel Edit, Access Apps and Policies Edit, Access identity-provider read, and DNS Edit permissions scoped to the selected account and zone. `skills/citadel-cloudflare/SKILL.md` documents assisted ID discovery and diagnostics.

## Scan Flow (`scan.sh`)

1. Build `ss.json` from `ss -tlnHp`
2. Apply port policy (`ports.filter.json`)
3. Probe ports for HTTP/HTTPS + HTML detection
4. Update per-port cache (`cache/<port>.json`)
5. Build `services.json`
6. Run provider dispatcher and reconcile active Tailscale and Cloudflare routes
7. Write `last_scan.txt`

## Config Examples

### Main `config.ini` (optional)

```ini
[CITADEL]
ca_cert = /path/to/certs/cert.pem
```

### UI defaults (`extensions/ui.json`)

```json
{
  "default_provider": "tailscale",
  "default_refresh_seconds": 0
}
```

### Port policy (`ports.filter.json`)

```json
{
  "whitelist": [],
  "blacklist": [4000, "5000-5010"],
  "cloudflare": {
    "399": {
      "subdomain": "citadel.internal.example.net",
      "whitelist": true,
      "emails": ["engineer@example.net"]
    }
  }
}
```

Template: `ports.filter.json.example`

### Provider route schema

Each enabled provider keeps its own `routes.json`. Service routes use the same schema:

```json
{
  "mode": "direct",
  "url": "http://node.example.ts.net:18789",
  "target": null,
  "owns_listener": false
}
```

`mode` is `direct` or `proxy`. `target` identifies a proxy origin, and `owns_listener` records whether the provider claims the service port locally.

## Frontend

`webui.py` serves the FastAPI dashboard. It reads `services.json`, provider state, and per-provider routes. Features:

- Provider dropdown
- Save default provider (browser storage)
- Cloudflare hostname and Access whitelist editor
- Optional auto-refresh

## Cron Example

```cron
* * * * * /home/user/CITADEL/scan.sh
* * * * * sleep 30 && /home/user/CITADEL/scan.sh
```
