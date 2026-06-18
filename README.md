# CITADEL

![CITADEL](CITADEL.png)

Self-hosted service dashboard for local/remote routes with a modular provider system.

## Why CITADEL?

CITADEL is built for the real-world homelab/dev workflow:

- You run multiple services/containers, each on a different port.
- You want one clean dashboard to discover and open them.
- You want flexible routing targets (localhost, subnet, tailscale, caddy, cloudflare).
- You want Tailscale links when Tailscale is already running and logged in.

## How it works

CITADEL scans all listening ports on the host, probes them for HTTP services, and maps every discovered service to all enabled providers. With `CITADEL_TAILSCALE=true` and an already logged-in Tailscale daemon, it adds tailnet links. CITADEL does not start or authenticate Tailscale.

Example: you start a new service on port 3000. Next scan, it shows up on the dashboard with working links for every provider:

| Provider | Generated URL |
|---|---|
| localhost | `https://localhost:3000` |
| subnet | `https://192.168.1.50:3000` |
| tailscale | `https://citadel-bold-falcon.tailnet.ts.net:3000` |

Start a service, scan, done. Every port is mapped to every provider automatically.

## Quick Start

```bash
cp config.conf_example config.conf
python3 webui.py
```

### Environment variables

| Variable | Default | Description |
|---|---|---|
| `HOST` | `127.0.0.1` | Web UI bind host |
| `CITADEL_WEBUI_PORT` | `10999` | Web UI port |
| `CITADEL_SUBNET_IP` | empty | IP used by the subnet provider |
| `CITADEL_TAILSCALE` | `true` | Generate Tailscale links if `tailscale status` is logged in |

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
- `subnet` — routes to `<subnet_ip>:<port>` (needs `config.ini`)
- `tailscale` — routes to `<tailnet-domain>:<port>`

Disabled by default:
- `caddy` — generates Caddy reverse proxy routes (`/p/<port>`)
- `cloudflare` — placeholder for future integration

Provider scripts live in `functions/providers/`. `dispatch.py` runs all enabled providers and aggregates state.

### Provider Config

- `localhost` and `tailscale` work out of the box (no config required).
- `subnet` needs `extensions/enabled/subnet/config.ini` with `subnet_ip`.
- `caddy` and `cloudflare` can be configured once enabled.

### Tailscale Provider

- Checks runtime via `tailscale status`; never starts Tailscale
- Default mode: direct-port routing
- Generates URLs like `https://<tailnet-domain>:<port>`

### Caddy Provider

Generates reverse proxy snippets for path-based routing. Output goes to `CADDYFILES/<provider_id>.caddy`, imported via wildcard:

```caddy
import /opt/citadel/CADDYFILES/*.caddy
```

When duplicating caddy extensions (`caddy`, `caddy_subnet`, etc.), the directory name is used as provider identity to avoid collisions.

## Scan Flow (`scan.sh`)

1. Build `ss.json` from `ss -tlnHp`
2. Apply port policy (`ports.filter.json`)
3. Probe ports for HTTP/HTTPS + HTML detection
4. Update per-port cache (`cache/<port>.json`)
5. Build `services.json`
6. Run provider dispatcher
7. Write `last_scan.txt`

## Config Examples

### Main `config.ini` (optional)

```ini
[CITADEL]
ca_cert = /path/to/certs/cert.pem
```

### Subnet provider

```ini
[provider]
subnet_ip = 192.168.x.x
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
  "blacklist": [4000, "5000-5010"]
}
```

Template: `ports.filter.json.example`

## Frontend

`webui.py` serves the FastAPI dashboard. It reads `services.json`, provider state, and per-provider routes. Features:

- Provider dropdown
- Save default provider (browser storage)
- Fallback route indicator
- Optional auto-refresh

## Cron Example

```cron
* * * * * /home/user/CITADEL/scan.sh
* * * * * sleep 30 && /home/user/CITADEL/scan.sh
```
