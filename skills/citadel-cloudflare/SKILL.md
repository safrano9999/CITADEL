---
name: citadel-cloudflare
description: Configure and diagnose CITADEL Cloudflare routing, including API-token validation, Account/Zone/Tunnel discovery, deterministic DNS and Tunnel ingress reconciliation, per-port hostnames, and Cloudflare Access email one-time-PIN policies. Use for CITADEL Cloudflare setup, missing Cloudflare environment values, route audits, or Access whitelist configuration.
---

# CITADEL Cloudflare

Keep setup agent-assisted and runtime deterministic. Never replace `scan.sh` or the provider modules with generated shell commands.

## Discover configuration

1. Read `config.conf_example`, `env.example`, and `references/api.md`.
2. Require `CLOUDFLARE_API_TOKEN`; never ask for a Global API Key.
3. Run discovery without printing the token:

```bash
CLOUDFLARE_API_TOKEN="$CLOUDFLARE_API_TOKEN" \
  python3 skills/citadel-cloudflare/scripts/discover.py \
  --domain services.example.net
```

4. If multiple Tunnels exist, show their names and IDs and request one selection. Never guess.
5. Write discovered non-secret values to `config.conf` and secrets to `.env`. Keep `.env` mode `0600`.
6. Retrieve `TUNNEL_TOKEN` only when explicitly configuring the separate cloudflared service:

```bash
python3 skills/citadel-cloudflare/scripts/discover.py \
  --domain services.example.net \
  --tunnel TUNNEL_NAME \
  --include-tunnel-token
```

Do not commit either token.

## Activate routing

Verify all conditions before setting `CITADEL_CLOUDFLARE=true`:

- `cloudflared.service` is active.
- The selected Tunnel has an active connection.
- The API token can read the zone and edit DNS, Tunnel config, and Access apps/policies.
- One-time PIN is enabled when any port uses an email whitelist.

Run `./scan.sh` after configuration. Inspect:

- `extensions/enabled/cloudflare/routes.json`
- `extensions/providers_state.json`
- `services.json`

Treat any provider error as a failed reconcile. Do not report success from partial API changes.

## Configure routes

Use the Cloudflare provider in the WebUI. Select **EDIT**, configure each tile, and select **SAVE**.

- Leave Subdomain empty to use the port number.
- Enter one DNS label to prepend it to `CITADEL_CLOUDFLARE_DOMAIN`.
- Enter a full hostname to use a direct subdomain or subsubdomain inside the configured zone.
- Enable Whitelist to protect that hostname with Cloudflare Access.
- Require at least one valid email when Whitelist is enabled.

The WebUI writes only `ports.filter.json`. The next `scan.sh` performs the API reconcile.

## Preserve ownership boundaries

Modify only resources whose IDs or hostnames are recorded in the Cloudflare provider state. Preserve foreign Tunnel ingress rules, DNS records, Access applications, and policies. Keep the catch-all ingress rule last. When Cloudflare is disabled, remove previously managed CITADEL resources if valid credentials remain available.
