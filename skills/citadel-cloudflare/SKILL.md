---
name: citadel-cloudflare
description: Configure and diagnose CITADEL Cloudflare routing, including API-token validation, Account/Zone/Tunnel discovery, deterministic DNS and Tunnel ingress reconciliation, per-port hostnames, and Cloudflare Access email one-time-PIN policies. Use for CITADEL Cloudflare setup, missing Cloudflare environment values, route audits, or Access whitelist configuration.
---

# CITADEL Cloudflare

Keep setup agent-assisted and runtime deterministic. Never replace `scan.sh` or the provider modules with generated shell commands.

## Discover configuration

1. Read `config.conf_example`, `env.example`, and `references/api.md`.
2. Require `CLOUDFLARE_API_TOKEN`; never ask for a Global API Key. Prefer the broad setup token documented in `CITADEL_CLOUDFLARE.md`, scoped to all accounts and all zones, so setup does not stop halfway through.
3. Create or reuse the requested zone and print its assigned Cloudflare nameservers. Wait until the user has entered them at the domain provider and the zone reports `active`.
4. Create or reuse the named Tunnel for this host. If multiple Tunnels exist, show them and ask which one to use; never modify an unrelated Tunnel.
5. Run discovery without printing the token:

```bash
CLOUDFLARE_API_TOKEN="$CLOUDFLARE_API_TOKEN" \
  python3 skills/citadel-cloudflare/scripts/discover.py \
  --domain services.example.net
```

Discovery idempotently creates the Zero Trust organization and One-time PIN provider when they are missing. Error code `10000` during this step means the token lacks `Access: Organizations, Identity Providers, and Groups -> Edit`; stop instead of exposing unprotected routes.

6. Write discovered non-secret values to `config.conf` and secrets to `.env`. Keep `.env` mode `0600`.
7. Retrieve `TUNNEL_TOKEN` when configuring the separate cloudflared service:

```bash
python3 skills/citadel-cloudflare/scripts/discover.py \
  --domain services.example.net \
  --tunnel TUNNEL_NAME \
  --include-tunnel-token
```

Do not commit either token.

After the provider nameserver change, the agent owns every remaining setup action: account/zone/Tunnel discovery, Access initialization, One-time PIN, DNS records, Tunnel ingress, configuration files, connector token, and verification. Do not send the user through Cloudflare dashboard pages for resources the API token can manage.

## Activate routing

Verify all conditions before setting `CITADEL_CLOUDFLARE=true`:

- The selected Tunnel is the intended Tunnel for this host.
- The API token can read the zone and edit DNS, Tunnel config, and Access apps/policies.
- One-time PIN is enabled when any port uses an email whitelist.

Run `./scan.sh` after configuration. Inspect:

- `extensions/enabled/cloudflare/routes.json`
- `extensions/providers_state.json`
- `services.json`

Treat any provider error as a failed reconcile. Do not report success from partial API changes.

## Configure routes

Use the Cloudflare provider in the WebUI. Select **EDIT**, configure each tile, and select **SAVE & SCAN**.

- Leave Subdomain empty to use the port number.
- Enter one DNS label to prepend it to `CITADEL_CLOUDFLARE_DOMAIN`.
- Enter a full hostname to use a direct subdomain or subsubdomain inside the configured zone.
- Enable Whitelist to protect that hostname with Cloudflare Access.
- Require at least one valid email when Whitelist is enabled.

The WebUI writes `ports.filter.json` and immediately runs `scan.sh` to perform the API reconcile.

## Preserve ownership boundaries

Modify only resources whose IDs or hostnames are recorded in the Cloudflare provider state. Preserve foreign Tunnel ingress rules, DNS records, Access applications, and policies. Keep the catch-all ingress rule last. When Cloudflare is disabled, remove previously managed CITADEL resources if valid credentials remain available.
