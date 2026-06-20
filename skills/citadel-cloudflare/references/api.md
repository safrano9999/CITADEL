# Cloudflare API Contract

Use a scoped API token. Never request or store a Global API Key.

## Token permissions

- Account: Cloudflare Tunnel, Edit
- Account: Access Apps and Policies, Edit
- Account: Access Organizations, Identity Providers, and Groups, Read
- Zone: DNS, Edit

Limit account permissions to the selected account and zone permissions to the selected zone.

## Runtime ownership

CITADEL owns only resources recorded in `extensions/enabled/cloudflare/routes.json`:

- DNS record IDs in `dns_records`
- Access application IDs in `access_apps`
- Access reusable policy IDs in `access_policies`
- Tunnel ingress hostnames in `managed_hostnames`

Preserve every unrelated DNS record, Access application, policy, and Tunnel ingress rule. Keep the Tunnel catch-all rule last.

## Configuration

Store non-secret identifiers in `config.conf`:

```ini
CITADEL_CLOUDFLARE=true
CITADEL_CLOUDFLARE_DOMAIN=services.example.net
CITADEL_CLOUDFLARE_ACCOUNT_ID=
CITADEL_CLOUDFLARE_ZONE_ID=
CITADEL_CLOUDFLARE_TUNNEL_ID=
CITADEL_CLOUDFLARE_ORIGIN_HOST=127.0.0.1
CITADEL_CLOUDFLARE_SERVICE=cloudflared.service
```

Store secrets in `.env`:

```ini
CLOUDFLARE_API_TOKEN=
TUNNEL_TOKEN=
```

`TUNNEL_TOKEN` belongs to the separately managed cloudflared service. CITADEL does not start or authenticate cloudflared.
