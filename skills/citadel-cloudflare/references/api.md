# Cloudflare API Contract

Use a scoped API token. Never request or store a Global API Key.

## Token permissions

- Account: Account Settings, Edit or Read when Edit is unavailable
- Account: Cloudflare Tunnel, Edit
- Account: Access Apps and Policies, Edit
- Account: Access Organizations, Identity Providers, and Groups, Edit
- Account: Workers Scripts, Edit when available
- Account: Workers Routes, Edit when available
- Zone: Zone, Edit
- Zone: DNS, Edit
- Zone: Zone Settings, Edit
- Zone: SSL and Certificates, Edit
- User: User Details, Read when available

During deterministic setup, include all accounts and all zones. The token can be narrowed after setup and verification.

Before whitelist reconciliation, create or reuse the Zero Trust organization through `POST /accounts/{account_id}/access/organizations`, then create or reuse the `onetimepin` identity provider through `POST /accounts/{account_id}/access/identity_providers`. Error `9999` from the organization lookup means Access is not initialized and creation should continue; error `10000` during creation or reconciliation means the token lacks the required Access permission.

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
CITADEL_SUBNET_IP=
```

When `CITADEL_SUBNET_IP` is set, Cloudflare uses it as the origin host. When it is blank, the origin defaults to `127.0.0.1`.

Store secrets in `.env`:

```ini
CLOUDFLARE_API_TOKEN=
TUNNEL_TOKEN=
```

`TUNNEL_TOKEN` belongs to the systemd-managed `cloudflared.service`. CITADEL reconciles routes but never starts, stops, installs, or otherwise owns the connector service.
