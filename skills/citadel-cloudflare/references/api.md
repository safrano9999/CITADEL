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
- Zone → Dynamic URL Redirects → Edit on the routed zone for the default HTTP-to-HTTPS rule (`CITADEL_CLOUDFLARE_HTTP_TO_HTTPS=1`) and the optional www redirect. Check this permission if redirect reconciliation returns HTTP 403.
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
CITADEL_CLOUDFLARE_DOMAIN=services.example.net
CITADEL_CLOUDFLARE_ACCOUNT_ID=
CITADEL_CLOUDFLARE_ZONE_ID=
CITADEL_CLOUDFLARE_TUNNEL_ID=
CITADEL_SUBNET_IP=
```

Cloudflare always targets `127.0.0.1` on the discovered service's original port.
`CITADEL_SUBNET_IP` controls only the separate subnet provider.

Store secrets in `.env`:

```ini
CLOUDFLARE_API_TOKEN=
CLOUDFLARE_TUNNEL_TOKEN=
```

Activation is controlled by the extension's enabled directory/manifest and
the presence of `CLOUDFLARE_API_TOKEN`, not a separate environment toggle.

`CLOUDFLARE_TUNNEL_TOKEN` belongs to the systemd-managed `cloudflared.service`. CITADEL reconciles routes but never starts, stops, installs, or otherwise owns the connector service.
