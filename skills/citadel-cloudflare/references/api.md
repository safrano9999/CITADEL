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
- Zone → Single Redirect → Edit (API permission `Dynamic URL Redirects Write`) on the routed zone for the default HTTP-to-HTTPS rule (`CITADEL_CLOUDFLARE_HTTP_TO_HTTPS=1`) and the optional www redirect. Check this permission if redirect reconciliation returns HTTP 403.
- Zone: SSL and Certificates, Edit
- User: User Details, Read when available

During deterministic setup, include all accounts and all zones. The token can be narrowed after setup and verification.

Before whitelist reconciliation, create or reuse the Zero Trust organization through `POST /accounts/{account_id}/access/organizations`, then create or reuse the `onetimepin` identity provider through `POST /accounts/{account_id}/access/identity_providers`. Error `9999` from the organization lookup means Access is not initialized and creation should continue; error `10000` during creation or reconciliation means the token lacks the required Access permission.

## Mail during a nameserver change

- **Incoming mail.** If the existing provider hosts the mailboxes, copy its complete MX record set, including priorities, for each domain that receives mail. Use the provider’s control panel or query its previous authoritative nameserver. After delegation, compare `dig @<cloudflare-nameserver> <domain> MX +short` on each assigned nameserver with the provider’s values. Restore any missing entries in Cloudflare DNS.
- **Webmail, IMAP, and SMTP.** If users connect through names under the migrated domain, restore the provider’s A, AAAA, or CNAME records for the names they actually use. Use **DNS only** for IMAP, SMTP, and any in-zone MX target. Follow the provider’s HTTPS and certificate instructions for a custom webmail hostname. A provider-owned webmail URL uses the provider’s own DNS. [Cloudflare mail DNS troubleshooting](https://developers.cloudflare.com/dns/troubleshooting/email-issues/)
- **Optional forwarding.** If the operator chooses Cloudflare Email Routing, use its MX configuration and verify the destination mailbox. Forwarded mail is read at that destination. Keep the provider’s MX records when direct delivery to its mailboxes is intended. [Cloudflare Email Routing](https://developers.cloudflare.com/email-service/get-started/route-emails/)

### ALL-INKL example

This account’s verified zone entry is shown in DNS zone-file format. In the Cloudflare dashboard, the name is `@` and the priority is `10`.

```dns
@ IN MX 10 w0203fda.kasserver.com.
```

The target is account-specific. For another ALL-INKL account, look up its assigned `<login>.kasserver.com` hostname in KAS or query the previous authoritative nameservers. [ALL-INKL mail server settings](https://all-inkl.com/wichtig/anleitungen/kas/tools/dns-werkzeuge/a-record-fuer-domain-aendern_241.html)

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
