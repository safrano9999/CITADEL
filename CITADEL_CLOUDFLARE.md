# CITADEL Cloudflare Setup

This guide is written for humans and agents. Follow it strictly one stage at a time. Do not continue with the next stage until the current stage has been completed and explicitly confirmed.

## 1. Cloudflare Account, API Token, And Nameservers

This stage is a dialogue between the user and the agent. It ends only when Cloudflare confirms that the domain is active on Cloudflare nameservers.

### User

Create a Cloudflare account or use an existing one.

Open Cloudflare API Tokens:

https://dash.cloudflare.com/profile/api-tokens

Create a custom API token. Prefer too much access over too little access for this setup phase; the token can be tightened later after the deterministic setup is complete.

Token permissions:

- `Account` -> `Account Settings` -> `Edit` or `Read` if `Edit` is not available
- `Account` -> `Cloudflare Tunnel` -> `Edit`
- `Account` -> `Access: Apps and Policies` -> `Edit`
- `Account` -> `Access: Organizations, Identity Providers, and Groups` -> `Edit`
- `Account` -> `Workers Scripts` -> `Edit` if available
- `Account` -> `Workers Routes` -> `Edit` if available
- `Zone` -> `Zone` -> `Edit`
- `Zone` -> `DNS` -> `Edit`
- `Zone` -> `Zone Settings` -> `Edit`
- `Zone` -> `SSL and Certificates` -> `Edit`
- `User` -> `User Details` -> `Read` if available

Token resources:

- `Account Resources`: `Include` -> `All accounts`
- `Zone Resources`: `Include` -> `All zones`

Store the generated token in `.env`:

```env
CLOUDFLARE_API_TOKEN=your_token_here
CLOUDFLARE_EMAIL=admin@example.com
```

### Agent

Read `CLOUDFLARE_API_TOKEN` from `.env` and verify that the token can see the Cloudflare account. Ask the user for the domain or domains that should be managed by CITADEL.

For each domain, create or reuse a Cloudflare zone and print the Cloudflare nameservers that must be configured at the current domain provider.

### User

Open the current domain provider or registrar and replace the existing authoritative nameservers with the two Cloudflare nameservers printed by the agent.

Do not change DNS records, tunnels, Access policies, or CITADEL routing yet. This step is only the nameserver change.

### Agent

Check the Cloudflare zone status and nameserver state until Cloudflare reports the zone as active. When the domain is active, print a clear green-light message. Only after that, the next setup stage may begin.

Create or reuse the CITADEL tunnel. Discover the selected account, zone, and tunnel identifiers through the Cloudflare API, then write all resolved values to `.env`. Never leave placeholders and never print secrets:

```env
CITADEL_CLOUDFLARE=1
CITADEL_CLOUDFLARE_DOMAIN=example.com
CITADEL_CLOUDFLARE_ACCOUNT_ID=resolved_account_id
CITADEL_CLOUDFLARE_ZONE_ID=resolved_zone_id
CITADEL_CLOUDFLARE_TUNNEL_ID=resolved_tunnel_id
```

Preserve the existing `CLOUDFLARE_API_TOKEN` and `CLOUDFLARE_EMAIL`. Verify that every value can be read through `python_header.py` before the first scan.

Initialize Cloudflare Access through the API before applying any email whitelist:

1. Read the current Zero Trust organization.
2. If Access is not enabled, create the Zero Trust organization with a unique `*.cloudflareaccess.com` authentication domain.
3. Read the configured identity providers.
4. If `onetimepin` is missing, create the One-time PIN identity provider.
5. Verify both resources through the API before running `scan.sh`.

This requires `Account -> Access: Organizations, Identity Providers, and Groups -> Edit` for the selected account. If either organization endpoint returns HTTP 403 with Cloudflare error code `10000`, stop and ask the user to edit or replace the API token with that permission. Never fall back to exposing routes without Access after an email whitelist is configured.

## 2. Conservative Cloudflare Mapping Defaults

This stage decides how newly discovered local services should be exposed through Cloudflare. Cloudflare routes are public internet routes, so the default should be conservative.

### User

Run the normal CITADEL scan after the agent has written and verified the Cloudflare values in `.env`.

```sh
./scan.sh
```

Set `CLOUDFLARE_EMAIL` in `.env` before the first scan, for example:

```env
CLOUDFLARE_EMAIL=admin@example.com,ops@example.com
```

New Cloudflare routes use this address list as the default Access email whitelist.

If `CLOUDFLARE_EMAIL` is missing or invalid, CITADEL skips Cloudflare during scan instead of creating public routes.

### Agent

During `scan.sh`, after local services have been discovered and before Cloudflare routes are applied, check these conditions:

- Cloudflare provider is in `extensions/enabled/cloudflare`
- `CITADEL_CLOUDFLARE=1`
- `CLOUDFLARE_API_TOKEN` exists and is valid
- `CLOUDFLARE_EMAIL` exists and is valid
- HTTP services were discovered

If the Cloudflare defaults were not configured yet, read `CLOUDFLARE_EMAIL` and store it as the default whitelist in `ports.filter.json` so the next scan does not ask again.

If whitelist emails are provided, apply them to every newly discovered Cloudflare port that does not already have an explicit rule.

To make a route intentionally public, edit that route after the initial scan and remove its whitelist. Do not create public Cloudflare routes automatically.

### User

Use the CITADEL WebUI Cloudflare edit mode for per-port overrides.

A port with whitelist emails is protected by Cloudflare Access email login. A port without whitelist emails is intentionally public through Cloudflare.

### Agent

Preserve existing per-port rules. Only apply the saved default to newly discovered ports. Do not overwrite custom subdomains, public ports, or custom per-port email lists.
