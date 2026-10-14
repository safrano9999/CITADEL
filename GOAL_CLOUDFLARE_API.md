# Cloudflare API and MCP refactoring goal

Status: implementation candidate on `codex/cloudflare-api`; live acceptance is
pending. This goal remains the acceptance contract. It does not activate an
extension, publish a Worker, run a scan, or change live routes by itself.

The source suite and plugin packaging passed on GitHub Actions at `d06a395`:
[validation run](https://github.com/safrano9999/CITADEL/actions/runs/38602270082).
That run executed 370 Python tests (369 passed; the existing Caddy-binary test
was skipped) and 17 Worker tests. These use fixtures for Cloudflare and upstream
protocol behavior. They are not evidence of a deployed OAuth flow. The
Containerfile and build workflows are prepared in the matching SCRIPTS branch;
no image build or pull has been performed for this implementation.

Live preview on 2026-10-14: at the operator's request, the host checkout and
service on HTTPS port 2000 now use the extension code. A normal scan ran with
both client authentication modes configured. The actual dashboard response
contains API-Bearer and API-OAuth. Configured menus remain visible on empty
discovery or publication failure, without claiming usable endpoint links.
Cloudflare rejected origin service-token creation with HTTP 403; a subsequent
provider reconciliation timed out. Public API publication and the OpenCode
OAuth/OTP flow have therefore not been accepted. Existing planning documents
and local configuration were preserved before adopting the preview.

The follow-up isolated the Cloudflare rejection to the account's service-token
creation endpoint: the management token verifies as active and can list service
tokens, while creation returns HTTP 403 with API error code 1010. No origin
service credentials have been created. Token permission inspection is also
denied; the operator has been asked to check account-scoped
`Access: Service Tokens Write` before further publication attempts.

The existing backend MCP credential was verified through the normal local
discovery implementation on port 3005 (`/api/v2/mcp`, initialize HTTP 200) and
stored using the generic route credential registry with mode 0600. No tool was
called. This establishes local backend readiness only, not public Bearer or
OAuth connectivity.

Remaining live acceptance on the authorized preview deployment includes real
nested-domain TLS and Managed OAuth API behavior; a real
client's registration, OTP callback, PKCE/resource binding and token refresh;
read-only MCP checks through both public auth modes; origin rejection without
service credentials and with a forged/wrong-audience assertion; stable Access
IDs and sessions across rescans; and exclusion cleanup while browser OTP stays
functional. The README contains the Blender/OpenCode procedure and the bundled
`functions/mcp_check.py` sends no `tools/call`. Do not mark this goal complete
until those results have been recorded.

## Objective

Add one optional `CLOUDFLARE-API` extension that discovers API and MCP endpoints
on the services already scanned by Citadel and publishes additional protected
Cloudflare URLs. Offer two independent dashboard modes, **API-Bearer** and
**API-OAuth**, through one shared Cloudflare Worker per Citadel installation.
Keep the existing browser URLs and their email/OTP policies intact.

Follow Citadel's existing operating model: scan everything eligible, map the
recognized endpoints automatically, exclude unwanted ports, and scan again.
Do not require a manually numbered list of applications or ports in the
environment. This work concerns Cloudflare; localhost, subnet, Tailscale Serve,
Caddy port allocation, container networking, and connector lifecycle retain
their current responsibilities.

## Extension and the two example files

Ship the extension disabled, at `extensions/disabled/CLOUDFLARE-API/`, with its
own `extension.json`. Moving that directory to
`extensions/enabled/CLOUDFLARE-API/` activates consideration during scans.
The existing Cloudflare extension is actually named
`extensions/enabled/cloudflare/`; keep that name and its existing configuration.
There is no additional environment variable for extension activation.

Add exactly two public configuration variables to the existing root examples.
These snippets are planned changes, not settings implemented by this document.

In `env.example`:

```dotenv
# Optional API client bearer: skip, enter, or generate through config.sh.
#secret
CITADEL_CLOUDFLARE_API_BEARER=example: openssl rand -hex 32
```

The `example:` notation is a `config.sh` generator hint, not a shell command
or a valid credential. The existing optional-secret prompt already offers
skip, manual entry, and generation. Blank remains valid, including unattended
configuration. Preserve an existing secret on ordinary regeneration. Reject
unrendered generator hints as credentials when examples are loaded as defaults.

In `config.conf_example`:

```dotenv
# Optional OAuth access, independent of the fixed bearer.
#choices: 0 1
#default-preset: 0
CITADEL_CLOUDFLARE_API_OAUTH=0
```

Render these into `.env` and `config.conf` through the existing loader and
`config.sh`. Do not add `_N` groups, duplicate example files inside the extension,
or conditional prompts that erase the bearer when OAuth is enabled.

| Bearer configured | OAuth setting | Desired API modes |
|---|---|---|
| No | `0` | None |
| Yes | `0` | API-Bearer |
| No | `1` | API-OAuth |
| Yes | `1` | API-Bearer and API-OAuth |

Both extension directories must be enabled and the existing
`CLOUDFLARE_API_TOKEN` must permit the required management operations. Resolve
account, zone, domain, and Tunnel through the existing configuration. OAuth
also requires a valid email policy and supported client registration. Missing
OAuth prerequisites must never result in an unauthenticated OAuth URL.
An OAuth failure can be reported separately while a valid bearer mode remains
usable. The management API token and the client bearer are different secrets.

## Stable URLs and dashboard modes

For an illustrative Blender MCP HTTP bridge discovered through Caddy on port
3070 with endpoint `/mcp`, generate:

| Dashboard mode | URL | Authentication |
|---|---|---|
| API-Bearer | `https://api-3070.example.com/mcp` | Fixed client bearer checked by the Worker |
| API-OAuth | `https://oauth.api-3070.example.com/mcp` | Cloudflare Managed OAuth |

The OAuth hostname keeps its `oauth.api-` form even when no bearer is configured.
Use the discovered port and preserve each endpoint path. Multiple endpoints on
one port share the hostname but remain individually visible and copyable.

Attach both hostnames as **Worker Custom Domains** to the same Worker. These
provide certificates for nested hostnames such as `oauth.api-3070.example.com`
without a separate Advanced Certificate Manager subscription. Manage their
certificate readiness and ownership during reconciliation; do not create a
Tunnel CNAME on the same hostname as a Worker Custom Domain.
[Cloudflare Custom Domains](https://developers.cloudflare.com/workers/configuration/routing/custom-domains/#certificates)

The two menu entries are views of one extension, not separately enabled
extensions or separate Workers. Hide inactive modes. Show pending and failed
publication explicitly instead of presenting an unverified URL as connected.
Keep the existing Cloudflare menu and browser routes unchanged.

## Whole-port exclusions

Add `CLOUDFLARE-API_ignore.json` at the repository root, initially:

```json
{
  "ports": []
}
```

To exclude ports after inspecting a scan:

```json
{
  "ports": [3070, 4001]
}
```

A listed port is completely excluded from this extension: all its API and MCP
paths, both authentication modes, and both dashboard views. An empty list maps
all recognized eligible endpoints. There are no per-path, per-URL, wildcard,
or regex exclusions. The ordinary Cloudflare browser route is unaffected.

On the next successful full scan, remove the extension-owned public bindings
for excluded ports and deny their paths in the Worker before removing related
resources. Removing a port from the file makes it eligible again. Validate
integer ports in the range 1–65535. Malformed JSON or invalid entries stop API
publication; they must not become an empty exclusion list. Preserve operator
edits during updates and container refreshes, and document how container
installations supply this repository-relative file.

## Discovery and endpoint inventory

Reuse the normal TCP listener scan and HTTPS-before-HTTP probing. Host Citadel
sees listeners reachable from its own network namespace, including published
Caddy ports. It does not automatically enter a user's Podman network or discover
Unix sockets. Caddy can continue bridging those backends to scanned listeners.

Run bounded endpoint discovery when the extension has an active auth mode.
Start with known MCP paths (`/mcp`, `/api/mcp`, `/api/v1/mcp`, `/api/v2/mcp`),
OpenAPI/Swagger documents, common API roots, and GraphQL endpoints. Follow
same-origin documentation links only within bounded limits. A generic HTML 200
or a bare 401/403 is insufficient proof of a working API or MCP protocol.
Record authentication-required and unknown candidates with their evidence.

Produce a normalized inventory with stable route IDs, original port, origin
scheme, endpoint path, protocol, discovered operations/path scope, authentication
requirements, and probe status. Publication is automatic for recognized,
non-excluded endpoints whose prerequisites are satisfied. Report candidates
that need backend credentials instead of guessing their secrets or claiming
that arbitrary APIs can all be discovered from their URL names.

MCP discovery and connection checks may use `initialize`, the initialized
notification, and `tools/list`; never execute `tools/call`. REST/OpenAPI and
GraphQL probes must also be read-only. Version 1 must support MCP Streamable
HTTP including SSE responses, REST HTTP, and GraphQL over HTTP. Explicitly
report unsupported transports instead of advertising them as working.

## Authentication and forwarding

```mermaid
flowchart LR
    B[Client with fixed bearer] --> W[One Citadel API Worker]
    O[Client using OAuth] --> A[Cloudflare Access Managed OAuth]
    A --> W
    W --> S[Origin protected by service authentication]
    S --> T[Existing cloudflared Tunnel]
    T --> C[Existing Caddy listener]
    C --> P[API or MCP backend]
```

The Worker accepts only configured hostnames and the endpoint paths belonging
to their scanned routes. It is not an arbitrary URL proxy. Disable alternative
`workers.dev` and preview entry points or reject them identically. The shared
route table must deny unknown paths, Citadel's own management API, and attempts
to escape path restrictions through encoding, traversal, or redirects.

### Fixed bearer

Store the configured client bearer as a Worker Secret and validate it before
forwarding. Missing or invalid credentials produce a machine-readable 401.
Cloudflare Access does not automatically validate an `openssl`-generated bearer;
this validation is the Worker's responsibility. A single configured bearer
grants access to all active bearer routes in this installation.

### Optional Managed OAuth

Attach Access with Managed OAuth to the OAuth hostnames only, so the fixed
bearer URLs remain usable. Reuse the configured email allowlist; an explicitly
public browser route is not an OAuth email policy. Cloudflare performs login,
token issuance, and refresh. The Worker validates the signed
`Cf-Access-Jwt-Assertion`, including issuer, audience, signature, and expiry,
and checks the current route identity policy before forwarding.
Do not decode the opaque client access token as though it were a JWT.
[Cloudflare Managed OAuth](https://developers.cloudflare.com/cloudflare-one/access-controls/applications/http-apps/managed-oauth/)

Use short access-token lifetimes, initially five minutes. Configure explicit
client callback permissions; localhost and loopback registration are off by
default and require a deliberate client-specific opt-in. OpenCode's container
callback is part of the documented setup, not an implied ability to type OTP
into a CLI. Verify target clients' discovery, registration, PKCE, and resource
indicator support before claiming compatibility. Keep registration settings in
extension-owned policy metadata rather than introducing more global env vars.

Cache signing keys with bounded lifetime and refresh on an unknown key ID.
Check each request, including requests carrying an existing MCP session ID.
Bind session handling to the authorized principal and route so another route
or identity cannot reuse it. Use per-identity or per-bearer rate controls, not
the Tunnel's loopback IP as a user identity.

### Origin and backend credentials

Use a separate, extension-owned origin hostname per port, protected by
Cloudflare service authentication. The Worker supplies those machine credentials
to reach the Tunnel origin. Do not weaken the original email/OTP route to make
Worker fetches work. The origin must reject a request that bypasses the Worker
without valid service credentials; preserve origin assertion validation where
the connector supports it. The Tunnel still targets the existing Caddy
listener, not a Podman-only address unreachable from host cloudflared.

Backend authentication is separate again. If the upstream needs its own API
key or bearer, attach that credential to the detected route and inject it only
after successful client authorization. Remove client Authorization and
untrusted identity headers first. Never forward the Cloudflare management token
or a client bearer as an assumed backend credential.

Provide a private per-route credential registry under
`CITADEL_DATA/cloudflare-api/` and publish secret values through Worker Secrets.
Use secret references in generated metadata; no secret values in route JSON,
logs, URLs, source control, or dashboard output. This registry supplies optional
backend credentials, not a manual inventory of servers to discover. Its schema
must permit later identity-to-secret mappings without changing the two global
example variables. Version 1 may use one backend credential per route; all
authorized clients then receive that credential's backend permissions.

Stream requests and responses without buffering complete MCP/SSE streams.
Preserve protocol headers and cancellation. Do not follow upstream redirects
with credentials or leak upstream secrets in errors and response headers.

## Code factoring

Keep Cloudflare resource changes separate from discovery and UI rendering.
The existing `functions/providers/cloudflare_api.py` is the Cloudflare API client;
do not repurpose its name for the new API-routing extension.

| Component | Responsibility |
|---|---|
| `extensions/disabled/CLOUDFLARE-API/extension.json` | Optional extension manifest; implementation ID `cloudflare_api_routes` |
| `functions/api_discovery.py` | Bounded read-only detection and normalized endpoint inventory |
| `functions/cloudflare_api_policy.py` | Mode matrix, whole-port exclusions, route identity, auth policy and secret references |
| `functions/cloudflare_plan.py` | Pure desired-state planning for ordinary Cloudflare routes and API routes together |
| `functions/cloudflare_apply.py` | One locked inventory/diff/apply coordinator for DNS, Tunnel, Access, Worker and domains |
| `functions/providers/cloudflare_api.py` | Existing API transport extended with Worker, Secret, Custom Domain, service-token and Access update operations |
| `functions/providers/cloudflare.py` | Existing provider entry point adapted to shared planning/apply |
| `functions/providers/cloudflare_api_routes.py` | Extension adapter and two mode views; no independent Tunnel writer |
| `workers/cloudflare-api/` | Worker routing, authentication, origin credential injection and streaming |
| `functions/providers/dispatch.py`, `functions/core.py`, `templates/index.html` | One extension yielding multiple endpoint links and two dropdown modes |
| `functions/runtime_state.py`, `functions/health.py`, `index.js` | Runtime output, auth-aware health, and consistent plugin route presentation |

Retain the existing scan lock. All selected Cloudflare participants contribute
to a combined desired state before a single apply phase. A normal scan, an API
scan, or an ordinary Cloudflare-only scan must not overwrite the other mode's
live bindings. Snapshot local configuration and complete remote pagination
before planning destructive operations. Unchanged scans perform no writes.

Preserve append-only `--add`: it must not reset, remove, or replace existing
routes. A changed ignore file or disabled mode is applied by a full scan;
report that pending removal explicitly during Add. Keep `--del` and Tailscale
reset semantics outside this feature.

Use stable resource ownership derived from the configured account, zone, and
dedicated Tunnel, with supported API metadata and explicit collision checks.
Another installation must not take over an existing Worker, DNS record, app,
or policy just because its name matches. Reconstruct remote inventory from
Cloudflare rather than depending on disposable route output as an ID ledger.

Update Access applications in place. GET the current object, merge the intended
changes while preserving unrelated writable settings, then PUT the complete
update payload. Preserve app IDs/audiences and client registrations on normal
rescans. Full rebuild mode must not silently rotate OAuth identity or delete
the sibling mode; intentional credential replacement needs an explicit action.

Provision protection before publishing URLs. On removal, deny the route before
retiring its owned resources. Validate and deploy a complete Worker route table
as one configuration version. Check platform limits before applying. Failure
must leave a known protected configuration, not a public fallback.

Fix the existing implicit-public fallback as part of the factoring: a newly
discovered ordinary Cloudflare port without an explicit rule and without valid
default emails must not be published as `whitelist: false`. Preserve deliberate
existing public rules. Add regression coverage before changing the provider.

## State, disable behavior and operational boundaries

Generated endpoint inventory and API route output belong in `cache/`; private
backend configuration belongs in the ignored persistent data directory. The
root ignore file is operator policy and must survive refreshes. Publish no
secrets to the existing health API or OpenClaw route output.

Turning a mode off, removing its bearer, or moving the extension to disabled
must cause the next successful full reconciliation to retire that mode's owned
public routes. The cleanup coordinator must discover these resources even when
the extension directory is no longer enabled. Keep the remaining auth mode and
ordinary browser routes intact.

Without a working management token, Citadel cannot revoke already published
Cloudflare resources. Report cleanup as pending and remote state as unverified;
never claim that removing a local value immediately revoked a remote token.
Do not remove protection to recover from configuration or API errors.

This feature does not start, stop, or restart cloudflared, Caddy, Podman, or
systemd services. Use GitHub Actions workflows from `SCRIPTS/githubactions` for
image builds, substantial image tests, smoke tests, and restart tests. Do not
build images or start test containers on core/rafael infrastructure. Image pulls
and local adoption remain separately requested Smart1 operations. Retain the
agreed Fedora image pins and other existing image-reference rules.

## Implementation sequence and acceptance

1. **Prove the protocol and ownership assumptions.** Exercise Managed OAuth
   discovery, registration, refresh, nested Worker domains, service-protected
   origin forwarding, and a real OpenCode callback in an isolated integration
   setup. Record actual client results rather than promising every Web UI works.
2. **Factor ordinary Cloudflare reconciliation.** Introduce plan/apply and the
   missing-email regression test, preserve current browser behavior, and prove
   resource ownership, pagination, locking, Add semantics and in-place updates.
3. **Add extension policy and discovery.** Implement the two example settings,
   four mode combinations, whole-port ignore file, protocol detection, bounded
   requests, and actionable results for missing backend credentials.
4. **Implement the Worker and protected origins.** Test bearer rejection and
   success, route/path boundaries, secret injection, streaming, cancellation,
   session isolation and rejection of direct unauthenticated origin access.
5. **Add optional OAuth.** Test missing/forged/expired assertions, wrong audience,
   another app in the same team, signing-key rotation, allowed identities,
   callback restrictions, token refresh and OAuth-only operation with no bearer.
6. **Integrate presentation and lifecycle.** Show two modes from one extension,
   retain all endpoints per port, reconcile exclusions and removals, report
   pending cleanup, and keep ordinary Cloudflare, localhost, subnet, Tailscale
   and Caddy behavior covered by regression tests.
7. **Finish operator documentation.** Maintain the README's Blender example,
   explain URL versus local MCP name, browser OTP and the container callback,
   distinguish every credential, document permissions and private state backup,
   and remove the planned-feature notice only after implementation is complete.

Completion requires meaningful automated tests plus a documented read-only
connection check through both public auth modes. A full scan repeated without
changes must preserve Worker identity, Access app IDs and OAuth sessions. An
ignored port must disappear from both API modes after full reconciliation,
and its old API URLs must reject access while the original browser route still
works. No test may call a Blender operation, mutate an application's data, or
silently publish a route after an auth failure.

## Related documentation

- [Blender and OpenCode walkthrough](README.md#planned-cloudflare-api-and-mcp-access)
- [Existing Cloudflare setup](CITADEL_CLOUDFLARE.md)
- [Cloudflare hostname-specific Worker protection](https://developers.cloudflare.com/workers/configuration/cloudflare-access/)
- [OpenCode MCP configuration and authentication](https://docs.opencode.ai/docs/mcp-servers/)
