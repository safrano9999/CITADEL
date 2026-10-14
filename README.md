# CITADEL

> **Type:** standalone service dashboard with an optional OpenClaw plugin.
>
> The FastAPI dashboard and scanner run on bare metal. The release ZIP is an
> OpenClaw plugin package, not a generic bare-metal installer.

[![OpenClaw plugin](https://github.com/safrano9999/CITADEL/actions/workflows/openclaw-plugin-release.yml/badge.svg)](https://github.com/safrano9999/CITADEL/actions/workflows/openclaw-plugin-release.yml)

![CITADEL dashboard](CITADEL.png)

CITADEL discovers listening TCP services, identifies HTTP endpoints, and builds
one dashboard for local, subnet, Tailscale, and Cloudflare routes. Providers are
reconciled independently, so local discovery remains useful even when a remote
provider is disabled or unavailable.

## Features

- Discovers listeners with `ss` and probes HTTPS before HTTP.
- Recognizes HTML services, generic HTTP services, and OpenAI-compatible
  `/v1/models` endpoints.
- Produces deterministic service metadata in `services.json`.
- Presents discovered services in a FastAPI dashboard.
- Supports localhost, subnet, Tailscale Serve, and Cloudflare providers.
- Rebuilds all Tailscale Serve routes as same-port HTTPS; preserves unrelated Cloudflare resources.
- Supports port allowlists, blocklists, Cloudflare hostnames, and Access email
  policies.
- Exposes the same route data through the `/citadel` OpenClaw command.
- `./scan.sh --add` probes only unknown ports, appending routes without resetting
  Serve, removing Cloudflare bindings, renumbering Caddy mappings or touching old logos.
  Failed additions remain pending and are retried on the next Add.
- `./scan.sh --del PORT` deletes only that port's live Tailscale Serve route,
  without scanning or changing Citadel metadata, logos, Caddy, Cloudflare or SSH.
  Explicit deletion also works when automatic Serve management is `off`.
- Telegram offers **Add** next to **Scan**, and **Tailscale → EDIT** lists live
  Serve ports with individual Delete buttons, alongside **Reset Serve Routes**.
  Direct HTTPS services without Serve are not listed. `/citadel tailscale del PORT`
  uses the same deletion function as the CLI.
  `/citadel tailscale reset` explicitly clears Serve only (not SSH), without scanning.
  Scans, deletes and resets share a lock; `/citadel add` is the fast append-only command.

## Supported deployment modes

| Mode | Status | What is provided |
|---|---|---|
| Bare metal | **Supported** | Scanner, FastAPI dashboard, configuration scripts, and a user-systemd installer |
| OpenClaw | **Supported** | Optional release ZIP with the `/citadel` command and scan integration |
| Hermes | **Not provided** | This repository contains no Hermes plugin, hook, or manifest |

CITADEL can discover a running Hermes service like any other listener. That is
service discovery, not a native Hermes integration.

## Releases

The [latest release](https://github.com/safrano9999/CITADEL/releases/latest)
contains:

- [`citadel-latest.zip`](https://github.com/safrano9999/CITADEL/releases/download/latest/citadel-latest.zip)
  · [SHA-256](https://github.com/safrano9999/CITADEL/releases/download/latest/citadel-latest.zip.sha256)

This ZIP is assembled and validated as an **OpenClaw plugin package**. For a
bare-metal installation, clone the source repository instead.

## Bare-metal installation

Requirements:

- System Python 3 and distribution-packaged Python dependencies (no virtual environment)
- `curl`
- `ss` from `iproute2`
- `flock` from `util-linux`
- Tailscale CLI only when the Tailscale provider is enabled

Install dependencies through the operating system's package manager. On Fedora:

```bash
sudo dnf install python3-fastapi 'python3-uvicorn+standard' python3-jinja2 python3-dotenv
```

On Fedora CoreOS/uCore, use persistent package layering instead of `dnf`:

```bash
sudo rpm-ostree install --idempotent --allow-inactive \
  python3-fastapi 'python3-uvicorn+standard' python3-jinja2 python3-dotenv
```

Activate the resulting deployment before switching the service. Package-only
additions can use `--apply-live` when no conflicting pending changes exist;
otherwise plan a reboot. Do not force replacements or overwrite RPM-managed
Python modules with `sudo pip`. Other distributions should install the packages
corresponding to `requirements.txt` through their own package manager.

Clone the source and configure it:

```bash
git clone https://github.com/safrano9999/CITADEL.git
cd CITADEL
./config.sh --no-container
```

Run one scan, then start the dashboard:

```bash
./scan.sh
/usr/bin/python3 webui.py
```

The default example binds the dashboard to `127.0.0.1:11000`.

### User systemd service

`set_daemon.sh` checks the system dependencies, writes and links the unit, then
enables and restarts `citadel.service`. It defaults explicitly to
`/usr/bin/python3`, regardless of an activated environment in `PATH`.
`PYTHON_BIN` can select a different
system interpreter when required.

```bash
./set_daemon.sh
systemctl --user status citadel.service
```

The installer also attempts to enable user lingering when it is available.
`CITADEL_WEBUI_TRANSPORT=tcp` is the default, including an unset or empty
value. Explicitly select `unix` to serve the same WebUI over a Unix socket,
on either the host or inside a container. `CITADEL_WEBUI_SOCKET` selects its
absolute path; empty uses the repository's `CITADEL_DATA/CADDY/citadel.sock` on the host
and in the image. An explicit `%t/` path uses `XDG_RUNTIME_DIR`. The web server creates
the socket; Podman can share its directory using a bind mount. A browser still
needs a TCP/HTTP(S) proxy in front of a socket-only WebUI.

The WebUI transport does not enable, disable, or otherwise control Caddyfile
generation. Neither transport requires Caddy, and neither starts it.

For an existing HTTPS reverse proxy, point its upstream at the dashboard's HTTP
port. `CITADEL_HIDE_HTTP_WEBUI_DUPE=1` (default) hides only the duplicate HTTP
tile when the same WebUI is simultaneously reachable through a scanned HTTPS
frontend. There is no HTTPS-port setting, JSON mapping, or Caddy dependency.
Discovery compares the WebUI's per-process `X-Citadel-Instance` response header,
so another container's Citadel cannot hide this instance by sharing its title.
Only successful, non-redirected responses count. The marker is not an auth token
and is not persisted. This is a local discovery check, not public TLS verification.
The rule is recomputed each scan; if HTTPS disappears, is filtered out, or fails,
HTTP appears again. Setting the option to `0` keeps both tiles. The HTTP backend
remains available for route providers; no blacklist or firewall rule is changed.
A containerized proxy must be able to reach the host bind address; its own
`127.0.0.1` is not the host's loopback.

## Containerfile and container definitions

Configure and render the host unit, Quadlet and runtime files without starting anything:

```bash
./setup.sh
```

`setup.sh` takes no arguments and always renders both service variants, then
prints their `ln -s` commands. Run only one variant per instance.
When Unix WebUI or Caddyfile generation is selected, setup also prints the
corresponding read-only Caddy bind mount, using the shared configuration loader.
It recommends that integration; it does not modify or restart Caddy.

Both definitions stay in the same project directory as `config.conf`, `.env`
and `container.conf`. The host service reads these application settings there;
the Quadlet injects the same `config.conf` and `.env` through absolute
`EnvironmentFile=` paths. The generated links reference these definitions,
not copies in another configuration directory. Configuration changes are read
at the next service/container start; setup itself does not restart anything.

The Alpine Containerfile is maintained in
`SCRIPTS/githubactions/CITADEL/scripts/Containerfile` and synchronized to
`.github/scripts/Containerfile`. Builds run exclusively on GitHub Actions:
version-tag pushes or the manual **Citadel Alpine image** workflow build, test
TCP/Unix startup, and push `ghcr.io/safrano9999/citadel:YYYY.MM.N` plus `:latest`.
The month has two digits; `N` increments within the month. Existing image
versions cannot be overwritten unless a manual run explicitly enables
`replace_existing` for a requested version. Only the safrano9999 repository publishes images.

GHCR initially creates packages as private. After the first push, set the
`citadel` package's **Package settings → Change visibility → Public** once.
The workflow checks visibility and fails that final check until public access
is enabled; the successfully pushed image remains available. See
[GitHub's visibility documentation](https://docs.github.com/en/packages/learn-github-packages/configuring-a-packages-access-control-and-visibility).

The image includes the scanner, WebUI, Tailscale and cloudflared. It uses a
small supervised bootstrap, not systemd internally. Missing credentials disable
the corresponding clients and providers. Runtime secrets are injected, never
baked into the image. A separate named volume retains Tailscale state at
`/opt/safrano9999/CITADEL/CITADEL_TAILSCALE` in Alpine and Fedora/uCore from
the Citadel/base layer onward. By default,
one bind mount, `./CITADEL_DATA:/opt/safrano9999/CITADEL/CITADEL_DATA:z`, shares all Citadel data with the host
service: policy, scan/provider state, logos, Caddy configuration and its
generated files/socket. Both the host and Alpine/Fedora/uCore read and write
`CITADEL_DATA/` directly inside the Citadel repository: no alias directories,
file symlinks or migration fallbacks. Setup creates the directories; application code is never
covered by the mount. Named volumes remain
possible by changing `container.conf`, but are then separate from host state.
Cloudflare has no volume and no persistent ID ledger. Its `routes.json` is
disposable dashboard output and is excluded from the shared state mount.
A missing filter file is not required for WebUI startup; the scan creates an
empty policy. The shared `CADDY` directory holds the generated Caddyfile,
allocation ledger and optional `citadel.sock`. Mount `CITADEL_DATA/CADDY`
directly at `/CADDY` in
Caddy, not the private Citadel state. Caddy's `unix//CADDY/citadel.sock` upstream stays
the same when switching between host service and container. TCP is the default.
Conditional mounts remain visible as commented `#Volume=...` lines when inactive.

Use `./config.sh` to configure a container, or regenerate only Compose and
Quadlet from existing configuration with `./config.sh --render-container`.
The `#container-command: image` directive in `container.example` makes both
use the image's bootstrap entrypoint, so runtime TCP/Unix
selection works without a Uvicorn command override. Regenerate older container
definitions to remove that override. Neither rendering command builds, pushes,
or starts an image; runtime secrets and scan state are not copied into the image.

## OpenClaw installation

Download and verify the public release package:

```bash
curl -fL \
  -o citadel-latest.zip \
  https://github.com/safrano9999/CITADEL/releases/download/latest/citadel-latest.zip
curl -fL \
  -o citadel-latest.zip.sha256 \
  https://github.com/safrano9999/CITADEL/releases/download/latest/citadel-latest.zip.sha256
sha256sum -c citadel-latest.zip.sha256
openclaw plugins install ./citadel-latest.zip \
  --force \
  --dangerously-force-unsafe-install
openclaw gateway restart
```

The plugin can use its packaged scanner and state, or it can point to an
existing bare-metal CITADEL checkout:

```json
{
  "plugins": {
    "entries": {
      "citadel": {
        "enabled": true,
        "config": {
          "servicesPath": "/opt/citadel/services.json",
          "scanScript": "/opt/citadel/scan.sh"
        }
      }
    }
  }
}
```

Available commands:

```text
/citadel
/citadel localhost
/citadel subnet
/citadel tailscale
/citadel cloudflare
/citadel other
/citadel scan
```

The plugin does not launch the FastAPI dashboard. It reads CITADEL state,
renders provider buttons, and can run the configured scanner.

## Configuration

`config.sh --no-container` renders local configuration from
`config.conf_example` and `env.example`.

| Setting | Example default | Purpose |
|---|---:|---|
| `CITADEL_WEBUI_TRANSPORT` | `tcp` | `tcp` or explicit `unix`, on host and in containers |
| `CITADEL_WEBUI_SOCKET` | empty | Optional absolute socket path for Unix transport |
| `FASTAPI_HOST` | `127.0.0.1` | Dashboard bind address |
| `CITADEL_WEBUI_PORT` | `11000` | Dashboard port |
| `CITADEL_HIDE_HTTP_WEBUI_DUPE` | `1` | Hide this WebUI's HTTP tile only while the same instance also responds successfully over HTTPS |
| `CADDYFILE_START` | empty | First generated HTTPS frontend port; empty/0 disables export |
| `CADDYFILE_STEPS` | `1` | Explicit positive increment retains assignments; empty/blank uses 1 and rebuilds assignments each scan |
| `CADDYFILE_BACKEND` | `127.0.0.1` | Address of this instance as reachable from Caddy; hostname/IP, without scheme or port |
| `CITADEL_TOKEN` | generated | Optional token protecting Cloudflare edits in the dashboard |
| `CITADEL_SUBNET_IP` | empty | Address used only for subnet routes; Cloudflare always targets localhost |
| `CITADEL_HTTPS_ONLY` | `0` | When enabled, route only services that already speak HTTPS on localhost; HTTP services remain visible |
| `CITADEL_TAILSCALE_SERVE` | `full` | `off`: direct HTTPS only; `http_to_https`: proxy HTTP only; `full`: proxy all ports |
| `CITADEL_LOGO_PERSISTENT` | `1` | Retain logos independently; service metadata is always rescanned |
| `CITADEL_USER_AGENT` | `Mozilla/5.0 (compatible; CITADEL/1.0)` | HTTP probe user agent |
| `CITADEL_CLOUDFLARE_DOMAIN` | empty | DNS suffix used for generated hostnames |
| `CITADEL_CLOUDFLARE_SERVERSIDE_PERSISTENCE` | `1` | Keep unchanged Cloudflare bindings; 0 deletes/rebuilds all managed bindings each scan. Local CF output remains ephemeral. |
| `CITADEL_CLOUDFLARE_WWW443` | `0` | Add `www.<domain>` for Cloudflare port 443 |
| `CITADEL_CLOUDFLARE_DOMAIN443` | `0` | Add the bare domain for Cloudflare port 443 |
| `CITADEL_CLOUDFLARE_REDIRECT_TO_WWW` | `0` | Redirect the bare domain to HTTPS www with HTTP 301; requires both 443 hostname flags and Dynamic URL Redirects Edit |
| `CITADEL_CLOUDFLARE_ACCOUNT_ID` | empty | Existing Cloudflare account ID |
| `CITADEL_CLOUDFLARE_ZONE_ID` | empty | Existing Cloudflare zone ID |
| `CITADEL_CLOUDFLARE_TUNNEL_ID` | empty | Existing named Tunnel ID |
| `CLOUDFLARE_API_TOKEN` | empty | Scoped Cloudflare API token |
| `CLOUDFLARE_EMAIL` | empty | Default Access email allowlist |
| `CLOUDFLARE_TUNNEL_TOKEN` | empty | Token consumed by the separately managed connector |

Non-secret service settings belong in `config.conf`. Secrets belong in `.env`,
which is ignored by Git.

During interactive configuration, `CITADEL_TOKEN` offers three choices: no
token, enter a token, or generate one with `openssl rand -hex 32` (the default).
An empty or `blank` value disables the prompt in the dashboard. When configured,
the token is required to enter Cloudflare edit mode and to save Cloudflare
rules. Five invalid attempts within five minutes lock that client out for
15 minutes.

An optional `config.ini` selects a custom CA:

```ini
[CITADEL]
ca_cert = /path/to/certs/ca.pem
```

### Port policy

`CITADEL_DATA/ports.filter.json` is created during the first scan. Start from
`ports.filter.json.example` when a policy should be prepared in advance:

```json
{
  "whitelist": [],
  "blacklist": [4000, "5000-5010"],
  "cloudflare": {
    "11000": {
      "subdomains": ["citadel"],
      "whitelist": true,
      "emails": ["operator@example.net"]
    }
  }
}
```

A non-empty whitelist takes precedence. Otherwise the blacklist is applied.

### Persistent Fedora container state

Mounts and volumes are configured separately at the container/Quadlet level.
Neither `CITADEL_TAILSCALE_SERVE` nor `CITADEL_LOGO_PERSISTENT` generates mounts.
The old `CITADEL_PERSISTENT` setting has been removed without an alias.
Existing mounts are not removed by changing a runtime flag.
Useful state paths to retain across container recreation include:

```text
CITADEL_DATA/ports.filter.json
CITADEL_DATA/icons/
CITADEL_DATA/CADDY/
```

CITADEL writes directly into `CITADEL_DATA/`; no state symlinks are needed.
Cloudflare output remains ephemeral in `cache/`. Provider code is not hidden by the mount.
`CITADEL_LOGO_PERSISTENT=1` reuses downloaded icons between scans. With `0`,
HTML services get a fresh download attempt; successful downloads replace that
port's icon, failed downloads leave the previous icon available. The icon
directory is not cleared. Discovery, titles and route results are always fresh.

## Extensions: URL providers and file exporters

Provider activation is directory based:

```text
extensions/enabled/<provider>/
extensions/disabled/<provider>/
```

`extension.json` describes an extension; directory placement controls whether
it participates. URL providers supply dashboard links. An extension with
`"kind": "export"` generates files instead: it never appears in the provider
dropdown or supplies tile URLs. Export status is recorded in `status.json`,
separately from URL providers' `routes.json`.

### Caddyfile export

`extensions/enabled/caddy/` is an optional, file-only export extension. Set:

```dotenv
CADDYFILE_START=4000
CADDYFILE_STEPS=1
CADDYFILE_BACKEND=ucore
```

An unset, empty, or zero start disables generation; no output directory is
created. Empty steps use 1. The extension reads the current service scan and
writes `CITADEL_DATA/CADDY/Caddyfile`, independently of the WebUI's `tcp`/`unix`
transport. It never starts/reloads Caddy, changes Quadlets, opens ports, calls
Podman, or issues certificates. No running Caddy is required for generation.

These three settings use the normal config/injection loader. No persistent
Caddy configuration JSON or frontend-host list is read. The default backend
`127.0.0.1` is for a same-host deployment. Use `host.containers.internal` when
Caddy runs in Podman and proxies host services, or the source container's
network name when both containers share a Podman network. This is explicit;
Citadel does not guess where the consuming Caddy runs.

Each generated `https://:PORT` block accepts every HTTP Host header, including
loopback, Tailscale and Cloudflare. Thus the ordinary scanner can fetch HTML
and icons through loopback without DNS overrides or logo copies. HTTPS remains
required; clients still need a certificate-valid hostname. The consuming
Caddy supplies its existing certificates/Tailscale integration.
For HTTPS upstreams, Citadel reads its own logged-in Tailscale DNS name as the
TLS server name and HTTP Host header. Without a logged-in daemon it uses the backend's normal TLS
name; certificate verification is never disabled. Resolved export settings
are written afresh to ephemeral `cache/caddy-config.json` for diagnostics,
never read back as configuration. No old JSON is needed to regenerate a file.

Use the **Caddy host's** real Tailscale DNS name for original Tailscale
certificates, not a different container's Tailscale name. For `.ts.net`, Caddy
obtains the official certificate from that node's Tailscale daemon at the TLS
handshake; give the consuming Caddy access to the daemon socket and certificate
permissions. Both Caddys on a node can use the same daemon and certificate.
The generated file does not embed certs,
keys, self-signed workarounds, or disable HTTPS upstream verification.

Backend ports receive sequential slots beginning at START. Empty/blank START
or START=0 disables export without deleting existing artifacts.
With empty/blank STEPS, every scan assigns currently discovered ports afresh in
numeric order, incrementing by 1. The old allocation ledger is not read and is
removed only after a new Caddyfile is successfully written.
With explicit positive STEPS (including 1), `CITADEL_DATA/CADDY/ports.json` remembers
the numeric mapping: newly
discovered ports append, disappeared ports keep their slots, and titles,
icons, and process identities are not used to recognize services. Preserve
this directory across container recreation. Changing START/STEPS requires
explicitly moving the old mapping aside; it never silently renumbers.
The generated Caddyfile contains only currently discovered services, including
HTTP backends (its frontends are HTTPS). An empty scan produces an empty
import while retaining allocated slots. Malformed scan/config/state does not
overwrite the last successful Caddyfile. Unchanged output is not rewritten.

Optionally bind-mount the **directory**, not the individual generated file,
read-only into Caddy, e.g. in its Quadlet:

```ini
Volume=/absolute/host/path/citadel/CITADEL_DATA/CADDY:/CADDY:ro,z
PublishPort=4000-4099:4000-4099
```

The Citadel container already receives this directory through its single
`./CITADEL_DATA:/opt/safrano9999/CITADEL/CITADEL_DATA:z` bind mount. This also persists the mapping. The published
range is an operator choice, not managed by Citadel; use nonoverlapping
ranges for multiple exporters. Check Unix ownership and SELinux labels for
the shared directory. Import `/CADDY/Caddyfile` in Caddy and validate
then reload it after changes. An atomic replacement is visible through the
directory mount. Disabling export stops writing; it does **not** delete an
existing mounted file or remove Caddy routes. Remove the import separately
when decommissioning it.

The sequence is discovery → Caddyfile generation → consuming Caddy validates
and reloads. A restart is not normally necessary. Tailscale and Cloudflare can
process the same initial discovery without waiting for Caddy. Newly published
Caddy ports appear in the next host scan; they must not be advertised as live
merely because a file was generated. Keep the exporter on the source instance,
not on a host scanning its own generated frontends (which would feed them back
into the export).

`./scan.sh --provider caddy` scans and runs only this export extension.

### Live ucore refresh through an init bind mount

`image/init/citadel-refresh.py` shallow-clones `f24sales/citadel` main into
`/opt/safrano9999/CITADEL`. Install it as `00-refresh.py` in the existing
bind-mounted init directory, alongside these instance-specific inputs:

- `instance.conf`: service environment, including `CADDYFILE_START=4000`,
  `CADDYFILE_STEPS=1`, `CITADEL_TAILSCALE_SERVE=full`, and `CITADEL_LOGO_PERSISTENT=1`.
- `export-config.json`: the consuming Caddy's hostnames and the source
  container's reachable Podman-network name as `backend`.
- `service.conf`: a systemd drop-in with `After=fedora45-ai-init-hooks.service`
  in `[Unit]` and the absolute container-side `EnvironmentFile=.../instance.conf`
  in `[Service]`.
- `CADDY/`: persistent generated output, shared read-only with Caddy.

Install the ordering drop-in for both Citadel units **before boot**; the hook
cannot reorder an already started WebUI. On recreation, provide that drop-in
through the image or a bind mount too. The refresh preserves instance secrets,
policy, logos, known disabled extension selections and runtime volume links,
but replaces the code tree completely. Previous trees remain as backups.
Missing Python dependencies are installed as Fedora packages, never in a venv.

For an explicit live refresh, run `python3 -s /path/to/00-refresh.py --live`
inside the container. It refuses an active scan, validates the clone first,
and restarts only Citadel's WebUI. It does not scan, reset routes, restart
Caddy, recreate the container or build an image. Run the subsequent scan and
Caddy validation/reload separately.

### Localhost and subnet

- `localhost` maps services to `127.0.0.1:<port>`.
- `subnet` maps services to `CITADEL_SUBNET_IP:<port>`.

### Tailscale

CITADEL's Tailscale extension runs when it is in `extensions/enabled` and its
manifest is enabled. `CITADEL_TAILSCALE_SERVE` controls Serve management, not
extension activation. It checks the daemon and makes one bounded,
noninteractive start attempt when necessary, then checks again. Missing CLI,
login requirements or failed startup produce an error instead of retry loops
or fabricated URLs.

The existing `config.sh` choice menu writes one of `off`, `http_to_https` or
`full` into the configuration, not a menu number. Empty uses `full`; old numeric
and boolean mode values are rejected before any provider commands run.

With `CITADEL_TAILSCALE_SERVE=full` (default), after validating discovery and the running
node, every full Tailscale scan runs
`tailscale serve reset` and rebuilds the currently discovered ports 1:1 using
**HTTPS only**. This deliberately replaces manual/foreign Serve routes too,
including their HTTP handlers and Funnel configuration. Existing connections
may be interrupted during a rebuild. Do not share this node's Serve configuration
with another route manager.

With `CITADEL_TAILSCALE_SERVE=http_to_https`, full scans also reset Serve first,
then verify direct HTTPS on the node's Tailscale address. Valid direct HTTPS
is kept without a proxy; HTTP-only backends receive same-port HTTPS Serve.
An already-discovered HTTPS backend with a failed certificate/connectivity check
is reported as skipped, never silently wrapped or downgraded to HTTP. `--add`
never resets, replaces or removes existing listeners. Existing Serve listeners
are not mistaken for native HTTPS during Add retries. This does not disable
the backend's original HTTP listener. Caddy HTTPS ports therefore need no Serve
listener, while HTTP ports still have the documented wildcard-binding risk.

With `CITADEL_TAILSCALE_SERVE=off`, no Serve commands or configuration writes run,
including via `unroute.sh`. HTTPS endpoints are probed directly on the node's
Tailscale IP with hostname/certificate verification, then published as direct
links. HTTP-only backends are not advertised as HTTPS. Existing Serve routes
are not cleared merely by setting this flag. Node-level systemd reset hooks
are independent of this scan setting.

`TAILSCALE_SERVE_RESET=1` enables a separate bootstrap reset after successful
`tailscale-up.service` startup, before the container WebUI. Any other value,
including missing/empty/0, does nothing. It clears **all** Serve/Funnel routes
on that Tailscale node, not its identity or Tailscale SSH. A WebUI restart alone
does not run it. The shared helper and unit drop-in are hardlinked from
`SCRIPTS/safrano9999-lib/tailscale/`, also used by Fedora Core-pre. The current
Alpine image invokes the same helper after Tailscale is ready and before WebUI
startup. Restarting that entire container repeats its bootstrap.

In `full` mode, both HTTP on `127.0.0.1:4096` and HTTPS on `127.0.0.1:2000` receive HTTPS on
`<node>.ts.net:4096` and `<node>.ts.net:2000`, respectively. There is no public
HTTP fallback, second port range, ownership ledger, or service identity matching.
An internal HTTP backend is still allowed. HTTPS backends remain encrypted on
loopback; Serve's local `https+insecure` target accepts their local certificates.
The **public** certificate is the official node certificate managed and renewed
by Tailscale Serve. Citadel does not generate or copy certificate keys.

**Restart constraint on TUN-mode nodes:** bind backends to explicit non-Tailscale
addresses, not `0.0.0.0` or `[::]`, when Serve uses the same port. Peer HTTPS can
work while a wildcard backend is running, but after it stops, tailscaled can
claim the Tailscale-IP listener and prevent that backend from restarting with
`EADDRINUSE`. This also applies to wildcard Podman-published ports. A successful
peer probe or index health result does not prove restart safety.
[Tailscale's local listener implementation](https://github.com/tailscale/tailscale/blob/v1.98.8/ipn/ipnlocal/serve.go#L104-L113)
explains the separate host-level listener. Userspace networking avoids those
listeners but changes normal tailnet networking; choose that mode deliberately.
Citadel does not silently change daemon modes or rebind unrelated services.

The port filter and `CITADEL_HTTPS_ONLY` still decide which local services enter
the scan; the latter filters locally HTTP-speaking backends, not the public
Tailscale scheme. A failed reset stops reconstruction; failed route applications
are reported without a dashboard URL. Adding or removing a service never
renumbers the other ports.

`./scan.sh --provider tailscale` performs discovery and reconciles only
Tailscale, without calling Cloudflare or subnet providers.

### HTTPS and Caddy

Caddy is optional. Quadlets and Caddy own the published host ports; Citadel's
host scan consumes those listeners 1:1. The optional Caddy export extension
can generate a separate container's frontend mapping, but never changes
container networking or requires a Caddy installation.

By default the dashboard serves HTTP on `127.0.0.1:11000`. If Caddy exposes the
same instance over HTTPS, `CITADEL_HIDE_HTTP_WEBUI_DUPE=1` automatically hides its
duplicate HTTP tile while both endpoints work. Without working HTTPS, the HTTP
dashboard stays visible and usable.

For a Tailscale hostname, Caddy obtains the original node certificate from
the local Tailscale daemon. Two Caddys serving the same node hostname should
use the same daemon, with access to its socket and certificate permissions;
do not substitute a locally generated certificate for that hostname.
Certificates for localhost or IP addresses are separate.

Allow the scanning user to manage Tailscale without running every scan as root:

```bash
sudo tailscale set --operator="$USER"
./scan.sh
```

Release selected Serve ports with:

```bash
./unroute.sh 11000
```

With no port arguments, `unroute.sh` uses `CITADEL_WEBUI_PORT`. It never runs a
global Tailscale Serve reset.

With `CITADEL_TAILSCALE_SERVE=off`, `unroute.sh` is a no-op: neither the daemon's
Serve configuration nor cached direct links are touched.

### Cloudflare

Cloudflare runs when its extension is in `extensions/enabled`, its manifest is
enabled, and `CLOUDFLARE_API_TOKEN` is configured. There is no separate activation
variable. The token is verified and account, zone, Tunnel, domain and Access
settings are validated before route changes. Missing tokens skip the provider;
invalid tokens or incomplete required configuration are reported. It manages:

- DNS records for discovered services;
- ingress entries on an existing named Tunnel;
- optional Cloudflare Access email policies.

`CITADEL_CLOUDFLARE_SERVERSIDE_PERSISTENCE=1` is the default preset. Every scan
queries Cloudflare and retains unchanged DNS bindings, Access rules and Tunnel
routes. Only changes are applied; disappeared services are removed. Unchanged
scans perform no writes to Cloudflare. Set the flag to `0` to clear all ingress
on the configured Tunnel to a 404 fallback and recreate all its managed bindings
on every scan. Both modes target `127.0.0.1:<original-port>` with the discovered
HTTP/HTTPS scheme; an empty scan leaves the Tunnel empty. Use a dedicated Tunnel.

No old local route file or resource IDs are read. All relevant inventory pages
are fetched before reset. Invalid scans, inventory failures and foreign-object
conflicts abort before changes. Routes whose Access rules are replaced are
disabled first and enabled only after successful recreation. A full rebuild
intentionally interrupts all routes; persistent mode leaves unchanged ones up.
Other Tunnels and unrelated DNS/Access objects are not reset. The flag controls
server-side behavior only: local route output is rewritten and remains ephemeral
in `cache/`, with no Cloudflare volume.
See [CITADEL_CLOUDFLARE.md](CITADEL_CLOUDFLARE.md) for the required API
permissions and provider-specific setup.

For port 443, the local Caddy site block must include both `<domain>:443` and
`www.<domain>:443` when both hostname flags are enabled. Reload or restart Caddy
after changing the site block; CITADEL manages the Cloudflare DNS and Tunnel routes.

Set `CITADEL_CLOUDFLARE_REDIRECT_TO_WWW=1` together with `WWW443=1` and
`DOMAIN443=1` to redirect the bare domain to `https://www.<domain>` at Cloudflare.
Paths and query strings are preserved. The Cloudflare token needs the zone-scoped
**Dynamic URL Redirects → Edit** permission. No Caddy restart is required for
this edge redirect. A scan installs or reconciles one rule identified by the
configured Tunnel; unchanged rules cause no write. Setting the flag to `0`
removes only this Tunnel's rule, retaining all unrelated rules. Removing port
443 from a full scan also removes its redirect. Add mode never replaces or
removes an existing rule. Existing installations without the variable do not
query the Rulesets API. With explicit `0` and a token lacking read permission,
normal routing continues, but the provider reports that redirect removal could
not be verified; retain the permission when switching an enabled redirect off.

## Planned Cloudflare API and MCP access

**Implementation candidate, not yet live-accepted:** this branch implements
the [Cloudflare API refactoring goal](GOAL_CLOUDFLARE_API.md). The extension ships
disabled. Automated protocol and lifecycle checks do not establish that a
particular Cloudflare account or OAuth client works. Real Managed OAuth login,
refresh and the OpenCode container callback remain integration acceptance items.
The instructions below apply after deliberate deployment and configuration.

Citadel scans the existing reachable listeners, identifies API/MCP endpoints,
and map recognized endpoints through one shared Worker per installation. The
existing Cloudflare browser URLs keep their email/OTP protection. Two additional
dropdown modes provide API credentials suitable for clients:

| Mode | Example endpoint | Client authentication |
|---|---|---|
| **API-Bearer** | `https://api-3070.example.com/mcp` | Configured fixed bearer |
| **API-OAuth** | `https://oauth.api-3070.example.com/mcp` | Cloudflare Managed OAuth |

Both hostnames attach to the same Worker as Custom Domains. Cloudflare issues
certificates for these domains, including the nested OAuth hostname.
[Worker Custom Domains](https://developers.cloudflare.com/workers/configuration/routing/custom-domains/#certificates)

### Extension configuration and exclusions

Both `extensions/enabled/cloudflare/` and
`extensions/enabled/CLOUDFLARE-API/` must be active, and the existing
`CLOUDFLARE_API_TOKEN` must have the required management permissions.
Directory placement controls activation; no extra enable flag is needed.

The two existing example files contain:

```dotenv
# env.example: optional secret; config.sh offers skip, entry, or generation.
#secret
CITADEL_CLOUDFLARE_API_BEARER=example: openssl rand -hex 32
```

```dotenv
# config.conf_example: independent OAuth option.
#choices: 0 1
#default-preset: 0
CITADEL_CLOUDFLARE_API_OAUTH=0
```

The generator hint belongs in the example only. The rendered `.env` contains
the actual bearer or an empty value. For OAuth-only access, leave the bearer
empty and set `CITADEL_CLOUDFLARE_API_OAUTH=1` in `config.conf`.

| Bearer present | OAuth | Active API modes |
|---|---|---|
| No | `0` | None |
| Yes | `0` | API-Bearer |
| No | `1` | API-OAuth |
| Yes | `1` | Both |

OAuth-only URLs still use `oauth.api-<port>.<domain>`. OAuth also needs an
allowed-email policy and client registration/callback settings; it does not
need a fixed client bearer.

Configured modes remain visible after a scan even if no eligible endpoints were
found or Cloudflare rejected publication. API modes list only services with
detected REST, HTTP RPC, GraphQL or MCP endpoints; ordinary browser-only tiles and other
listening ports are hidden. Discovery runs before Cloudflare management calls,
so detected endpoints remain visible during a Cloudflare failure, with an
explicit unpublished or backend-authentication status and no public link.
An OpenAPI document proves an API exists even when its operations require a
backend credential. A guessed path, HTML login or bare 401 does not. Inactive
modes are hidden. A visible tile alone does not confirm a working connection.

Discovery also checks `/api-doc/openapi.json`, `/api/schema/` and `/doc` for
OpenAPI schemas. Schema requests allow up to three seconds inside the shared
ten-second listener deadline. Up to 26 requests per listener are allowed,
including at most three linked documents.

The `/tools/invoke` HTTP RPC probe runs on every eligible listener, without
matching an application name or port. It requires `GET` to return `405` with
`Allow: POST`, a missing control path to return `404`, and an empty `POST {}` to
return a JSON authentication error or a specific missing-tool validation error.
The probe never sends a tool name, action or arguments. A protected endpoint is
shown as requiring backend credentials; publication requires successful empty
request validation. Only the exact `POST /tools/invoke` operation is mapped.
A generic 401, catch-all 405, redirect or HTML login does not qualify.

Activate the extension by moving the shipped directory from
`extensions/disabled/CLOUDFLARE-API` to `extensions/enabled/CLOUDFLARE-API`.
Use `./config.sh` to render the two settings; the existing secret prompt offers
skip, manual entry, or `openssl rand -hex 32` generation. Regeneration preserves
an existing bearer. An unchanged example hint is rejected as a credential.

In addition to the existing Tunnel, DNS and Access permissions, the management
token needs account **Workers Scripts Edit**, account **Access: Service Tokens
Edit**, and **Workers Routes Edit** for the affected zone. Keep Access application,
policy and identity-provider permissions for OAuth. Scope these to the configured
account and zone. Citadel requires an initialized Access team domain. A missing
permission stops publication; it does not create a public fallback.
[Worker permissions](https://developers.cloudflare.com/workers/authorization/workers/),
[service-token permission](https://developers.cloudflare.com/api/resources/zero_trust/subresources/access/subresources/service_tokens/methods/create/)

For OAuth, configure permitted emails in the existing `CLOUDFLARE_EMAIL` and
create `CITADEL_DATA/cloudflare-api/policy.json`. For a remote web client, use
its exact documented HTTPS callback:

```json
{
  "oauth": {
    "allowed_redirect_uris": ["https://your-client.example/oauth/callback"],
    "allow_localhost": false,
    "allow_loopback": false
  }
}
```

Replace the illustrative URI with the actual client's URI; no broad wildcards.
For OpenCode's `127.0.0.1` callback, deliberately set `allow_loopback` to `true`;
`allowed_redirect_uris` can be empty if no web clients are used. This Cloudflare
option permits loopback callbacks, not only OpenCode's particular port or path.
Leave `allow_localhost` off unless a selected client needs the `localhost` name.
All endpoints in this installation share this registration policy. OAuth uses
five-minute access tokens. The Worker additionally checks the current allowed
emails on every request, including existing MCP sessions. A configuration change
takes effect remotely after a successful full scan.

Exclude an entire port through the repository-root `CLOUDFLARE-API_ignore.json`:

```json
{
  "ports": [3070]
}
```

The next successful full `./scan.sh` removes every API-Bearer and API-OAuth
route for that port. Its ordinary browser route is unaffected. Use an empty
list to exclude nothing. There are no individual URL/path exclusions. Add mode
does not remove existing routes; use a full scan after changing this list.

### Discovery, backend credentials and persistent state

Discovery uses the normal scanned `127.0.0.1` HTTP(S) listeners, including Caddy's
published ports. Citadel does not enter Podman networks or scan Unix sockets.
Keep those bridges in Caddy. Detection supports MCP Streamable HTTP with JSON or
SSE responses, local OpenAPI/Swagger operation maps, and GraphQL HTTP queries.
It does not turn stdio, WebSocket or legacy SSE transports into Streamable HTTP.
Path names, an HTML page, or a bare 401 are insufficient evidence. Probes have
request, time and body-size limits and never execute application tools.

Inspect `cache/cloudflare-api-inventory.json` for route IDs, paths and evidence;
the API extension also reports candidates needing backend authentication.
An app can have several endpoints, all individually linked in each active menu.
Only discovered OpenAPI methods and paths are forwarded for REST. Generic APIs
without recognizable metadata remain unverified instead of exposing arbitrary
paths. Encoded or ambiguous paths and Citadel administration routes are denied.

When a backend requires its own token, create the private file
`CITADEL_DATA/cloudflare-api/credentials.json` with mode `0600`:

```json
{
  "routes": {
    "p3070_REPLACE_WITH_DISCOVERED_ID": {
      "headers": {"Authorization": "Bearer REPLACE_WITH_BACKEND_TOKEN"}
    }
  }
}
```

Replace the entire key with the `id` from discovery; the placeholder is not a
valid route ID. Add further route IDs to the same `routes` object. This file
attaches credentials to detected routes; it is not a list of ports to publish.
For protected OpenAPI documents, the document candidate and the resolved API
base can have different IDs and need separate entries. Scan again after editing.
Never use the Cloudflare management token as a backend token. Version 1 shares
each route's backend permissions among its authorized clients. Identity-specific
credential mappings are reserved in the schema but not implemented.

The Worker authenticates the client, strips incoming authorization/identity
headers, then injects the configured backend credential plus a separate origin
service credential. `origin-api-<port>.<domain>` is a Tunnel hostname protected by
Access Service Auth and cloudflared assertion validation. The original browser
hostname retains its OTP policy. Backend redirects are refused. MCP responses
stream without whole-response buffering; session IDs are encrypted and bound to
the authenticated identity and route. The rate control is 120 requests per
minute per bearer/identity at each Cloudflare location, not a global quota.

Back up `.env`, `config.conf`, the root ignore file, and the private
`CITADEL_DATA/cloudflare-api/` directory. Its `runtime.json` contains the session
key and origin service secret; it is not disposable cache. Losing it requires
restoration or explicit credential recovery, not automatic OAuth app replacement.
The origin service token is created for one year; renewal is an explicit
operation. Do not delete private state to force rotation.

Container installations persist `CITADEL_DATA` through the existing data mount.
The ignore file lives beside `scan.sh`, not inside that data directory. Supply
and retain it in the writable Citadel runtime tree (normally
`/opt/safrano9999/CITADEL/CLOUDFLARE-API_ignore.json`), or mount it there from the
host when using an immutable tree. Citadel's refresh preserves this file and the
enabled/disabled extension selection.

### Scan and disable behavior

Normal scans and Cloudflare-specific scans use one shared reconciliation for
browser routes and API modes. Unchanged scans preserve Worker and Access IDs.
`--add` preserves deployed routes, policies and credentials and reports changes
requiring a full scan. Full scans remove excluded ports or disabled modes after
first denying them in the Worker. Moving the extension back to `disabled` also
requires a successful full scan to remove remote bindings. An empty deny-only
Worker may remain to preserve installation ownership.

Without a working `CLOUDFLARE_API_TOKEN`, removal is **pending**, and remote
state is **unverified**. Removing the local bearer alone does not revoke its
deployed copy. Do not delete the management token or private state before
cleanup. A malformed ignore file, incomplete remote inventory, ownership
collision or incomplete rediscovery prevents destructive reconciliation.

The dashboard's `provisioned` status means that HTTPS and the anonymous machine
auth challenge were verified. It does not mean a client's token exchange or
authenticated backend connection succeeded. `TLS pending` and `Auth pending`
remain visible. Existing foreign Access wildcard policies covering API hostnames
must be resolved before publishing, because they can force an unwanted OTP page
onto bearer endpoints.

### Example connecting a Blender MCP from OpenCode

Assume a Blender MCP server has already been exposed through an HTTP bridge
and Caddy at `https://127.0.0.1:3070/mcp`, as reachable by the Citadel scanner.
Port 3070 and `/mcp` are illustrative; use the actual discovered values.
This example does not imply that Blender itself, a stdio-only MCP server, or a
raw add-on TCP socket is an HTTP MCP endpoint. The bridge must already support
the required remote MCP transport.

Use your own domain in place of `example.com`. Container commands below target
the existing OpenCode container `fedora45-ai-base-opencode`; substitute your
container name and run Podman as its owning host user. The command syntax was
checked with OpenCode 1.18.34.

1. **Prepare the published OAuth endpoint.** Enable the extension and OAuth,
   configure the allowed emails and the OpenCode callback policy, then perform
   a successful full scan. If the bridge requires a backend token, attach it
   to the detected route through the extension's credential configuration.
   Copy the endpoint from **API-OAuth**:

   ```text
   https://oauth.api-3070.example.com/mcp
   ```

   The Worker uses a separately authenticated origin connection to reach the
   existing Tunnel and Caddy. The browser's OTP-protected service URL remains
   separate. [Cloudflare Managed OAuth](https://developers.cloudflare.com/cloudflare-one/access-controls/applications/http-apps/managed-oauth/)

2. **Save the endpoint in OpenCode under a local name.**

   ```bash
   podman exec -it fedora45-ai-base-opencode \
     opencode mcp add blender \
     --url https://oauth.api-3070.example.com/mcp
   ```

   `blender` is the name of this MCP configuration entry. It is not a username
   or a container lookup. The relevant configuration is equivalent to:

   ```json
   {
     "mcp": {
       "blender": {
         "type": "remote",
         "url": "https://oauth.api-3070.example.com/mcp"
       }
     }
   }
   ```

   Add this entry to the existing configuration; do not replace unrelated
   settings. A separate OpenCode process reads it when it starts.

3. **Start authentication for the saved name.**

   ```bash
   podman exec -it fedora45-ai-base-opencode opencode mcp auth blender
   ```

   OpenCode resolves `blender` to the configured URL and begins OAuth discovery
   and client registration. Keep this terminal open. It prints
   `Authorize in your browser:`, the authorization link, and
   `Waiting for authorization...`.
   [OpenCode 1.18.34 CLI implementation](https://github.com/anomalyco/opencode/blob/v1.18.34/packages/opencode/src/cli/cmd/mcp.ts#L239)

4. **Open that authorization link on your computer.** Enter your allowed email
   address and the emailed OTP on Cloudflare's browser page. The OTP is not
   entered into OpenCode's terminal. Cloudflare authenticates your identity;
   the OAuth transaction separately identifies the waiting CLI request.

5. **Deliver the browser callback to the waiting OpenCode process.** The
   default callback in this version is:

   ```text
   http://127.0.0.1:19876/mcp/oauth/callback?code=...&state=...
   ```

   OpenCode checks `state` to match the response and exchanges the short-lived
   code using its saved PKCE verifier. Cloudflare must allow the selected
   callback; its loopback registration setting needs an explicit opt-in for
   this client. [OpenCode OAuth provider](https://github.com/anomalyco/opencode/blob/v1.18.34/packages/opencode/src/mcp/oauth-provider.ts)

   In a remote container, the browser's `127.0.0.1` is your computer, while
   OpenCode's callback listener is inside the container. Arrange forwarding
   into that container's loopback namespace before login. An SSH forward only
   to the host's loopback, or publishing a port whose listener binds only to
   container loopback, does not by itself solve this.

   For a first manual test without forwarding, the browser may display a
   connection error at the callback URL. Copy the **complete** URL from its
   address bar, including `code` and `state`. In a second terminal, invoke the
   callback inside the same container with the following helper. Paste the
   URL at its hidden prompt; keep the first authentication process running.

   ```bash
   podman exec -it fedora45-ai-base-opencode python3 -c '
   import getpass
   import urllib.parse
   import urllib.request

   callback = getpass.getpass("Complete callback URL (hidden): ")
   parsed = urllib.parse.urlsplit(callback)
   if (parsed.scheme != "http" or parsed.hostname != "127.0.0.1"
           or parsed.port != 19876 or parsed.path != "/mcp/oauth/callback"
           or parsed.username is not None or parsed.password is not None):
       raise SystemExit("Unexpected callback URL")
   opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
   with opener.open(callback, timeout=10) as response:
       print("Callback HTTP status:", response.status)
   '
   ```

   This forwards the OAuth callback, not the OTP. It follows the callback
   handler's code/state contract; it still requires an end-to-end check against
   the deployed integration. Version 1.18.34 waits up to five minutes. On
   timeout, start a fresh login and use its new URL. Check the first terminal
   for authentication success; an HTTP response alone does not prove that
   token exchange or the MCP connection succeeded.
   [OpenCode callback handler](https://github.com/anomalyco/opencode/blob/v1.18.34/packages/opencode/src/mcp/oauth-callback.ts)

6. **Check the resulting connection.**

   ```bash
   podman exec -it fedora45-ai-base-opencode opencode mcp list
   ```

   OpenCode stores OAuth credentials in
   `~/.local/share/opencode/mcp-auth.json` for the user inside the container.
   Keep that data directory persistent. Subsequent connections reuse valid
   credentials and refresh them while the authorization grant permits it;
   expiry or revocation can require another login.
   [OpenCode MCP authentication](https://docs.opencode.ai/docs/mcp-servers/#authenticating)

   Each request then follows client → Cloudflare OAuth validation → Worker →
   authenticated Tunnel origin → Caddy → Blender MCP bridge. Any backend
   credential remains on the proxy side. All users sharing one backend token
   receive its permissions. A connection check must stop at initialization
   and listing tools; it must not execute Blender operations.

### Fixed bearer alternative

Clients supporting custom headers can instead use **API-Bearer**. An OpenCode
configuration entry would look like this:

```json
{
  "mcp": {
    "blender-bearer": {
      "type": "remote",
      "url": "https://api-3070.example.com/mcp",
      "oauth": false,
      "headers": {
        "Authorization": "Bearer {env:CITADEL_CLOUDFLARE_API_BEARER}"
      }
    }
  }
}
```

Supply the configured client bearer in the OpenCode process environment; the
container does not automatically inherit Citadel's `.env`. This method needs
no browser login or OAuth callback. The client bearer, Cloudflare management
API token, machine credential for the origin, and optional backend token serve
different purposes and must not be substituted for each other.

### Read-only acceptance check

After intentional deployment, test both public URLs with the bundled checker:

```bash
python3 functions/mcp_check.py https://api-3070.example.com/mcp
python3 functions/mcp_check.py https://oauth.api-3070.example.com/mcp
```

The hidden prompt takes the configured client bearer for the first URL and an
actual OAuth **access token** obtained through the selected client's login for
the second. Never paste the management token, backend secret, authorization code
or refresh token. Alternatively use `--token-file` with a private `0600` file
containing only the access token; avoid secrets in command arguments. The checker
does not perform OAuth login or token refresh itself.

It sends only `initialize`, `notifications/initialized` and paginated `tools/list`,
checks sessions and protocol responses, and refuses redirects and HTML login
pages. Success reports a tool count and `tools_called: 0`; tool descriptions and
token values are not printed. Also verify the real client's OAuth registration,
browser callback and refresh after access-token expiry. Do not assume that all
ChatGPT, Claude, Grok or other Web UI variants support static headers or this
OAuth flow without checking the particular client.

For full acceptance, repeat an unchanged scan, confirm stable Access IDs and the
existing client session, then exclude the test port and scan again. Both old API
URLs must reject access while the ordinary OTP browser URL remains functional.
Direct requests to the machine origin without service credentials must fail;
an invalid or wrong-audience assertion must also fail at cloudflared. Record the
actual deployment/client results separately from the automated fixtures.

## Operations

Run or repeat discovery:

```bash
./scan.sh
```

The scan updates:

```text
CITADEL_DATA/ss.json
CITADEL_DATA/services.json
cache/<port>.json
CITADEL_DATA/providers_state.json
CITADEL_DATA/<provider>-routes.json
CITADEL_DATA/caddy-status.json
cache/cloudflare-routes.json
CITADEL_DATA/tailscale.json
CITADEL_DATA/last_scan.txt
```

The dashboard does not execute scans. Cloudflare edits made in the dashboard
are saved immediately and applied by the next `./scan.sh` CLI run.

Inspect the user service:

```bash
systemctl --user status citadel.service
journalctl --user -u citadel.service
```

## Security and storage

- Keep the dashboard bound to `127.0.0.1` unless remote exposure is deliberate.
- Treat `.env`, Cloudflare tokens, Tunnel tokens, and private CA material as
  secrets.
- Give the Cloudflare token only the account- and zone-scoped permissions
  described in `CITADEL_CLOUDFLARE.md`.
- The scanner records listener metadata and service titles. Protect the
  repository directory if that inventory is sensitive.
- Downloaded service icons are limited to 1 MiB, passive image formats, and
  the same host and port as the discovered service.
- Dashboard templates use automatic HTML escaping.
- Runtime JSON is written through durable temporary files and atomically
  replaced so readers never observe a partial update.
- Runtime state, caches, generated routes, local configuration, and release
  archives are excluded by `.gitignore`.
- Back up `ports.filter.json` for custom exclusions/access rules and `CADDY/`
  for explicit persistent port assignments. Cloudflare needs no saved IDs.

## Development and checks

Install dependencies, then run the same source checks used by the release
workflow:

```bash
/usr/bin/python3 -s -m unittest discover -s tests
node --check index.js
bash -n scan.sh
bash -n unroute.sh
```

The release workflow builds `citadel-latest.zip`, writes its SHA-256 file, and
publishes both only for a version tag.

## Health: index view and external reachability

`/healthz` is a separate page with ✅ / ❌ / ⏭️ indicators. The existing
service overview is unchanged. `/api/health?extensions=tailscale,cloudflare`
returns the same **index state** as JSON (`schema_version: 1`). Health only reads
existing index files, provider routes and caches. It never starts a scan,
executes a provider, changes routing, or writes to the index. `last_index_at`
is read from the existing `last_scan.txt` timestamp; it is shown without claiming
that old data describes the current deployment. No implicit age limit is applied.

An extension absent or unconfigured in the index is `SKIP`. A configured but
unavailable extension, failed provider or broken route/cache is `FAIL`. If no
extension can be tested, the result is `NOT_TESTED`, never a successful gate.
The endpoint defaults to showing all enabled extensions; its `extensions`
parameter restricts the selection. The CLI requires an explicit selection.

For file exporters, health verifies that generated artifacts exist under the
Citadel directory and match the last successful export's SHA-256.
The generated file lives directly in `CITADEL_DATA/CADDY/`. No dropdown
URLs are required. This verifies the exported files, **not** whether an
external Caddy has imported them, reloaded, or can reach its backends. The
standalone checker does not turn file exporters into HTTP probe jobs.

### Standalone checker (also suitable for n8n SSH nodes)

Download the standard-library-only checker from the Citadel instance being tested:

```bash
CITADEL_URL='https://your-container.your-tailnet.ts.net:10002'
curl --fail --show-error --silent "$CITADEL_URL/healthz/check.py" \
  --output citadel-health-check.py.new &&
  mv citadel-health-check.py.new citadel-health-check.py
python3 citadel-health-check.py --url "$CITADEL_URL" \
  --extensions tailscale cloudflare
```

Only the supplied extensions are checked. Do not pass `localhost` from another
machine: those addresses refer to the checker machine. The CLI first requires
HTTP 200 from Citadel's dashboard, then reads its selected index entries and
checks their URLs from the caller's network. It does not call `systemctl` on the
caller, which would say nothing about Citadel inside a remote container.

Tailscale requires HTTP 200. Cloudflare requires HTTP 200 **and an identifiable
Cloudflare Access login form** on its HTTPS `*.cloudflareaccess.com` login route.
An arbitrary successful page, a challenge page or a denial page is insufficient.
No credentials are submitted and the application behind Access is **NOT_TESTED**.
The checker never scans, logs in, retries, or exposes URL query tokens in results.

Output is a single JSON object with `status`, `gates.citadel_self`,
`gates.citadel_links`, `extensions`, `results`, and `last_index_at`.
Exit code 0 means PASS, 1 means a failed/incomplete check, 2 means invalid CLI
arguments. If Citadel itself is unreachable, extension checks remain NOT_TESTED.
Default per-request socket timeout: 5 seconds, up to 8 concurrent route checks.
A workflow should also set its overall command timeout. Download failure must
stop the gate rather than executing an older cached checker.
