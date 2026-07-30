"""
core.py — CITADEL dashboard business logic.
No Flask/HTTP dependencies. Returns plain dicts/lists.
"""

import json
import os
from pathlib import Path

from cloudflare_policy import (
    cloudflare_rules,
    normalize_emails,
    normalize_rule,
    read_policy,
    write_cloudflare_rules,
)

BASE_DIR = Path(__file__).resolve().parent.parent

SERVICES_FILE = BASE_DIR / "services.json"
HOST_SERVICES_FILE = BASE_DIR / "host_services.json"
TAILSCALE_FILE = BASE_DIR / "tailscale.json"
LAST_SCAN_FILE = BASE_DIR / "last_scan.txt"
EXTENSIONS_DIR = BASE_DIR / "extensions"
ENABLED_EXT_DIR = EXTENSIONS_DIR / "enabled"
DISABLED_EXT_DIR = EXTENSIONS_DIR / "disabled"
PROVIDERS_STATE_FILE = EXTENSIONS_DIR / "providers_state.json"
UI_CONFIG_FILE = EXTENSIONS_DIR / "ui.json"
PORT_FILTER_FILE = BASE_DIR / "ports.filter.json"


# ── Helpers ───────────────────────────────────────────────────────────────


def _read_json(path: Path, default: dict | list | None = None):
    """Read a JSON file, returning the default on any error."""
    if default is None:
        default = {}
    if not path.is_file():
        return default
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        return data if isinstance(data, (dict, list)) else default
    except Exception:
        return default


def _route_url(route: object) -> str:
    if not isinstance(route, dict):
        return ""
    url = route.get("url")
    return url if isinstance(url, str) else ""


def _cloudflare_assignment(port: str, subdomain: str) -> str:
    value = subdomain.strip().rstrip(".").lower()
    domain = os.environ.get("CITADEL_CLOUDFLARE_DOMAIN", "").strip().rstrip(".").lower()
    if "." in value or not domain:
        return value or port
    return f"{value or port}.{domain}"


def _cloudflare_assignments(port: str, rule: dict) -> list[str]:
    aliases = rule.get("subdomains") or [port]
    return [_cloudflare_assignment(port, str(alias)) for alias in aliases]


def _service_port(tile: dict) -> int:
    try:
        return int(tile.get("port", 0))
    except (TypeError, ValueError):
        return 0


def _is_citadel_service(tile: dict) -> bool:
    if tile.get("origin") == "host":
        return False
    configured = os.environ.get("CITADEL_WEBUI_PORT", "").strip()
    port = _service_port(tile)
    if configured.isdigit():
        return port == int(configured)
    name = str(tile.get("name") or tile.get("title") or "").strip().casefold()
    return name == "citadel"


def _cloudflare_default_emails() -> list[str]:
    policy = read_policy(PORT_FILTER_FILE)
    defaults = policy.get("cloudflare_defaults", {})
    values = defaults.get("emails", []) if isinstance(defaults, dict) else []
    emails = normalize_emails(values)
    if emails:
        return emails
    return normalize_emails(os.environ.get("CLOUDFLARE_EMAIL", "").split(","))


# ── Server Config ─────────────────────────────────────────────────────────


def load_server_config() -> tuple[str, int]:
    """Read host/port from the already loaded environment."""
    host = os.environ.get("FASTAPI_HOST") or "0.0.0.0"
    port = int(os.environ.get("CITADEL_WEBUI_PORT", "800") or "800")
    if not (1 <= port <= 65535):
        raise ValueError("CITADEL_WEBUI_PORT must be 1-65535.")

    return host, port


# ── Provider Discovery ────────────────────────────────────────────────────


def _load_providers() -> dict:
    """
    Scan extensions/enabled for provider directories.
    Returns dict with keys: provider_options, provider_urls_by_port,
    provider_header_meta, provider_order, alerts.
    """
    providers_state = _read_json(PROVIDERS_STATE_FILE, {
        "considered_providers": [],
        "available_providers": [],
        "errors": [],
    })

    alerts: list[str] = []
    provider_options: dict[str, str] = {}
    provider_urls_by_port: dict[str, dict[str, str]] = {}
    provider_header_meta: list[dict[str, str]] = []

    # Collect dispatch errors
    for err in providers_state.get("errors") or []:
        if isinstance(err, str) and err:
            alerts.append(f"[dispatch] {err}")

    # Find enabled provider directories
    enabled_dirs: list[Path] = []
    if ENABLED_EXT_DIR.is_dir():
        enabled_dirs = sorted(
            [d for d in ENABLED_EXT_DIR.iterdir() if d.is_dir()],
            key=lambda p: p.name,
        )

    if not enabled_dirs:
        alerts.append(
            "Keine Extension in extensions/enabled gefunden. "
            "Bitte mindestens localhost/subnet/tailscale aktivieren."
        )

    considered = [str(x) for x in providers_state.get("considered_providers") or []]
    available = [str(x) for x in providers_state.get("available_providers") or []]

    for provider_dir in enabled_dirs:
        pid = provider_dir.name

        ext = _read_json(provider_dir / "extension.json", {})
        routes = _read_json(provider_dir / "routes.json", {})

        label = str(routes.get("label") or ext.get("label") or pid.capitalize())

        is_considered = bool(routes.get("considered", pid in considered))
        is_available = bool(routes.get("available", pid in available))

        # Header meta (IP / domain display)
        header_value = ""
        if pid == "localhost":
            header_value = "127.0.0.1"
        elif pid == "subnet":
            header_value = str(routes.get("subnet_ip") or "")
        elif pid == "tailscale":
            header_value = str(routes.get("domain") or "")
        elif pid == "cloudflare":
            header_value = str(routes.get("domain") or "")

        if is_considered and header_value:
            provider_header_meta.append({"label": label, "value": header_value})

        if is_considered:
            provider_options[pid] = label

        # Service URLs by port
        svc_routes = routes.get("services") or {}
        if isinstance(svc_routes, dict):
            for port_str, route in svc_routes.items():
                url = _route_url(route)
                if url:
                    provider_urls_by_port.setdefault(pid, {})[str(port_str)] = url

        # Provider-level errors
        for err in routes.get("errors") or []:
            if err:
                alerts.append(f"[{pid}] {err}")

        if is_considered and not is_available:
            alerts.append(
                f"[{pid}] beim letzten Scan beruecksichtigt, "
                "aber ohne aktive Routen."
            )

    if not provider_options:
        alerts.append(
            "Keine Provider aus extensions/enabled wurden im letzten Scan beruecksichtigt."
        )

    return {
        "provider_options": provider_options,
        "provider_urls_by_port": provider_urls_by_port,
        "provider_header_meta": provider_header_meta,
        "provider_order": list(provider_options.keys()),
        "alerts": alerts,
    }


# ── Dashboard Payload ─────────────────────────────────────────────────────


def build_dashboard() -> dict:
    """
    Build the full dashboard payload for rendering.
    Returns everything the template needs in one dict.
    """
    # Services
    services_payload = _read_json(SERVICES_FILE, {
        "http_services": [],
        "other_ports": [],
    })
    host_payload = _read_json(HOST_SERVICES_FILE, {})
    http_tiles = [
        dict(item)
        for item in services_payload.get("http_services") or []
        if isinstance(item, dict)
    ]
    host_http_tiles = [
        dict(item)
        for item in (
            host_payload.get("host_http_services")
            or services_payload.get("host_http_services")
            or []
        )
        if isinstance(item, dict)
    ]
    http_tiles.extend(
        item for item in host_http_tiles if int(item.get("route_port") or 0) > 0
    )
    other_ports = services_payload.get("other_ports") or []
    host_other_ports = (
        host_payload.get("host_other_ports")
        or services_payload.get("host_other_ports")
        or []
    )
    host_listeners = host_http_tiles + [
        dict(item) for item in host_other_ports if isinstance(item, dict)
    ]
    cloudflare = cloudflare_rules(PORT_FILTER_FILE)

    # UI config
    ui_cfg = _read_json(UI_CONFIG_FILE, {
        "default_provider": "localhost",
        "default_refresh_seconds": 0,
    })

    # Providers
    providers = _load_providers()
    provider_order = providers["provider_order"]

    # Default mode
    configured_default = str(ui_cfg.get("default_provider") or "localhost")
    default_mode = configured_default
    if default_mode not in providers["provider_options"]:
        default_mode = provider_order[0] if provider_order else "localhost"

    default_refresh = int(ui_cfg.get("default_refresh_seconds") or 0)

    # Last scan timestamp
    last_scan = None
    if LAST_SCAN_FILE.is_file():
        last_scan = LAST_SCAN_FILE.read_text().strip() or None

    # Build tile URL maps for template
    for tile in http_tiles:
        port = str(int(tile.get("port", 0)))
        route_port = str(int(tile.get("route_port") or port))
        tile["route_port"] = int(route_port)
        tile["origin_port"] = int(tile.get("origin_port") or port)
        tile["origin"] = str(tile.get("origin") or "localhost")
        name = str(tile.get("name") or tile.get("title") or f"Port {port}")
        tile["featured"] = _is_citadel_service(tile)
        tile["display_name"] = f"⭐ {name} ⭐" if tile["featured"] else name
        tile["cloudflare_rule"] = cloudflare.get(
            route_port,
            {"subdomains": [route_port], "whitelist": False, "emails": []},
        )
        tile_urls: dict[str, str] = {}
        for pid in provider_order:
            url = (
                providers["provider_urls_by_port"]
                .get(pid, {})
                .get(route_port, "")
            )
            if not url:
                url = (tile.get("urls") or {}).get(pid, "")
            tile_urls[pid] = url
        tile["provider_urls"] = tile_urls

    http_tiles.sort(key=lambda tile: (not tile["featured"], _service_port(tile)))

    return {
        "http_tiles": http_tiles,
        "other_ports": other_ports,
        "host_listeners": sorted(
            host_listeners,
            key=lambda item: int(item.get("port") or 0),
        ),
        "deduplicated_ports": (
            host_payload.get("deduplicated_ports")
            or services_payload.get("deduplicated_ports")
            or []
        ),
        "alerts": providers["alerts"],
        "provider_options": providers["provider_options"],
        "provider_header_meta": providers["provider_header_meta"],
        "provider_order": provider_order,
        "default_mode": default_mode,
        "default_refresh": default_refresh,
        "last_scan": last_scan,
        "cloudflare_default_emails": _cloudflare_default_emails(),
    }


def save_cloudflare_rule(port: int, payload: dict) -> dict:
    if not (1 <= port <= 65535):
        raise ValueError("Port must be between 1 and 65535.")

    services = _read_json(SERVICES_FILE, {"http_services": []})
    host_services = _read_json(HOST_SERVICES_FILE, {})
    known_services = list(services.get("http_services", []))
    known_services.extend(
        host_services.get("host_http_services")
        or services.get("host_http_services", [])
    )
    known_ports = {
        int(item.get("route_port") or item.get("port", 0))
        for item in known_services
        if (
            isinstance(item, dict)
            and str(item.get("port", "")).isdigit()
            and (item.get("origin") != "host" or item.get("route_port") is not None)
        )
    }
    if port not in known_ports:
        raise ValueError(f"Port {port} is not a discovered HTTP service.")

    rule = normalize_rule(payload, port)
    rules = cloudflare_rules(PORT_FILTER_FILE)
    for assignment in _cloudflare_assignments(str(port), rule):
        for other_port, other_rule in rules.items():
            if other_port == str(port):
                continue
            if assignment in _cloudflare_assignments(other_port, other_rule):
                raise ValueError(f"Subdomain or hostname is already assigned to port {other_port}.")

    rules[str(port)] = rule
    write_cloudflare_rules(PORT_FILTER_FILE, rules)
    return rule


def save_all_cloudflare_rules(payload: dict) -> dict[str, dict]:
    if not isinstance(payload, dict):
        raise ValueError("Rules must be a JSON object keyed by port.")

    services = _read_json(SERVICES_FILE, {"http_services": []})
    host_services = _read_json(HOST_SERVICES_FILE, {})
    known_services = list(services.get("http_services", []))
    known_services.extend(
        host_services.get("host_http_services")
        or services.get("host_http_services", [])
    )
    known_ports = {
        str(int(item.get("route_port") or item.get("port", 0)))
        for item in known_services
        if (
            isinstance(item, dict)
            and str(item.get("port", "")).isdigit()
            and (item.get("origin") != "host" or item.get("route_port") is not None)
        )
    }

    existing = cloudflare_rules(PORT_FILTER_FILE)
    incoming: dict[str, dict] = {}
    for raw_port, raw_rule in payload.items():
        port = str(int(str(raw_port))) if str(raw_port).isdigit() else ""
        if port not in known_ports:
            raise ValueError(f"Port {raw_port} is not a discovered HTTP service.")
        incoming[port] = normalize_rule(raw_rule, int(port))

    rules: dict[str, dict] = {
        port: rule
        for port, rule in existing.items()
        if port not in incoming
    }
    assigned: dict[str, str] = {}

    for port, rule in rules.items():
        for assignment in _cloudflare_assignments(port, rule):
            assigned[assignment] = port

    for port, rule in incoming.items():
        for assignment in _cloudflare_assignments(port, rule):
            if assignment in assigned:
                raise ValueError(
                    f"Subdomain or hostname is assigned to ports {assigned[assignment]} and {port}."
                )
            assigned[assignment] = port
        rules[port] = rule

    write_cloudflare_rules(PORT_FILTER_FILE, rules)
    return rules
