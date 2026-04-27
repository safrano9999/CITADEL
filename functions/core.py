"""
core.py — CITADEL dashboard business logic.
No Flask/HTTP dependencies. Returns plain dicts/lists.
"""

import json
import os
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent

SERVICES_FILE = BASE_DIR / "services.json"
TAILSCALE_FILE = BASE_DIR / "tailscale.json"
LAST_SCAN_FILE = BASE_DIR / "last_scan.txt"
EXTENSIONS_DIR = BASE_DIR / "extensions"
ENABLED_EXT_DIR = EXTENSIONS_DIR / "enabled"
DISABLED_EXT_DIR = EXTENSIONS_DIR / "disabled"
PROVIDERS_STATE_FILE = EXTENSIONS_DIR / "providers_state.json"
UI_CONFIG_FILE = EXTENSIONS_DIR / "ui.json"
SERVER_CONFIG_FILE = BASE_DIR / "citadel.server.conf"


# ── Helpers ───────────────────────────────────────────────────────────────


def _read_json(path: Path, fallback: dict | list | None = None):
    """Read a JSON file, returning fallback on any error."""
    if fallback is None:
        fallback = {}
    if not path.is_file():
        return fallback
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        return data if isinstance(data, (dict, list)) else fallback
    except Exception:
        return fallback


# ── Server Config ─────────────────────────────────────────────────────────


def load_server_config() -> tuple[str, int]:
    """Read host/port from .conf file, with env overrides."""
    host = "0.0.0.0"
    port = 800

    if SERVER_CONFIG_FILE.exists():
        for raw_line in SERVER_CONFIG_FILE.read_text().splitlines():
            line = raw_line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, value = [part.strip() for part in line.split("=", 1)]
            if key.lower() == "host" and value:
                host = value
            elif key.lower() == "port" and value:
                parsed = int(value)
                if not (1 <= parsed <= 65535):
                    raise ValueError(
                        f"Port in {SERVER_CONFIG_FILE.name} must be 1-65535."
                    )
                port = parsed

    host = os.environ.get("HOST") or os.environ.get("CITADEL_HOST") or host
    env_port = os.environ.get("CITADEL_PORT")
    if env_port:
        port = int(env_port)

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

        if is_considered and header_value:
            provider_header_meta.append({"label": label, "value": header_value})

        if is_considered:
            provider_options[pid] = label

        # Service URLs by port
        svc_routes = routes.get("services") or {}
        if isinstance(svc_routes, dict):
            for port_str, url in svc_routes.items():
                if isinstance(url, str) and url:
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
    http_tiles = services_payload.get("http_services") or []
    other_ports = services_payload.get("other_ports") or []

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
        tile_urls: dict[str, str] = {}
        for pid in provider_order:
            url = (
                providers["provider_urls_by_port"]
                .get(pid, {})
                .get(port, "")
            )
            if not url:
                url = (tile.get("urls") or {}).get(pid, "")
            tile_urls[pid] = url
        tile["provider_urls"] = tile_urls

    return {
        "http_tiles": http_tiles,
        "other_ports": other_ports,
        "alerts": providers["alerts"],
        "provider_options": providers["provider_options"],
        "provider_header_meta": providers["provider_header_meta"],
        "provider_order": provider_order,
        "default_mode": default_mode,
        "default_refresh": default_refresh,
        "last_scan": last_scan,
    }
