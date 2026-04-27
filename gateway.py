"""
gateway.py — Unified entry point for all SAF services.

Discovers sibling repos via CONTAINER/module.toml, imports their
webui.py FastAPI apps, and mounts them under /{module_name}/.
Citadel's own webui.py serves as the root app (/).

Usage:
    python gateway.py                    # default :800
    GATEWAY_PORT=9000 python gateway.py  # custom port
"""

import importlib.util
import sys
import tomllib
from pathlib import Path

SAF_DIR = Path(__file__).resolve().parent.parent
CITADEL_DIR = Path(__file__).resolve().parent


def discover_services() -> list[dict]:
    """
    Scan sibling directories for CONTAINER/module.toml + webui.py.
    Returns list of dicts: {name, path, port, description, module_toml}.
    """
    services = []
    for candidate in sorted(SAF_DIR.iterdir()):
        if not candidate.is_dir() or candidate == CITADEL_DIR:
            continue

        toml_path = candidate / "CONTAINER" / "module.toml"
        webui_path = candidate / "webui.py"
        if not toml_path.exists() or not webui_path.exists():
            continue

        with open(toml_path, "rb") as f:
            cfg = tomllib.load(f)

        module = cfg.get("module", {})
        name = module.get("name", candidate.name.lower())

        # Extract first port
        ports = cfg.get("ports", [])
        port = ports[0].get("internal", ports[0].get("default", 0)) if ports else 0

        services.append({
            "name": name,
            "path": str(candidate),
            "webui": str(webui_path),
            "port": int(port) if port else 0,
            "description": module.get("description", ""),
        })

    return services


def load_fastapi_app(service: dict):
    """Import a webui.py module and return its FastAPI app."""
    webui_path = service["webui"]
    mod_name = f"saf_webui_{service['name']}"

    # Add the service's functions/ dir to sys.path for its internal imports
    svc_dir = Path(service["path"])
    functions_dir = svc_dir / "functions"
    for p in [str(svc_dir), str(functions_dir)]:
        if p not in sys.path:
            sys.path.insert(0, p)

    spec = importlib.util.spec_from_file_location(mod_name, webui_path)
    mod = importlib.util.module_from_spec(spec)
    sys.modules[mod_name] = mod
    spec.loader.exec_module(mod)

    app = getattr(mod, "app", None)
    if app is None:
        raise RuntimeError(f"{webui_path} has no 'app' attribute")

    return app


def build_gateway():
    """Build the combined FastAPI application."""
    from fastapi import FastAPI

    # Citadel's own app at /
    sys.path.insert(0, str(CITADEL_DIR / "functions"))
    sys.path.insert(0, str(CITADEL_DIR))
    import webui as citadel_webui
    root_app = citadel_webui.app

    # Create gateway app that wraps citadel
    gateway = FastAPI()

    # Discover and mount sibling services
    services = discover_services()

    for svc in services:
        try:
            sub_app = load_fastapi_app(svc)
            prefix = f"/{svc['name']}"
            gateway.mount(prefix, sub_app)
            print(f"[gateway] mounted {svc['name']} at {prefix}")
        except Exception as exc:
            print(f"[gateway] SKIP {svc['name']}: {exc}")

    # Mount citadel root last (catch-all)
    gateway.mount("/", root_app)

    return gateway, services


def main():
    import os
    import uvicorn

    gateway, services = build_gateway()

    host = os.environ.get("GATEWAY_HOST", "0.0.0.0")
    port = int(os.environ.get("GATEWAY_PORT", "800"))

    print(f"\n[gateway] SAF Gateway on {host}:{port}")
    print(f"[gateway] Root: CITADEL (/)")
    for svc in services:
        print(f"[gateway]   /{svc['name']}  ({svc['description']})")
    print()

    uvicorn.run(gateway, host=host, port=port)


if __name__ == "__main__":
    main()
