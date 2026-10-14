#!/usr/bin/env python3
"""API extension adapter: presentation and the shared Cloudflare entry point."""
from __future__ import annotations

import concurrent.futures
import http.client
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from api_discovery import discover_service
from cloudflare_api_policy import MODE_LABELS
from common import now_iso, parse_bool


def discover(services, settings, credentials, admin_port):
    if not settings.modes:
        return []
    rows = services.get("http_services")
    if not isinstance(rows, list):
        raise ValueError("API discovery requires a complete HTTP listener scan")
    if any(not isinstance(row, dict) or type(row.get("port")) is not int for row in rows):
        raise ValueError("Invalid HTTP listener inventory")
    rows = [row for row in rows if row["port"] not in settings.excluded
            and (not parse_bool(services.get("https_only")) or row.get("scheme") == "https")]
    with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:
        results = list(pool.map(lambda row: discover_service(row, credentials, admin_ports=[admin_port]), rows))
    return sorted((endpoint for group in results for endpoint in group), key=lambda row: row["id"])


def route_readiness(hostname):
    """Check TLS and the anonymous machine challenge; never send credentials."""
    connection = http.client.HTTPSConnection(hostname, timeout=3)
    try:
        connection.request("GET", "/", headers={"Accept": "application/json", "User-Agent": "Citadel-Route-Check/1"})
        response = connection.getresponse()
        if response.status == 401:
            challenge = response.getheader("WWW-Authenticate", "")
            content_type = response.getheader("Content-Type", "")
            if challenge.startswith("Bearer ") and ("resource_metadata=" in challenge if hostname.startswith("oauth.") else content_type.startswith("application/json")):
                return "provisioned"
        return "pending-auth"
    except (OSError, ValueError, http.client.HTTPException):
        return "pending-tls"
    finally:
        connection.close()


def output(table, *, considered, authenticated, errors=(), warnings=(), diagnostics=(), verify=route_readiness):
    hosts = table.get("hosts", {})
    with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:
        readiness = dict(zip(hosts, pool.map(verify, hosts)))
    views, services = {}, {}
    for hostname, host in hosts.items():
        mode = host["mode"]
        view = views.setdefault(mode, {"label": MODE_LABELS[mode], "considered": True, "services": {}})
        port = str(host["port"])
        endpoints = [{"id": route["id"], "protocol": route["protocol"], "path": route["path"],
                      "url": f"https://{hostname}{route['path']}",
                      "status": ("provisioned" if readiness[hostname] is True else "pending-tls" if readiness[hostname] is False
                                 else readiness[hostname])}
                     for route in host["routes"]]
        if not endpoints:
            continue
        view["services"][port] = {"url": endpoints[0]["url"], "endpoints": endpoints,
                                  "status": endpoints[0]["status"]}
        services.setdefault(port, {"endpoints": []})["endpoints"].extend(endpoints)
    for view in views.values():
        view["available"] = any(route["status"] == "provisioned" for route in view["services"].values())
    return {"provider_id": "CLOUDFLARE-API", "label": "Cloudflare API", "generated_at": now_iso(),
            "route_schema": 2, "considered": considered, "authenticated": authenticated,
            "available": any(view["available"] for view in views.values()), "remote_verified": authenticated,
            "views": views, "services": services, "errors": list(errors), "warnings": list(warnings),
            "diagnostics": list(diagnostics)}


def main():
    # All changes go through the same coordinator as the ordinary provider.
    from cloudflare import main as reconcile
    return reconcile()


if __name__ == "__main__":
    raise SystemExit(main())
