#!/usr/bin/env python3
"""API extension adapter: presentation and the shared Cloudflare entry point."""
from __future__ import annotations

import concurrent.futures
import http.client
import socket
import ssl
from urllib.parse import urlsplit
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from api_discovery import discover_service
from cloudflare_api_policy import MODE_LABELS, owner_id, route_id
from cloudflare_api_state import table_from_settings, worker_name
from common import now_iso, parse_bool, read_json


def retained_mcp_routes(api, root, account, zone, tunnel, settings):
    """Read deployed routes, not historical discovery, before any MCP probes."""
    if not settings.keep_mcp_routes or not settings.modes:
        return [], {}
    owner = owner_id(account, zone, tunnel)
    remote = api.worker_settings(account, worker_name(owner))
    if remote is None:
        return [], {}
    if f"citadel-owner:{owner}" not in remote.get("tags", []):
        raise ValueError("Worker name is occupied by a foreign resource")
    table = table_from_settings(remote)
    config = api.tunnel_configuration(account, tunnel)
    origins = {row.get("hostname"): row.get("service", "") for row in config.get("ingress", [])}
    previous = read_json(root / "cache/CLOUDFLARE-API-routes.json", {})
    endpoints, statuses = {}, {}
    for hostname, host in table["hosts"].items():
        if host.get("mode") not in settings.modes or host.get("port") in settings.excluded:
            continue
        port = host["port"]
        for route in host.get("routes", []):
            if route.get("protocol") != "mcp":
                continue
            origin = origins.get(urlsplit(host.get("origin", "")).hostname)
            parsed = urlsplit(origin or "")
            if parsed.scheme not in {"http", "https"} or parsed.hostname != "127.0.0.1" or parsed.port != port:
                raise ValueError("Published MCP route has no matching local Tunnel origin")
            identity = route_id(port, "mcp", route["path"])
            if route.get("id") != identity:
                raise ValueError("Invalid published MCP route identity")
            endpoints[identity] = {"id": identity, "port": port, "scheme": parsed.scheme,
                "protocol": "mcp", "path": route["path"], "status": "ready", "detected": True,
                "http_status": None, "retained": True,
                "evidence": "Published MCP route retained; probe skipped", "operations": route["operations"]}
        old = previous.get("views", {}).get(host["mode"], {}).get("services", {}).get(str(port), {})
        statuses[hostname] = old.get("status", "not-checked") if previous.get("remote_verified") else "not-checked"
    return list(endpoints.values()), statuses


def discover(services, settings, credentials, admin_port, *, rules=(), retained=()):
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
        results = list(pool.map(lambda row: discover_service(row, credentials, admin_ports=[admin_port], rules=rules,
            skip_mcp_paths=[endpoint["path"] for endpoint in retained if endpoint["port"] == row["port"]]), rows))
    endpoints = {endpoint["id"]: endpoint for group in results for endpoint in group}
    endpoints.update({endpoint["id"]: endpoint for endpoint in retained})
    return sorted(endpoints.values(), key=lambda row: row["id"])


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
    except socket.gaierror:
        return "pending-dns"
    except ssl.SSLError:
        return "pending-tls"
    except (OSError, ValueError, http.client.HTTPException):
        return "unreachable"
    finally:
        connection.close()


def output(table, *, considered, authenticated, modes=(), inventory=(), errors=(), warnings=(), diagnostics=(), verify=route_readiness, retained_statuses=None):
    hosts = table.get("hosts", {})
    retained_ids = {row["id"] for row in inventory if row.get("retained")}
    readiness = {hostname: status for hostname, status in (retained_statuses or {}).items()
                 if hostname in hosts and hosts[hostname].get("routes") and all(
                     route.get("protocol") == "mcp" and route.get("id") in retained_ids
                     for route in hosts[hostname]["routes"])}
    checked_hosts = [hostname for hostname in hosts if hostname not in readiness]
    with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:
        readiness.update(zip(checked_hosts, pool.map(verify, checked_hosts)))
    # A configured mode remains visible when discovery is empty or publication
    # fails. Only verified apply results supply URLs; an empty menu is not a
    # successful connection and never advertises an unprovisioned endpoint.
    views = {mode: {"label": MODE_LABELS[mode], "considered": True, "services": {}}
             for mode in modes if considered and mode in MODE_LABELS}
    services = {}
    for hostname, host in hosts.items():
        mode = host["mode"]
        view = views.setdefault(mode, {"label": MODE_LABELS[mode], "considered": True, "services": {}})
        port = str(host["port"])
        endpoints = [{"id": route["id"], "protocol": route["protocol"], "path": route["path"],
                      "retained": route["id"] in retained_ids,
                      "url": f"https://{hostname}{route['path']}",
                      "access_configured": bool(authenticated),
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
    discovered = [{key: row.get(key) for key in ("id", "port", "protocol", "path", "status")}
                  for row in inventory if row.get("detected") is True or row.get("status") == "ready"
                  or (row.get("protocol") == "rest" and row.get("operations"))]
    return {"provider_id": "CLOUDFLARE-API", "label": "Cloudflare API", "generated_at": now_iso(),
            "route_schema": 2, "considered": considered, "authenticated": authenticated,
            "available": any(view["available"] for view in views.values()), "remote_verified": authenticated,
            "views": views, "services": services, "discovered": discovered,
            "errors": list(errors), "warnings": list(warnings),
            "diagnostics": list(diagnostics)}


def main():
    # All changes go through the same coordinator as the ordinary provider.
    from cloudflare import main as reconcile
    return reconcile()


if __name__ == "__main__":
    raise SystemExit(main())
