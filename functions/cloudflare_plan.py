"""Pure Cloudflare desired-state planning; never changes remote resources."""
from __future__ import annotations

from copy import deepcopy

from cloudflare_policy import normalize_emails, normalize_rule, resolve_hostname
from cloudflare_api_policy import APISettings, endpoint_path, hostnames, route_id


def browser_routes(services: dict, policy: dict, domain: str, zone: str,
                   default_emails: list[str], *, add: bool = False) -> tuple[dict, list[str]]:
    scanned = services.get("http_services")
    if not isinstance(scanned, list):
        raise ValueError("services.json must contain an http_services list")
    if any(not isinstance(row, dict) or type(row.get("port")) is not int
           or not 1 <= row["port"] <= 65535 or row.get("scheme") not in {"http", "https"}
           for row in scanned):
        raise ValueError("Invalid scanned service; Cloudflare reconciliation aborted")
    emails = normalize_emails(default_emails)
    desired, warnings = {}, []
    for row in scanned:
        port = row["port"]
        if add and port not in services.get("added_ports", []):
            continue
        if str(services.get("https_only", "")).lower() in {"true", "1", "yes", "on"} and row["scheme"] != "https":
            continue
        rule = policy.get(str(port))
        if rule is None:
            if not emails:
                warnings.append(f"Port {port}: no explicit Cloudflare rule or default emails; not published")
                continue
            rule = {"whitelist": True, "emails": emails}
        rule = normalize_rule(rule, port)
        for alias in rule["subdomains"]:
            hostname = resolve_hostname(port, alias, domain, zone)
            if hostname in desired:
                raise ValueError(f"Duplicate Cloudflare hostname: {hostname}")
            desired[hostname] = {
                "port": port, "scheme": row["scheme"], "origin_host": "127.0.0.1",
                "origin_port": port, "whitelist": rule["whitelist"], "emails": list(rule["emails"]),
            }
    return desired, warnings


def combine_routes(*groups: dict) -> dict:
    result = {}
    for routes in groups:
        for hostname, route in routes.items():
            if hostname in result:
                raise ValueError(f"Cloudflare route ownership conflict: {hostname}")
            result[hostname] = deepcopy(route)
    return result


def ingress_entry(hostname: str, route: dict) -> dict:
    result = {"hostname": hostname,
              "service": f"{route['scheme']}://{route['origin_host']}:{route['origin_port']}"}
    if route["scheme"] == "https":
        result["originRequest"] = {"noTLSVerify": True}
    if route.get("origin_access"):
        result.setdefault("originRequest", {})["access"] = deepcopy(route["origin_access"])
    return result


def merge_ingress(config: dict, desired: dict, *, add: bool = False) -> dict:
    entries = [ingress_entry(hostname, route) for hostname, route in desired.items()]
    if add:
        previous = config.get("ingress", [])
        if previous and ("hostname" in previous[-1] or any("hostname" not in e for e in previous[:-1])):
            raise ValueError("Invalid catch-all ordering; Add aborted")
        names = {e.get("hostname") for e in previous}
        entries = previous[:-1] + [e for e in entries if e["hostname"] not in names]
        entries += previous[-1:] or [{"service": "http_status:404"}]
    else:
        entries.append({"service": "http_status:404"})
    return {**deepcopy(config), "ingress": entries}


def api_routes(inventory: list[dict], settings: APISettings, domain: str) -> dict:
    """Plan public Worker hosts and their separately protected Tunnel origins.

    Origin service-token IDs and OAuth audiences are filled from verified remote
    Access objects during apply. No hostname is published from this pure plan.
    """
    if not isinstance(inventory, list):
        raise ValueError("API inventory must be a list")
    hosts, origins, diagnostics = {}, {}, []
    for row in inventory:
        if not isinstance(row, dict):
            raise ValueError("Invalid API inventory entry")
        port, protocol, path = row.get("port"), row.get("protocol"), row.get("path")
        identity = route_id(port, protocol, path)
        if row.get("id") != identity or row.get("scheme") not in {"http", "https"}:
            raise ValueError("Invalid API route identity or origin scheme")
        if not settings.modes or port in settings.excluded:
            continue
        if row.get("status") != "ready":
            diagnostics.append({"id": identity, "port": port, "path": path,
                                "status": row.get("status", "unknown")})
            continue
        operations = row.get("operations")
        if not isinstance(operations, list) or not operations or len(operations) > 2000:
            raise ValueError("Invalid discovered operation list")
        for operation in operations:
            if not isinstance(operation, dict) or operation.get("method") not in {
                "GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS",
            }:
                raise ValueError("Invalid discovered operation")
            endpoint_path(operation.get("path"), template=protocol == "rest")
            if protocol != "rest" and operation["path"] != path:
                raise ValueError("Endpoint operation escapes its route")
        credential_ref = row.get("credential_ref")
        if credential_ref not in {None, identity}:
            raise ValueError("Invalid backend credential reference")
        names = hostnames(port, domain)
        origin = {"port": port, "scheme": row["scheme"], "origin_host": "127.0.0.1", "origin_port": port,
                  "access_kind": "service", "whitelist": True, "emails": []}
        if names["origin"] in origins and origins[names["origin"]] != origin:
            raise ValueError("Conflicting API origin listeners")
        origins[names["origin"]] = origin
        endpoint = {"id": identity, "protocol": protocol, "path": path, "credential_ref": credential_ref,
                    "operations": [{"path": op["path"], "method": op["method"]} for op in operations]}
        for mode in settings.modes:
            host = hosts.setdefault(names[mode], {"mode": mode, "port": port,
                "origin": f"https://{names['origin']}", "routes": [],
                **({"emails": list(settings.emails)} if mode == "api-oauth" else {})})
            if any(route["id"] == identity for route in host["routes"]):
                raise ValueError("Duplicate API inventory route")
            host["routes"].append(deepcopy(endpoint))
    if len(hosts) > 200 or any(len(host["routes"]) > 100 for host in hosts.values()):
        raise ValueError("API Worker host/route limit exceeded")
    for host in hosts.values():
        host["routes"].sort(key=lambda route: route["id"])
    return {"hosts": dict(sorted(hosts.items())), "origins": dict(sorted(origins.items())), "diagnostics": diagnostics}
