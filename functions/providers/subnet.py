#!/usr/bin/env python3
from __future__ import annotations

import argparse
import importlib
import sys
from pathlib import Path
from typing import Any

from common import ROUTE_SCHEMA_VERSION, now_iso, read_json, routable_services, route_record, write_json


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--provider-dir", required=True)
    parser.add_argument("--services-file", required=True)
    parser.add_argument("--routes-out", required=True)
    parser.add_argument("--cache-dir")
    parser.add_argument("--config-ini")
    parser.add_argument("--tailscale-file")
    args = parser.parse_args()

    ext_cfg = read_json(f"{args.provider_dir}/extension.json", {})
    services_payload = read_json(args.services_file, {})
    label = str(ext_cfg.get("label") or "Subnet")
    root = Path(args.provider_dir).resolve().parents[2]
    if str(root) not in sys.path:
        sys.path.insert(0, str(root))
    header = importlib.import_module("python_header")
    subnet_ip = header.get("CITADEL_SUBNET_IP", "").strip()
    if subnet_ip.casefold() == "blank":
        subnet_ip = ""

    routes: dict[str, dict[str, Any]] = {}

    http_services = routable_services(services_payload)

    for svc in http_services if subnet_ip else []:
        port = int(svc.get("port", 0))
        if port <= 0:
            continue

        scheme = (svc.get("scheme") or "http").strip().lower()
        if scheme not in {"http", "https"}:
            scheme = "http"

        url = f"{scheme}://{subnet_ip}:{port}"

        urls = svc.get("urls")
        if not isinstance(urls, dict):
            urls = {}
            svc["urls"] = urls
        urls["subnet"] = url
        svc["network_ip"] = subnet_ip

        routes[str(port)] = route_record("direct", url)

    write_json(args.services_file, services_payload)

    payload = {
        "provider_id": "subnet",
        "label": label,
        "considered": bool(subnet_ip),
        "available": bool(routes),
        "generated_at": now_iso(),
        "default_candidate": bool(subnet_ip),
        "route_schema": ROUTE_SCHEMA_VERSION,
        "subnet_ip": subnet_ip,
        "services": routes,
        "errors": [],
    }
    write_json(args.routes_out, payload)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
