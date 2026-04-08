#!/usr/bin/env python3
from __future__ import annotations

import argparse
from common import ensure_provider_ini, ini_get, now_iso, read_json, write_json


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

    parser_ini, ini_path, created_ini = ensure_provider_ini(
        args.provider_dir,
        {
            "label": str(ext_cfg.get("label") or "Subnet"),
            "subnet_ip": "",
        },
    )

    label = ini_get(parser_ini, "label", str(ext_cfg.get("label") or "Subnet"))
    subnet_ip = ini_get(parser_ini, "subnet_ip", "")

    routes: dict[str, str] = {}
    errors: list[str] = []

    if created_ini:
        errors.append(f"created {ini_path}; please fill config.ini")

    http_services = services_payload.get("http_services", []) if isinstance(services_payload, dict) else []

    if not subnet_ip:
        errors.append(f"Missing subnet_ip in {ini_path} (set subnet_ip = 192.168.x.x)")

    for svc in http_services:
        port = int(svc.get("port", 0))
        if port <= 0:
            continue

        scheme = (svc.get("scheme") or "http").strip().lower()
        if scheme not in {"http", "https"}:
            scheme = "http"

        ip = subnet_ip or str(svc.get("network_ip") or "").strip()
        if not ip:
            continue

        url = f"{scheme}://{ip}:{port}"

        urls = svc.get("urls")
        if not isinstance(urls, dict):
            urls = {}
            svc["urls"] = urls
        urls["subnet"] = url
        svc["network_ip"] = ip

        routes[str(port)] = url

    write_json(args.services_file, services_payload)

    payload = {
        "provider_id": "subnet",
        "label": label,
        "considered": True,
        "available": bool(routes),
        "generated_at": now_iso(),
        "default_candidate": True,
        "config_file": ini_path,
        "subnet_ip": subnet_ip,
        "services": routes,
        "errors": errors,
    }
    write_json(args.routes_out, payload)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
