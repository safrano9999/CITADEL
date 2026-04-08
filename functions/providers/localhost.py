#!/usr/bin/env python3
from __future__ import annotations

import argparse
from common import now_iso, read_json, write_json


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

    label = str(ext_cfg.get("label") or "Localhost")

    routes: dict[str, str] = {}
    http_services = services_payload.get("http_services", []) if isinstance(services_payload, dict) else []

    for svc in http_services:
        port = int(svc.get("port", 0))
        if port <= 0:
            continue

        scheme = (svc.get("scheme") or "http").strip().lower()
        if scheme not in {"http", "https"}:
            scheme = "http"

        urls = svc.get("urls")
        if not isinstance(urls, dict):
            urls = {}
            svc["urls"] = urls

        url = urls.get("localhost") or f"{scheme}://127.0.0.1:{port}"
        urls["localhost"] = url
        routes[str(port)] = url

    write_json(args.services_file, services_payload)

    payload = {
        "provider_id": "localhost",
        "label": label,
        "considered": True,
        "available": bool(routes),
        "generated_at": now_iso(),
        "default_candidate": True,
        "services": routes,
        "errors": [],
    }
    write_json(args.routes_out, payload)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
