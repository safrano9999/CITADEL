#!/usr/bin/env python3
from __future__ import annotations

import argparse
from common import ensure_provider_ini, ini_get, now_iso, read_json, write_json


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--provider-dir", required=True)
    parser.add_argument("--routes-out", required=True)
    parser.add_argument("--services-file")
    parser.add_argument("--cache-dir")
    parser.add_argument("--config-ini")
    parser.add_argument("--tailscale-file")
    args = parser.parse_args()

    ext_cfg = read_json(f"{args.provider_dir}/extension.json", {})
    parser_ini, ini_path, created_ini = ensure_provider_ini(
        args.provider_dir,
        {
            "label": str(ext_cfg.get("label") or "Cloudflare Tunnel Router"),
            "hostname": "",
            "path_template": "/p/{port}",
        },
    )

    errors: list[str] = ["Dummy provider (disabled by default)"]
    if created_ini:
        errors.append(f"created {ini_path}; review config.ini")

    payload = {
        "provider_id": "cloudflare",
        "label": ini_get(parser_ini, "label", str(ext_cfg.get("label") or "Cloudflare Tunnel Router")),
        "considered": True,
        "available": False,
        "generated_at": now_iso(),
        "config_file": ini_path,
        "services": {},
        "hostname": ini_get(parser_ini, "hostname", ""),
        "path_template": ini_get(parser_ini, "path_template", "/p/{port}"),
        "errors": errors,
    }
    write_json(args.routes_out, payload)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
