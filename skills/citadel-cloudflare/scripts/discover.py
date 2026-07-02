#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path


CITADEL_ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(CITADEL_ROOT / "functions" / "providers"))

from cloudflare_api import CloudflareAPI, CloudflareAPIError  # noqa: E402
from cloudflare import ensure_one_time_pin  # noqa: E402


def select_zone(zones: list[dict], domain: str) -> dict:
    domain = domain.rstrip(".").lower()
    matches = [
        zone
        for zone in zones
        if domain == str(zone.get("name") or "").lower()
        or domain.endswith(f".{str(zone.get('name') or '').lower()}")
    ]
    matches.sort(key=lambda zone: len(str(zone.get("name") or "")), reverse=True)
    if not matches:
        raise ValueError(f"No accessible Cloudflare zone contains {domain}")
    return matches[0]


def select_tunnel(tunnels: list[dict], requested: str) -> dict:
    if requested:
        matches = [
            tunnel
            for tunnel in tunnels
            if requested in {str(tunnel.get("id") or ""), str(tunnel.get("name") or "")}
        ]
        if len(matches) != 1:
            raise ValueError(f"Tunnel selection is not unique: {requested}")
        return matches[0]
    if len(tunnels) != 1:
        choices = ", ".join(
            f"{tunnel.get('name')} ({tunnel.get('id')})" for tunnel in tunnels
        )
        raise ValueError(f"Specify --tunnel; available tunnels: {choices or 'none'}")
    return tunnels[0]


def main() -> int:
    parser = argparse.ArgumentParser(description="Discover CITADEL Cloudflare settings")
    parser.add_argument("--domain", required=True, help="Base domain or subdomain used by CITADEL")
    parser.add_argument("--tunnel", default="", help="Tunnel name or id when more than one exists")
    parser.add_argument(
        "--include-tunnel-token",
        action="store_true",
        help="Include the connector token in output",
    )
    args = parser.parse_args()

    token = os.environ.get("CLOUDFLARE_API_TOKEN", "").strip()
    if not token:
        print("CLOUDFLARE_API_TOKEN is required", file=sys.stderr)
        return 2

    try:
        api = CloudflareAPI(token)
        api.verify_token()
        zone = select_zone(api.zones(), args.domain)
        account = zone.get("account") if isinstance(zone.get("account"), dict) else {}
        account_id = str(account.get("id") or "")
        if not account_id:
            raise ValueError("Selected zone has no account id")
        tunnel = select_tunnel(api.tunnels(account_id), args.tunnel)
        tunnel_id = str(tunnel.get("id") or "")
        providers = ensure_one_time_pin(api, account_id, args.domain)
        otp_enabled = any(
            str(provider.get("type") or "").lower() in {"onetimepin", "one_time_pin", "onetime_pin"}
            for provider in providers
            if isinstance(provider, dict)
        )
        result = {
            "CITADEL_CLOUDFLARE_DOMAIN": args.domain.rstrip(".").lower(),
            "CITADEL_CLOUDFLARE_ACCOUNT_ID": account_id,
            "CITADEL_CLOUDFLARE_ZONE_ID": str(zone.get("id") or ""),
            "CITADEL_CLOUDFLARE_TUNNEL_ID": tunnel_id,
            "CITADEL_CLOUDFLARE_ORIGIN_HOST": "127.0.0.1",
            "one_time_pin_enabled": otp_enabled,
            "tunnel_name": str(tunnel.get("name") or ""),
            "tunnel_connections": len(api.tunnel_connections(account_id, tunnel_id)),
        }
        if args.include_tunnel_token:
            result["TUNNEL_TOKEN"] = api.tunnel_token(account_id, tunnel_id)
        print(json.dumps(result, indent=2))
        return 0
    except (CloudflareAPIError, ValueError) as exc:
        print(str(exc), file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
