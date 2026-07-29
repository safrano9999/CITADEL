#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import os
import re
import sys
import tempfile
from pathlib import Path


CITADEL_ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(CITADEL_ROOT / "functions" / "providers"))

from cloudflare_api import CloudflareAPI, CloudflareAPIError  # noqa: E402
from cloudflare import ensure_one_time_pin  # noqa: E402


KEY_VALUE = re.compile(r"^([A-Za-z_][A-Za-z0-9_]*)=(.*)$")


def read_key_values(path: Path) -> dict[str, str]:
    values: dict[str, str] = {}
    if not path.is_file():
        return values
    for raw_line in path.read_text(encoding="utf-8").splitlines():
        match = KEY_VALUE.fullmatch(raw_line.strip())
        if match is None:
            continue
        value = match.group(2).strip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in {"'", '"'}:
            value = value[1:-1]
        values[match.group(1)] = value
    return values


def update_key_values(
    path: Path,
    updates: dict[str, str],
    *,
    secret: bool = False,
) -> None:
    for key, value in updates.items():
        if "\n" in value or "\r" in value:
            raise ValueError(f"Invalid newline in {key}")

    original = path.read_text(encoding="utf-8").splitlines() if path.exists() else []
    output: list[str] = []
    remaining = dict(updates)
    for line in original:
        match = KEY_VALUE.fullmatch(line.strip())
        if match is not None and match.group(1) in remaining:
            key = match.group(1)
            output.append(f"{key}={remaining.pop(key)}")
        else:
            output.append(line)
    if output and output[-1]:
        output.append("")
    output.extend(f"{key}={value}" for key, value in remaining.items())

    path.parent.mkdir(parents=True, exist_ok=True)
    previous = path.stat() if path.exists() else None
    descriptor, temporary_name = tempfile.mkstemp(
        dir=path.parent,
        prefix=f".{path.name}.",
    )
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            handle.write("\n".join(output))
            handle.write("\n")
        if previous is not None:
            current = temporary.stat()
            if (current.st_uid, current.st_gid) != (previous.st_uid, previous.st_gid):
                os.chown(temporary, previous.st_uid, previous.st_gid)
        temporary.chmod(0o600 if secret else ((previous.st_mode & 0o777) if previous else 0o600))
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


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
    parser.add_argument(
        "--token-file",
        type=Path,
        help="Read CLOUDFLARE_API_TOKEN from this key-value file when it is not exported",
    )
    parser.add_argument(
        "--write-config",
        type=Path,
        help="Write discovered non-secret CITADEL values to this key-value file",
    )
    parser.add_argument(
        "--write-env",
        type=Path,
        help="Write the connector token to this mode-0600 key-value file",
    )
    args = parser.parse_args()

    token = os.environ.get("CLOUDFLARE_API_TOKEN", "").strip()
    if not token and args.token_file is not None:
        token = read_key_values(args.token_file).get("CLOUDFLARE_API_TOKEN", "").strip()
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
            "one_time_pin_enabled": otp_enabled,
            "tunnel_name": str(tunnel.get("name") or ""),
            "tunnel_connections": len(api.tunnel_connections(account_id, tunnel_id)),
        }
        if args.include_tunnel_token or args.write_env is not None:
            result["TUNNEL_TOKEN"] = api.tunnel_token(account_id, tunnel_id)

        if args.write_config is not None:
            update_key_values(
                args.write_config,
                {
                    "CITADEL_CLOUDFLARE": "1",
                    "CITADEL_CLOUDFLARE_DOMAIN": result["CITADEL_CLOUDFLARE_DOMAIN"],
                    "CITADEL_CLOUDFLARE_ACCOUNT_ID": result[
                        "CITADEL_CLOUDFLARE_ACCOUNT_ID"
                    ],
                    "CITADEL_CLOUDFLARE_ZONE_ID": result["CITADEL_CLOUDFLARE_ZONE_ID"],
                    "CITADEL_CLOUDFLARE_TUNNEL_ID": result[
                        "CITADEL_CLOUDFLARE_TUNNEL_ID"
                    ],
                },
            )
        if args.write_env is not None:
            update_key_values(
                args.write_env,
                {"TUNNEL_TOKEN": result["TUNNEL_TOKEN"]},
                secret=True,
            )

        public_result = dict(result)
        if "TUNNEL_TOKEN" in public_result and args.write_env is not None:
            public_result["TUNNEL_TOKEN"] = "<written>"
        print(json.dumps(public_result, indent=2))
        return 0
    except (CloudflareAPIError, ValueError) as exc:
        print(str(exc), file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
