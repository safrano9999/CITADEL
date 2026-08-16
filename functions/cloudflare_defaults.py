#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import os
import re
import importlib
import sys
from pathlib import Path
from typing import Any

from cloudflare_policy import normalize_rule
from providers.atomic_io import atomic_write_json

PROVIDERS_DIR = Path(__file__).resolve().parent / "providers"
sys.path.insert(0, str(PROVIDERS_DIR))
from common import routable_services

EMAIL_RE = re.compile(r"^[^\s@]+@[^\s@]+\.[^\s@]+$")




def cloudflare_ready(root: Path) -> tuple[bool, str]:
    if not (root / "extensions" / "enabled" / "cloudflare").is_dir():
        return False, "provider is disabled"

    sys.path.insert(0, str(root))
    os.chdir(root)
    get = importlib.import_module("python_header").get
    if str(get("CITADEL_CLOUDFLARE", "0")).strip().lower() not in {"1", "true", "yes", "on"}:
        return False, "CITADEL_CLOUDFLARE is not 1"

    token = get("CLOUDFLARE_API_TOKEN", "")
    if not token:
        return False, "CLOUDFLARE_API_TOKEN is missing"

    providers_dir = root / "functions" / "providers"
    sys.path.insert(0, str(providers_dir))
    try:
        api_module = importlib.import_module("cloudflare_api")
        api_module.CloudflareAPI(token).verify_token()
    except Exception as exc:
        return False, str(exc)
    return True, "API token verified"


def project_get(root: Path, key: str, default: str = "") -> str:
    sys.path.insert(0, str(root))
    os.chdir(root)
    get = importlib.import_module("python_header").get
    return get(key, default)


def read_json(path: Path, default: Any) -> Any:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return default
    return payload


def write_json(path: Path, payload: Any) -> None:
    atomic_write_json(path, payload)



def normalize_emails_csv(value: str) -> list[str]:
    emails: list[str] = []
    for item in value.split(","):
        email = item.strip().lower()
        if not email:
            continue
        if not EMAIL_RE.fullmatch(email):
            raise ValueError(f"Invalid email address: {email}")
        if email not in emails:
            emails.append(email)
    return emails


def http_ports(services_file: Path) -> list[str]:
    services = read_json(services_file, {"http_services": []})
    rows = routable_services(services)
    rows.extend(routable_services(services, "host_http_services"))
    ports: list[str] = []
    for row in rows:
        if not isinstance(row, dict):
            continue
        try:
            if row.get("origin") == "host":
                port = int(str(row.get("route_port") or ""))
            else:
                port = int(str(row.get("port") or ""))
        except ValueError:
            continue
        if 1 <= port <= 65535 and str(port) not in ports:
            ports.append(str(port))
    return sorted(ports, key=int)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", required=True)
    parser.add_argument("--services-file", required=True)
    parser.add_argument("--policy-file", required=True)
    args = parser.parse_args()

    root = Path(args.root).resolve()
    services_file = Path(args.services_file).resolve()
    policy_file = Path(args.policy_file).resolve()

    ready, reason = cloudflare_ready(root)
    if not ready:
        print(f"cloudflare defaults: skipped ({reason})")
        return 0

    ports = http_ports(services_file)
    if not ports:
        print("cloudflare defaults: skipped (no HTTP services)")
        return 0

    policy = read_json(policy_file, {})
    if not isinstance(policy, dict):
        policy = {}
    policy.setdefault("whitelist", [])
    policy.setdefault("blacklist", [])

    defaults = policy.get("cloudflare_defaults")
    defaults = defaults if isinstance(defaults, dict) else {}
    configured = bool(defaults.get("configured", False))

    if not configured:
        raw_email = project_get(root, "CLOUDFLARE_EMAIL", "")
        if not raw_email:
            print("cloudflare defaults: skipped (CLOUDFLARE_EMAIL is missing)")
            return 0
        try:
            emails = normalize_emails_csv(raw_email)
        except ValueError as exc:
            print(f"cloudflare defaults: skipped ({exc})")
            return 0
        if not emails:
            print("cloudflare defaults: skipped (CLOUDFLARE_EMAIL is empty)")
            return 0
        defaults = {
            "configured": True,
            "whitelist": True,
            "emails": emails,
        }
        policy["cloudflare_defaults"] = defaults
        print("cloudflare defaults: saved from CLOUDFLARE_EMAIL")

    default_whitelist = bool(defaults.get("whitelist", False))
    default_emails = []
    for item in defaults.get("emails", []):
        email = str(item).strip().lower()
        if email and EMAIL_RE.fullmatch(email) and email not in default_emails:
            default_emails.append(email)
    if not default_emails:
        default_whitelist = False

    rules = policy.get("cloudflare")
    rules = rules if isinstance(rules, dict) else {}
    normalized = {
        str(int(port)): normalize_rule(rule, int(port))
        for port, rule in rules.items()
        if str(port).isdigit()
    }

    added = 0
    if default_whitelist:
        for port in ports:
            if port not in normalized:
                normalized[port] = {
                    "subdomains": [port],
                    "whitelist": True,
                    "emails": list(default_emails),
                }
                added += 1

    policy["cloudflare"] = {
        port: normalized[port]
        for port in sorted(normalized, key=int)
        if port in ports or normalized[port].get("subdomains") or normalized[port].get("whitelist")
    }
    write_json(policy_file, policy)

    mode = "email whitelist" if default_whitelist else "no default"
    print(f"cloudflare defaults: mode={mode} ports={len(ports)} new_rules={added}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
