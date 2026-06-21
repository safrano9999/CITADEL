from __future__ import annotations

import json
import os
import re
import tempfile
from pathlib import Path
from typing import Any


DNS_LABEL_RE = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")
EMAIL_RE = re.compile(r"^[^\s@]+@[^\s@]+\.[^\s@]+$")


def normalize_hostname(value: str) -> str:
    hostname = value.strip().rstrip(".").lower()
    if not hostname or len(hostname) > 253:
        raise ValueError("Subdomain or hostname is invalid.")
    labels = hostname.split(".")
    if any(not DNS_LABEL_RE.fullmatch(label) for label in labels):
        raise ValueError("Subdomain or hostname contains an invalid DNS label.")
    return hostname


def resolve_hostname(port: int, value: str, base_domain: str, zone_domain: str) -> str:
    suffix = normalize_hostname(base_domain)
    zone = normalize_hostname(zone_domain)
    requested = value.strip()
    hostname = normalize_hostname(requested if "." in requested else f"{requested or port}.{suffix}")
    if hostname != zone and not hostname.endswith(f".{zone}"):
        raise ValueError(f"Hostname {hostname} is outside Cloudflare zone {zone}.")
    return hostname


def normalize_subdomains(values: Any, port: int | str | None = None) -> list[str]:
    if isinstance(values, list):
        raw_values = values
    elif values is None:
        raw_values = []
    else:
        raw_values = [values]

    aliases: list[str] = []
    for raw_value in raw_values:
        for part in str(raw_value).split(","):
            item = part.strip().lower()
            if not item:
                continue
            alias = normalize_hostname(item)
            if alias in aliases:
                raise ValueError(f"Subdomain or hostname is listed more than once: {alias}")
            aliases.append(alias)

    if not aliases and port is not None:
        aliases.append(normalize_hostname(str(port)))

    return aliases


def normalize_emails(values: Any) -> list[str]:
    if not isinstance(values, list):
        return []
    emails: list[str] = []
    for value in values:
        email = str(value).strip().lower()
        if not email:
            continue
        if not EMAIL_RE.fullmatch(email):
            raise ValueError(f"Invalid email address: {email}")
        if email not in emails:
            emails.append(email)
    return emails


def normalize_rule(value: Any, port: int | str | None = None) -> dict[str, Any]:
    rule = value if isinstance(value, dict) else {}
    raw_subdomains = rule.get("subdomains")
    if raw_subdomains is None:
        raw_subdomains = rule.get("subdomain")
    subdomains = normalize_subdomains(raw_subdomains, port)
    whitelist = bool(rule.get("whitelist", False))
    emails = normalize_emails(rule.get("emails", []))
    if whitelist and not emails:
        raise ValueError("At least one email address is required when whitelist is enabled.")
    return {
        "subdomains": subdomains,
        "whitelist": whitelist,
        "emails": emails if whitelist else [],
    }


def read_policy(path: Path) -> dict[str, Any]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        payload = {}
    return payload if isinstance(payload, dict) else {}


def cloudflare_rules(path: Path, *, strict: bool = False) -> dict[str, dict[str, Any]]:
    raw = read_policy(path).get("cloudflare", {})
    if not isinstance(raw, dict):
        if strict:
            raise ValueError("Cloudflare policy must be a JSON object keyed by port.")
        return {}
    rules: dict[str, dict[str, Any]] = {}
    for port, value in raw.items():
        try:
            port_number = int(str(port))
            if not (1 <= port_number <= 65535):
                continue
            rules[str(port_number)] = normalize_rule(value, port_number)
        except (TypeError, ValueError) as exc:
            if strict:
                raise ValueError(f"Invalid Cloudflare rule for port {port}: {exc}") from exc
    return rules


def write_cloudflare_rules(path: Path, rules: dict[str, dict[str, Any]]) -> None:
    payload = read_policy(path)
    payload.setdefault("whitelist", [])
    payload.setdefault("blacklist", [])
    payload["cloudflare"] = {
        str(port): normalize_rule(rule, int(port))
        for port, rule in sorted(rules.items(), key=lambda item: int(item[0]))
    }
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            json.dump(payload, handle, indent=2)
            handle.write("\n")
        os.replace(temporary, path)
    except Exception:
        try:
            os.unlink(temporary)
        except OSError:
            pass
        raise
