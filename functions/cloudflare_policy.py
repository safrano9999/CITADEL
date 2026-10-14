from __future__ import annotations

import json
import os
import re
from pathlib import Path
from typing import Any

from providers.atomic_io import atomic_write_json


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


WWW443_SETTING = "CITADEL_CLOUDFLARE_WWW443"
DOMAIN443_SETTING = "CITADEL_CLOUDFLARE_DOMAIN443"


def _enabled(value: Any) -> bool:
    return str(value or "").strip().lower() in {"1", "true", "yes", "on"}


def _configured_443_subdomains() -> list[str] | None:
    settings = (WWW443_SETTING, DOMAIN443_SETTING)
    if not any(setting in os.environ for setting in settings):
        return None
    aliases: list[str] = []
    if _enabled(os.environ.get(WWW443_SETTING)):
        aliases.append("www")
    if _enabled(os.environ.get(DOMAIN443_SETTING)):
        aliases.append("domain")
    return aliases or ["443"]


def resolve_hostname(port: int, value: str, base_domain: str, zone_domain: str) -> str:
    suffix = normalize_hostname(base_domain)
    zone = normalize_hostname(zone_domain)
    requested = value.strip()
    if requested.lower() in {"domain", "@"}:
        hostname = suffix
    else:
        hostname = normalize_hostname(requested if "." in requested else f"{requested or port}.{suffix}")
    if hostname != zone and not hostname.endswith(f".{zone}"):
        raise ValueError(f"Hostname {hostname} is outside Cloudflare zone {zone}.")
    return hostname


def default_subdomains(port: int | str) -> list[str]:
    """Return CITADEL's default Cloudflare label for a discovered port."""
    try:
        port_number = int(str(port))
    except (TypeError, ValueError):
        port_number = None
    if port_number == 443:
        return _configured_443_subdomains() or ["443"]
    return [str(port)]


def normalize_subdomains(values: Any, port: int | str | None = None) -> list[str]:
    if isinstance(values, list):
        raw_values = values
    elif values is None:
        raw_values = []
    else:
        raw_values = [values]

    aliases: list[str] = []
    port_number = None
    try:
        port_number = int(str(port)) if port is not None else None
    except (TypeError, ValueError):
        pass
    if port_number == 443:
        configured = _configured_443_subdomains()
        if configured is not None:
            return configured
    for raw_value in raw_values:
        for part in str(raw_value).split(","):
            item = part.strip().lower()
            if not item:
                continue
            alias = normalize_hostname(item)
            if port_number == 443 and alias == "443":
                alias = "www"
            if alias in aliases:
                raise ValueError(f"Subdomain or hostname is listed more than once: {alias}")
            aliases.append(alias)

    if not aliases and port is not None:
        aliases.extend(default_subdomains(port))

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
    if strict:
        try:
            document = json.loads(path.read_text(encoding="utf-8"))
        except FileNotFoundError:
            document = {}
        except (UnicodeError, json.JSONDecodeError) as exc:
            raise ValueError("Invalid Cloudflare policy JSON; reconciliation aborted") from exc
        if not isinstance(document, dict):
            raise ValueError("Cloudflare policy must be a JSON object")
    else:
        document = read_policy(path)
    raw = document.get("cloudflare", {})
    if not isinstance(raw, dict):
        if strict:
            raise ValueError("Cloudflare policy must be a JSON object keyed by port.")
        return {}
    rules: dict[str, dict[str, Any]] = {}
    for port, value in raw.items():
        try:
            port_number = int(str(port))
            if not (1 <= port_number <= 65535):
                raise ValueError("Port must be between 1 and 65535")
            if strict and (not isinstance(value, dict) or
                           type(value.get("whitelist", False)) is not bool):
                raise ValueError("Rule must be an object with a boolean whitelist")
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
    atomic_write_json(path, payload)
