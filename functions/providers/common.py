from __future__ import annotations

import configparser
import datetime as dt
import ipaddress
import json
import os
import subprocess
from typing import Any

from atomic_io import atomic_write_json


ROUTE_SCHEMA_VERSION = 1
WILDCARD_ADDRESSES = {"*", "0.0.0.0", "::"}


def now_iso() -> str:
    return dt.datetime.now().isoformat(timespec="seconds")


def read_json(path: str, default: Any) -> Any:
    if not os.path.exists(path):
        return default
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return default


def write_json(path: str, payload: Any) -> None:
    atomic_write_json(path, payload)


def parse_bool(value: Any) -> bool:
    if isinstance(value, bool):
        return value
    if value is None:
        return False
    return str(value).strip().lower() in {"1", "true", "yes", "on"}


def read_key_value(path: str, key: str) -> str:
    if not os.path.exists(path):
        return ""
    try:
        with open(path, "r", encoding="utf-8") as f:
            for raw in f:
                line = raw.strip()
                if not line or line.startswith("#") or "=" not in line:
                    continue
                name, value = line.split("=", 1)
                if name.strip() == key:
                    return value.strip().strip('"').strip("'")
    except Exception:
        return ""
    return ""


def set_ini_value(path: str, key: str, value: str) -> None:
    new_line = f"{key} = {value}\n"
    if not os.path.exists(path):
        with open(path, "w", encoding="utf-8") as f:
            f.write("[CITADEL]\n")
            f.write(new_line)
        return

    with open(path, "r", encoding="utf-8") as f:
        lines = f.readlines()

    updated = False
    for idx, raw in enumerate(lines):
        stripped = raw.strip()
        if stripped.startswith(f"{key}") and "=" in stripped:
            lines[idx] = new_line
            updated = True
            break

    if not updated:
        lines.append(new_line)

    with open(path, "w", encoding="utf-8") as f:
        f.writelines(lines)


def run(cmd: list[str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(cmd, capture_output=True, text=True, check=False)


def normalize_address(value: Any) -> str:
    address = str(value or "").strip()
    if address.startswith("[") and address.endswith("]"):
        address = address[1:-1]
    return address.split("%", 1)[0]


def service_addresses(service: dict[str, Any]) -> list[str]:
    listeners = service.get("listeners")
    origin_values: list[Any] = []
    if isinstance(listeners, list):
        for listener in listeners:
            if not isinstance(listener, dict):
                continue
            process = str(listener.get("process") or "").strip().lower()
            if process == "tailscaled":
                continue
            origin_values.append(listener.get("addr"))

    raw = service.get("addrs")
    values = origin_values or (raw if isinstance(raw, list) else [service.get("addr")])
    addresses: list[str] = []
    for value in values:
        address = normalize_address(value)
        if address and address not in addresses:
            addresses.append(address)
    return addresses


def is_loopback_address(address: str) -> bool:
    if address.lower() == "localhost":
        return True
    try:
        return ipaddress.ip_address(address).is_loopback
    except ValueError:
        return False


def route_record(
    mode: str,
    url: str,
    *,
    target: str | None = None,
    owns_listener: bool = False,
) -> dict[str, Any]:
    return {
        "mode": mode,
        "url": url,
        "target": target,
        "owns_listener": owns_listener,
    }


def ensure_provider_ini(
    provider_dir: str,
    defaults: dict[str, Any],
    *,
    section: str = "provider",
) -> tuple[configparser.ConfigParser, str, bool]:
    ini_path = os.path.join(provider_dir, "config.ini")
    parser = configparser.ConfigParser()
    created = False

    if os.path.exists(ini_path):
        try:
            parser.read(ini_path, encoding="utf-8")
        except Exception:
            parser = configparser.ConfigParser()
    else:
        created = True

    changed = False
    if section not in parser:
        parser[section] = {}
        changed = True

    sec = parser[section]
    for key, default_value in defaults.items():
        if key not in sec:
            sec[key] = "" if default_value is None else str(default_value)
            changed = True

    if created or changed:
        os.makedirs(provider_dir, exist_ok=True)
        with open(ini_path, "w", encoding="utf-8") as f:
            parser.write(f)

    return parser, ini_path, created


def ini_get(parser: configparser.ConfigParser, key: str, default: str = "", *, section: str = "provider") -> str:
    try:
        if parser.has_section(section) and parser.has_option(section, key):
            return parser.get(section, key).strip()
        return default
    except Exception:
        return default
