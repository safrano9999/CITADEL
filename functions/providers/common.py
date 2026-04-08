from __future__ import annotations

import configparser
import datetime as dt
import json
import os
import subprocess
from typing import Any


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
    parent = os.path.dirname(path)
    if parent:
        os.makedirs(parent, exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(payload, f, indent=2)


def parse_bool(value: Any) -> bool:
    if isinstance(value, bool):
        return value
    if value is None:
        return False
    return str(value).strip().lower() in {"1", "true", "yes", "on"}


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


def ini_get(parser: configparser.ConfigParser, key: str, fallback: str = "", *, section: str = "provider") -> str:
    try:
        return parser.get(section, key, fallback=fallback).strip()
    except Exception:
        return fallback
