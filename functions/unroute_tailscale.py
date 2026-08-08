#!/usr/bin/env python3
"""Release selected ports from Tailscale Serve."""

from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any, Callable

from providers.atomic_io import atomic_write_json


PORT_MAP_KEYS = (
    "managed_routes",
    "services",
    "serve_routes",
    "remembered_services",
    "remembered_serve_routes",
    "service_signatures",
    "route_failures",
    "fallbacks",
)


class UnrouteError(RuntimeError):
    pass


def read_configured_port(project_dir: Path) -> int:
    config_path = project_dir / "config.conf"
    if not config_path.is_file():
        raise UnrouteError(f"missing configuration file: {config_path}")

    raw_value: str | None = None
    try:
        for raw_line in config_path.read_text(encoding="utf-8").splitlines():
            line = raw_line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, value = line.split("=", 1)
            if key.strip() == "CITADEL_WEBUI_PORT":
                raw_value = value.split("#", 1)[0].strip().strip("\"'")
    except OSError as exc:
        raise UnrouteError(f"cannot read {config_path}: {exc}") from exc

    if raw_value is None:
        raise UnrouteError(f"CITADEL_WEBUI_PORT is missing in {config_path}")
    try:
        port = int(raw_value)
    except ValueError as exc:
        raise UnrouteError(
            f"CITADEL_WEBUI_PORT={raw_value!r} is not a valid port"
        ) from exc
    if not 1 <= port <= 65535:
        raise UnrouteError(
            f"CITADEL_WEBUI_PORT={port} is not a valid port (1-65535)"
        )
    return port


def command_succeeded(result: subprocess.CompletedProcess[str]) -> bool:
    if result.returncode == 0:
        return True
    message = f"{result.stderr}\n{result.stdout}".lower()
    return "handler does not exist" in message


def release_serve_port(
    tailscale_bin: str,
    port: int,
    runner: Callable[..., subprocess.CompletedProcess[str]] = subprocess.run,
) -> None:
    failures: list[str] = []
    for scheme in ("https", "http"):
        command = [
            tailscale_bin,
            "serve",
            "--yes",
            f"--{scheme}={port}",
            "off",
        ]
        result = runner(
            command,
            capture_output=True,
            text=True,
            check=False,
        )
        if command_succeeded(result):
            continue
        detail = result.stderr.strip() or result.stdout.strip() or "unknown error"
        failures.append(f"{scheme}: {detail}")

    if failures:
        raise UnrouteError(
            f"could not release Tailscale Serve port {port}: {'; '.join(failures)}"
        )


def read_json_object(path: Path) -> dict[str, Any] | None:
    if not path.exists():
        return None
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise UnrouteError(f"cannot read valid JSON from {path}: {exc}") from exc
    if not isinstance(payload, dict):
        raise UnrouteError(f"expected a JSON object in {path}")
    return payload


def prune_route_state(payload: dict[str, Any], port_key: str) -> bool:
    changed = False
    managed_ports = payload.get("managed_ports")
    if isinstance(managed_ports, list):
        retained = [value for value in managed_ports if str(value) != port_key]
        if retained != managed_ports:
            payload["managed_ports"] = retained
            changed = True

    for key in PORT_MAP_KEYS:
        values = payload.get(key)
        if isinstance(values, dict) and port_key in values:
            values.pop(port_key)
            changed = True
    return changed


def prune_service_entries(payload: dict[str, Any], port: int) -> bool:
    changed = False
    for key in ("http_services", "other_ports"):
        entries = payload.get(key)
        if not isinstance(entries, list):
            continue
        retained = [
            entry
            for entry in entries
            if not isinstance(entry, dict) or str(entry.get("port")) != str(port)
        ]
        if retained != entries:
            payload[key] = retained
            changed = True
    return changed


def remove_file(path: Path) -> None:
    try:
        path.unlink(missing_ok=True)
    except OSError as exc:
        raise UnrouteError(f"cannot remove {path}: {exc}") from exc


def clear_cached_metadata(project_dir: Path, port: int) -> None:
    remove_file(project_dir / "cache" / f"{port}.json")
    icons_dir = project_dir / "icons"
    if not icons_dir.is_dir():
        return
    for icon_path in icons_dir.glob(f"{port}.*"):
        if icon_path.is_file() or icon_path.is_symlink():
            remove_file(icon_path)


def write_json_atomic(path: Path, payload: dict[str, Any]) -> None:
    try:
        atomic_write_json(path, payload)
    except OSError as exc:
        raise UnrouteError(f"cannot update {path}: {exc}") from exc


def clear_persisted_port(project_dir: Path, port: int) -> None:
    port_key = str(port)
    updates: dict[Path, dict[str, Any]] = {}
    data_dir = Path(os.environ.get("CITADEL_DATA_DIR") or project_dir).expanduser()

    for path in (
        project_dir / "tailscale.json",
        data_dir / "extensions" / "enabled" / "tailscale" / "routes.json",
    ):
        payload = read_json_object(path)
        if payload is not None and prune_route_state(payload, port_key):
            updates[path] = payload

    services_path = project_dir / "services.json"
    services = read_json_object(services_path)
    if services is not None and prune_service_entries(services, port):
        updates[services_path] = services

    for path, payload in updates.items():
        write_json_atomic(path, payload)
    clear_cached_metadata(project_dir, port)


def unroute(project_dir: Path, requested_ports: list[int] | None = None) -> int:
    project_dir = project_dir.resolve()
    ports = requested_ports or [read_configured_port(project_dir)]
    if any(port < 1 or port > 65535 for port in ports):
        raise UnrouteError("ports must be between 1 and 65535")
    ports = list(dict.fromkeys(ports))

    tailscale_bin = shutil.which("tailscale")
    if tailscale_bin is None:
        raise UnrouteError("tailscale CLI is unavailable")

    if requested_ports:
        print(f"[unroute] requested ports: {', '.join(map(str, ports))}")
    else:
        print(f"[unroute] configured CITADEL port: {ports[0]}")

    for port in ports:
        release_serve_port(tailscale_bin, port)
        clear_persisted_port(project_dir, port)
        print(f"[unroute] released only Tailscale Serve port {port}")
        print(f"[unroute] cleared cached metadata and icons for port {port}")
    print("[unroute] the next ./scan.sh run will fetch them again")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("ports", nargs="*", type=int, metavar="PORT")
    args = parser.parse_args()
    try:
        return unroute(args.root, args.ports)
    except UnrouteError as exc:
        print(f"[unroute] failed: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
