#!/usr/bin/env python3
"""Release only CITADEL's configured web UI port from Tailscale Serve."""

from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any, Callable


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


def prune_services(payload: dict[str, Any], port: int) -> bool:
    services = payload.get("http_services")
    if not isinstance(services, list):
        return False

    changed = False
    for service in services:
        if not isinstance(service, dict) or str(service.get("port")) != str(port):
            continue
        urls = service.get("urls")
        if isinstance(urls, dict) and "tailscale" in urls:
            urls.pop("tailscale")
            changed = True
    return changed


def prune_cache(payload: dict[str, Any]) -> bool:
    changed = False
    for key in ("tailscale_url", "tailscale_path"):
        if key in payload:
            payload.pop(key)
            changed = True
    return changed


def write_json_atomic(path: Path, payload: dict[str, Any]) -> None:
    stat = path.stat()
    temp_name: str | None = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w",
            encoding="utf-8",
            dir=path.parent,
            prefix=f".{path.name}.",
            suffix=".tmp",
            delete=False,
        ) as handle:
            temp_name = handle.name
            json.dump(payload, handle, indent=2)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(temp_name, stat.st_mode & 0o777)
        os.chown(temp_name, stat.st_uid, stat.st_gid)
        os.replace(temp_name, path)
    except OSError as exc:
        raise UnrouteError(f"cannot update {path}: {exc}") from exc
    finally:
        if temp_name is not None:
            try:
                os.unlink(temp_name)
            except FileNotFoundError:
                pass


def clear_persisted_port(project_dir: Path, port: int) -> None:
    port_key = str(port)
    updates: dict[Path, dict[str, Any]] = {}

    for path in (
        project_dir / "tailscale.json",
        project_dir / "extensions" / "enabled" / "tailscale" / "routes.json",
    ):
        payload = read_json_object(path)
        if payload is not None and prune_route_state(payload, port_key):
            updates[path] = payload

    services_path = project_dir / "services.json"
    services = read_json_object(services_path)
    if services is not None and prune_services(services, port):
        updates[services_path] = services

    cache_path = project_dir / "cache" / f"{port}.json"
    cache = read_json_object(cache_path)
    if cache is not None and prune_cache(cache):
        updates[cache_path] = cache

    for path, payload in updates.items():
        write_json_atomic(path, payload)


def unroute(project_dir: Path) -> int:
    project_dir = project_dir.resolve()
    port = read_configured_port(project_dir)
    tailscale_bin = shutil.which("tailscale")
    if tailscale_bin is None:
        raise UnrouteError("tailscale CLI is unavailable")

    print(f"[unroute] configured CITADEL port: {port}")
    release_serve_port(tailscale_bin, port)
    clear_persisted_port(project_dir, port)
    print(f"[unroute] released only Tailscale Serve port {port}")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path, required=True)
    args = parser.parse_args()
    try:
        return unroute(args.root)
    except UnrouteError as exc:
        print(f"[unroute] failed: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
