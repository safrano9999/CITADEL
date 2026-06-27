from __future__ import annotations

import subprocess
from collections.abc import Callable


TRUE_VALUES = {"1", "true", "yes", "on"}
SERVICE = "cloudflared.service"


def run_systemctl(
    runner: Callable[..., subprocess.CompletedProcess[str]],
    command: list[str],
) -> subprocess.CompletedProcess[str] | None:
    try:
        return runner(command, capture_output=True, text=True, check=False)
    except OSError:
        return None


def ensure_cloudflared_service(
    get_value: Callable[[str, str], str],
    runner: Callable[..., subprocess.CompletedProcess[str]] = subprocess.run,
) -> str:
    enabled = str(get_value("CITADEL_CLOUDFLARE", "0") or "").strip().lower()
    if enabled not in TRUE_VALUES:
        return "disabled"

    if not str(get_value("TUNNEL_TOKEN", "") or "").strip():
        return "missing setting: TUNNEL_TOKEN"

    errors: list[str] = []
    for scope in (["systemctl"], ["systemctl", "--user"]):
        loaded = run_systemctl(
            runner,
            [*scope, "show", SERVICE, "--property=LoadState", "--value"],
        )
        if loaded is None or loaded.returncode != 0 or loaded.stdout.strip() != "loaded":
            continue

        active = run_systemctl(
            runner,
            [*scope, "is-active", "--quiet", SERVICE],
        )
        if active is not None and active.returncode == 0:
            return "already running"

        started = run_systemctl(
            runner,
            [*scope, "start", SERVICE],
        )
        if started is not None and started.returncode == 0:
            return "started"
        detail = "" if started is None else (started.stderr or started.stdout).strip()
        if detail:
            errors.append(detail)

    if errors:
        return "start failed: " + errors[-1]
    return "cloudflared.service not found"
