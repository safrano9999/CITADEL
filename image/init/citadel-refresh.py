#!/usr/bin/env python3
"""Refresh CITADEL without running scans or changing provider routes.

The init loader recursively runs *.sh and *.py. Install one 00-refresh.py
beside instance.conf, export-config.json and service.conf for a no-argument hook.
Boot ordering before citadel.service must be installed before boot, separately.
Deploy its After=fedora45-ai-init-hooks.service drop-in through the image or a
pre-boot bind mount on container recreation; this hook cannot retroactively
order a WebUI already started in the same boot transaction.
"""

import argparse
from contextlib import contextmanager
import fcntl
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile
import time


SETTINGS = {
    "CADDYFILE_START": "4000",
    "CADDYFILE_STEPS": "1",
    "CITADEL_TAILSCALE_SERVE": "full",
    "CITADEL_LOGO_PERSISTENT": "1",
    "CITADEL_HIDE_HTTP_WEBUI_DUPE": "1",
}
UNITS = ("citadel.service", "citadel-scan.service")
# Remove retired settings at the final service-environment stage: the image's
# global PassEnvironment generator otherwise adds them back to every service.
RETIRED = (
    "CITADEL_PERSISTENT",
    "CITADEL_WEBUI_HTTPS_PORT", "CITADEL_CADDY_BACKEND", "CITADEL_CADDY_HOST",
    "CITADEL_CADDY_HTTPS_START", "CITADEL_CADDY_RANGE", "CITADEL_CADDY_REAL_IP_PORTS",
    "CITADEL_CONTAINER", "CITADEL_CONTAINER_MAP", "CITADEL_DEDUPE_PORT",
    "CITADEL_CLEAR_TAILSCALE", "CITADEL_TS_DISCOVERY", "CITADEL_TAILSCALE",
    "CITADEL_TAILSCALE_DEFAULT", "CITADEL_TAILSCALE_HTTP_START",
    "CITADEL_TAILSCALE_HTTPS_START", "CITADEL_TAILSCALE_RANGE", "CITADEL_CLOUDFLARE",
)
RUNTIME = (
    ".env", ".tunnel-token", "config.conf", "config.ini", "cert.pem",
    "ports.filter.json", "cache", "icons", "services.json", "ss.json",
    "last_scan.txt", "tailscale.json", "extensions/providers_state.json",
    "extensions/ui.json", "CLOUDFLARE-API_ignore.json", "CLOUDFLARE-API_discovery.json",
)


def run(command, **kwargs):
    return subprocess.run(command, check=True, timeout=kwargs.pop("timeout", 30),
                          stdout=subprocess.PIPE, stderr=subprocess.PIPE, **kwargs)


def exists(path):
    return path.exists() or path.is_symlink()


def copy_entry(source, target):
    """Copy data without following links into persistent volumes."""
    target.parent.mkdir(parents=True, exist_ok=True)
    if source.is_symlink():
        target.symlink_to(os.readlink(source))
    elif source.is_dir():
        shutil.copytree(source, target, symlinks=True)
    else:
        shutil.copy2(source, target)


def retained_tree(source, label, retained):
    """Reserve a unique backup outside the temporary clone cleanup scope."""
    directory = Path(tempfile.mkdtemp(prefix=f".{source.name}-{label}-", dir=source.parent))
    target = directory / "tree"
    retained.append(target)
    return target


def move_tree(source, target):
    """GNU mv handles overlay EXDEV via copy/remove, retaining symlink targets.

    A successful move can expose an image lowerdir at source. Callers must
    check that path separately; never treat it as an empty destination.
    """
    if exists(target):
        raise RuntimeError("Refusing to move a tree onto an occupied destination")
    run(["/usr/bin/mv", "-T", "--", str(source), str(target)], timeout=90)
    if not exists(target):
        raise RuntimeError("Tree move returned without creating its destination")


def vacate_tree(source, label, retained):
    """Archive revealed lowerdirs/partial installs instead of deleting them."""
    for _ in range(4):
        if not exists(source):
            return
        move_tree(source, retained_tree(source, label, retained))
    if exists(source):
        raise RuntimeError("Source remains occupied after preserving overlay trees")


def restore_tree(source, backup, retained):
    vacate_tree(source, "failed", retained)
    move_tree(backup, source)


def rollback(source, backup, retained, saved_units, restart_attempted, stopped):
    """Attempt every recovery step even when an earlier recovery step fails."""
    failures = []

    def attempt(label, action):
        try:
            action()
        except BaseException as exc:
            # Log operation/type only: subprocess arguments/output may be secret.
            failures.append(f"{label}: {type(exc).__name__}")

    if restart_attempted:
        attempt("stop new WebUI", lambda: run(["systemctl", "stop", "citadel.service"], timeout=90))
    if backup is not None:
        attempt("restore source tree", lambda: restore_tree(source, backup, retained))
    for target, previous, mode in reversed(saved_units):
        if previous is None:
            attempt(f"remove new {target.name}", lambda target=target: target.unlink(missing_ok=True))
        else:
            attempt(f"restore {target.name}", lambda target=target, previous=previous, mode=mode:
                    atomic_write(target, previous, mode))
    attempt("daemon-reload", lambda: run(["systemctl", "daemon-reload"]))
    if stopped:
        attempt("start previous WebUI", lambda: run(["systemctl", "start", "citadel.service"], timeout=90))
    if failures:
        print("CITADEL rollback incomplete: " + "; ".join(failures), file=sys.stderr)
    for path in retained:
        if exists(path):
            print(f"CITADEL retained tree: {path}", file=sys.stderr)


def aligned_config(text, settings=None):
    settings = SETTINGS if settings is None else settings
    lines = []
    for line in text.splitlines():
        match = re.match(r"\s*(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*=", line)
        if not match or (match[1] not in settings and match[1] not in RETIRED):
            lines.append(line)
    return "\n".join(lines + [f"{key}={value}" for key, value in settings.items()]) + "\n"


def instance_configuration(args):
    """Read shared instance inputs without modifying them or copying secrets."""
    directory = args.instance_dir
    files = [directory / name for name in ("instance.conf", "export-config.json", "service.conf")]
    if any(path.exists() for path in files):
        if not all(path.is_file() for path in files):
            raise RuntimeError("Shared instance requires instance.conf, export-config.json and service.conf")
        allowed = set(SETTINGS) | {"FASTAPI_HOST", "CITADEL_WEBUI_TRANSPORT", "CITADEL_WEBUI_SOCKET", "CITADEL_WEBUI_PORT"}
        settings = {}
        for line in files[0].read_text().splitlines():
            match = re.fullmatch(r"\s*([A-Za-z_][A-Za-z0-9_]*)\s*=(.*)", line)
            if match and match[1] in allowed:
                settings[match[1]] = match[2].strip()
        export_content = files[1].read_bytes()
        try:
            export = json.loads(export_content)
        except ValueError as exc:
            raise RuntimeError("Invalid shared export-config.json") from exc
        service = files[2].read_bytes()
        if b"EnvironmentFile=" not in service:
            raise RuntimeError("Shared service.conf must reference its instance.conf EnvironmentFile")
    else:
        settings = SETTINGS
        export = {"backend": args.backend, "hosts": args.host}
        export_content = (json.dumps(export, indent=2) + "\n").encode()
        service = ("[Service]\n" + "".join(f"Environment={key}={value}\n" for key, value in settings.items())).encode()
    if (not isinstance(export, dict) or not isinstance(export.get("hosts"), list)
            or not export["hosts"] or not export.get("backend")):
        raise RuntimeError("Supply shared export config or --backend and --host")
    for value in [export["backend"], *export["hosts"]]:
        if not isinstance(value, str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._:-]*", value):
            raise RuntimeError("Export backend and hosts must be plain hostnames or addresses")
    dropin = service.rstrip() + b"\n[Service]\nUnsetEnvironment=" + " ".join(RETIRED).encode() + b"\n"
    return settings, export_content, dropin


def atomic_write(path, content, mode=0o600):
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, name = tempfile.mkstemp(prefix=".citadel-refresh-", dir=path.parent)
    try:
        with os.fdopen(fd, "wb") as stream:
            stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())
        os.chmod(name, mode)
        os.replace(name, path)
    finally:
        if os.path.exists(name):
            os.unlink(name)


def extension_selections(old, staged):
    """Retain known disabled selections using only the new extension code."""
    for candidate in (old / "extensions/disabled").glob("*"):
        name = candidate.name
        enabled = staged / "extensions/enabled" / name
        disabled = staged / "extensions/disabled" / name
        if (old / "extensions/enabled" / name).exists():
            raise RuntimeError(f"Ambiguous enabled/disabled extension: {name}")
        if enabled.is_dir() and not enabled.is_symlink() and not exists(disabled):
            disabled.parent.mkdir(parents=True, exist_ok=True)
            enabled.rename(disabled)
    # Optional extensions ship disabled; retain an operator's enabled selection
    # while taking their implementation from the new checkout.
    for candidate in (old / "extensions/enabled").glob("*"):
        enabled = staged / "extensions/enabled" / candidate.name
        disabled = staged / "extensions/disabled" / candidate.name
        if (old / "extensions/disabled" / candidate.name).exists():
            raise RuntimeError(f"Ambiguous enabled/disabled extension: {candidate.name}")
        if disabled.is_dir() and not disabled.is_symlink() and not exists(enabled):
            enabled.parent.mkdir(parents=True, exist_ok=True)
            disabled.rename(enabled)


def prepare_tree(old, staged, export_dir, settings, export_content):
    extension_selections(old, staged)
    entries = list(RUNTIME) + [path.name for path in old.glob("*.env") if path.name != ".env"]
    for state in ("enabled", "disabled"):
        for extension in (staged / "extensions" / state).glob("*"):
            entries.extend(f"extensions/{state}/{extension.name}/{name}"
                           for name in ("routes.json", "status.json", "config.ini"))
    for relative in entries:
        source, target = old / relative, staged / relative
        if not exists(source):
            continue
        if exists(target):
            if target.is_dir() and not target.is_symlink():
                raise RuntimeError(f"Runtime directory unexpectedly tracked: {relative}")
            target.unlink()  # Only a file in our fresh clone, never the old tree.
        copy_entry(source, target)
    config = old / "config.conf"
    atomic_write(staged / "config.conf", aligned_config(config.read_text() if config.exists() else "", settings).encode())
    caddy = next((staged / "extensions" / state / "caddy" for state in ("enabled", "disabled")
                  if (staged / "extensions" / state / "caddy").is_dir()), None)
    if caddy is None:
        raise RuntimeError("Clone has no Caddy exporter extension")
    atomic_write(caddy / "config.json", export_content, 0o644)
    link = staged / "CADDY"
    if exists(link):
        raise RuntimeError("Clone unexpectedly contains CADDY runtime output")
    link.symlink_to(export_dir, target_is_directory=True)


def revision(tree):
    if not (tree / ".git").is_dir():
        return None
    return run(["git", "-C", str(tree), "rev-parse", "HEAD"]).stdout.strip()


def same_installation(old, staged):
    if revision(old) != revision(staged):
        return False
    for relative in ("config.conf", "extensions/enabled/caddy/config.json", "extensions/disabled/caddy/config.json"):
        left, right = old / relative, staged / relative
        if left.exists() != right.exists() or (left.exists() and left.read_bytes() != right.read_bytes()):
            return False
    return (old / "CADDY").is_symlink() and os.readlink(old / "CADDY") == os.readlink(staged / "CADDY")


@contextmanager
def exclusive_lock(path):
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a") as stream:
        try:
            fcntl.flock(stream, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as exc:
            raise RuntimeError("Another refresh or scan is running; nothing stopped") from exc
        yield


def active_state(unit):
    return run(["systemctl", "show", unit, "--property=ActiveState", "--value"]).stdout.decode().strip()


def check_dependencies():
    command = ["/usr/bin/python3", "-s", "-c", "import dotenv, fastapi, jinja2, uvicorn"]
    try:
        run(command)
    except subprocess.CalledProcessError:
        run(["dnf", "-y", "install", "python3-dotenv", "python3-fastapi", "python3-jinja2", "python3-uvicorn"], timeout=300)
        run(command)


def install_units(staged, unit_dir, saved, dropin):
    for name in UNITS:
        for target, content in (
            (unit_dir / name, (staged / "image/runtime/etc/systemd/system" / name).read_bytes()),
            (unit_dir / f"{name}.d/95-citadel-instance.conf", dropin),
        ):
            if target.is_symlink():
                raise RuntimeError(f"Refusing to overwrite a unit symlink: {target.name}")
            previous = target.read_bytes() if target.exists() else None
            if previous == content:
                continue
            saved.append((target, previous, target.stat().st_mode & 0o777 if previous is not None else 0o644))
            if previous is not None:
                copy_entry(target, target.with_name(target.name + f".citadel-backup-{time.time_ns()}"))
            atomic_write(target, content, 0o644)


def refresh(args):
    source, export_dir = args.source, args.export_dir
    settings, export_content, dropin = instance_configuration(args)
    if (source.is_symlink() or not source.is_dir() or source == Path("/")
            or not all((source / name).is_file() for name in ("webui.py", "scan.sh"))):
        raise RuntimeError("Source must be an existing, non-symlink Citadel project directory")
    if export_dir == source or export_dir.is_relative_to(source):
        raise RuntimeError("Export directory must be outside the replaced source tree")
    lock_root = Path(os.environ.get("XDG_RUNTIME_DIR") or os.environ.get("TMPDIR") or "/tmp")
    scan_lock = Path(os.environ.get("CITADEL_SCAN_LOCK_FILE") or lock_root / f"citadel-scan-{os.getuid()}.lock")
    with exclusive_lock(source.parent / ".citadel-refresh.lock"):
        with tempfile.TemporaryDirectory(prefix=".citadel-refresh-", dir=source.parent) as temporary:
            staged = Path(temporary) / "checkout"
            run(["git", "clone", "--depth", "1", "--single-branch", "--branch", args.branch,
                 "--", args.repository, str(staged)], timeout=90)
            for relative in ("webui.py", "python_header.py", "scan.sh", "functions/webui_transport.py",
                             *(f"image/runtime/etc/systemd/system/{name}" for name in UNITS)):
                if not (staged / relative).is_file():
                    raise RuntimeError(f"Incomplete clone: missing {relative}")
            check_dependencies()
            with exclusive_lock(scan_lock):
                if active_state("citadel-scan.service") not in ("inactive", "failed"):
                    raise RuntimeError("Citadel scan is active; refusing refresh")
                state = active_state("citadel.service")
                if state not in ("active", "inactive", "failed"):
                    raise RuntimeError("Citadel is transitioning; retry later")
                running = state == "active"
                if running and not args.live:
                    raise RuntimeError("Boot refresh found a running WebUI; fix boot ordering or use --live")
                backup = None
                retained = []
                stopped = False
                restart_attempted = False
                saved_units = []
                try:
                    # Clone and dependency checks finish before the only stop.
                    if running:
                        stopped = True
                        run(["systemctl", "stop", "citadel.service"], timeout=90)
                    prepare_tree(source, staged, export_dir, settings, export_content)
                    export_dir.mkdir(parents=True, exist_ok=True)
                    if not same_installation(source, staged):
                        candidate = retained_tree(source, "backup", retained)
                        move_tree(source, candidate)
                        # Only a completed move is eligible as a restore source.
                        backup = candidate
                        vacate_tree(source, "image-fallback", retained)
                        move_tree(staged, source)
                    install_units(source, args.unit_dir, saved_units, dropin)
                    run(["systemctl", "daemon-reload"])
                    if args.live:
                        restart_attempted = True
                        run(["systemctl", "restart", "citadel.service"], timeout=90)
                except BaseException:
                    rollback(source, backup, retained, saved_units, restart_attempted, stopped)
                    raise
                print("CITADEL refresh complete" + (f"; retained backup: {backup}" if backup else "; code unchanged"))
                for path in retained:
                    if path != backup and exists(path):
                        print(f"CITADEL retained overlay tree: {path}")


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, default=Path("/opt/safrano9999/CITADEL"))
    parser.add_argument("--repository", default="https://github.com/f24sales/citadel.git")
    parser.add_argument("--branch", default="main")
    parser.add_argument("--instance-dir", type=Path, default=Path(__file__).resolve().parent)
    parser.add_argument("--export-dir", type=Path, help="defaults to INSTANCE_DIR/caddyfile")
    parser.add_argument("--backend", help="required only without shared instance files")
    parser.add_argument("--host", action="append", help="required only without shared instance files")
    parser.add_argument("--unit-dir", type=Path, default=Path("/etc/systemd/system"))
    parser.add_argument("--live", action="store_true", help="restart only the WebUI after installation")
    args = parser.parse_args(argv)
    args.export_dir = args.export_dir or args.instance_dir / "CADDY"
    for path in (args.source, args.export_dir, args.unit_dir, args.instance_dir):
        if not path.is_absolute() or ".." in path.parts:
            parser.error("paths must be absolute and contain no '..'")
    try:
        refresh(args)
    except (OSError, RuntimeError, subprocess.SubprocessError) as exc:
        # Do not print subprocess output or arguments that might contain secrets.
        print(f"CITADEL refresh failed: {type(exc).__name__}" + (f": {exc}" if isinstance(exc, RuntimeError) else ""), file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
