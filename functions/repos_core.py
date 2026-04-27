"""repos_core.py — REPOS integration for CITADEL dashboard.

Discovers REPOS as sibling dir, loads modules/configs, manages builds.
All public functions are safe to call even when REPOS is absent.
"""

from __future__ import annotations

import json
import os
import signal
import subprocess
import sys
import time
from pathlib import Path

try:
    import tomllib
except ModuleNotFoundError:
    import tomli as tomllib

BASE_DIR = Path(__file__).resolve().parent.parent          # citadel/
SAF_DIR = BASE_DIR.parent                                   # saf/
REPOS_DIR = SAF_DIR / "REPOS"
REPOS_FUNCTIONS = REPOS_DIR / "functions"
REPOS_CONFIGS = REPOS_DIR / "CONFIGS"
REPOS_GENERATED = REPOS_DIR / "generated"

BUILD_PID_FILE = BASE_DIR / ".repos_build.pid"
BUILD_LOG_FILE = BASE_DIR / ".repos_build.log"
BUILD_CONFIG_FILE = BASE_DIR / ".repos_build_config.json"

# Guard against repeated sys.path insertions
_repos_path_added = False


# ── Availability ─────────────────────────────────────────────────────────


def repos_available() -> bool:
    return (REPOS_DIR / "configure.py").is_file()


def repos_image_path() -> Path | None:
    p = REPOS_DIR / "REPOS.png"
    return p if p.is_file() else None


# ── Module Discovery ─────────────────────────────────────────────────────


def _ensure_repos_path():
    """Add REPOS/functions to sys.path exactly once."""
    global _repos_path_added
    if _repos_path_added:
        return
    s = str(REPOS_FUNCTIONS)
    if s not in sys.path:
        sys.path.insert(0, s)
    _repos_path_added = True


def list_modules() -> list[dict]:
    """Load all REPOS modules and return serializable dicts.

    Returns empty list on any import/parse error (never crashes the server).
    """
    try:
        _ensure_repos_path()
        from config_modules import load_modules as _load_modules
        modules = _load_modules()
    except Exception as exc:
        return [{"_error": f"Failed to load modules: {exc}"}]

    result = []
    for m in modules:
        try:
            result.append({
                "name": m.name,
                "group": m.group,
                "kind": m.kind,
                "description": m.description,
                "default_selected": m.default_selected,
                "dependencies": list(m.dependencies),
                "target_dir": m.target_dir,
                "source": m.source,
                "exclude_network": list(m.exclude_network),
                "port_prompts": [
                    {"env_key": pk, "default": pd, "publish": pp}
                    for pk, pd, pp in m.port_prompts
                ],
                "env_prompts": [
                    {
                        "key": ep.key,
                        "default": ep.default,
                        "description": ep.description,
                        "required": ep.required,
                        "when_litellm_mode": ep.when_litellm_mode,
                        "when_network": ep.when_network,
                        "when_selected": sorted(ep.when_selected) if ep.when_selected else [],
                        "when_env_key": ep.when_env_key,
                        "when_env_values": sorted(ep.when_env_values) if ep.when_env_values else [],
                    }
                    for ep in m.env_prompts
                ],
                "persistence": list(m.persistence),
            })
        except Exception:
            result.append({"name": getattr(m, "name", "?"), "_error": "serialize failed"})
    return result


def resolve_deps(selected: list[str]) -> dict:
    """Resolve dependencies for a set of selected module names.

    Unknown module names in `selected` are silently ignored.
    """
    try:
        _ensure_repos_path()
        from config_modules import (
            apply_dependencies,
            load_modules as _load_modules,
            module_map,
        )

        modules = _load_modules()
        by_name = module_map(modules)
        # Filter to only known module names
        selected_set = {n for n in selected if n in by_name}
        original = set(selected_set)
        resolved = apply_dependencies(selected_set, by_name)
        auto = sorted(resolved - original)
        return {"selected": sorted(resolved), "auto": auto}
    except Exception as exc:
        return {"selected": list(selected), "auto": [], "error": str(exc)}


# ── Config Management ────────────────────────────────────────────────────


def _safe_stem(name: str) -> str:
    """Extract safe filename stem — no path traversal, no null bytes."""
    cleaned = name.replace("\x00", "").strip()
    return Path(cleaned).stem


def list_configs() -> list[dict]:
    """List all saved CONFIGS/*.toml files with summary data."""
    if not REPOS_CONFIGS.is_dir():
        return []
    configs = []
    for f in sorted(REPOS_CONFIGS.glob("*.toml")):
        try:
            data = tomllib.loads(f.read_text(encoding="utf-8"))
            if not isinstance(data, dict):
                raise ValueError("not a dict")
            meta = data.get("meta", {})
            if not isinstance(meta, dict):
                meta = {}
            configs.append({
                "name": f.stem,
                "file": f.name,
                "stack": str(meta.get("stack", f.stem)),
                "container_name": str(meta.get("container_name", "")),
                "network": str(meta.get("network", "")),
                "selected_modules": list(data.get("selected_modules", [])),
                "image_tag": str(meta.get("image_tag", "")),
            })
        except Exception:
            configs.append({"name": f.stem, "file": f.name, "error": "parse error"})
    return configs


def load_config(name: str) -> dict | None:
    """Load a full CONFIGS/<name>.toml and return as dict."""
    safe = _safe_stem(name)
    if not safe:
        return None
    f = REPOS_CONFIGS / f"{safe}.toml"
    if not f.is_file():
        return None
    try:
        data = tomllib.loads(f.read_text(encoding="utf-8"))
        return data if isinstance(data, dict) else {"error": "invalid format"}
    except Exception:
        return {"error": "parse error"}


def delete_config(name: str) -> bool:
    safe = _safe_stem(name)
    if not safe:
        return False
    f = REPOS_CONFIGS / f"{safe}.toml"
    if not f.is_file():
        return False
    # Verify the file is actually inside CONFIGS (defense in depth)
    if not f.resolve().is_relative_to(REPOS_CONFIGS.resolve()):
        return False
    f.unlink()
    return True


# ── Generated Stacks ─────────────────────────────────────────────────────


DOWNLOADABLE_SUFFIXES = frozenset({
    ".Dockerfile", ".env", ".sh", ".toml", ".json", ".container", ".conf",
})
DOWNLOADABLE_NAMES = frozenset({
    "fly.toml", "supervisord.conf", "entrypoint.sh", "meta.json",
})


def list_generated() -> list[dict]:
    """List generated stacks with their meta.json data and downloadable files."""
    if not REPOS_GENERATED.is_dir():
        return []
    stacks = []
    for d in sorted(REPOS_GENERATED.iterdir()):
        if not d.is_dir() or d.name == "base":
            continue
        meta_file = d / "meta.json"
        entry: dict = {"_dir": d.name, "stack": d.name}
        if meta_file.is_file():
            try:
                raw = json.loads(meta_file.read_text(encoding="utf-8"))
                if isinstance(raw, dict):
                    raw["_dir"] = d.name
                    entry = raw
                else:
                    entry["error"] = "meta.json is not a dict"
            except (json.JSONDecodeError, OSError):
                entry["error"] = "parse error"

        # Collect downloadable files (top-level only, skip dirs and vendor/)
        files = []
        try:
            for f in sorted(d.iterdir()):
                if f.is_dir():
                    continue
                if f.suffix in DOWNLOADABLE_SUFFIXES or f.name in DOWNLOADABLE_NAMES:
                    files.append(f.name)
        except OSError:
            pass
        entry["files"] = files
        stacks.append(entry)
    return stacks


def get_generated_file(stack: str, filename: str) -> Path | None:
    """Resolve a downloadable file inside a generated stack dir.

    Returns None if path is invalid, outside REPOS_GENERATED, or not allowlisted.
    """
    if not REPOS_GENERATED.is_dir():
        return None
    # Sanitize: strip path components, null bytes
    safe_stack = Path(stack.replace("\x00", "")).name
    safe_file = Path(filename.replace("\x00", "")).name
    if not safe_stack or not safe_file or safe_stack.startswith("."):
        return None
    target = (REPOS_GENERATED / safe_stack / safe_file).resolve()
    # Must be inside REPOS_GENERATED
    try:
        if not target.is_relative_to(REPOS_GENERATED.resolve()):
            return None
    except ValueError:
        return None
    if not target.is_file():
        return None
    if target.suffix not in DOWNLOADABLE_SUFFIXES and target.name not in DOWNLOADABLE_NAMES:
        return None
    return target


# ── Base Image ───────────────────────────────────────────────────────────


def base_image_status() -> dict:
    """Check if shared base image exists. Never raises."""
    for engine in ("podman", "docker"):
        try:
            r = subprocess.run(
                [engine, "image", "exists", "localhost/repos-base:latest"],
                capture_output=True, timeout=5,
            )
            if r.returncode == 0:
                return {"exists": True, "engine": engine}
        except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
            continue
    return {"exists": False, "engine": None}


# ── Build Execution ──────────────────────────────────────────────────────


def _is_build_running() -> tuple[bool, int | None]:
    """Check if a build subprocess is still running.

    Cleans up stale PID files automatically.
    """
    if not BUILD_PID_FILE.is_file():
        return False, None
    try:
        raw = BUILD_PID_FILE.read_text(encoding="utf-8").strip()
        if not raw:
            BUILD_PID_FILE.unlink(missing_ok=True)
            return False, None
        pid = int(raw)
        os.kill(pid, 0)  # signal 0 = check if alive
        return True, pid
    except (ValueError, ProcessLookupError, PermissionError, OSError):
        BUILD_PID_FILE.unlink(missing_ok=True)
        return False, None


def build_status() -> dict:
    """Return current build status. Never raises."""
    running, pid = _is_build_running()
    log_tail = ""
    try:
        if BUILD_LOG_FILE.is_file():
            text = BUILD_LOG_FILE.read_text(encoding="utf-8", errors="replace")
            lines = text.splitlines()
            log_tail = "\n".join(lines[-20:])
    except OSError:
        pass

    return {
        "running": running,
        "pid": pid,
        "log_tail": log_tail,
        "has_log": BUILD_LOG_FILE.is_file(),
    }


def start_build(config: dict, *, mode: str = "generate") -> dict:
    """Launch a build subprocess.

    mode: "generate" | "build" | "base"
    Returns dict with running/pid/mode on success, or error key on failure.
    """
    running, _ = _is_build_running()
    if running:
        return {"error": "Build already running.", "running": True}

    runner = REPOS_FUNCTIONS / "webapi_build.py"
    if not runner.is_file():
        return {"error": "webapi_build.py not found."}

    try:
        # Clear old log
        BUILD_LOG_FILE.write_text("", encoding="utf-8")

        if mode == "base":
            cmd = [sys.executable, "-u", str(runner), "--base"]
        else:
            # Write config to temp file
            BUILD_CONFIG_FILE.write_text(
                json.dumps(config, indent=2, default=str),
                encoding="utf-8",
            )
            cmd = [sys.executable, "-u", str(runner), str(BUILD_CONFIG_FILE)]
            if mode == "build":
                cmd.append("--build")

        # Open log file — Popen takes ownership for stdout redirection.
        # We keep it open; the OS closes it when the child exits.
        log_fd = open(BUILD_LOG_FILE, "w", encoding="utf-8")
        proc = subprocess.Popen(
            cmd,
            stdout=log_fd,
            stderr=subprocess.STDOUT,
            cwd=str(REPOS_DIR),
            start_new_session=True,
        )
        # Close our copy of the fd — child has its own
        log_fd.close()
        BUILD_PID_FILE.write_text(str(proc.pid), encoding="utf-8")

        return {"running": True, "pid": proc.pid, "mode": mode}
    except OSError as exc:
        return {"error": f"Failed to start build: {exc}"}


def stream_build_log():
    """Generator yielding SSE events as build log lines appear.

    Handles missing log file, encoding errors, and multi-line data.
    Yields `event: done` when build finishes.
    """
    offset = 0
    # If no build ever ran, immediately signal done
    if not BUILD_LOG_FILE.is_file() and not _is_build_running()[0]:
        yield "event: done\ndata: no build log available\n\n"
        return

    stale_cycles = 0
    max_stale = 100  # ~30s of no output and no running process → bail

    while True:
        running, _ = _is_build_running()

        try:
            if BUILD_LOG_FILE.is_file():
                with open(BUILD_LOG_FILE, "r", encoding="utf-8", errors="replace") as f:
                    f.seek(offset)
                    new_data = f.read()
                    if new_data:
                        offset = f.tell()
                        stale_cycles = 0
                        for line in new_data.splitlines():
                            # SSE data lines must not contain bare newlines
                            yield f"data: {line}\n\n"
        except OSError:
            pass  # file deleted mid-read; continue

        if not running:
            # Final flush — read anything written between last check and now
            try:
                if BUILD_LOG_FILE.is_file():
                    with open(BUILD_LOG_FILE, "r", encoding="utf-8", errors="replace") as f:
                        f.seek(offset)
                        remaining = f.read()
                        for line in remaining.splitlines():
                            yield f"data: {line}\n\n"
            except OSError:
                pass
            yield "event: done\ndata: build finished\n\n"
            return

        stale_cycles += 1
        if stale_cycles > max_stale:
            yield "event: done\ndata: stream timeout (no output)\n\n"
            return

        time.sleep(0.3)


def cancel_build() -> dict:
    """Cancel a running build. Never raises."""
    running, pid = _is_build_running()
    if not running or pid is None:
        return {"running": False}
    try:
        os.killpg(os.getpgid(pid), signal.SIGTERM)
    except (ProcessLookupError, PermissionError, OSError):
        pass
    BUILD_PID_FILE.unlink(missing_ok=True)
    return {"running": False, "cancelled": True}
