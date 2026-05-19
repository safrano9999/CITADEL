"""
Shared environment bootstrap for all REPOS programs.

Usage - add this as first import in every entrypoint:

    from python_header import env, get, get_int, get_port

How it works:
  1. Loads config.yaml defaults from the calling script's directory
  2. Loads auxiliary *.env files, then .env
  3. inject_overwrite decides whether injected process env wins over file values
  4. If HOST was injected by the process, the web server binds 0.0.0.0
  5. All values are accessible via env dict, get(), or os.environ

Requires: pip install python-dotenv
"""

import os
from pathlib import Path

from dotenv import dotenv_values

_process_env = dict(os.environ)
_process_env_has_host = "HOST" in _process_env


def _find_project_dir() -> Path:
    """Walk the call stack to find the project directory."""
    import inspect
    for frame_info in inspect.stack():
        caller_file = frame_info.filename
        if caller_file and not caller_file.startswith("<"):
            directory = Path(caller_file).resolve().parent
            if (directory / "config.yaml").exists() or (directory / ".env").exists():
                return directory
    return Path.cwd()


def _clean_value(value: str) -> str:
    value = value.strip()
    if value in {"", "null", "Null", "NULL", "~"}:
        return ""
    if len(value) >= 2 and value[0] == value[-1] and value[0] in {"'", '"'}:
        return value[1:-1]
    return value


def _split_yaml_value(line: str) -> tuple[str, str]:
    key, _, value = line.partition(":")
    return key.strip(), _clean_value(value)


def _as_bool(value: str, default: bool) -> bool:
    if not value:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


def _apply_values(values: dict[str, str], overwrite: bool) -> None:
    for key, value in values.items():
        if not key:
            continue
        if overwrite or key not in os.environ:
            os.environ[key] = value


def _read_config_yaml(path: Path) -> tuple[bool, dict[str, str]]:
    inject_overwrite = True
    values: dict[str, str] = {}
    if not path.exists():
        return inject_overwrite, values

    scope = ""
    service = ""
    section = ""
    ports: dict[str, str] = {}
    env_ports: dict[str, str] = {}

    for raw_line in path.read_text(encoding="utf-8").splitlines():
        line = raw_line.split("#", 1)[0].rstrip()
        if not line.strip():
            continue
        indent = len(line) - len(line.lstrip(" "))
        text = line.strip()

        if indent == 0:
            service = ""
            section = ""
            key, value = _split_yaml_value(text)
            if key == "inject_overwrite":
                inject_overwrite = _as_bool(value, True)
                scope = ""
            elif text == "services:":
                scope = "services"
            else:
                scope = ""
            continue

        if scope != "services":
            continue
        if indent == 2 and text.endswith(":"):
            service = text[:-1]
            section = ""
            continue
        if service and indent == 4 and text.endswith(":"):
            section = text[:-1]
            continue
        if not service or indent != 6 or ":" not in text:
            continue

        key, value = _split_yaml_value(text)
        if section == "webui":
            if key == "host" and value:
                values.setdefault("HOST", value)
            elif key == "port" and value:
                ports[service] = value
                if service in env_ports:
                    values.setdefault(env_ports[service], value)
            elif key == "env_port" and value:
                env_ports[service] = value
                if service in ports:
                    values.setdefault(value, ports[service])
        elif section == "env":
            values.setdefault(key, value)

    return inject_overwrite, values


def _read_env_files(env_dir: Path) -> dict[str, str]:
    values: dict[str, str] = {}
    files = sorted(p for p in env_dir.glob("*.env") if p.name != ".env")
    dot_env = env_dir / ".env"
    if dot_env.exists():
        files.append(dot_env)
    for path in files:
        for key, value in dotenv_values(path).items():
            values[key] = "" if value is None else str(value)
    return values


_env_dir = _find_project_dir()
_inject_overwrite, _config_values = _read_config_yaml(_env_dir / "config.yaml")
_file_values = dict(_config_values)
_file_values.update(_read_env_files(_env_dir))
_apply_values(_file_values, overwrite=not _inject_overwrite)

if _inject_overwrite:
    _apply_values(_process_env, overwrite=True)

if _process_env_has_host:
    os.environ["HOST"] = "0.0.0.0"


def get(key: str, default: str = "") -> str:
    """Get env var as string."""
    return os.environ.get(key, default).strip()


def get_int(key: str, default: int = 0) -> int:
    """Get env var as int, fallback to default on bad input."""
    raw = os.environ.get(key, "").strip()
    if not raw:
        return default
    try:
        return int(raw)
    except (ValueError, TypeError):
        return default


def get_bool(key: str, default: bool = False) -> bool:
    """Get env var as bool (1/true/yes/on -> True)."""
    raw = os.environ.get(key, "").strip().lower()
    if not raw:
        return default
    return raw in {"1", "true", "yes", "on"}


def get_port(key: str, default: int = 8080) -> int:
    """Get env var as validated port number (1-65535)."""
    port = get_int(key, default)
    if not (1 <= port <= 65535):
        raise ValueError(f"{key}={port} is not a valid port (1-65535)")
    return port


# Snapshot for dict-style access: env["KEY"] or env.get("KEY", "default")
env = dict(os.environ)
