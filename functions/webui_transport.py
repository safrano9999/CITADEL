"""Transport selection and safe Unix socket ownership for the WebUI."""

from collections.abc import Iterator, Mapping
from contextlib import contextmanager
import os
from pathlib import Path
import socket
import stat
from runtime_state import data_directory

PROJECT_DIR = Path(__file__).resolve().parents[1]


def caddy_directory(root: Path = PROJECT_DIR) -> Path:
    return data_directory(root) / "CADDY"


def tcp_address() -> tuple[str, int]:
    host = os.environ.get("FASTAPI_HOST") or "127.0.0.1"
    port = int(os.environ.get("CITADEL_WEBUI_PORT", "11000") or "11000")
    if not 1 <= port <= 65535:
        raise ValueError("CITADEL_WEBUI_PORT must be 1-65535.")
    return host, port


def _absolute_path(value: str, setting: str) -> Path:
    path = Path(value)
    if "\0" in value or not path.is_absolute() or ".." in path.parts:
        raise ValueError(f"{setting} must be an absolute path without '..'.")
    return path


def unix_socket_path(environment: Mapping[str, str] | None = None) -> Path | None:
    """Return None for TCP, or the validated Unix path, without touching disk.

    Read the environment after python_header has loaded the project's config.
    Only Unix mode consumes socket settings; TCP keeps its existing defaults.
    """
    environment = os.environ if environment is None else environment
    transport = environment.get("CITADEL_WEBUI_TRANSPORT", "").strip() or "tcp"
    if transport == "tcp":
        return None
    if transport != "unix":
        raise ValueError("CITADEL_WEBUI_TRANSPORT must be 'tcp' or 'unix'.")

    value = environment.get("CITADEL_WEBUI_SOCKET", "").strip()
    if not value:
        return caddy_directory() / "citadel.sock"
    if value.startswith("%t/"):
        runtime = _absolute_path(
            environment.get("XDG_RUNTIME_DIR", "").strip() or "/run",
            "XDG_RUNTIME_DIR",
        )
        value = str(runtime) + "/" + value[3:]
    path = _absolute_path(value, "CITADEL_WEBUI_SOCKET")
    if not path.name or value.endswith("/") or value.endswith("/."):
        raise ValueError("CITADEL_WEBUI_SOCKET must name a socket, not a directory.")
    return path


def probe_target() -> list[str]:
    path = unix_socket_path()
    if path is not None:
        return ["unix", str(path)]
    host, port = tcp_address()
    return ["tcp", {"0.0.0.0": "127.0.0.1", "::": "::1"}.get(host, host), str(port)]


def listener_ready() -> bool:
    target = probe_target()
    try:
        if target[0] == "unix":
            with socket.socket(socket.AF_UNIX) as connection:
                connection.settimeout(0.5)
                connection.connect(target[1])
        else:
            with socket.create_connection((target[1], int(target[2])), timeout=0.5):
                pass
        return True
    except OSError:
        return False


@contextmanager
def bind_unix_socket(path: Path) -> Iterator[socket.socket]:
    """Replace an existing Unix socket and bind the WebUI at the same path.

    Create only the immediate socket directory, respecting the caller's umask
    and existing permissions. Missing ancestors must be provisioned separately.
    Regular files, directories and symlinks are not replaced. Clean shutdown
    removes only the socket created by this invocation.
    """
    path.parent.mkdir(mode=0o755, exist_ok=True)
    try:
        existing = path.lstat()
    except FileNotFoundError:
        pass
    else:
        if stat.S_ISSOCK(existing.st_mode):
            path.unlink()
    owned = None
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as listener:
        try:
            listener.bind(str(path))
            owned = path.lstat()
            yield listener
        finally:
            listener.close()
            if owned is not None:
                try:
                    current = path.lstat()
                except FileNotFoundError:
                    pass
                else:
                    if stat.S_ISSOCK(current.st_mode) and (
                        current.st_dev, current.st_ino
                    ) == (owned.st_dev, owned.st_ino):
                        path.unlink()
