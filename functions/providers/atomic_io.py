from __future__ import annotations

import json
import os
import tempfile
from pathlib import Path
from typing import Any


def atomic_write_json(
    path_value: str | os.PathLike[str],
    payload: Any,
    *,
    indent: int | None = 2,
    mode: int = 0o644,
    preserve_owner: bool = False,
) -> None:
    """Durably replace a JSON file without exposing a partial write."""
    path = Path(path_value)
    if path.is_symlink():
        path = path.resolve(strict=False)
    path.parent.mkdir(parents=True, exist_ok=True)
    try:
        target_stat = path.stat()
        target_mode = target_stat.st_mode & 0o777
    except FileNotFoundError:
        target_stat = None
        target_mode = mode

    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{path.name}.",
        suffix=".tmp",
        dir=path.parent,
    )
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            if preserve_owner and target_stat is not None and os.geteuid() == 0:
                os.fchown(handle.fileno(), target_stat.st_uid, target_stat.st_gid)
            json.dump(payload, handle, indent=indent)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        temporary.chmod(target_mode)
        os.replace(temporary, path)
        try:
            directory_fd = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
        except (AttributeError, OSError):
            return
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    except Exception:
        temporary.unlink(missing_ok=True)
        raise
