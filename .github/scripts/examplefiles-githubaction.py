#!/usr/bin/env python3
# Source of truth: SCRIPTS/githubactions. Generated copies are overwritten.
"""Build the repository's deterministic example-files release archive."""

from __future__ import annotations

import fnmatch
import os
import stat
import subprocess
import sys
import zipfile
from pathlib import Path


EXAMPLE_PATTERNS = (
    "env*example",
    "config*example",
    "container*example",
    "config*.container",
)


def main() -> None:
    result = subprocess.run(
        ["git", "rev-parse", "--show-toplevel"],
        check=True,
        text=True,
        stdout=subprocess.PIPE,
    )
    repository = Path(result.stdout.strip()).resolve()
    github_repository = os.environ.get("GITHUB_REPOSITORY", "")
    repository_name = github_repository.rsplit("/", 1)[-1] or repository.name
    output = repository / f"{repository_name}-examplefiles.zip"

    tracked = subprocess.run(
        ["git", "-C", str(repository), "ls-files", "-z"],
        check=True,
        stdout=subprocess.PIPE,
    ).stdout.split(b"\0")
    files: list[tuple[str, Path]] = []
    for encoded in tracked:
        if not encoded:
            continue
        relative = encoded.decode("utf-8", errors="strict")
        path = repository / relative
        if (
            not any(fnmatch.fnmatchcase(path.name, pattern) for pattern in EXAMPLE_PATTERNS)
            or not path.exists()
            or path.is_symlink()
        ):
            continue
        if not stat.S_ISREG(path.stat().st_mode):
            continue
        files.append((relative, path))

    if not files:
        output.unlink(missing_ok=True)
        print("No tracked configuration example files; skipping archive.")
        return

    with zipfile.ZipFile(
        output,
        mode="w",
        compression=zipfile.ZIP_DEFLATED,
        compresslevel=9,
    ) as archive:
        for relative, path in sorted(files):
            info = zipfile.ZipInfo(relative, date_time=(1980, 1, 1, 0, 0, 0))
            info.compress_type = zipfile.ZIP_DEFLATED
            info.external_attr = (stat.S_IMODE(path.stat().st_mode) & 0o777) << 16
            archive.writestr(info, path.read_bytes())

    print(output.name)


if __name__ == "__main__":
    try:
        main()
    except (OSError, subprocess.SubprocessError, UnicodeError) as error:
        print(f"examplefiles-githubaction: {error}", file=sys.stderr)
        raise SystemExit(1)
