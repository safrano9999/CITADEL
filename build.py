#!/usr/bin/env python3
"""Build helper for the regular CITADEL image."""

from __future__ import annotations

import argparse
import shlex
import subprocess
from pathlib import Path


def parse_args() -> argparse.Namespace:
    here = Path(__file__).resolve().parent
    parser = argparse.ArgumentParser(description="Build the CITADEL container image.")
    parser.add_argument(
        "--engine",
        default="podman",
        choices=["podman", "docker"],
        help="Container build engine (default: podman).",
    )
    parser.add_argument(
        "--image",
        default="localhost/citadel:latest",
        help="Target image tag (default: localhost/citadel:latest).",
    )
    parser.add_argument(
        "--dockerfile",
        default=str(here / "Dockerfile"),
        help="Path to Dockerfile (default: CITADEL/Dockerfile).",
    )
    parser.add_argument(
        "--context",
        default=str(here),
        help="Build context path (default: CITADEL directory).",
    )
    parser.add_argument(
        "--no-cache",
        action="store_true",
        help="Build without cache.",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()

    image = args.image.lower()
    dockerfile = Path(args.dockerfile).resolve()
    context = Path(args.context).resolve()

    print(f"[build] engine: {args.engine}")
    if image != args.image:
        print(f"[build] note: image normalized to lowercase: {image}")
    print(f"[build] image: {image}")
    print(f"[build] dockerfile: {dockerfile}")
    print(f"[build] context: {context}")
    print(f"[build] no-cache: {'yes' if args.no_cache else 'no'}")

    cmd = [args.engine, "build", "-f", str(dockerfile), "-t", image]
    if args.no_cache:
        cmd.append("--no-cache")
    cmd.append(str(context))

    print("[build] cmd:", " ".join(shlex.quote(part) for part in cmd))
    subprocess.run(cmd, check=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

