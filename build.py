#!/usr/bin/env python3
"""Build helper for the regular CITADEL image."""

from __future__ import annotations

import argparse
import shlex
import subprocess
from pathlib import Path

try:
    import tomllib
except ModuleNotFoundError:  # pragma: no cover
    import tomli as tomllib


DEFAULTS: dict[str, object] = {
    "engine": "podman",
    "image": "localhost/citadel:latest",
    "dockerfile": "Dockerfile",
    "context": ".",
    "base_image": "quay.io/fedora/fedora:43",
    "no_cache": False,
}


def parse_args() -> argparse.Namespace:
    here = Path(__file__).resolve().parent
    parser = argparse.ArgumentParser(description="Build the CITADEL container image.")
    parser.add_argument(
        "--config",
        default=str(here / "build.toml"),
        help="Path to build TOML config (default: CITADEL/build.toml).",
    )
    parser.add_argument(
        "--engine",
        default=None,
        choices=["podman", "docker"],
        help="Container build engine (overrides config).",
    )
    parser.add_argument(
        "--image",
        default=None,
        help="Target image tag (overrides config).",
    )
    parser.add_argument(
        "--dockerfile",
        default=None,
        help="Path to Dockerfile (overrides config).",
    )
    parser.add_argument(
        "--context",
        default=None,
        help="Build context path (overrides config).",
    )
    parser.add_argument(
        "--base-image",
        dest="base_image",
        default=None,
        help="Base image for Dockerfile ARG BASE_IMAGE (overrides config).",
    )
    parser.add_argument(
        "--no-cache",
        dest="no_cache",
        action="store_true",
        default=None,
        help="Build without cache (overrides config).",
    )
    parser.add_argument(
        "--cache",
        dest="no_cache",
        action="store_false",
        help="Force cache usage (overrides config).",
    )
    return parser.parse_args()


def load_build_config(path: Path) -> dict[str, object]:
    if not path.exists():
        return {}
    with path.open("rb") as fh:
        parsed = tomllib.load(fh)
    build_cfg = parsed.get("build", {})
    if not isinstance(build_cfg, dict):
        raise SystemExit(f"[build] invalid config: [build] section missing or not a table in {path}")
    return build_cfg


def resolve_value(cli_value: object, cfg: dict[str, object], key: str) -> object:
    if cli_value is not None:
        return cli_value
    if key in cfg:
        return cfg[key]
    return DEFAULTS[key]


def resolve_path(raw_value: object, base_dir: Path) -> Path:
    value = str(raw_value)
    path = Path(value)
    if not path.is_absolute():
        path = base_dir / path
    return path.resolve()


def main() -> int:
    args = parse_args()
    here = Path(__file__).resolve().parent
    config_path = Path(args.config).expanduser().resolve()
    cfg = load_build_config(config_path)

    engine = str(resolve_value(args.engine, cfg, "engine"))
    if engine not in {"podman", "docker"}:
        raise SystemExit(f"[build] invalid engine: {engine} (expected podman or docker)")

    image_raw = str(resolve_value(args.image, cfg, "image"))
    image = image_raw.lower()
    dockerfile = resolve_path(resolve_value(args.dockerfile, cfg, "dockerfile"), here)
    context = resolve_path(resolve_value(args.context, cfg, "context"), here)
    base_image = str(resolve_value(args.base_image, cfg, "base_image"))
    no_cache = bool(resolve_value(args.no_cache, cfg, "no_cache"))

    print(f"[build] config: {config_path}")
    print(f"[build] engine: {engine}")
    if image != image_raw:
        print(f"[build] note: image normalized to lowercase: {image}")
    print(f"[build] image: {image}")
    print(f"[build] base_image: {base_image}")
    print(f"[build] dockerfile: {dockerfile}")
    print(f"[build] context: {context}")
    print(f"[build] no-cache: {'yes' if no_cache else 'no'}")

    cmd = [
        engine,
        "build",
        "-f",
        str(dockerfile),
        "-t",
        image,
        "--build-arg",
        f"BASE_IMAGE={base_image}",
    ]
    if no_cache:
        cmd.append("--no-cache")
    cmd.append(str(context))

    print("[build] cmd:", " ".join(shlex.quote(part) for part in cmd))
    subprocess.run(cmd, check=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

