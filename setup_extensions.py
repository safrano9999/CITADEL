#!/usr/bin/env python3
"""Manage Citadel extensions based on environment variables.

Runs at container startup before supervisord.
- localhost is always enabled
- tailscale is enabled only if CITADEL_ENABLE_TAILSCALE=1
- all others stay disabled
"""
from pathlib import Path
from python_header import get_bool

EXT = Path(__file__).resolve().parent / "extensions"
ENABLED = EXT / "enabled"
DISABLED = EXT / "disabled"


def move(name: str, to_enabled: bool) -> None:
    src = (DISABLED if to_enabled else ENABLED) / name
    dst = (ENABLED if to_enabled else DISABLED) / name
    if src.is_dir() and not dst.exists():
        src.rename(dst)
        print(f"[extensions] {'enabled' if to_enabled else 'disabled'} {name}")


def main() -> None:
    ENABLED.mkdir(parents=True, exist_ok=True)
    DISABLED.mkdir(parents=True, exist_ok=True)

    ts = get_bool("CITADEL_ENABLE_TAILSCALE")

    move("tailscale", to_enabled=ts)
    move("subnet", to_enabled=False)


if __name__ == "__main__":
    main()
