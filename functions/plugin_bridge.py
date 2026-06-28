#!/usr/bin/env python3
"""JSON bridge exposing CITADEL core operations to the OpenClaw plugin."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

import core


def _configure_paths(args: argparse.Namespace) -> None:
    if args.services_path:
        core.SERVICES_FILE = Path(args.services_path).expanduser().resolve()
    if args.policy_path:
        core.PORT_FILTER_FILE = Path(args.policy_path).expanduser().resolve()


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--services-path")
    parser.add_argument("--policy-path")
    subparsers = parser.add_subparsers(dest="operation", required=True)
    subparsers.add_parser("dashboard")
    save_parser = subparsers.add_parser("save-cloudflare-rule")
    save_parser.add_argument("port", type=int)
    args = parser.parse_args()
    _configure_paths(args)

    if args.operation == "dashboard":
        payload = core.build_dashboard()
    else:
        rule = json.load(sys.stdin)
        if not isinstance(rule, dict):
            raise ValueError("Cloudflare rule must be a JSON object.")
        payload = core.save_cloudflare_rule(args.port, rule)

    json.dump(payload, sys.stdout, ensure_ascii=False)
    sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        print(str(exc), file=sys.stderr)
        raise SystemExit(2) from exc
