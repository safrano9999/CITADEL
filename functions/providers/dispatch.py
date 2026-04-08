#!/usr/bin/env python3
from __future__ import annotations

import argparse
import os
import subprocess
import sys
from common import now_iso, read_json, write_json


def discover_enabled_provider_dirs(enabled_dir: str) -> list[str]:
    if not os.path.isdir(enabled_dir):
        return []
    dirs = []
    for name in sorted(os.listdir(enabled_dir)):
        full = os.path.join(enabled_dir, name)
        if os.path.isdir(full):
            dirs.append(full)
    return dirs


def yn(flag: bool) -> str:
    return "yes" if flag else "no"


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--enabled-dir", required=True)
    parser.add_argument("--services-file", required=True)
    parser.add_argument("--cache-dir", required=True)
    parser.add_argument("--config-ini", required=True)
    parser.add_argument("--state-file", required=True)
    parser.add_argument("--tailscale-file", required=True)
    args = parser.parse_args()

    provider_dirs = discover_enabled_provider_dirs(args.enabled_dir)

    state = {
        "generated_at": now_iso(),
        "enabled_providers": [],
        "considered_providers": [],
        "available_providers": [],
        "providers": {},
        "errors": [],
    }

    if not provider_dirs:
        state["errors"].append("No extensions in extensions/enabled")
        write_json(args.state_file, state)
        print("  no enabled extensions found")
        return 0

    this_dir = os.path.dirname(os.path.abspath(__file__))

    for provider_dir in provider_dirs:
        provider_id = os.path.basename(provider_dir)
        state["enabled_providers"].append(provider_id)

        ext_payload = read_json(os.path.join(provider_dir, "extension.json"), {})
        provider_impl = str(ext_payload.get("provider") or provider_id).strip() or provider_id

        script_path = os.path.join(this_dir, f"{provider_impl}.py")
        routes_out = os.path.join(provider_dir, "routes.json")

        if not os.path.isfile(script_path):
            state["errors"].append(f"Missing provider script: {script_path}")
            state["providers"][provider_id] = {
                "script": script_path,
                "provider_impl": provider_impl,
                "status": "missing",
                "considered": False,
                "available": False,
            }
            print(f"  {provider_id:<12} status=missing considered=no available=no routes=0")
            continue

        cmd = [
            sys.executable,
            script_path,
            "--provider-dir",
            provider_dir,
            "--services-file",
            args.services_file,
            "--cache-dir",
            args.cache_dir,
            "--config-ini",
            args.config_ini,
            "--routes-out",
            routes_out,
            "--tailscale-file",
            args.tailscale_file,
        ]

        run_res = subprocess.run(cmd, capture_output=True, text=True, check=False)

        routes_payload = read_json(routes_out, {})
        considered = bool(routes_payload.get("considered", False))
        available = bool(routes_payload.get("available", False))
        routes_count = len(routes_payload.get("services", {}) or {})
        label = str(routes_payload.get("label") or provider_id)
        meta: list[str] = []
        if "subnet_ip" in routes_payload and routes_payload.get("subnet_ip"):
            meta.append(f"ip={routes_payload.get('subnet_ip')}")
        if "domain" in routes_payload and routes_payload.get("domain"):
            meta.append(f"domain={routes_payload.get('domain')}")
        if "running" in routes_payload:
            meta.append(f"running={yn(bool(routes_payload.get('running')))}")
        if "fetch_enabled" in routes_payload:
            meta.append(f"fetch={yn(bool(routes_payload.get('fetch_enabled')))}")
        if "base_url" in routes_payload and routes_payload.get("base_url"):
            meta.append(f"base={routes_payload.get('base_url')}")
        if "generated_file" in routes_payload and routes_payload.get("generated_file"):
            meta.append(f"file={routes_payload.get('generated_file')}")
        meta_text = f" meta[{', '.join(meta)}]" if meta else ""

        if considered:
            state["considered_providers"].append(provider_id)
        if available:
            state["available_providers"].append(provider_id)

        state["providers"][provider_id] = {
            "script": script_path,
            "provider_impl": provider_impl,
            "status": "ok" if run_res.returncode == 0 else "error",
            "returncode": run_res.returncode,
            "considered": considered,
            "available": available,
            "label": label,
            "routes_count": routes_count,
            "stderr": (run_res.stderr or "").strip()[-800:],
        }

        print(
            f"  {provider_id:<12} considered={yn(considered)} "
            f"available={yn(available)} routes={routes_count} label={label!r}{meta_text}"
        )

        if run_res.returncode != 0:
            state["errors"].append(f"Provider {provider_id} failed")
            print(f"    error: provider script failed (rc={run_res.returncode})")

        route_errors = routes_payload.get("errors", [])
        if isinstance(route_errors, list):
            for err in route_errors:
                if err:
                    print(f"    warn: {provider_id}: {err}")

        if run_res.stderr and run_res.returncode != 0:
            tail = run_res.stderr.strip().splitlines()[-1] if run_res.stderr.strip() else ""
            if tail:
                print(f"    stderr: {tail}")

    write_json(args.state_file, state)
    considered_count = len(state["considered_providers"])
    available_count = len(state["available_providers"])
    total_routes = sum(
        int((state["providers"].get(pid, {}) or {}).get("routes_count", 0))
        for pid in state["enabled_providers"]
    )
    print(
        f"  summary: enabled={len(provider_dirs)} considered={considered_count} "
        f"available={available_count} total_routes={total_routes}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
