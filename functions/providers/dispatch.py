#!/usr/bin/env python3
from __future__ import annotations

import argparse
import os
import re
import subprocess
import sys
from pathlib import Path
from common import now_iso, read_json, write_json, adding
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from runtime_state import provider_output


PROVIDER_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*$")


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
    parser.add_argument(
        "--routes-dir",
        help=(
            "Optional runtime root for routes.json or export status.json files. "
            "Provider code and configuration remain in --enabled-dir."
        ),
    )
    parser.add_argument("--tailscale-file", required=True)
    parser.add_argument(
        "--provider",
        action="append",
        default=[],
        help="Reconcile only this enabled provider ID (repeatable).",
    )
    parser.add_argument(
        "--strict",
        action="store_true",
        help="Return non-zero when a requested provider is missing or fails.",
    )
    args = parser.parse_args()

    provider_dirs = discover_enabled_provider_dirs(args.enabled_dir)
    project_root = Path(args.enabled_dir).absolute().parent.parent
    cloudflare_family = {"cloudflare", "CLOUDFLARE-API"}
    all_provider_dirs = list(provider_dirs)
    requested = []
    for provider_id in args.provider:
        if not PROVIDER_ID.fullmatch(provider_id):
            parser.error(f"invalid provider ID: {provider_id!r}")
        if provider_id not in requested:
            requested.append(provider_id)
    if requested:
        by_id = {
            os.path.basename(provider_dir): provider_dir
            for provider_dir in provider_dirs
        }
        provider_dirs = [
            by_id[provider_id]
            for provider_id in requested
            if provider_id in by_id
        ]
        if cloudflare_family.intersection(requested):
            provider_dirs += [directory for directory in all_provider_dirs
                              if Path(directory).name in cloudflare_family and directory not in provider_dirs]

    cleanup_hint = (project_root / "CITADEL_DATA/cloudflare-api/runtime.json").is_file()
    synthetic_cleanup = None
    if cleanup_hint and not requested and not any(Path(directory).name in cloudflare_family for directory in provider_dirs):
        synthetic_cleanup = str(project_root / "extensions/enabled/cloudflare")
        provider_dirs.append(synthetic_cleanup)
    cloudflare_run = None

    previous_state = read_json(args.state_file, {}) if adding() or requested else {}
    state = {
        "generated_at": now_iso(),
        "enabled_providers": [],
        "considered_providers": [],
        "available_providers": [],
        "enabled_exports": [],
        "considered_exports": [],
        "available_exports": [],
        "providers": {},
        "errors": [],
    }
    missing = [
        provider_id
        for provider_id in requested
        if not any(
            os.path.basename(provider_dir) == provider_id
            for provider_dir in provider_dirs
        )
    ]
    for provider_id in missing:
        state["errors"].append(
            f"Requested provider is not enabled: {provider_id}"
        )

    if not provider_dirs:
        if not requested:
            state["errors"].append("No extensions in extensions/enabled")
        write_json(args.state_file, state)
        if requested:
            print("  no requested enabled providers found")
        else:
            print("  no enabled extensions found")
        return 1 if args.strict and state["errors"] else 0

    this_dir = os.path.dirname(os.path.abspath(__file__))

    for provider_dir in provider_dirs:
        provider_id = os.path.basename(provider_dir)
        kind = "provider"
        try:
            if not PROVIDER_ID.fullmatch(provider_id):
                raise ValueError(f"Invalid provider ID: {provider_id!r}")
            if not Path(provider_dir).resolve().is_relative_to(Path(args.enabled_dir).resolve()):
                raise ValueError("Extension directory escapes enabled directory")
            ext_payload = read_json(os.path.join(provider_dir, "extension.json"), {})
            if not isinstance(ext_payload, dict):
                raise ValueError("Invalid extension manifest")
            kind = ext_payload.get("kind", "provider")
            if kind not in ("provider", "export"):
                raise ValueError(f"Unknown extension kind: {kind!r}")
            provider_impl = ext_payload.get("provider", provider_id)
            if not isinstance(provider_impl, str) or not PROVIDER_ID.fullmatch(provider_impl):
                raise ValueError(f"Invalid provider implementation: {provider_impl!r}")
            script_dir = Path(this_dir) if kind == "provider" else Path(this_dir).parent / "exporters"
            script_path = str(script_dir / f"{provider_impl}.py")
            if Path(script_path).resolve().parent != script_dir.resolve():
                raise ValueError("Provider script escapes implementation directory")
            project = Path(args.enabled_dir).absolute().parent.parent
            output = provider_output(project, provider_id, kind)
            if args.routes_dir:
                output = Path(args.routes_dir).absolute() / output.name
            if output.is_symlink():
                raise ValueError("Extension output must be a direct file, not a symlink")
            routes_out = str(output)
        except (ValueError, OSError, RuntimeError) as error:
            state["errors"].append(f"Provider {provider_id}: {error}")
            state["providers"][provider_id] = {
                "kind": kind, "status": "error", "considered": False, "available": False,
            }
            print(f"  {provider_id}: {error}")
            continue

        cleanup_only = provider_dir == synthetic_cleanup or (
            cleanup_hint and provider_id in cloudflare_family and ext_payload.get("enabled") is False)
        if ext_payload.get("enabled") is False and not cleanup_only:
            state["providers"][provider_id] = {
                "kind": kind, "status": "disabled", "considered": False, "available": False,
            }
            continue
        category = "exports" if kind == "export" else "providers"
        if not cleanup_only:
            state[f"enabled_{category}"].append(provider_id)
        os.makedirs(os.path.dirname(routes_out), exist_ok=True)

        if not os.path.isfile(script_path):
            state["errors"].append(f"Missing provider script: {script_path}")
            state["providers"][provider_id] = {
                "script": script_path,
                "provider_impl": provider_impl,
                "kind": kind,
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

        if provider_id in cloudflare_family and cloudflare_run is not None:
            run_res = cloudflare_run
        else:
            run_res = subprocess.run(cmd, capture_output=True, text=True, check=False)
            if provider_id in cloudflare_family:
                cloudflare_run = run_res

        routes_payload = read_json(routes_out, {})
        if not isinstance(routes_payload, dict):
            routes_payload = {"errors": ["Invalid extension output"]}
        if kind == "export" and (
            routes_payload.get("kind") != "export"
            or routes_payload.get("services") != {}
            or not isinstance(routes_payload.get("artifacts"), list)
            or not isinstance(routes_payload.get("errors"), list)
            or not isinstance(routes_payload.get("considered"), bool)
            or not isinstance(routes_payload.get("available"), bool)
            or (not routes_payload.get("considered") and
                (routes_payload.get("available") or routes_payload.get("artifacts")))
        ):
            routes_payload = {"errors": ["Invalid export status.json"]}
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
        if "base_url" in routes_payload and routes_payload.get("base_url"):
            meta.append(f"base={routes_payload.get('base_url')}")
        if "generated_file" in routes_payload and routes_payload.get("generated_file"):
            meta.append(f"file={routes_payload.get('generated_file')}")
        meta_text = f" meta[{', '.join(meta)}]" if meta else ""

        if considered:
            state[f"considered_{category}"].append(provider_id)
        if available:
            state[f"available_{category}"].append(provider_id)

        state["providers"][provider_id] = {
            "script": script_path,
            "provider_impl": provider_impl,
            "kind": kind,
            "status": "ok" if run_res.returncode == 0 and not routes_payload.get("errors") else "error",
            "returncode": run_res.returncode,
            "considered": considered,
            "available": available,
            "label": label,
            "routes_count": routes_count,
            "stderr": (run_res.stderr or "").strip()[-800:],
        }
        if kind == "export":
            state["providers"][provider_id]["artifacts"] = routes_payload.get("artifacts", [])
            for key in ("generated_file", "mappings_count"):
                if key in routes_payload:
                    state["providers"][provider_id][key] = routes_payload[key]

        print(
            f"  {provider_id:<12} considered={yn(considered)} "
            f"available={yn(available)} routes={routes_count} label={label!r}{meta_text}"
        )

        if run_res.returncode != 0:
            state["errors"].append(f"Provider {provider_id} failed")
            print(f"    error: provider script failed (rc={run_res.returncode})")

        route_warnings = routes_payload.get("warnings", [])
        if isinstance(route_warnings, list):
            for warning in route_warnings:
                if warning:
                    print(f"    warn: {provider_id}: {warning}")

        route_errors = routes_payload.get("errors", [])
        if isinstance(route_errors, list):
            for err in route_errors:
                if err:
                    message = f"Provider {provider_id}: {err}"
                    state["errors"].append(message)
                    print(f"    error: {provider_id}: {err}")

        if run_res.stderr and run_res.returncode != 0:
            stderr_lines = [
                line.strip()
                for line in run_res.stderr.strip().splitlines()
                if line.strip()
            ]
            for line in stderr_lines:
                message = f"Provider {provider_id}: {line}"
                if message not in state["errors"]:
                    state["errors"].append(message)
                print(f"    stderr: {line}")

    if adding() or requested:
        refreshed = set(state["providers"]) | set(requested)
        state["providers"] = {**previous_state.get("providers", {}), **state["providers"]}
        for key in ("enabled_providers", "considered_providers", "available_providers",
                    "enabled_exports", "considered_exports", "available_exports"):
            state[key] = list(dict.fromkeys([pid for pid in previous_state.get(key, []) if pid not in refreshed] + state[key]))
        # Keep failures for untouched providers, but discard stale failures for
        # providers that this run has reconciled successfully.
        for error in previous_state.get("errors", []):
            match = re.match(r"Provider ([A-Za-z0-9._-]+)(?: |:)", error)
            if match and match[1] not in refreshed and error not in state["errors"]:
                state["errors"].append(error)
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
    return 1 if args.strict and state["errors"] else 0


if __name__ == "__main__":
    raise SystemExit(main())
