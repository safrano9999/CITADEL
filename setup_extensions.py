#!/usr/bin/env python3
"""Citadel setup — single script for all config generation and runtime.

Modes:
  --generate    Configure/build time on host: generate Caddyfile + certs
  --runtime     Container start: setup extensions, certs, caddyfile, start caddy
  --tailscale   Container start: bring up tailscale, update Caddyfile, reload caddy
"""
import argparse
import json
import subprocess
import sys
import time
from pathlib import Path
from python_header import get, get_bool, get_int

ROOT = Path(__file__).resolve().parent
EXT = ROOT / "extensions"
ENABLED = EXT / "enabled"
DISABLED = EXT / "disabled"
CERT_DIR = ROOT / "certs"
CADDYFILE = Path("/etc/caddy/Caddyfile")
CADDYFILES_DIR = ROOT / "CADDYFILES"

TS_STATE_DIR = Path(get("TS_STATE_DIR", "/var/lib/tailscale"))
TS_CERT_DIR = TS_STATE_DIR / "certs"
TS_SOCKET = Path("/var/run/tailscale/tailscaled.sock")


# ── Extensions ────────────────────────────────────────────────────────────

def move_ext(name: str, to_enabled: bool) -> None:
    src = (DISABLED if to_enabled else ENABLED) / name
    dst = (ENABLED if to_enabled else DISABLED) / name
    if src.is_dir() and not dst.exists():
        src.rename(dst)
        print(f"[ext] {'enabled' if to_enabled else 'disabled'} {name}")


# ── Caddyfile ─────────────────────────────────────────────────────────────

def _server_block(listen: str, tls_cert: str, tls_key: str,
                  citadel_root: str = "/opt/citadel") -> str:
    return (
        f"{listen} {{\n"
        f"\ttls {tls_cert} {tls_key}\n"
        f"\n"
        f"\troute {{\n"
        f"\t\timport {citadel_root}/CADDYFILES/*.caddy\n"
        f"\n"
        f"\t\troot * {citadel_root}\n"
        f"\t\tphp_fastcgi unix//run/php-fpm/www.sock {{\n"
        f"\t\t\theader_up Accept-Encoding identity\n"
        f"\t\t}}\n"
        f"\t\tfile_server\n"
        f"\t}}\n"
        f"}}"
    )


def write_caddyfile(port: int, target: Path) -> None:
    content = "{\n\tauto_https off\n}\n\n"
    content += _server_block(
        f"https://:{port}",
        f"{CERT_DIR}/local.pem",
        f"{CERT_DIR}/local-key.pem",
    )
    content += "\n"
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(content)
    print(f"[setup] Caddyfile: port={port}")


# ── Certs ─────────────────────────────────────────────────────────────────

def generate_local_cert() -> None:
    CERT_DIR.mkdir(parents=True, exist_ok=True)
    key, cert = CERT_DIR / "local-key.pem", CERT_DIR / "local.pem"
    if cert.exists() and key.exists():
        return
    subprocess.run([
        "openssl", "req", "-x509",
        "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:prime256v1",
        "-days", "3650", "-nodes",
        "-keyout", str(key), "-out", str(cert),
        "-subj", "/CN=citadel",
        "-addext", "subjectAltName=DNS:localhost,IP:127.0.0.1",
    ], capture_output=True, check=True)
    print("[setup] self-signed cert generated")


# ── Generate mode (runs on host at configure time) ───────────────────────

def do_generate() -> None:
    ts_enabled = get_bool("CITADEL_ENABLE_TAILSCALE")
    port = get_int("CITADEL_PORT", 1000)
    out_dir = Path(get("CITADEL_GENERATE_DIR", str(ROOT / "generated")))
    out_dir.mkdir(parents=True, exist_ok=True)

    ENABLED.mkdir(parents=True, exist_ok=True)
    DISABLED.mkdir(parents=True, exist_ok=True)
    move_ext("tailscale", to_enabled=ts_enabled)
    move_ext("subnet", to_enabled=False)

    generate_local_cert()
    write_caddyfile(port, out_dir / "Caddyfile")
    print("[setup] generate done")


# ── Runtime mode (runs in container, replaces citadel-caddy.sh) ──────────

def do_runtime() -> None:
    ts_enabled = get_bool("CITADEL_ENABLE_TAILSCALE")
    port = get_int("CITADEL_PORT", 1000)

    ENABLED.mkdir(parents=True, exist_ok=True)
    DISABLED.mkdir(parents=True, exist_ok=True)
    CADDYFILES_DIR.mkdir(parents=True, exist_ok=True)

    move_ext("tailscale", to_enabled=ts_enabled)
    move_ext("subnet", to_enabled=False)

    generate_local_cert()

    # Write Caddyfile if not already present (from build)
    if not CADDYFILE.exists():
        write_caddyfile(port, CADDYFILE)

    # Start caddy (exec — replaces this process)
    print(f"[setup] starting caddy on :{port}")
    import os
    os.execvp("caddy", ["caddy", "run", "--config", str(CADDYFILE)])


# ── Tailscale mode (runs in container after tailscaled is up) ────────────

def do_tailscale() -> None:
    if not get_bool("CITADEL_ENABLE_TAILSCALE"):
        return

    TS_STATE_DIR.mkdir(parents=True, exist_ok=True)
    TS_CERT_DIR.mkdir(parents=True, exist_ok=True)
    Path("/var/run/tailscale").mkdir(parents=True, exist_ok=True)

    # Wait for tailscaled
    for _ in range(60):
        if TS_SOCKET.is_socket():
            break
        time.sleep(1)
    else:
        print("[tailscale] socket not available")
        return

    # tailscale up
    args = ["tailscale", "up"]
    authkey = get("TS_AUTHKEY")
    hostname = get("TS_HOSTNAME")
    if authkey:
        args.append(f"--authkey={authkey}")
    if hostname:
        args.append(f"--hostname={hostname}")

    r = subprocess.run(args, capture_output=True, text=True)
    if r.returncode != 0:
        print(f"[tailscale] up failed: {r.stderr.strip()}")
        return

    # Wait for Running state
    for _ in range(90):
        try:
            out = subprocess.run(
                ["tailscale", "status", "--json"],
                capture_output=True, text=True, timeout=5,
            )
            if json.loads(out.stdout).get("BackendState") == "Running":
                break
        except Exception:
            pass
        time.sleep(2)

    # Get domain
    try:
        out = subprocess.run(
            ["tailscale", "status", "--json"],
            capture_output=True, text=True, timeout=5,
        )
        domain = json.loads(out.stdout).get("Self", {}).get("DNSName", "").rstrip(".")
    except Exception:
        domain = ""

    if not domain:
        print("[tailscale] no DNS name")
        return

    print(f"[tailscale] domain: {domain}")

    # Fetch cert
    subprocess.run([
        "tailscale", "cert",
        f"--cert-file={TS_CERT_DIR}/cert.pem",
        f"--key-file={TS_CERT_DIR}/key.pem",
        domain,
    ], capture_output=True)

    # Append tailscale block to Caddyfile + reload
    block = "\n" + _server_block(
        f"{domain}:443",
        f"{TS_CERT_DIR}/cert.pem",
        f"{TS_CERT_DIR}/key.pem",
    ) + "\n"
    with open(CADDYFILE, "a") as f:
        f.write(block)

    subprocess.run(["caddy", "reload", "--config", str(CADDYFILE)],
                    capture_output=True)
    print(f"[tailscale] caddy reloaded with {domain}:443")


# ── Main ──────────────────────────────────────────────────────────────────

def main() -> int:
    p = argparse.ArgumentParser()
    p.add_argument("--generate", action="store_true")
    p.add_argument("--runtime", action="store_true")
    p.add_argument("--tailscale", action="store_true")
    args = p.parse_args()

    if not any([args.generate, args.runtime, args.tailscale]):
        args.generate = True

    if args.generate:
        do_generate()
    if args.runtime:
        do_runtime()
    if args.tailscale:
        do_tailscale()

    return 0


if __name__ == "__main__":
    sys.exit(main())
