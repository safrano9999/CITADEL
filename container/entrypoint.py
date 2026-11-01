#!/usr/bin/env python3
"""Alpine bootstrap: optional tunnel clients, WebUI, then one scan. No systemd."""
import json
import os
from pathlib import Path
import shlex
import shutil
import signal
import subprocess
import sys
import time

ROOT = Path("/opt/safrano9999/CITADEL")


class Runtime:
    def __init__(self):
        self.children = []

    def start(self, *command):
        child = subprocess.Popen(command)
        self.children.append(child)
        return child

    def check(self):
        if any(child.poll() is not None for child in self.children):
            raise RuntimeError("a supervised service exited")

    def wait_ready(self, probe, seconds=40):
        deadline = time.monotonic() + seconds
        while time.monotonic() < deadline:
            self.check()
            if probe():
                return
            time.sleep(0.2)
        raise RuntimeError("service readiness timed out")

    def close(self):
        for child in reversed(self.children):
            if child.poll() is None:
                child.terminate()
        for child in self.children:
            try:
                child.wait(timeout=5)
            except subprocess.TimeoutExpired:
                child.kill()
                child.wait()


def enabled(root, provider):
    path = root / "extensions/enabled" / provider / "extension.json"
    return path.is_file() and json.loads(path.read_text()).get("enabled") is not False


def configure_optional_clients(root):
    # Image-local extension state only; absent credentials must not start clients
    # indirectly through the scanner either. Recreating the container resets this.
    for provider, keys in (("tailscale", ("TS_AUTHKEY",)),
                           ("cloudflare", ("CLOUDFLARE_API_TOKEN", "CLOUDFLARE_TUNNEL_TOKEN"))):
        if not any(os.environ.get(key, "").strip() for key in keys):
            source = root / "extensions/enabled" / provider
            if source.exists():
                shutil.move(source, root / "extensions/disabled" / provider)


def tailscale_state():
    result = subprocess.run(["tailscale", "status", "--json"], capture_output=True,
                            text=True, timeout=3)
    try:
        return json.loads(result.stdout).get("BackendState", "")
    except (ValueError, AttributeError):
        return ""


def start_tailscale(runtime, root):
    if not os.environ.get("TS_AUTHKEY", "").strip() or not enabled(root, "tailscale"):
        return
    # A mounted host socket is reused, never replaced or owned by this process.
    external = Path("/var/run/tailscale/tailscaled.sock").exists()
    if not external:
        state_dir = root / "CITADEL_TAILSCALE"
        state_dir.mkdir(mode=0o700, exist_ok=True)
        command = ["tailscaled", f"--statedir={state_dir}"]
        if os.environ.get("TS_USERSPACE") == "1":
            command.append("--tun=userspace-networking")
        runtime.start(*command)
    runtime.wait_ready(tailscale_state)
    state = tailscale_state()
    if not external and (state in ("Running", "Stopped") or os.environ.get("TS_AUTHKEY")):
        command = ["tailscale", "up", "--timeout=30s"]
        command.extend(shlex.split(os.environ.get("TS_EXTRA_ARGS", "")))
        if os.environ.get("TS_HOSTNAME"):
            command.append("--hostname=" + os.environ["TS_HOSTNAME"])
        if state not in ("Running", "Stopped") and os.environ.get("TS_AUTHKEY"):
            command.append("--auth-key=" + os.environ["TS_AUTHKEY"])
        # Do not include argv in an exception: the first login can contain a key.
        if subprocess.run(command, timeout=35).returncode:
            raise RuntimeError("Tailscale login/state restore failed")
        state = tailscale_state()
    if state == "Running":
        if subprocess.run(["/usr/local/bin/tailscale-serve-reset.sh"], timeout=15).returncode:
            raise RuntimeError("Tailscale Serve reset failed")
    else:
        print("[citadel] Tailscale is not authenticated; WebUI remains available", flush=True)


def start_cloudflare(runtime, root):
    if not enabled(root, "cloudflare"):
        return
    token = os.environ.get("CLOUDFLARE_TUNNEL_TOKEN", "")
    if not token and all(os.environ.get(key) for key in (
            "CLOUDFLARE_API_TOKEN", "CITADEL_CLOUDFLARE_ACCOUNT_ID", "CITADEL_CLOUDFLARE_TUNNEL_ID")):
        from cloudflare_api import CloudflareAPI
        token = CloudflareAPI(os.environ["CLOUDFLARE_API_TOKEN"]).tunnel_token(
            os.environ["CITADEL_CLOUDFLARE_ACCOUNT_ID"], os.environ["CITADEL_CLOUDFLARE_TUNNEL_ID"])
    if token:
        # Cloudflared's token file is ephemeral; never log it or put it in argv.
        path = Path("/run/citadel/cloudflared.token")
        with open(path, "w", opener=lambda name, flags: os.open(name, flags, 0o600)) as handle:
            handle.write(token)
        runtime.start("cloudflared", "tunnel", "--no-autoupdate", "run", "--token-file", str(path))


def main():
    os.chdir(ROOT)
    sys.path[:0] = [str(ROOT), str(ROOT / "functions"), str(ROOT / "functions/providers")]
    import python_header  # Load shared config; never source/eval user input.
    from runtime_state import prepare_image
    from webui_transport import listener_ready
    prepare_image(ROOT)
    Path("/run/citadel").mkdir(parents=True, exist_ok=True)
    runtime = Runtime()
    def stop(*_):
        raise SystemExit(0)
    signal.signal(signal.SIGTERM, stop)
    signal.signal(signal.SIGINT, stop)
    scan = None
    try:
        configure_optional_clients(ROOT)
        start_tailscale(runtime, ROOT)
        start_cloudflare(runtime, ROOT)
        runtime.start(sys.executable, "-E", str(ROOT / "webui.py"))
        runtime.wait_ready(listener_ready)
        scan = subprocess.Popen(["/bin/bash", str(ROOT / "scan.sh")])
        while True:
            runtime.check()
            if scan is not None and scan.poll() is not None:
                print(f"[citadel] initial scan finished: {scan.returncode}", flush=True)
                scan = None
            time.sleep(0.5)
    finally:
        if scan is not None:
            scan.terminate()
            try:
                scan.wait(timeout=5)
            except subprocess.TimeoutExpired:
                scan.kill()
                scan.wait()
        runtime.close()


if __name__ == "__main__":
    try:
        main()
    except Exception:
        # Do not print exceptions containing token-bearing subprocess argv.
        print("[citadel] bootstrap/service failed; inspect preceding service logs", file=sys.stderr)
        sys.exit(1)
