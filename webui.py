"""CITADEL FastAPI WebUI."""

import argparse
import hmac
import json
import secrets
import signal
import subprocess
import sys
import threading
import time
from collections import OrderedDict, deque
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent / "functions"))

import uvicorn
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import FileResponse, HTMLResponse
from fastapi.staticfiles import StaticFiles
from jinja2 import Environment, FileSystemLoader, select_autoescape
from starlette.datastructures import MutableHeaders
from starlette.types import Message, Receive, Scope, Send

from python_header import get, get_port  # noqa: F401

import core
import health
from webui_transport import bind_unix_socket, unix_socket_path, probe_target
from runtime_state import prepare_state
from cloudflare_api_access import management_view, save_access, revision


class EditTokenGuard:
    """In-memory per-client brute-force protection for WebUI edit tokens."""

    def __init__(
        self,
        *,
        max_failures: int = 5,
        failure_window: int = 300,
        lock_seconds: int = 900,
        max_clients: int = 2048,
    ):
        self.max_failures = max_failures
        self.failure_window = failure_window
        self.lock_seconds = lock_seconds
        self.max_clients = max_clients
        self._failures: OrderedDict[str, deque[float]] = OrderedDict()
        self._blocked_until: dict[str, float] = {}
        self._lock = threading.Lock()

    def authenticate(
        self,
        client: str,
        supplied: str,
        expected: str,
        *,
        now: float | None = None,
    ) -> tuple[bool, int]:
        if not expected:
            return True, 0

        current = time.monotonic() if now is None else now
        with self._lock:
            blocked_until = self._blocked_until.get(client, 0)
            if blocked_until > current:
                return False, max(1, int(blocked_until - current + 0.999))
            self._blocked_until.pop(client, None)

            if hmac.compare_digest(
                supplied.encode("utf-8"),
                expected.encode("utf-8"),
            ):
                self._failures.pop(client, None)
                return True, 0

            failures = self._failures.setdefault(client, deque())
            cutoff = current - self.failure_window
            while failures and failures[0] <= cutoff:
                failures.popleft()
            failures.append(current)
            self._failures.move_to_end(client)

            if len(failures) >= self.max_failures:
                self._failures.pop(client, None)
                self._blocked_until[client] = current + self.lock_seconds
                while len(self._blocked_until) > self.max_clients:
                    self._blocked_until.pop(next(iter(self._blocked_until)))
                return False, self.lock_seconds

            while len(self._failures) > self.max_clients:
                oldest, _ = self._failures.popitem(last=False)
                self._blocked_until.pop(oldest, None)
            return False, 0


_edit_token_guard = EditTokenGuard()


def _configured_edit_token() -> str:
    return get("CITADEL_TOKEN", "")


def _client_key(request: Request) -> str:
    return request.client.host if request.client else "unknown"


def _require_edit_token(request: Request, supplied: str) -> None:
    accepted, retry_after = _edit_token_guard.authenticate(
        _client_key(request),
        supplied,
        _configured_edit_token(),
    )
    if accepted:
        return
    if retry_after:
        raise HTTPException(
            status_code=429,
            detail="Too many invalid token attempts. Try again later.",
            headers={"Retry-After": str(retry_after)},
        )
    raise HTTPException(status_code=401, detail="Invalid token.")


_instance_id = secrets.token_hex(16)


class InstanceIdentifiedFastAPI(FastAPI):
    """Identify this process on every HTTP response, including unhandled 500s."""

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        async def identify_response(message: Message) -> None:
            if message["type"] == "http.response.start":
                MutableHeaders(scope=message)["X-Citadel-Instance"] = _instance_id
                if scope.get("path", "").startswith(("/api/cloudflare/access", "/cloudflare-api")):
                    headers = MutableHeaders(scope=message)
                    headers["Cache-Control"] = "no-store"
                    headers["Referrer-Policy"] = "no-referrer"
                    headers["X-Content-Type-Options"] = "nosniff"
                    headers["Content-Security-Policy"] = "default-src 'self'; script-src 'self'; style-src 'self'; frame-ancestors 'none'; form-action 'self'; base-uri 'none'"
            await send(message)

        # Wrap the complete middleware stack, including ServerErrorMiddleware.
        await super().__call__(scope, receive, identify_response)


app = InstanceIdentifiedFastAPI()
_jinja = Environment(
    loader=FileSystemLoader(str(core.BASE_DIR / "templates")),
    autoescape=select_autoescape(["html", "xml"]),
)

prepare_state(core.BASE_DIR)
app.mount("/icons", StaticFiles(directory=str(core.DATA_DIR / "icons")), name="icons")
app.mount("/assets", StaticFiles(directory=str(core.BASE_DIR / "assets")), name="assets")


@app.get("/citadel.svg")
def favicon_svg():
    return FileResponse(core.BASE_DIR / "citadel.svg", media_type="image/svg+xml")


@app.get("/", response_class=HTMLResponse)
def index():
    data = core.build_dashboard()
    data["edit_token_required"] = bool(_configured_edit_token())
    return _jinja.get_template("index.html").render(
        data=data,
    )


def _health_data(extensions: str):
    try:
        selected = health.extensions_arg(extensions) if extensions.strip() else None
        return health.snapshot(core.BASE_DIR, selected)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@app.get("/api/health")
def health_json(extensions: str = ""):
    return _health_data(extensions)


@app.get("/healthz", response_class=HTMLResponse)
def health_page(extensions: str = ""):
    return _jinja.get_template("health.html").render(
        data=_health_data(extensions), selection=extensions,
    )


@app.get("/healthz/check.py")
def health_checker():
    return FileResponse(
        core.BASE_DIR / "functions" / "citadel-health-check.py",
        media_type="text/x-python", filename="citadel-health-check.py",
        headers={"Cache-Control": "no-cache"},
    )


def _require_access_admin(request: Request) -> None:
    # Unlike ordinary dashboard edits, secret management must never become
    # anonymous when CITADEL_TOKEN is unset.
    if not _configured_edit_token():
        raise HTTPException(status_code=503, detail="Set CITADEL_TOKEN to manage API access.")
    if request.headers.get("Sec-Fetch-Site") == "cross-site":
        raise HTTPException(status_code=403, detail="Cross-site access is not allowed.")
    _require_edit_token(request, request.headers.get("X-Citadel-Token", ""))


@app.get("/cloudflare-api", response_class=HTMLResponse)
def api_access_page():
    # Public login shell only: inventory and credentials require the token API.
    return _jinja.get_template("cloudflare-api.html").render()


@app.get("/api/cloudflare/access")
def api_access_get(request: Request):
    _require_access_admin(request)
    try:
        return management_view(core.BASE_DIR)
    except (ValueError, OSError):
        raise HTTPException(status_code=409, detail="Cannot read private API access configuration. Check the JSON and file permissions.") from None


@app.put("/api/cloudflare/access")
async def api_access_put(request: Request):
    _require_access_admin(request)
    body = bytearray()
    async for chunk in request.stream():
        body.extend(chunk)
        if len(body) > 1024 * 1024:
            raise HTTPException(status_code=413, detail="Access configuration is too large.")
    try:
        payload = json.loads(body)
        if not isinstance(payload, dict) or set(payload) != {"routes", "revision"}:
            raise ValueError("Expected routes and revision.")
        routes = save_access(core.BASE_DIR, payload["routes"], payload["revision"])
    except FileExistsError:
        raise HTTPException(status_code=409, detail="Configuration changed. Reload before saving.") from None
    except (ValueError, UnicodeError):
        raise HTTPException(status_code=400, detail="Invalid access entries. Use email;bearer, outer;inner, bearer, or email. Duplicate identities are not allowed.") from None
    except OSError:
        raise HTTPException(status_code=409, detail="Cannot save private API access configuration.") from None
    return {"ok": True, "revision": revision(routes), "applies_on": "next_scan"}


@app.put("/api/cloudflare/ports/{port}")
async def update_cloudflare_port(port: int, request: Request):
    _require_edit_token(request, request.headers.get("X-Citadel-Token", ""))
    try:
        payload = await request.json()
        if not isinstance(payload, dict):
            raise ValueError("Request body must be a JSON object.")
        rule = core.save_cloudflare_rule(port, payload)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return {"ok": True, "port": port, "rule": rule, "applies_on": "next_scan"}


@app.put("/api/cloudflare/ports")
async def update_all_cloudflare_ports(request: Request):
    _require_edit_token(request, request.headers.get("X-Citadel-Token", ""))
    try:
        payload = await request.json()
        rules = core.save_all_cloudflare_rules(payload)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return {"ok": True, "rules": rules, "applies_on": "next_scan"}


@app.post("/api/cloudflare/edit-auth")
async def authorize_cloudflare_edit(request: Request):
    try:
        payload = await request.json()
    except json.JSONDecodeError as exc:
        raise HTTPException(status_code=400, detail="Request body must be valid JSON.") from exc
    if not isinstance(payload, dict):
        raise HTTPException(status_code=400, detail="Request body must be a JSON object.")
    token = payload.get("token", "")
    if not isinstance(token, str):
        raise HTTPException(status_code=400, detail="Token must be a string.")
    _require_edit_token(request, token)
    return {"ok": True}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--wait-ready", metavar="PROGRAM",
        help="use PROGRAM to wait for the configured TCP or Unix listener",
    )
    arguments = parser.parse_args(argv)
    try:
        path = unix_socket_path()
        if path is None:
            host, port = core.load_server_config()
        if arguments.wait_ready:
            return subprocess.run(
                [arguments.wait_ready, "--timeout", "60", *probe_target()], check=False,
            ).returncode
        if path is None:
            uvicorn.run(app, host=host, port=port)
        else:
            with bind_unix_socket(path) as listener:
                # Uvicorn re-raises SIGTERM after graceful shutdown. Let Python
                # unwind the socket context instead of immediately terminating.
                previous = signal.signal(signal.SIGTERM, lambda *_: sys.exit(0))
                try:
                    uvicorn.run(app, fd=listener.fileno())
                finally:
                    signal.signal(signal.SIGTERM, previous)
    except (ValueError, OSError) as exc:
        parser.exit(2, f"CITADEL WebUI: {exc}\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
