"""CITADEL FastAPI WebUI."""

import hmac
import json
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

from python_header import get, get_port  # noqa: F401

import core


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


app = FastAPI()
_jinja = Environment(
    loader=FileSystemLoader(str(core.BASE_DIR / "templates")),
    autoescape=select_autoescape(["html", "xml"]),
)

(core.BASE_DIR / "icons").mkdir(exist_ok=True)
app.mount("/icons", StaticFiles(directory=str(core.BASE_DIR / "icons")), name="icons")
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


if __name__ == "__main__":
    host, port = core.load_server_config()
    uvicorn.run(app, host=host, port=port)
