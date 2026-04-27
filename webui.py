"""CITADEL — FastAPI WebUI."""

import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent / "functions"))

from python_header import get, get_port  # noqa: F401 — loads .env

import json
import uvicorn
from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, JSONResponse, FileResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles
from jinja2 import Environment, FileSystemLoader

import core
import repos_core

app = FastAPI()

_jinja = Environment(loader=FileSystemLoader(str(core.BASE_DIR / "templates")))
_jinja.filters["tojson"] = lambda val: json.dumps(val)

app.mount("/icons", StaticFiles(directory=str(core.BASE_DIR / "icons")), name="icons")
app.mount("/assets", StaticFiles(directory=str(core.BASE_DIR / "assets")), name="assets")


async def _safe_json(request: Request) -> dict | None:
    """Parse JSON body, returning None on empty/invalid input."""
    try:
        body = await request.body()
        if not body:
            return None
        data = json.loads(body)
        return data if isinstance(data, dict) else None
    except (json.JSONDecodeError, UnicodeDecodeError):
        return None


@app.get("/citadel.svg")
def favicon_svg():
    return FileResponse(core.BASE_DIR / "citadel.svg", media_type="image/svg+xml")


@app.get("/", response_class=HTMLResponse)
def index():
    data = core.build_dashboard()
    tmpl = _jinja.get_template("index.html")
    return tmpl.render(
        data=data,
        provider_order_json=json.dumps(data["provider_order"]),
        repos_available=repos_core.repos_available(),
    )


# ── REPOS API ────────────────────────────────────────────────────────────


@app.get("/api/repos/status")
def api_repos_status():
    if not repos_core.repos_available():
        return {"available": False}
    try:
        return {
            "available": True,
            "configs": repos_core.list_configs(),
            "generated": repos_core.list_generated(),
            "build": repos_core.build_status(),
            "base_image": repos_core.base_image_status(),
        }
    except Exception as exc:
        return JSONResponse({"available": True, "error": str(exc)}, status_code=500)


@app.get("/api/repos/modules")
def api_repos_modules():
    if not repos_core.repos_available():
        return JSONResponse({"error": "REPOS not found"}, status_code=404)
    try:
        return repos_core.list_modules()
    except Exception as exc:
        return JSONResponse({"error": f"Module load failed: {exc}"}, status_code=500)


@app.get("/api/repos/configs")
def api_repos_configs():
    return repos_core.list_configs()


@app.get("/api/repos/config/{name:path}")
def api_repos_config(name: str):
    if not name or not name.strip():
        return JSONResponse({"error": "Missing name"}, status_code=400)
    cfg = repos_core.load_config(name)
    if cfg is None:
        return JSONResponse({"error": "Config not found"}, status_code=404)
    return cfg


@app.delete("/api/repos/config/{name:path}")
def api_repos_config_delete(name: str):
    if not name or not name.strip():
        return JSONResponse({"error": "Missing name"}, status_code=400)
    if repos_core.delete_config(name):
        return {"ok": True}
    return JSONResponse({"error": "Config not found"}, status_code=404)


@app.post("/api/repos/resolve-deps")
async def api_repos_resolve_deps(request: Request):
    data = await _safe_json(request)
    if data is None:
        return JSONResponse({"error": "Invalid or empty JSON body"}, status_code=400)
    selected = data.get("selected", [])
    if not isinstance(selected, list):
        return JSONResponse({"error": "selected must be an array"}, status_code=400)
    # Coerce all entries to strings, skip non-strings
    selected = [str(s) for s in selected if isinstance(s, str)]
    return repos_core.resolve_deps(selected)


@app.post("/api/repos/build/start")
async def api_repos_build_start(request: Request):
    data = await _safe_json(request)
    if data is None:
        data = {}
    mode = str(data.pop("_mode", "generate"))
    if mode not in {"generate", "build", "base"}:
        return JSONResponse({"error": "Invalid mode"}, status_code=400)
    result = repos_core.start_build(data, mode=mode)
    if "error" in result:
        return JSONResponse(result, status_code=409)
    return result


@app.get("/api/repos/build/status")
def api_repos_build_status():
    return repos_core.build_status()


@app.get("/api/repos/build/log")
def api_repos_build_log():
    return StreamingResponse(
        repos_core.stream_build_log(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "X-Accel-Buffering": "no",
            "Connection": "keep-alive",
        },
    )


@app.post("/api/repos/build/cancel")
def api_repos_build_cancel():
    return repos_core.cancel_build()


@app.get("/api/repos/generated/{stack}/{filename:path}")
def api_repos_download(stack: str, filename: str):
    path = repos_core.get_generated_file(stack, filename)
    if path is None:
        return JSONResponse({"error": "File not found"}, status_code=404)
    # RFC 5987 safe filename for Content-Disposition
    safe_name = path.name.replace('"', '\\"')
    return FileResponse(
        path,
        filename=path.name,
        media_type="application/octet-stream",
        headers={"Content-Disposition": f'attachment; filename="{safe_name}"'},
    )


@app.get("/api/repos/image")
def api_repos_image():
    p = repos_core.repos_image_path()
    if p is None:
        return JSONResponse({"error": "Image not found"}, status_code=404)
    return FileResponse(p, media_type="image/png")


# ── Main ─────────────────────────────────────────────────────────────────


if __name__ == "__main__":
    host, port = core.load_server_config()
    uvicorn.run(app, host=host, port=port)
