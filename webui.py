"""CITADEL FastAPI WebUI."""

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent / "functions"))

import uvicorn
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import FileResponse, HTMLResponse
from fastapi.staticfiles import StaticFiles
from jinja2 import Environment, FileSystemLoader

from python_header import get, get_port  # noqa: F401

import core

app = FastAPI()
_jinja = Environment(loader=FileSystemLoader(str(core.BASE_DIR / "templates")))
_jinja.filters["tojson"] = lambda val: json.dumps(val)

(core.BASE_DIR / "icons").mkdir(exist_ok=True)
app.mount("/icons", StaticFiles(directory=str(core.BASE_DIR / "icons")), name="icons")
app.mount("/assets", StaticFiles(directory=str(core.BASE_DIR / "assets")), name="assets")


@app.get("/citadel.svg")
def favicon_svg():
    return FileResponse(core.BASE_DIR / "citadel.svg", media_type="image/svg+xml")


@app.get("/", response_class=HTMLResponse)
def index():
    data = core.build_dashboard()
    return _jinja.get_template("index.html").render(
        data=data,
        provider_order_json=json.dumps(data["provider_order"]),
    )


@app.put("/api/cloudflare/ports/{port}")
async def update_cloudflare_port(port: int, request: Request):
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
    try:
        payload = await request.json()
        rules = core.save_all_cloudflare_rules(payload)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return {"ok": True, "rules": rules, "applies_on": "next_scan"}


if __name__ == "__main__":
    host, port = core.load_server_config()
    uvicorn.run(app, host=host, port=port)
