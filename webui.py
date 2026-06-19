"""CITADEL FastAPI WebUI."""

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent / "functions"))

import uvicorn
from fastapi import FastAPI
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


if __name__ == "__main__":
    host, port = core.load_server_config()
    uvicorn.run(app, host=host, port=port)
