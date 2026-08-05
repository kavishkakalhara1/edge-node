from __future__ import annotations

import json
from contextlib import asynccontextmanager
from pathlib import Path

import uvicorn
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from .config import Settings
from .database import Database

PACKAGE_DIR = Path(__file__).parent
settings = Settings.from_env()
database = Database(settings.database_path)
templates = Jinja2Templates(directory=PACKAGE_DIR / "templates")


def latency_benchmark() -> dict | None:
    path = settings.database_path.parent / "latency-benchmark.json"
    try:
        return json.loads(path.read_text())
    except (FileNotFoundError, json.JSONDecodeError, OSError):
        return None


@asynccontextmanager
async def lifespan(_app: FastAPI):
    database.initialize()
    yield


app = FastAPI(title="IoT Guard", version="0.1.0", lifespan=lifespan)
app.mount("/static", StaticFiles(directory=PACKAGE_DIR / "static"), name="static")


@app.get("/", response_class=HTMLResponse)
def dashboard(request: Request):
    data = database.dashboard()
    data["latency"] = latency_benchmark()
    return templates.TemplateResponse(request, "dashboard.html", data)


@app.get("/devices/{device_id}", response_class=HTMLResponse)
def device_detail(request: Request, device_id: str):
    data = database.device_detail(device_id)
    if data is None:
        raise HTTPException(status_code=404, detail="Device not found")
    return templates.TemplateResponse(request, "device.html", data)


@app.get("/api/devices")
def api_devices():
    return database.dashboard()


@app.get("/api/devices/{device_id}")
def api_device(device_id: str):
    data = database.device_detail(device_id)
    if data is None:
        raise HTTPException(status_code=404, detail="Device not found")
    return data


@app.get("/health")
def health():
    return {"status": "ok", "database": str(settings.database_path)}


def main() -> None:
    uvicorn.run(app, host=settings.web_host, port=settings.web_port, access_log=False)


if __name__ == "__main__":
    main()
