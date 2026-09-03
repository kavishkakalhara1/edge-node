from __future__ import annotations

import json
import secrets
import uuid
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from zoneinfo import ZoneInfo

import uvicorn
from fastapi import FastAPI, Header, HTTPException, Request, status
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel, Field

from .config import Settings
from .database import Database
from .healing import CLOUD_ACTIONS, SUPPORTED_ACTIONS

PACKAGE_DIR = Path(__file__).parent
SRI_LANKA_TIMEZONE = ZoneInfo("Asia/Colombo")
settings = Settings.from_env()
database = Database(settings.database_path)
templates = Jinja2Templates(directory=PACKAGE_DIR / "templates")


def _sri_lanka_time(value: str) -> datetime:
    timestamp = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if timestamp.tzinfo is None:
        timestamp = timestamp.replace(tzinfo=timezone.utc)
    return timestamp.astimezone(SRI_LANKA_TIMEZONE)


def sl_datetime(value: str) -> str:
    return _sri_lanka_time(value).strftime("%Y-%m-%d %H:%M:%S")


def sl_time(value: str) -> str:
    return _sri_lanka_time(value).strftime("%H:%M:%S")


templates.env.filters["sl_datetime"] = sl_datetime
templates.env.filters["sl_time"] = sl_time


def dashboard_data() -> dict:
    data = database.dashboard()
    data["cloud_connection"] = {
        "configured": bool(settings.cloud_api_endpoint),
        "enabled": database.cloud_delivery_enabled(),
    }
    ignored_macs = set(settings.ignored_device_macs)
    if not ignored_macs:
        return data
    ignored_ids = {
        device["device_id"]
        for device in data["devices"]
        if device.get("mac_address") in ignored_macs
    }
    data["devices"] = [
        device for device in data["devices"] if device["device_id"] not in ignored_ids
    ]
    data["recent"] = [
        event for event in data["recent"] if event["device_id"] not in ignored_ids
    ]
    data["counts"] = {
        "total": len(data["devices"]),
        "connected": sum(bool(device["connected"]) for device in data["devices"]),
        "elevated": sum(device["risk_score"] >= 0.50 for device in data["devices"]),
    }
    return data


class HealingRequestBody(BaseModel):
    parameters: dict[str, Any] = Field(default_factory=dict)


class AdminResetBody(BaseModel):
    confirmation: str


class CloudConnectionBody(BaseModel):
    enabled: bool


def require_healing_token(x_iot_guard_token: str | None = Header(default=None)) -> None:
    if not settings.healing_api_token:
        raise HTTPException(status_code=503, detail="Healing API is not configured")
    if x_iot_guard_token is None or not secrets.compare_digest(
        x_iot_guard_token, settings.healing_api_token
    ):
        raise HTTPException(status_code=401, detail="Invalid healing API token")


def latency_benchmark() -> dict | None:
    path = settings.database_path.parent / "latency-benchmark.json"
    try:
        return json.loads(path.read_text())
    except (FileNotFoundError, json.JSONDecodeError, OSError):
        return None


def model_feature_columns() -> list[str]:
    path = settings.artifact_dir / "metadata.json"
    try:
        columns = json.loads(path.read_text())["feature_columns"]
    except (FileNotFoundError, KeyError, json.JSONDecodeError, OSError):
        return []
    return [column for column in columns if isinstance(column, str)]


@asynccontextmanager
async def lifespan(_app: FastAPI):
    database.initialize()
    yield


app = FastAPI(title="IoT Guard", version="0.2.0", lifespan=lifespan)
app.mount("/static", StaticFiles(directory=PACKAGE_DIR / "static"), name="static")


@app.get("/", response_class=HTMLResponse)
def dashboard(request: Request):
    data = dashboard_data()
    data["latency"] = latency_benchmark()
    return templates.TemplateResponse(request, "dashboard.html", data)


@app.get("/devices/{device_id}", response_class=HTMLResponse)
def device_detail(request: Request, device_id: str):
    data = database.device_detail(device_id)
    if data is None:
        raise HTTPException(status_code=404, detail="Device not found")
    values = data["latest_features"]["values"] if data["latest_features"] else {}
    data["feature_rows"] = [
        {"name": name, "value": values.get(name)} for name in model_feature_columns()
    ]
    data["cloud_actions"] = CLOUD_ACTIONS
    return templates.TemplateResponse(request, "device.html", data)


@app.get("/api/devices")
def api_devices():
    return dashboard_data()


@app.get("/api/devices/{device_id}")
def api_device(device_id: str):
    data = database.device_detail(device_id)
    if data is None:
        raise HTTPException(status_code=404, detail="Device not found")
    return data


@app.get("/api/cloud-deliveries")
def api_cloud_deliveries(limit: int = 50):
    if limit < 1 or limit > 500:
        raise HTTPException(status_code=422, detail="limit must be between 1 and 500")
    return {"deliveries": database.cloud_deliveries(limit=limit)}


@app.get("/api/admin/cloud-connection")
def cloud_connection_status():
    return {
        "configured": bool(settings.cloud_api_endpoint),
        "enabled": database.cloud_delivery_enabled(),
    }


@app.put("/api/admin/cloud-connection")
def update_cloud_connection(
    body: CloudConnectionBody,
    x_iot_guard_token: str | None = Header(default=None),
):
    require_healing_token(x_iot_guard_token)
    database.set_cloud_delivery_enabled(body.enabled)
    return {
        "configured": bool(settings.cloud_api_endpoint),
        "enabled": body.enabled,
    }


@app.post(
    "/api/devices/{device_id}/healing-actions/{action_id}",
    status_code=status.HTTP_202_ACCEPTED,
)
def execute_healing_action(
    device_id: str,
    action_id: str,
    body: HealingRequestBody,
    x_iot_guard_token: str | None = Header(default=None),
):
    require_healing_token(x_iot_guard_token)
    normalized_action_id = action_id.upper()
    if normalized_action_id not in SUPPORTED_ACTIONS:
        raise HTTPException(
            status_code=422,
            detail={
                "message": f"Healing action {normalized_action_id} is not implemented",
                "supported_action_ids": sorted(SUPPORTED_ACTIONS),
            },
        )
    request = database.create_healing_request(
        uuid.uuid4().hex, normalized_action_id, device_id, body.parameters
    )
    if request is None:
        raise HTTPException(status_code=404, detail="Device not found")
    return request


@app.get("/api/healing-actions/{request_id}")
def healing_action_status(
    request_id: str, x_iot_guard_token: str | None = Header(default=None)
):
    require_healing_token(x_iot_guard_token)
    request = database.healing_request(request_id)
    if request is None:
        raise HTTPException(status_code=404, detail="Healing action request not found")
    return request


@app.post("/api/admin/reset-database")
def reset_database(
    body: AdminResetBody,
    x_iot_guard_token: str | None = Header(default=None),
):
    require_healing_token(x_iot_guard_token)
    if body.confirmation != "RESET":
        raise HTTPException(status_code=422, detail="Confirmation must be RESET")
    return {"reset": True, "deleted": database.reset()}


@app.get("/health")
def health():
    return {"status": "ok", "database": str(settings.database_path)}


def main() -> None:
    uvicorn.run(app, host=settings.web_host, port=settings.web_port, access_log=False)


if __name__ == "__main__":
    main()
