from __future__ import annotations

import os
import threading
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from pydantic import BaseModel, Field

from hackon.backend.core.orchestrator import Orchestrator
from hackon.backend.utils.net import normalize_target

# In-memory job store (swap for Redis/DB in production).
_scans: Dict[str, Dict[str, Any]] = {}
_lock = threading.Lock()


class ScanCreate(BaseModel):
    target: str = Field(..., description="Domain or IP (no scheme required)")
    max_workers: int = Field(6, ge=1, le=32)
    timeout: float = Field(12.0, ge=1.0, le=300.0)


def _run_scan_job(scan_id: str, target: str, max_workers: int, timeout: float) -> None:
    with _lock:
        row = _scans.get(scan_id)
        if row is None:
            return
        row["status"] = "running"
        row["error"] = None

    try:
        orch = Orchestrator(max_workers=max_workers, default_timeout_s=timeout)
        result = orch.run(target)
        with _lock:
            row = _scans.get(scan_id)
            if row is None:
                return
            row["status"] = "done"
            row["result"] = result
    except Exception as e:  # noqa: BLE001 — surface failure to client
        with _lock:
            row = _scans.get(scan_id)
            if row is None:
                return
            row["status"] = "failed"
            row["error"] = str(e)
            row["result"] = None


def create_app() -> FastAPI:
    app = FastAPI(
        title="HackOn Recon API",
        description="Authorized recon bridge for HackOn Recon dashboard and integrations.",
        version="0.1.0",
    )

    _default_cors = [
        "http://127.0.0.1:5173",
        "http://localhost:5173",
    ]
    _extra = os.getenv("HACKON_CORS_ORIGINS", "")
    _extra_origins = [o.strip() for o in _extra.split(",") if o.strip()]
    _allow_origins = list(dict.fromkeys(_default_cors + _extra_origins))

    app.add_middleware(
        CORSMiddleware,
        allow_origins=_allow_origins,
        # Vite may use another port; allow any localhost / 127.0.0.1 dev origin.
        allow_origin_regex=r"http://(127\.0\.0\.1|localhost):\d+$",
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    @app.get("/health")
    def health() -> Dict[str, str]:
        return {"status": "ok"}

    @app.get("/api/scans")
    def list_scans() -> List[Dict[str, Any]]:
        with _lock:
            return [
                {"id": s["id"], "status": s["status"], "target": s["target"]}
                for s in sorted(_scans.values(), key=lambda x: x.get("created", ""), reverse=True)
            ]

    @app.post("/api/scans")
    def create_scan(body: ScanCreate) -> Dict[str, Any]:
        target = normalize_target(body.target)
        if not target:
            raise HTTPException(status_code=400, detail="Invalid target")

        scan_id = str(uuid.uuid4())
        with _lock:
            _scans[scan_id] = {
                "id": scan_id,
                "status": "queued",
                "target": target,
                "result": None,
                "error": None,
                "created": datetime.now(timezone.utc).isoformat(),
            }

        t = threading.Thread(
            target=_run_scan_job,
            args=(scan_id, target, body.max_workers, body.timeout),
            daemon=True,
            name=f"scan-{scan_id}",
        )
        t.start()

        return {"id": scan_id, "status": "queued", "target": target}

    @app.get("/api/scans/{scan_id}")
    def get_scan(scan_id: str) -> Dict[str, Any]:
        with _lock:
            row = _scans.get(scan_id)
        if row is None:
            raise HTTPException(status_code=404, detail="Scan not found")
        return {
            "id": row["id"],
            "status": row["status"],
            "target": row["target"],
            "error": row.get("error"),
        }

    @app.get("/api/scans/{scan_id}/result")
    def get_scan_result(scan_id: str) -> Dict[str, Any]:
        with _lock:
            row = _scans.get(scan_id)
        if row is None:
            raise HTTPException(status_code=404, detail="Scan not found")
        if row["status"] == "running" or row["status"] == "queued":
            raise HTTPException(status_code=409, detail="Scan still in progress")
        if row["status"] == "failed":
            raise HTTPException(status_code=500, detail=row.get("error") or "Scan failed")
        result = row.get("result")
        if not isinstance(result, dict):
            raise HTTPException(status_code=500, detail="No result payload")
        # Include id for frontend convenience (not part of normalized schema file on disk).
        out = dict(result)
        out["id"] = scan_id
        return out

    @app.get("/api/scans/{scan_id}/report.md")
    def get_scan_report_md(scan_id: str) -> FileResponse:
        with _lock:
            row = _scans.get(scan_id)
        if row is None:
            raise HTTPException(status_code=404, detail="Scan not found")
        if row["status"] != "done":
            raise HTTPException(status_code=409, detail="Scan not complete")
        result = row.get("result") or {}
        artifacts = result.get("artifacts") or {}
        md_path = artifacts.get("markdown")
        if md_path and isinstance(md_path, str):
            try:
                return FileResponse(md_path, media_type="text/markdown; charset=utf-8", filename="report.md")
            except Exception:
                pass
        raise HTTPException(status_code=404, detail="Markdown report not available")

    return app


app = create_app()
