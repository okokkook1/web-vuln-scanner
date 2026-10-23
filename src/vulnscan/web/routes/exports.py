from __future__ import annotations

import json

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import HTMLResponse, Response

from ...report import build_report, render_html_report
from .common import get_db

router = APIRouter()


@router.get("/scans/{scan_id}/export/json")
async def export_json(request: Request, scan_id: str):
    db = get_db(request)
    scan = db.get_scan(scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="找不到掃描")
    payload = json.dumps(build_report(db, scan), ensure_ascii=False, indent=2)
    return Response(
        content=payload,
        media_type="application/json; charset=utf-8",
        headers={
            "Content-Disposition": f'attachment; filename="vulnscan-{scan.id}.json"',
        },
    )


@router.get("/scans/{scan_id}/export/html")
async def export_html(request: Request, scan_id: str):
    db = get_db(request)
    scan = db.get_scan(scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="找不到掃描")
    html = render_html_report(db, scan)
    return HTMLResponse(
        content=html,
        headers={
            "Content-Disposition": f'attachment; filename="vulnscan-{scan.id}.html"',
        },
    )
