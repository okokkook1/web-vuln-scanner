from __future__ import annotations

from urllib.parse import quote

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import RedirectResponse

from ...db import Database
from ...diff import compare_scans
from ..security import verify_csrf
from .common import get_db, render

router = APIRouter()


@router.get("/scans/{scan_id}/diff")
async def scan_diff(request: Request, scan_id: str):
    db: Database = get_db(request)
    scan = db.get_scan(scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="找不到掃描")
    previous_scans = db.list_previous_scans(scan_id, limit=50)
    baseline = db.get_baseline_for_scan(scan)
    baseline_is_current = baseline is not None and baseline.id == scan.id
    if baseline_is_current or (
        baseline is not None and not db.can_compare_scans(scan_id, baseline.id)
    ):
        baseline = None
    if baseline and baseline.id not in {item.id for item in previous_scans}:
        previous_scans.append(baseline)
        previous_scans.sort(key=lambda item: item.created_at, reverse=True)
    selected_id = request.query_params.get("previous") or ""
    if not selected_id and baseline:
        selected_id = baseline.id
    if not selected_id and previous_scans:
        selected_id = previous_scans[0].id
    result = None
    error = None
    valid_ids = {item.id for item in previous_scans}
    if selected_id and selected_id not in valid_ids:
        error = "只能比較相同目標、且較早完成的掃描"
    elif selected_id:
        try:
            result = compare_scans(db, scan_id, selected_id)
        except ValueError as exc:
            error = str(exc)
    return render(
        request,
        "diff.html",
        active="history",
        page_title="掃描差異",
        page_subtitle=f"{scan.id} · 與前次掃描比較",
        scan=scan,
        previous_scans=previous_scans,
        selected_id=selected_id,
        baseline=baseline,
        baseline_is_current=baseline_is_current,
        result=result,
        error=error,
        msg=request.query_params.get("msg"),
        kind=request.query_params.get("kind", "success"),
    )


@router.post("/scans/{scan_id}/baseline")
async def set_scan_baseline(request: Request, scan_id: str):
    form = await request.form()
    verify_csrf(request, form)
    db: Database = get_db(request)
    scan = db.get_scan(scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="找不到掃描")
    baseline = db.set_baseline(
        scan_id,
        created_by=str(form.get("created_by") or "local"),
    )
    if not baseline:
        raise HTTPException(
            status_code=400,
            detail="只有已完成或取消的掃描可以設為 baseline",
        )
    return RedirectResponse(
        url=f"/scans/{scan_id}/diff?msg={quote('已設為此目標的 baseline')}",
        status_code=303,
    )


@router.post("/scans/{scan_id}/baseline/clear")
async def clear_scan_baseline(request: Request, scan_id: str):
    form = await request.form()
    verify_csrf(request, form)
    db: Database = get_db(request)
    scan = db.get_scan(scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="找不到掃描")
    db.remove_baseline_for_scan(scan_id)
    return RedirectResponse(
        url=f"/scans/{scan_id}/diff?msg={quote('已清除此目標的 baseline')}",
        status_code=303,
    )
