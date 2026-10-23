from __future__ import annotations

import json

from fastapi import APIRouter, Request
from fastapi.responses import RedirectResponse
from pydantic import ValidationError

from ...checks import CHECK_CATALOG
from ...config import RuntimeSettings
from ...models import REVIEW_STATUSES
from ...presentation import severity_order
from ..security import verify_csrf
from .common import get_db, render

router = APIRouter()


@router.get("/")
async def dashboard(request: Request):
    db = get_db(request)
    data = db.dashboard()
    recent = []
    for scan in data["recent"]:
        recent.append(
            {
                "scan": scan,
                "findings": db.count_findings(scan.id),
                "targets": json.loads(scan.targets_json) if scan.targets_json else [],
            }
        )
    severity_total = sum(data["severity"].values())
    return render(
        request,
        "dashboard.html",
        active="dashboard",
        page_title="儀表板",
        page_subtitle="授權掃描總覽與最近活動",
        data=data,
        recent=recent,
        severity_total=severity_total,
        severity_order=severity_order(),
    )


@router.get("/review")
async def review_workbench_page(request: Request):
    db = get_db(request)
    status = request.query_params.get("status") or "needs_review"
    if status not in (*REVIEW_STATUSES, "all"):
        status = "needs_review"
    severity = request.query_params.get("severity") or None
    if severity not in severity_order():
        severity = None
    target = (request.query_params.get("target") or "").strip() or None
    data = db.review_workbench(
        status=status,
        severity=severity,
        target=target,
    )
    return render(
        request,
        "review.html",
        active="review",
        page_title="驗證工作台",
        page_subtitle=(
            f"待確認 {data['counts']['needs_review']} · "
            f"高風險以上 {data['high_priority']}"
        ),
        severity_order=severity_order(),
        statuses=REVIEW_STATUSES,
        **data,
    )


@router.get("/trends")
async def trends(request: Request):
    db = get_db(request)
    groups = db.target_trends()
    return render(
        request,
        "trends.html",
        active="trends",
        page_title="掃描趨勢",
        page_subtitle=f"{len(groups)} 個目標的近期變化",
        groups=groups,
        severity_order=severity_order(),
        msg=request.query_params.get("msg"),
        kind=request.query_params.get("kind", "success"),
    )


@router.get("/settings")
async def settings_page(request: Request):
    store = request.app.state.settings_store
    return render(
        request,
        "settings.html",
        active="settings",
        page_title="設定",
        page_subtitle="掃描預設值與內建規則",
        settings=store.load(),
        catalog=CHECK_CATALOG,
        data_dir=str(request.app.state.data_dir),
        msg=request.query_params.get("msg"),
        kind=request.query_params.get("kind", "success"),
    )


@router.post("/settings")
async def save_settings(request: Request):
    store = request.app.state.settings_store
    form = await request.form()
    verify_csrf(request, form)
    try:
        proxy = str(form.get("proxy") or "").strip() or None
        settings = RuntimeSettings(
            default_profile=str(form.get("default_profile") or "safe"),
            rps_per_host=float(form.get("rps_per_host") or 3),
            max_requests_per_host=int(form.get("max_requests_per_host") or 2000),
            max_depth=int(form.get("max_depth") or 3),
            timeout=float(form.get("timeout") or 10),
            user_agent=str(form.get("user_agent") or ""),
            proxy=proxy,
        )
        store.save(settings)
    except (ValidationError, ValueError) as exc:
        return render(
            request,
            "settings.html",
            active="settings",
            page_title="設定",
            page_subtitle="掃描預設值與內建規則",
            settings=store.load(),
            catalog=CHECK_CATALOG,
            data_dir=str(request.app.state.data_dir),
            error=str(exc),
            msg=None,
        )
    return RedirectResponse(url="/settings?msg=設定已儲存", status_code=303)
