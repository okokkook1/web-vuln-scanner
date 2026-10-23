from __future__ import annotations

from urllib.parse import quote

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import RedirectResponse

from ...web.security import verify_csrf
from .common import get_db, render

router = APIRouter()


@router.get("/suppressions")
async def suppressions(request: Request):
    db = get_db(request)
    rows = db.list_suppressions()
    return render(
        request,
        "suppressions.html",
        active="suppressions",
        page_title="抑制規則",
        page_subtitle=f"{len(rows)} 條跨掃描抑制規則",
        suppressions=rows,
        msg=request.query_params.get("msg"),
        kind=request.query_params.get("kind", "success"),
    )


@router.post("/findings/{finding_id}/suppress")
async def suppress_finding(request: Request, finding_id: int):
    db = get_db(request)
    finding = db.get_finding_view(finding_id)
    if not finding:
        raise HTTPException(status_code=404, detail="找不到弱點")
    form = await request.form()
    verify_csrf(request, form)
    reason = str(form.get("reason") or "").strip()
    created_by = str(form.get("created_by") or "").strip() or "local"
    if not reason:
        message = "請填寫抑制原因"
        return RedirectResponse(
            url=f"/findings/{finding_id}?msg={quote(message)}&kind=error",
            status_code=303,
        )
    db.add_suppression(finding, reason=reason[:500], created_by=created_by[:100])
    message = "已加入抑制規則；之後相同路徑與參數的發現會自動隱藏"
    return RedirectResponse(
        url=f"/findings/{finding_id}?msg={quote(message)}",
        status_code=303,
    )


@router.post("/findings/{finding_id}/unsuppress")
async def unsuppress_finding(request: Request, finding_id: int):
    db = get_db(request)
    finding = db.get_finding_view(finding_id)
    if not finding:
        raise HTTPException(status_code=404, detail="找不到弱點")
    form = await request.form()
    verify_csrf(request, form)
    if finding.suppression_id:
        db.remove_suppression(finding.suppression_id)
    message = "已移除抑制規則"
    return RedirectResponse(
        url=f"/findings/{finding_id}?msg={quote(message)}",
        status_code=303,
    )


@router.post("/suppressions/{suppression_id}/delete")
async def delete_suppression(request: Request, suppression_id: int):
    db = get_db(request)
    form = await request.form()
    verify_csrf(request, form)
    db.remove_suppression(suppression_id)
    return RedirectResponse(
        url=f"/suppressions?msg={quote('已刪除抑制規則')}",
        status_code=303,
    )
