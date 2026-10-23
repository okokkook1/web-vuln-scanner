from __future__ import annotations

from datetime import UTC, date, datetime, time
from urllib.parse import quote

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import RedirectResponse

from ...presentation import load_json, severity_order
from ..security import verify_csrf
from .common import get_db, render, scan_targets

router = APIRouter()


def _parse_expiry(raw: str) -> datetime | None:
    cleaned = raw.strip()
    if not cleaned:
        return None
    try:
        if len(cleaned) == 10:
            return datetime.combine(
                date.fromisoformat(cleaned),
                time(23, 59, 59),
                tzinfo=UTC,
            )
        value = datetime.fromisoformat(cleaned)
    except ValueError as exc:
        raise ValueError("到期日格式不正確") from exc
    if value.tzinfo is None:
        value = value.replace(tzinfo=UTC)
    return value.astimezone(UTC)


@router.get("/scans/{scan_id}/findings")
async def findings(request: Request, scan_id: str):
    db = get_db(request)
    scan = db.get_scan(scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="找不到掃描")
    severity = request.query_params.get("severity") or None
    confidence = request.query_params.get("confidence") or None
    category = request.query_params.get("category") or None
    review_status = request.query_params.get("review_status") or None
    query = (request.query_params.get("q") or "").strip() or None
    show_suppressed = request.query_params.get("show_suppressed") == "1"
    rows = db.get_findings(
        scan_id,
        severity=severity,
        confidence=confidence,
        category=category,
        review_status=review_status,
        query=query,
        include_suppressed=show_suppressed,
    )
    counts = db.severity_counts(scan_id)
    categories = db.category_counts(scan_id)
    suppressed_count = db.count_suppressed(scan_id)
    return render(
        request,
        "findings.html",
        active="history",
        page_title="弱點清單",
        page_subtitle=f"{scan.id} · {len(rows)} 個結果",
        scan=scan,
        targets=scan_targets(scan),
        findings=rows,
        counts=counts,
        total=sum(counts.values()),
        suppressed_count=suppressed_count,
        categories=categories,
        filters={
            "severity": severity or "",
            "confidence": confidence or "",
            "category": category or "",
            "review_status": review_status or "",
            "q": query or "",
            "show_suppressed": show_suppressed,
        },
        severity_order=severity_order(),
    )


@router.get("/fingerprints")
async def fingerprint_history(request: Request):
    fingerprint = (request.query_params.get("fingerprint") or "").strip()
    if not fingerprint or len(fingerprint) > 1000:
        raise HTTPException(status_code=404, detail="找不到 fingerprint")
    db = get_db(request)
    data = db.fingerprint_history(fingerprint)
    if not data:
        raise HTTPException(status_code=404, detail="找不到此 fingerprint 的發現")
    return render(
        request,
        "fingerprint_history.html",
        active="history",
        page_title="跨掃描弱點歷史",
        page_subtitle=data["title"],
        **data,
    )


@router.get("/findings/{finding_id}")
async def finding_detail(request: Request, finding_id: int):
    db = get_db(request)
    finding = db.get_finding_view(finding_id)
    if not finding:
        raise HTTPException(status_code=404, detail="找不到弱點")
    scan = db.get_scan(finding.scan_id)
    evidence = load_json(finding.evidence_json, {})
    refs = load_json(finding.refs_json, {})
    return render(
        request,
        "finding_detail.html",
        active="history",
        page_title="弱點詳情",
        page_subtitle=finding.title,
        finding=finding,
        scan=scan,
        evidence=evidence,
        refs=refs,
        review_history=db.get_review_history(finding_id),
        msg=request.query_params.get("msg"),
        kind=request.query_params.get("kind", "success"),
    )


@router.post("/findings/review-bulk")
async def bulk_review_findings(request: Request):
    form = await request.form()
    verify_csrf(request, form)
    db = get_db(request)
    scan_id = str(form.get("scan_id") or "").strip()
    if not scan_id or not db.get_scan(scan_id):
        raise HTTPException(status_code=404, detail="找不到掃描")
    finding_ids = []
    for raw in form.getlist("finding_ids")[:500]:
        try:
            finding_ids.append(int(raw))
        except (TypeError, ValueError):
            continue
    scan_ids = {
        item.id
        for item in db.get_findings(
            scan_id,
            limit=5000,
            include_suppressed=True,
        )
        if item.id is not None
    }
    finding_ids = [item for item in finding_ids if item in scan_ids]
    status = str(form.get("status") or "needs_review")
    note = str(form.get("note") or "")
    updated_by = str(form.get("updated_by") or "local")
    expires_raw = str(form.get("expires_at") or "")
    try:
        expires_at = _parse_expiry(expires_raw)
        changed = db.set_review_many(
            finding_ids,
            status,
            note,
            updated_by,
            expires_at=expires_at,
        )
    except ValueError as exc:
        return RedirectResponse(
            url=f"/scans/{scan_id}/findings?msg={quote(str(exc))}&kind=error",
            status_code=303,
        )
    return RedirectResponse(
        url=(
            f"/scans/{scan_id}/findings?"
            f"msg={quote(f'已更新 {changed} 筆驗證狀態')}&kind=success"
        ),
        status_code=303,
    )


@router.post("/findings/{finding_id}/review")
async def review_finding(request: Request, finding_id: int):
    form = await request.form()
    verify_csrf(request, form)
    db = get_db(request)
    finding = db.get_finding(finding_id)
    if not finding:
        raise HTTPException(status_code=404, detail="找不到弱點")
    status = str(form.get("status") or "needs_review")
    note = str(form.get("note") or "")
    updated_by = str(form.get("updated_by") or "local")
    expires_raw = str(form.get("expires_at") or "")
    try:
        expires_at = _parse_expiry(expires_raw)
        db.set_finding_review(
            finding_id,
            status,
            note,
            updated_by,
            expires_at=expires_at,
        )
    except ValueError as exc:
        return RedirectResponse(
            url=f"/findings/{finding_id}?msg={quote(str(exc))}&kind=error",
            status_code=303,
        )
    return RedirectResponse(
        url=f"/findings/{finding_id}?msg={quote('已更新弱點驗證狀態')}&kind=success",
        status_code=303,
    )
