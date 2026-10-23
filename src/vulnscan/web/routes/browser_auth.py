from __future__ import annotations

from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse

from ...browser_login import BrowserLoginError, BrowserLoginManager
from ..security import verify_csrf

router = APIRouter()


def _manager(request: Request) -> BrowserLoginManager:
    return request.app.state.browser_login


@router.post("/auth/browser/start")
async def start_browser_login(request: Request):
    form = await request.form()
    verify_csrf(request, form)
    if str(form.get("authorized_ack") or "") != "on":
        return JSONResponse(
            {"detail": "請先在 Step 1 確認已取得書面授權。"},
            status_code=400,
        )
    login_url = str(form.get("login_url") or "").strip()
    if not login_url.startswith(("http://", "https://")):
        return JSONResponse(
            {"detail": "登入 URL 必須是 http:// 或 https:// 網址。"},
            status_code=400,
        )
    try:
        session = _manager(request).start(login_url)
    except BrowserLoginError as exc:
        return JSONResponse({"detail": str(exc)}, status_code=400)
    return JSONResponse(session)


@router.post("/auth/browser/{session_id}/complete")
async def complete_browser_login(request: Request, session_id: str):
    form = await request.form()
    verify_csrf(request, form)
    session = _manager(request).complete(session_id)
    if session is None:
        return JSONResponse({"detail": "瀏覽器登入工作已不存在"}, status_code=404)
    return JSONResponse(session)


@router.post("/auth/browser/{session_id}/cancel")
async def cancel_browser_login(request: Request, session_id: str):
    form = await request.form()
    verify_csrf(request, form)
    session = _manager(request).cancel(session_id)
    if session is None:
        return JSONResponse({"detail": "瀏覽器登入工作已不存在"}, status_code=404)
    return JSONResponse(session)


@router.get("/auth/browser/{session_id}/status")
async def browser_login_status(request: Request, session_id: str):
    session = _manager(request).status(session_id)
    if session is None:
        return JSONResponse({"detail": "瀏覽器登入工作已不存在"}, status_code=404)
    return JSONResponse(session)
