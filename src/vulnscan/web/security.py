from __future__ import annotations

import secrets

from fastapi import HTTPException, Request
from starlette.datastructures import FormData

CSRF_COOKIE = "vs_csrf"


def ensure_token(request: Request) -> str:
    token = getattr(request.state, "csrf_token", None)
    if token:
        return token
    token = secrets.token_urlsafe(24)
    request.state.csrf_token = token
    request.state.csrf_new = True
    return token


def verify_csrf(request: Request, form: FormData) -> None:
    expected = getattr(request.state, "csrf_token", "") or request.cookies.get(CSRF_COOKIE, "")
    provided = str(form.get("csrf_token") or "")
    if not expected or not provided or not secrets.compare_digest(expected, provided):
        raise HTTPException(status_code=400, detail="CSRF token 驗證失敗，請重新載入頁面後再試。")
