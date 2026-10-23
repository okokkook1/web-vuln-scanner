from __future__ import annotations

import json
import secrets
from contextlib import asynccontextmanager
from datetime import datetime
from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from .. import __version__
from ..browser_login import BrowserLoginManager
from ..config import APP_NAME, SettingsStore, default_data_dir
from ..db import Database
from ..jobs import JobManager
from ..presentation import (
    ADVANCED_LABELS,
    AUTH_LABELS,
    CONFIDENCE_LABELS,
    PROFILE_LABELS,
    REVIEW_LABELS,
    SEVERITY_LABELS,
    STATUS_LABELS,
    format_dt,
    format_duration,
)
from .routes import browser_auth, diff_routes, exports, findings, pages, scans, suppressions
from .security import CSRF_COOKIE

BASE_DIR = Path(__file__).parent
TEMPLATE_DIR = BASE_DIR / "templates"
STATIC_DIR = BASE_DIR / "static"


def create_app(data_dir: Path | None = None) -> FastAPI:
    resolved_dir = (data_dir or default_data_dir()).resolve()
    resolved_dir.mkdir(parents=True, exist_ok=True)
    db = Database(resolved_dir / "vulnscan.db")
    settings_store = SettingsStore(resolved_dir)
    manager = JobManager(db, resolved_dir)
    browser_login = BrowserLoginManager()

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        db.init()
        db.mark_interrupted()
        await manager.start()
        try:
            yield
        finally:
            browser_login.shutdown()
            await manager.shutdown()

    app = FastAPI(
        title="VulnScan",
        version=__version__,
        docs_url="/api/docs",
        redoc_url=None,
        lifespan=lifespan,
    )

    templates = Jinja2Templates(directory=str(TEMPLATE_DIR))
    templates.env.filters["dt"] = format_dt
    templates.env.filters["duration"] = format_duration
    templates.env.filters["status_label"] = lambda value: STATUS_LABELS.get(value, value)
    templates.env.filters["severity_label"] = lambda value: SEVERITY_LABELS.get(value, value)
    templates.env.filters["confidence_label"] = lambda value: CONFIDENCE_LABELS.get(value, value)
    templates.env.filters["profile_label"] = lambda value: PROFILE_LABELS.get(value, value)
    templates.env.filters["advanced_label"] = lambda value: ADVANCED_LABELS.get(value, value)
    templates.env.filters["auth_label"] = lambda value: AUTH_LABELS.get(value, value)
    templates.env.filters["review_label"] = lambda value: REVIEW_LABELS.get(value, value)
    templates.env.filters["pretty"] = lambda value: json.dumps(value, ensure_ascii=False, indent=2)
    templates.env.globals.update(
        app_name=APP_NAME,
        app_version=__version__,
        severity_labels=SEVERITY_LABELS,
        status_labels=STATUS_LABELS,
        review_labels=REVIEW_LABELS,
    )

    app.state.db = db
    app.state.settings_store = settings_store
    app.state.manager = manager
    app.state.browser_login = browser_login
    app.state.data_dir = resolved_dir
    app.state.templates = templates
    app.state.started_at = datetime.now()

    @app.middleware("http")
    async def security_and_csrf(request: Request, call_next):
        token = request.cookies.get(CSRF_COOKIE)
        new_token = False
        if not token:
            token = secrets.token_urlsafe(24)
            new_token = True
        request.state.csrf_token = token
        request.state.csrf_new = new_token

        response = await call_next(request)
        if new_token:
            response.set_cookie(
                CSRF_COOKIE,
                token,
                max_age=60 * 60 * 8,
                httponly=True,
                samesite="strict",
                secure=request.url.scheme == "https",
                path="/",
            )
        response.headers.setdefault(
            "Content-Security-Policy",
            "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; "
            "img-src 'self' data:; connect-src 'self'; base-uri 'self'; "
            "form-action 'self'; frame-ancestors 'none'",
        )
        response.headers.setdefault("X-Frame-Options", "DENY")
        response.headers.setdefault("X-Content-Type-Options", "nosniff")
        response.headers.setdefault("Referrer-Policy", "no-referrer")
        response.headers.setdefault(
            "Permissions-Policy", "camera=(), microphone=(), geolocation=()"
        )
        if not request.url.path.startswith("/static/"):
            response.headers.setdefault("Cache-Control", "no-store")
        return response

    app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")
    app.include_router(pages.router)
    app.include_router(scans.router)
    app.include_router(browser_auth.router)
    app.include_router(findings.router)
    app.include_router(suppressions.router)
    app.include_router(diff_routes.router)
    app.include_router(exports.router)

    @app.exception_handler(404)
    async def not_found(request: Request, _exc):
        if request.url.path.startswith("/api/") or request.headers.get("accept", "").startswith(
            "application/json"
        ):
            return JSONResponse({"detail": "找不到資源"}, status_code=404)
        return templates.TemplateResponse(
            request,
            "404.html",
            {"request": request, "active": "", "page_title": "找不到頁面", "page_subtitle": "404"},
            status_code=404,
        )

    return app
