from __future__ import annotations

from typing import Any

from fastapi import Request
from fastapi.templating import Jinja2Templates

from ...db import Database
from ...jobs import JobManager
from ...presentation import load_json


def get_db(request: Request) -> Database:
    return request.app.state.db


def get_manager(request: Request) -> JobManager:
    return request.app.state.manager


def get_templates(request: Request) -> Jinja2Templates:
    return request.app.state.templates


def render(request: Request, name: str, **context: Any):
    context.setdefault("request", request)
    return get_templates(request).TemplateResponse(request, name, context)


def scan_targets(scan) -> list[str]:
    return load_json(scan.targets_json, [])
