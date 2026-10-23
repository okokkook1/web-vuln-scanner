from __future__ import annotations

import asyncio
import json
from pathlib import Path
from urllib.parse import urlsplit

import pytest

from vulnscan.audit import AuditLogger
from vulnscan.auth import AuthError, prepare_auth
from vulnscan.db import Database
from vulnscan.engine import ScanEngine
from vulnscan.http import HttpEngine
from vulnscan.jobs.manager import Job, JobManager, JobState
from vulnscan.models import AuthConfig, AuthType, Scan, new_scan_id
from vulnscan.scope import build_scope

from .fixture_server import fixture_server
from .helpers import make_config


def _form_auth(**overrides) -> AuthConfig:
    data = {
        "type": AuthType.FORM,
        "login_url": "/login",
        "username": "demo",
        "password": "demo123",
        "verify_text": "Welcome",
    }
    data.update(overrides)
    return AuthConfig(**data)


async def test_form_login_extracts_csrf_and_returns_cookies(tmp_path: Path):
    with fixture_server() as base:
        config = make_config(base, auth=_form_auth())
        scope = build_scope(config)
        audit = AuditLogger(tmp_path / "audit.jsonl", "auth_test")
        try:
            materials = await prepare_auth(config, scope, audit)
        finally:
            audit.close()

    assert materials.cookies.get("auth") == "ok"
    assert materials.headers == {}
    assert scope.snapshot()["auth"]["type"] == "form"
    assert "password" not in scope.snapshot()["auth"]


async def test_cookie_auth_reaches_private_page(tmp_path: Path):
    with fixture_server() as base:
        config = make_config(
            base,
            auth=AuthConfig(type=AuthType.COOKIE, cookie="auth=ok"),
        )
        scope = build_scope(config)
        audit = AuditLogger(tmp_path / "audit.jsonl", "cookie_test")
        engine = HttpEngine(
            scope=scope,
            config=config,
            audit=audit,
            cancel_event=asyncio.Event(),
            user_agent="VulnScan-Test",
            auth_cookies={"auth": "ok"},
        )
        try:
            page = await engine.get(base + "/private")
        finally:
            await engine.close()
            audit.close()
    assert page.status == 200
    assert "Private area" in page.text


async def test_cookie_and_header_auth_materials(tmp_path: Path):
    with fixture_server() as base:
        config = make_config(base, auth=AuthConfig(type=AuthType.COOKIE, cookie="session=abc; theme=dark"))
        scope = build_scope(config)
        audit = AuditLogger(tmp_path / "cookie.jsonl", "cookie")
        try:
            materials = await prepare_auth(config, scope, audit)
        finally:
            audit.close()
        assert materials.cookies == {"session": "abc", "theme": "dark"}

        config = make_config(
            base,
            auth=AuthConfig(
                type=AuthType.HEADER,
                header_name="X-API-Key",
                header_value="demo-key",
            ),
        )
        audit = AuditLogger(tmp_path / "header.jsonl", "header")
        try:
            materials = await prepare_auth(config, scope, audit)
        finally:
            audit.close()
        assert materials.headers == {"X-API-Key": "demo-key"}


async def test_storage_state_uses_cookies_and_localstorage_token(tmp_path: Path):
    with fixture_server() as base:
        parsed = urlsplit(base)
        state = {
            "cookies": [
                {
                    "name": "auth",
                    "value": "ok",
                    "domain": parsed.hostname,
                    "path": "/",
                }
            ],
            "origins": [
                {
                    "origin": base,
                    "localStorage": [
                        {"name": "access_token", "value": "token-123"}
                    ],
                }
            ],
        }
        config = make_config(
            base,
            auth=AuthConfig(
                type=AuthType.STATE,
                storage_state=state,
                storage_token_key="access_token",
                storage_header_name="Authorization",
            ),
        )
        scope = build_scope(config)
        audit = AuditLogger(tmp_path / "state.jsonl", "state")
        try:
            materials = await prepare_auth(config, scope, audit)
        finally:
            audit.close()

    assert materials.cookies == {"auth": "ok"}
    assert materials.headers == {"Authorization": "Bearer token-123"}
    assert "storage_state" not in scope.snapshot()["auth"]
    assert "token-123" not in str(scope.snapshot())


async def test_bad_password_fails_login(tmp_path: Path):
    with fixture_server() as base:
        config = make_config(base, auth=_form_auth(password="wrong"))
        scope = build_scope(config)
        audit = AuditLogger(tmp_path / "audit.jsonl", "bad_auth")
        try:
            with pytest.raises(AuthError):
                await prepare_auth(config, scope, audit)
        finally:
            audit.close()


async def test_authenticated_scan_crawls_private_area(tmp_path: Path):
    with fixture_server() as base:
        config = make_config(base, auth=_form_auth())
        scope = build_scope(config)
        db = Database(tmp_path / "vulnscan.db")
        db.init()
        scan_id = new_scan_id()
        db.create_scan(
            Scan(
                id=scan_id,
                status="running",
                profile=config.profile.value,
                targets_json=json.dumps(config.targets),
                scope_json=json.dumps(scope.snapshot(), ensure_ascii=False),
            )
        )
        engine = ScanEngine(
            scan_id=scan_id,
            config=config,
            db=db,
            data_dir=tmp_path,
            cancel_event=asyncio.Event(),
            on_update=lambda *args: None,
        )
        result = await engine.run()

    assert any("/private" in endpoint.url for endpoint in result.endpoints)
    audit_text = (tmp_path / "scans" / scan_id / "audit.jsonl").read_text(encoding="utf-8")
    assert "demo123" not in audit_text
    assert "auth=ok" not in audit_text
    scope_text = (tmp_path / "scans" / scan_id / "scope.yaml").read_text(encoding="utf-8")
    assert "demo123" not in scope_text
    assert "auth=ok" not in scope_text


def test_job_scrub_removes_credentials():
    config = make_config(
        "https://example.com",
        auth=AuthConfig(type=AuthType.COOKIE, cookie="session=secret"),
        proxy="http://user:pass@proxy.example:8080",
    )
    job = Job(scan_id="scan_scrub", config=config, state=JobState(scan_id="scan_scrub"))
    JobManager._scrub(job)
    assert job.config.auth.type is AuthType.NONE
    assert job.config.proxy is None


def test_audit_redacts_custom_auth_headers(tmp_path: Path):
    audit = AuditLogger(tmp_path / "audit.jsonl", "audit_redact")
    audit.log(
        method="GET",
        url="https://example.com/",
        status=200,
        request_headers={
            "X-API-Key": "super-secret-key",
            "Authorization": "Bearer top-secret",
        },
        response_headers={"Set-Cookie": "session=secret-cookie"},
        body_excerpt="",
    )
    audit.close()
    text = (tmp_path / "audit.jsonl").read_text(encoding="utf-8")
    assert "super-secret-key" not in text
    assert "top-secret" not in text
    assert "secret-cookie" not in text
