from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from pathlib import Path

from fastapi.testclient import TestClient

from vulnscan.browser_login import BrowserSession
from vulnscan.models import Confidence, Finding, Scan, Severity
from vulnscan.web.app import create_app

from .fixture_server import fixture_server


def test_pages_render_and_authorization_is_required(tmp_path: Path):
    app = create_app(tmp_path)
    with TestClient(app) as client:
        dashboard = client.get("/")
        assert dashboard.status_code == 200
        assert "新增掃描" in dashboard.text

        new_scan = client.get("/scans/new")
        assert new_scan.status_code == 200
        assert "目標與授權" in new_scan.text
        assert "布林型 SQL Injection" in new_scan.text
        assert "advanced_ssrf" in new_scan.text
        assert "登入後掃描" in new_scan.text
        assert "auth_state_file" in new_scan.text
        assert "browser-login-start" in new_scan.text
        assert "openapi_file" in new_scan.text
        assert "openapi_url" in new_scan.text
        assert "api_post_allowlist" in new_scan.text
        assert "api_post_all_ack" in new_scan.text
        assert "enable_bola" in new_scan.text
        assert "bola_auth_type" in new_scan.text
        assert "bola_login_url" in new_scan.text
        assert "bola_username" in new_scan.text
        assert "bola_password" in new_scan.text
        assert "bola_allowlist" in new_scan.text
        assert "bola_allow_all_ack" in new_scan.text
        assert "max_api_tests" in new_scan.text
        assert "openapi_fingerprint" in new_scan.text
        assert "api-preview-button" in new_scan.text
        assert 'enctype="multipart/form-data"' in new_scan.text
        token = client.cookies.get("vs_csrf")
        assert token

        scan = Scan(
            id="scan_api_test",
            status="completed",
            profile="safe",
            targets_json=json.dumps(["https://example.com"]),
            scope_json=json.dumps(
                {
                    "authorized_by": "測試",
                    "contact": "test@example.com",
                    "expires": "2026-12-31",
                },
                ensure_ascii=False,
            ),
            stats_json="{}",
        )
        app.state.db.create_scan(scan)
        app.state.db.add_findings(
            scan.id,
            [
                Finding(
                    rule_id="rule-api-suppression",
                    title="測試抑制發現",
                    severity=Severity.MEDIUM,
                    confidence=Confidence.HIGH,
                    url="https://example.com/test",
                    category="測試",
                    description="測試",
                    remediation="修正",
                )
            ],
        )
        finding_id = app.state.db.get_findings(scan.id)[0].id
        assert client.get(f"/findings/{finding_id}").status_code == 200
        suppressed = client.post(
            f"/findings/{finding_id}/suppress",
            data={
                "csrf_token": token,
                "reason": "測試用抑制",
                "created_by": "pytest",
            },
            follow_redirects=False,
        )
        assert suppressed.status_code == 303
        assert app.state.db.count_findings(scan.id) == 0
        assert app.state.db.count_suppressed(scan.id) == 1
        suppressed_page = client.get(f"/findings/{finding_id}")
        assert suppressed_page.status_code == 200
        assert "已抑制" in suppressed_page.text
        assert "測試用抑制" in suppressed_page.text
        reviewed = client.post(
            f"/findings/{finding_id}/review",
            data={
                "csrf_token": token,
                "status": "confirmed",
                "note": "人工確認",
                "updated_by": "pytest",
            },
            follow_redirects=False,
        )
        assert reviewed.status_code == 303
        reviewed_page = client.get(f"/findings/{finding_id}")
        assert reviewed_page.status_code == 200
        assert "已確認" in reviewed_page.text
        assert "人工確認" in reviewed_page.text
        bulk = client.post(
            "/findings/review-bulk",
            data={
                "csrf_token": token,
                "scan_id": scan.id,
                "finding_ids": [str(finding_id)],
                "status": "accepted_risk",
                "note": "批次接受",
                "updated_by": "pytest",
                "expires_at": "2027-01-01",
            },
            follow_redirects=False,
        )
        assert bulk.status_code == 303
        filtered = client.get(
            f"/scans/{scan.id}/findings?review_status=accepted_risk&show_suppressed=1"
        )
        assert filtered.status_code == 200
        assert "測試抑制發現" in filtered.text
        assert "接受風險" in filtered.text
        assert app.state.db.get_finding_view(finding_id).review_expires_at is not None
        rejected = client.post(
            f"/findings/{finding_id}/review",
            data={
                "csrf_token": token,
                "status": "false_positive",
                "note": "   ",
                "updated_by": "pytest",
            },
            follow_redirects=False,
        )
        assert rejected.status_code == 303
        view = app.state.db.get_finding_view(finding_id)
        assert view.review_status == "accepted_risk"
        fingerprint_page = client.get(
            "/fingerprints",
            params={"fingerprint": view.fingerprint},
        )
        assert fingerprint_page.status_code == 200
        assert "跨掃描弱點歷史" in fingerprint_page.text
        assert "出現紀錄" in fingerprint_page.text
        assert "驗證歷程" in fingerprint_page.text
        assert "跨掃描歷史" in client.get(f"/findings/{finding_id}").text
        assert client.get("/suppressions").status_code == 200
        assert client.get(f"/scans/{scan.id}/diff").status_code == 200
        assert client.get(f"/scans/{scan.id}/findings").status_code == 200
        with_suppressed = client.get(f"/scans/{scan.id}/findings?show_suppressed=1")
        assert with_suppressed.status_code == 200
        assert "測試用抑制" in with_suppressed.text

        history = client.get("/scans")
        assert history.status_code == 200
        assert "安全主動" in history.text

        for path in (
            "/scans/scan_api_test",
            "/scans/scan_api_test/findings",
            "/scans/scan_api_test/export/html",
            "/scans/scan_api_test/export/json",
        ):
            assert client.get(path).status_code == 200, path

        missing_ack = client.post(
            "/scans",
            data={
                "csrf_token": token,
                "targets": "http://127.0.0.1:9/",
                "allow_private": "on",
                "authorized_by": "測試",
                "contact": "test@example.com",
                "expires": "2099-01-01",
                "profile": "passive",
                "rps_per_host": "3",
                "max_requests_per_host": "100",
                "max_depth": "1",
                "timeout": "5",
            },
        )
        assert missing_ack.status_code == 200
        assert "書面授權" in missing_ack.text

        full_without_checks = client.post(
            "/scans",
            data={
                "csrf_token": token,
                "targets": "http://127.0.0.1:9/",
                "allow_private": "on",
                "authorized_by": "測試",
                "contact": "test@example.com",
                "expires": "2099-01-01",
                "authorized_ack": "on",
                "profile": "full",
                "advanced_ack": "on",
                "rps_per_host": "3",
                "max_requests_per_host": "100",
                "max_depth": "1",
                "timeout": "5",
            },
        )
        assert full_without_checks.status_code == 200
        assert "至少需要選擇" in full_without_checks.text

        full_without_ack = client.post(
            "/scans",
            data={
                "csrf_token": token,
                "targets": "http://127.0.0.1:9/",
                "allow_private": "on",
                "authorized_by": "測試",
                "contact": "test@example.com",
                "expires": "2099-01-01",
                "authorized_ack": "on",
                "profile": "full",
                "advanced_sqli_boolean": "on",
                "rps_per_host": "3",
                "max_requests_per_host": "100",
                "max_depth": "1",
                "timeout": "5",
            },
        )
        assert full_without_ack.status_code == 200
        assert "確認進階檢查" in full_without_ack.text

        invalid_auth = client.post(
            "/scans",
            data={
                "csrf_token": token,
                "targets": "http://127.0.0.1:9/",
                "allow_private": "on",
                "authorized_by": "測試",
                "contact": "test@example.com",
                "expires": "2099-01-01",
                "authorized_ack": "on",
                "profile": "safe",
                "auth_type": "form",
                "rps_per_host": "3",
                "max_requests_per_host": "100",
                "max_depth": "1",
                "timeout": "5",
            },
        )
        assert invalid_auth.status_code == 200
        assert "表單登入" in invalid_auth.text

        state_data = {
            "cookies": [
                {"name": "session", "value": "abc", "domain": "127.0.0.1", "path": "/"}
            ],
            "origins": [
                {"origin": "http://127.0.0.1:9", "localStorage": []}
            ],
        }
        state_scan = client.post(
            "/scans",
            data={
                "csrf_token": token,
                "targets": "http://127.0.0.1:9/",
                "allow_private": "on",
                "authorized_by": "測試",
                "contact": "test@example.com",
                "expires": "2099-01-01",
                "authorized_ack": "on",
                "profile": "passive",
                "auth_type": "state",
                "rps_per_host": "3",
                "max_requests_per_host": "100",
                "max_depth": "1",
                "timeout": "5",
            },
            files={
                "auth_state_file": (
                    "state.json",
                    json.dumps(state_data).encode(),
                    "application/json",
                )
            },
            follow_redirects=False,
        )
        assert state_scan.status_code == 303, state_scan.text[:1200]
        assert state_scan.headers["location"].startswith("/scans/")

        openapi_data = {
            "openapi": "3.0.0",
            "servers": [{"url": "http://127.0.0.1:9"}],
            "paths": {"/health": {"get": {}}},
        }
        openapi_scan = client.post(
            "/scans",
            data={
                "csrf_token": token,
                "targets": "http://127.0.0.1:9/",
                "allow_private": "on",
                "authorized_by": "測試",
                "contact": "test@example.com",
                "expires": "2099-01-01",
                "authorized_ack": "on",
                "profile": "safe",
                "rps_per_host": "3",
                "max_requests_per_host": "100",
                "max_depth": "1",
                "timeout": "5",
            },
            files={
                "openapi_file": (
                    "openapi.json",
                    json.dumps(openapi_data).encode(),
                    "application/json",
                )
            },
            follow_redirects=False,
        )
        assert openapi_scan.status_code == 303, openapi_scan.text[:1200]

        missing_api_ack = client.post(
            "/scans",
            data={
                "csrf_token": token,
                "targets": "http://127.0.0.1:9/",
                "allow_private": "on",
                "authorized_by": "測試",
                "contact": "test@example.com",
                "expires": "2099-01-01",
                "authorized_ack": "on",
                "profile": "safe",
                "allow_api_post": "on",
                "api_post_allowlist": "",
                "rps_per_host": "3",
                "max_requests_per_host": "100",
                "max_depth": "1",
                "timeout": "5",
            },
            files={
                "openapi_file": (
                    "openapi.json",
                    json.dumps(openapi_data).encode(),
                    "application/json",
                )
            },
        )
        assert missing_api_ack.status_code == 200
        assert "白名單為空" in missing_api_ack.text

        all_ack_scan = client.post(
            "/scans",
            data={
                "csrf_token": token,
                "targets": "http://127.0.0.1:9/",
                "allow_private": "on",
                "authorized_by": "測試",
                "contact": "test@example.com",
                "expires": "2099-01-01",
                "authorized_ack": "on",
                "profile": "safe",
                "allow_api_post": "on",
                "api_post_all_ack": "on",
                "api_post_allowlist": "",
                "rps_per_host": "3",
                "max_requests_per_host": "100",
                "max_depth": "1",
                "timeout": "5",
            },
            files={
                "openapi_file": (
                    "openapi.json",
                    json.dumps(openapi_data).encode(),
                    "application/json",
                )
            },
            follow_redirects=False,
        )
        assert all_ack_scan.status_code == 303, all_ack_scan.text[:1200]

        bola_scan = client.post(
            "/scans",
            data={
                "csrf_token": token,
                "targets": "http://127.0.0.1:9/",
                "allow_private": "on",
                "authorized_by": "測試",
                "contact": "test@example.com",
                "expires": "2099-01-01",
                "authorized_ack": "on",
                "profile": "safe",
                "auth_type": "cookie",
                "auth_cookie": "auth=primary",
                "enable_bola": "on",
                "bola_ack": "on",
                "bola_auth_type": "cookie",
                "bola_auth_cookie": "auth=secondary",
                "bola_allow_all_ack": "on",
                "rps_per_host": "3",
                "max_requests_per_host": "100",
                "max_depth": "1",
                "timeout": "5",
            },
            follow_redirects=False,
        )
        assert bola_scan.status_code == 303, bola_scan.text[:1200]

        openapi_url_scan = client.post(
            "/scans",
            data={
                "csrf_token": token,
                "targets": "http://127.0.0.1:9/",
                "allow_private": "on",
                "authorized_by": "測試",
                "contact": "test@example.com",
                "expires": "2099-01-01",
                "authorized_ack": "on",
                "profile": "safe",
                "openapi_url": "http://127.0.0.1:9/openapi.json",
                "rps_per_host": "3",
                "max_requests_per_host": "100",
                "max_depth": "1",
                "timeout": "5",
            },
            follow_redirects=False,
        )
        assert openapi_url_scan.status_code == 303, openapi_url_scan.text[:1200]

        browser_session = BrowserSession(
            id="browser-test-session",
            login_url="http://127.0.0.1:9/login",
        )
        browser_session.state = {
            "cookies": [
                {
                    "name": "session",
                    "value": "abc",
                    "domain": "127.0.0.1",
                    "path": "/",
                }
            ],
            "origins": [],
        }
        browser_session.set_status("ready", "登入完成")
        app.state.browser_login._sessions[browser_session.id] = browser_session
        browser_scan = client.post(
            "/scans",
            data={
                "csrf_token": token,
                "targets": "http://127.0.0.1:9/",
                "allow_private": "on",
                "authorized_by": "測試",
                "contact": "test@example.com",
                "expires": "2099-01-01",
                "authorized_ack": "on",
                "profile": "passive",
                "auth_type": "browser",
                "browser_session_id": browser_session.id,
                "browser_login_url": browser_session.login_url,
                "rps_per_host": "3",
                "max_requests_per_host": "100",
                "max_depth": "1",
                "timeout": "5",
            },
            follow_redirects=False,
        )
        assert browser_scan.status_code == 303, browser_scan.text[:1200]
        assert app.state.browser_login.get_state(browser_session.id) is None

        no_csrf = client.post(
            "/scans",
            data={"targets": "http://127.0.0.1:9/", "authorized_ack": "on"},
        )
        assert no_csrf.status_code == 400

        assert client.get("/findings/9999").status_code == 404


def test_openapi_preview_file_and_url(tmp_path: Path):
    app = create_app(tmp_path)
    with TestClient(app) as client:
        assert client.get("/scans/new").status_code == 200
        token = client.cookies.get("vs_csrf")
        spec = {
            "openapi": "3.0.0",
            "servers": [{"url": "http://127.0.0.1:9"}],
            "paths": {
                "/api/echo": {
                    "post": {
                        "requestBody": {
                            "content": {
                                "application/json": {
                                    "schema": {
                                        "type": "object",
                                        "properties": {
                                            "q": {"type": "string"},
                                            "user": {
                                                "type": "object",
                                                "properties": {
                                                    "name": {"type": "string"}
                                                },
                                            },
                                        },
                                    }
                                }
                            }
                        }
                    }
                },
                "/put-only": {"put": {}},
                "/external": {"$ref": "https://example.com/not-fetched.json"},
            },
        }
        form = {
            "csrf_token": token,
            "targets": "http://127.0.0.1:9/",
            "allow_private": "on",
            "authorized_ack": "on",
            "authorized_by": "測試",
            "contact": "test@example.com",
            "expires": "2099-01-01",
            "api_post_allowlist": "POST /api/echo",
        }
        response = client.post(
            "/scans/api/preview",
            data=form,
            files={
                "openapi_file": (
                    "openapi.json",
                    json.dumps(spec).encode(),
                    "application/json",
                )
            },
        )
        assert response.status_code == 200, response.text[:1200]
        preview = response.json()
        assert preview["count"] == 1
        assert preview["endpoints"][0]["path"] == "/api/echo"
        assert preview["endpoints"][0]["allowed"] is True
        assert preview["endpoints"][0]["fields"] == ["q", "user.name"]
        assert preview["endpoints"][0]["allowlist_pattern"].startswith(
            "POST http://127.0.0.1:9/api/echo"
        )
        assert preview["endpoints"][0]["request"]["body"] == {
            "q": "test",
            "user": {"name": "test"},
        }
        assert preview["stats"]["skipped_methods"] == 1
        assert any("外部 $ref" in item for item in preview["warnings"])
        assert len(preview["spec_fingerprint"]) == 64

        with fixture_server() as base:
            url_response = client.post(
                "/scans/api/preview",
                data={
                    **form,
                    "targets": base,
                    "openapi_url": f"{base}/api/openapi-redirect",
                    "api_post_allowlist": "",
                },
            )
            cookie_response = client.post(
                "/scans/api/preview",
                data={
                    **form,
                    "targets": base,
                    "openapi_url": f"{base}/api/openapi-protected",
                    "api_post_allowlist": "",
                    "auth_type": "cookie",
                    "auth_cookie": "demo-session=abc",
                },
            )
            header_response = client.post(
                "/scans/api/preview",
                data={
                    **form,
                    "targets": base,
                    "openapi_url": f"{base}/api/openapi-protected",
                    "api_post_allowlist": "",
                    "auth_type": "header",
                    "auth_header_name": "Authorization",
                    "auth_header_value": "Bearer demo",
                },
            )
            form_response = client.post(
                "/scans/api/preview",
                data={
                    **form,
                    "targets": base,
                    "openapi_url": f"{base}/api/openapi-protected",
                    "api_post_allowlist": "",
                    "auth_type": "form",
                    "login_url": f"{base}/login",
                    "username": "demo",
                    "password": "demo123",
                },
            )
            state_response = client.post(
                "/scans/api/preview",
                data={
                    **form,
                    "targets": base,
                    "openapi_url": f"{base}/api/openapi-protected",
                    "api_post_allowlist": "",
                    "auth_type": "state",
                },
                files={
                    "auth_state_file": (
                        "state.json",
                        json.dumps(
                            {
                                "cookies": [
                                    {
                                        "name": "demo-session",
                                        "value": "abc",
                                        "domain": "127.0.0.1",
                                        "path": "/",
                                    }
                                ],
                                "origins": [],
                            }
                        ).encode(),
                        "application/json",
                    )
                },
            )
        assert url_response.status_code == 200, url_response.text[:1200]
        url_preview = url_response.json()
        assert url_preview["source"].endswith("/api/openapi.json")
        assert url_preview["warning"]
        assert url_preview["count"] == 2

        assert cookie_response.status_code == 200, cookie_response.text[:1200]
        cookie_preview = cookie_response.json()
        assert cookie_preview["auth_used"] is True
        assert cookie_preview["auth"]["type"] == "cookie"
        assert cookie_preview["count"] == 1

        assert header_response.status_code == 200, header_response.text[:1200]
        header_preview = header_response.json()
        assert header_preview["auth_used"] is True
        assert header_preview["auth"]["type"] == "header"
        assert header_preview["count"] == 1

        assert form_response.status_code == 200, form_response.text[:1200]
        form_preview = form_response.json()
        assert form_preview["auth_used"] is True
        assert form_preview["auth"]["type"] == "form"
        assert form_preview["count"] == 1

        assert state_response.status_code == 200, state_response.text[:1200]
        state_preview = state_response.json()
        assert state_preview["auth_used"] is True
        assert state_preview["auth"]["type"] == "state"
        assert state_preview["count"] == 1


def test_diff_page_renders_result(tmp_path: Path):
    app = create_app(tmp_path)
    with TestClient(app) as client:
        db = app.state.db
        now = datetime.now(UTC)
        for scan_id, created_at in (
            ("scan_diff_previous", now - timedelta(days=1)),
            ("scan_diff_current", now),
        ):
            db.create_scan(
                Scan(
                    id=scan_id,
                    status="completed",
                    profile="safe",
                    targets_json=json.dumps(["https://example.com"]),
                    scope_json=json.dumps(
                        {"authorized_by": "test", "contact": "test@example.com"}
                    ),
                    stats_json="{}",
                    created_at=created_at,
                )
            )
        db.add_findings(
            "scan_diff_previous",
            [
                Finding(
                    rule_id="rule-old",
                    title="舊問題",
                    severity=Severity.MEDIUM,
                    confidence=Confidence.HIGH,
                    url="https://example.com/old",
                    category="測試",
                ),
                Finding(
                    rule_id="api-xss-reflected",
                    title="既有 API 問題",
                    severity=Severity.MEDIUM,
                    confidence=Confidence.HIGH,
                    url="https://example.com/api/echo",
                    category="API / XSS",
                ),
            ],
        )
        db.add_findings(
            "scan_diff_current",
            [
                Finding(
                    rule_id="rule-new",
                    title="新問題",
                    severity=Severity.HIGH,
                    confidence=Confidence.HIGH,
                    url="https://example.com/new",
                    category="測試",
                )
            ],
        )
        db.update_scan(
            "scan_diff_previous",
            scope_json=json.dumps(
                {
                    "authorized_by": "test",
                    "contact": "test@example.com",
                    "api": {
                        "allow_post": True,
                        "test_results": {
                            "endpoints": [
                                {
                                    "url": "https://example.com/api/echo",
                                    "path": "/api/echo",
                                    "tested": True,
                                    "checks": ["xss"],
                                    "findings": 1,
                                }
                            ]
                        },
                        "bola": {
                            "results": [
                                {
                                    "url": "https://example.com/api/object/1",
                                    "path": "/api/object/1",
                                    "result": "protected",
                                }
                            ]
                        },
                    },
                }
            ),
        )
        db.update_scan(
            "scan_diff_current",
            scope_json=json.dumps(
                {
                    "authorized_by": "test",
                    "contact": "test@example.com",
                    "api": {
                        "allow_post": True,
                        "test_results": {
                            "endpoints": [
                                {
                                    "url": "https://example.com/api/echo",
                                    "path": "/api/echo",
                                    "tested": False,
                                    "skipped_reason": "budget",
                                    "checks": [],
                                    "findings": 0,
                                }
                            ]
                        },
                        "bola": {
                            "results": [
                                {
                                    "url": "https://example.com/api/object/1",
                                    "path": "/api/object/1",
                                    "result": "vulnerable",
                                }
                            ]
                        },
                    },
                }
            ),
        )
        response = client.get("/scans/scan_diff_current/diff")
        assert response.status_code == 200
        assert "新增的弱點" in response.text
        assert "已修復" in response.text
        assert "新問題" in response.text
        assert "舊問題" in response.text
        assert "BOLA／BFLA 差異" in response.text
        assert "新出現疑似授權缺失" in response.text
        assert "API 測試覆蓋差異" in response.text
        assert "本次未測的既有發現" in response.text
        assert "既有 API 問題" in response.text


def test_baseline_and_trends_pages(tmp_path: Path):
    app = create_app(tmp_path)
    with TestClient(app) as client:
        db = app.state.db
        now = datetime.now(UTC)
        old_scan = Scan(
            id="scan_web_baseline_old",
            status="completed",
            profile="safe",
            targets_json=json.dumps(["https://example.com"]),
            scope_json=json.dumps(
                {"authorized_by": "test", "contact": "test@example.com"}
            ),
            stats_json="{}",
            created_at=now - timedelta(days=1),
        )
        new_scan = Scan(
            id="scan_web_baseline_new",
            status="completed",
            profile="safe",
            targets_json=json.dumps(["https://example.com"]),
            scope_json=json.dumps(
                {"authorized_by": "test", "contact": "test@example.com"}
            ),
            stats_json="{}",
            created_at=now,
        )
        db.create_scan(old_scan)
        db.create_scan(new_scan)
        db.add_findings(
            old_scan.id,
            [
                Finding(
                    rule_id="rule-baseline-old",
                    title="舊弱點",
                    severity=Severity.MEDIUM,
                    confidence=Confidence.HIGH,
                    url="https://example.com/old",
                    category="測試",
                    description="測試",
                    remediation="修正",
                )
            ],
        )
        db.add_findings(
            new_scan.id,
            [
                Finding(
                    rule_id="rule-baseline-new",
                    title="新弱點",
                    severity=Severity.HIGH,
                    confidence=Confidence.HIGH,
                    url="https://example.com/new",
                    category="測試",
                    description="測試",
                    remediation="修正",
                )
            ],
        )
        client.get("/")
        token = client.cookies.get("vs_csrf")
        assert token

        set_baseline = client.post(
            f"/scans/{old_scan.id}/baseline",
            data={"csrf_token": token, "created_by": "pytest"},
            follow_redirects=False,
        )
        assert set_baseline.status_code == 303
        diff_page = client.get(f"/scans/{new_scan.id}/diff")
        assert diff_page.status_code == 200
        assert "目前 baseline" in diff_page.text
        assert old_scan.id in diff_page.text
        assert "rule-baseline-new" in diff_page.text

        old_diff = client.get(f"/scans/{old_scan.id}/diff")
        assert old_diff.status_code == 200
        assert "此掃描是目前 baseline" in old_diff.text

        trends = client.get("/trends")
        assert trends.status_code == 200
        assert "掃描趨勢" in trends.text
        assert new_scan.id in trends.text
        assert "已確認新增" in trends.text

        review = client.get("/review")
        assert review.status_code == 200
        assert "驗證工作台" in review.text
        assert "待確認" in review.text
        assert "rule-baseline-new" in review.text
        assert "rule-baseline-old" in review.text
        review_confirmed = client.get("/review?status=all&severity=high")
        assert review_confirmed.status_code == 200
        assert "rule-baseline-new" in review_confirmed.text

        cleared = client.post(
            f"/scans/{new_scan.id}/baseline/clear",
            data={"csrf_token": token},
            follow_redirects=False,
        )
        assert cleared.status_code == 303
        assert db.get_baseline_for_scan(db.get_scan(new_scan.id)) is None
