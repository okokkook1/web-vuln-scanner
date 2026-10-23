from __future__ import annotations

import json
from datetime import UTC, date, datetime, timedelta
from pathlib import Path

from vulnscan.db import Database
from vulnscan.models import Confidence, Finding, Scan, Severity, new_scan_id
from vulnscan.report import build_report, render_html_report


def test_html_and_json_reports(tmp_path: Path):
    db = Database(tmp_path / "vulnscan.db")
    db.init()
    scan_id = new_scan_id()
    scan = Scan(
        id=scan_id,
        status="completed",
        profile="full",
        targets_json=json.dumps(["https://example.com"]),
        scope_json=json.dumps(
            {
                "authorized_by": "測試授權人",
                "contact": "security@example.com",
                "expires": (date.today() + timedelta(days=30)).isoformat(),
                "advanced_checks": ["ssrf"],
                "advanced_ack": True,
                "auth": {"type": "form", "login_url": "https://example.com/login"},
                "api": {
                    "openapi": True,
                    "name": "spec.json",
                    "allow_post": True,
                    "post_allowlist": ["POST https://example.com/api/*"],
                    "post_allow_all": False,
                    "spec_fingerprint": "a" * 64,
                    "expected_spec_fingerprint": "a" * 64,
                    "fingerprint_match": True,
                    "auth_session": {
                        "checked": True,
                        "valid": True,
                        "reason": "",
                    },
                    "import_stats": {
                        "get": 1,
                        "post": 2,
                        "skipped_scope": 0,
                        "skipped_methods": 1,
                        "unparsed_bodies": 0,
                    },
                    "import_warnings": ["外部 $ref 未解析"],
                    "selection": {
                        "allowlist": ["POST https://example.com/api/*"],
                        "allow_all": False,
                        "selected_count": 1,
                        "skipped_count": 1,
                        "manifest_summary": {
                            "count": 1,
                            "hosts": ["example.com"],
                            "field_count": 2,
                            "truncated": False,
                        },
                        "selected_endpoints": [
                            {
                                "method": "POST",
                                "url": "https://example.com/api/echo",
                                "path": "/api/echo",
                                "host": "example.com",
                                "fields": ["q", "user.name"],
                            }
                        ],
                    },
                    "test_results": {
                        "selected": 1,
                        "tested": 1,
                        "skipped": 0,
                        "api_tests": 3,
                        "max_api_tests": 20,
                        "findings": 1,
                        "truncated": False,
                        "endpoints": [
                            {
                                "method": "POST",
                                "url": "https://example.com/api/echo",
                                "path": "/api/echo",
                                "checks": ["xss", "sqli_error", "sqli_boolean"],
                                "findings": 1,
                                "skipped_reason": None,
                            }
                        ],
                    },
                    "bola": {
                        "enabled": True,
                        "candidates": 2,
                        "tested": 2,
                        "findings": 1,
                        "secondary_auth": "cookie",
                        "skipped_reason": None,
                    },
                },
            },
            ensure_ascii=False,
        ),
        stats_json=json.dumps(
            {
                "requests": 42,
                "pages": 5,
                "endpoints": 7,
                "findings": 1,
                "by_severity": {"high": 1},
                "fingerprint": {"hosts": {}},
            },
            ensure_ascii=False,
        ),
        started_at=datetime.now(UTC) - timedelta(seconds=20),
        finished_at=datetime.now(UTC),
    )
    db.create_scan(scan)
    db.add_findings(
        scan_id,
        [
            Finding(
                rule_id="hdr-csp-missing",
                title="缺少 Content-Security-Policy",
                severity=Severity.MEDIUM,
                confidence=Confidence.HIGH,
                url="https://example.com/",
                category="安全標頭",
                description="測試用發現",
                evidence={"headers": {"content-security-policy": None}},
                remediation="加上 CSP。",
                refs={"owasp": "A05:2021", "cwe": "693"},
            )
        ],
    )
    finding_id = db.get_findings(scan_id, include_suppressed=True)[0].id
    db.set_finding_review(
        finding_id,
        "confirmed",
        "已人工確認",
        "tester",
    )
    assert db.get_review_history(finding_id)[0].note == "已人工確認"

    report = build_report(db, scan)
    assert report["tool"]["name"] == "VulnScan"
    assert report["summary"]["total"] == 1
    assert report["findings"][0]["rule_id"] == "hdr-csp-missing"
    assert report["findings"][0]["fingerprint"]
    assert report["findings"][0]["review_status"] == "confirmed"
    assert report["findings"][0]["review_history"][0]["note"] == "已人工確認"
    assert report["summary"]["by_review_status"]["confirmed"] == 1
    assert report["api"]["selection"]["selected_count"] == 1
    assert report["api"]["import_warnings"] == ["外部 $ref 未解析"]

    html = render_html_report(db, scan)
    assert "缺少 Content-Security-Policy" in html
    assert "測試授權人" in html
    assert "hdr-csp-missing" in html
    assert "SSRF" in html
    assert "表單登入" in html
    assert "API 掃描範圍" in html
    assert "外部 $ref 未解析" in html
    assert "Spec fingerprint" in html
    assert "Session 檢查" in html
    assert "已選 POST 端點" in html
    assert "已確認" in html
    assert "已人工確認" in html
    assert "驗證歷程" in html
    assert "API 端點測試結果" in html
    assert "BOLA／BFLA 唯讀檢查" in html
    assert "/api/echo" in html
    assert "<script" not in html.lower()
