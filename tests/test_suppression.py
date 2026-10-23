from __future__ import annotations

import json
from pathlib import Path

from vulnscan.db import Database
from vulnscan.models import Confidence, Finding, Scan, Severity, new_scan_id
from vulnscan.report import build_report, render_html_report


def _finding(rule_id: str, url: str, title: str) -> Finding:
    return Finding(
        rule_id=rule_id,
        title=title,
        severity=Severity.MEDIUM,
        confidence=Confidence.HIGH,
        url=url,
        category="測試",
        description="測試用",
        evidence={"demo": True},
        remediation="修正",
        refs={"owasp": "A05:2021"},
    )


def _scan(scan_id: str) -> Scan:
    return Scan(
        id=scan_id,
        status="completed",
        profile="safe",
        targets_json=json.dumps(["https://example.com"]),
        scope_json=json.dumps({"authorized_by": "test", "contact": "test@example.com"}),
        stats_json="{}",
    )


def test_suppression_hides_from_active_list_and_report(tmp_path: Path):
    db = Database(tmp_path / "vulnscan.db")
    db.init()
    scan_id = new_scan_id()
    db.create_scan(_scan(scan_id))
    db.add_findings(
        scan_id,
        [
            _finding("rule-a", "https://example.com/a?x=1", "A"),
            _finding("rule-b", "https://example.com/b", "B"),
        ],
    )
    target = next(
        item for item in db.get_findings(scan_id, include_suppressed=True) if item.rule_id == "rule-a"
    )
    db.add_suppression(target, reason="已知誤報", created_by="tester")

    active = db.get_findings(scan_id)
    assert [item.rule_id for item in active] == ["rule-b"]
    assert db.count_findings(scan_id) == 1
    assert db.count_suppressed(scan_id) == 1

    view = db.get_finding_view(target.id)
    assert view is not None and view.suppressed
    assert view.suppression_reason == "已知誤報"
    assert view.suppression_created_by == "tester"

    report = build_report(db, db.get_scan(scan_id))
    assert report["summary"]["total"] == 1
    assert report["summary"]["suppressed"] == 1
    assert report["suppressed_findings"][0]["rule_id"] == "rule-a"
    assert report["suppressed_findings"][0]["suppression_reason"] == "已知誤報"

    html = render_html_report(db, db.get_scan(scan_id))
    assert "已抑制" in html
    assert "已知誤報" in html

    db.remove_suppression(view.suppression_id or 0)
    assert db.count_findings(scan_id) == 2
    assert db.count_suppressed(scan_id) == 0


def test_suppression_is_idempotent(tmp_path: Path):
    db = Database(tmp_path / "vulnscan.db")
    db.init()
    scan_id = new_scan_id()
    db.create_scan(_scan(scan_id))
    db.add_findings(scan_id, [_finding("rule-a", "https://example.com/a", "A")])
    view = db.get_findings(scan_id, include_suppressed=True)[0]
    db.add_suppression(view, reason="first", created_by="tester")
    db.add_suppression(view, reason="updated", created_by="tester")
    assert len(db.list_suppressions()) == 1
    assert db.list_suppressions()[0].reason == "updated"
