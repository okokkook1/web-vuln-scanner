from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from pathlib import Path

from vulnscan.db import Database
from vulnscan.models import Confidence, Finding, Scan, Severity


def _finding(rule_id: str, path: str) -> Finding:
    return Finding(
        rule_id=rule_id,
        title=rule_id,
        severity=Severity.MEDIUM,
        confidence=Confidence.HIGH,
        url=f"https://example.com{path}",
        category="測試",
        description="測試",
        remediation="修正",
    )


def _scan(
    scan_id: str,
    created_at: datetime,
    target: str = "https://example.com",
    status: str = "completed",
) -> Scan:
    return Scan(
        id=scan_id,
        status=status,
        profile="safe",
        targets_json=json.dumps([target]),
        scope_json=json.dumps({"authorized_by": "test", "contact": "test@example.com"}),
        stats_json="{}",
        created_at=created_at,
    )


def test_baseline_is_stored_per_target(tmp_path: Path):
    db = Database(tmp_path / "vulnscan.db")
    db.init()
    base_time = datetime(2026, 1, 1, tzinfo=UTC)
    db.create_scan(_scan("scan_base_old", base_time))
    db.create_scan(_scan("scan_base_new", base_time + timedelta(days=1)))
    db.create_scan(
        _scan("scan_base_other", base_time, target="https://other.example")
    )
    db.create_scan(_scan("scan_base_running", base_time, status="running"))

    assert db.get_baseline_for_scan(db.get_scan("scan_base_new")) is None
    stored = db.set_baseline("scan_base_old", "tester")
    assert stored is not None
    assert stored.scan_id == "scan_base_old"

    baseline = db.get_baseline_for_scan(db.get_scan("scan_base_new"))
    assert baseline is not None
    assert baseline.id == "scan_base_old"
    assert db.get_baseline_for_scan(db.get_scan("scan_base_other")) is None
    assert db.can_compare_scans("scan_base_new", "scan_base_old") is True
    assert db.can_compare_scans("scan_base_old", "scan_base_new") is False

    assert db.remove_baseline_for_scan("scan_base_new") is True
    assert db.get_baseline_for_scan(db.get_scan("scan_base_new")) is None
    assert db.set_baseline("scan_base_running") is None

    assert db.set_baseline("scan_base_old") is not None
    db.delete_scan("scan_base_old")
    assert db.get_baseline_for_scan(db.get_scan("scan_base_new")) is None


def test_target_trends_compare_each_scan_with_previous(tmp_path: Path):
    db = Database(tmp_path / "vulnscan.db")
    db.init()
    base_time = datetime(2026, 1, 1, tzinfo=UTC)
    for offset, scan_id in enumerate(
        ["scan_trend_one", "scan_trend_two", "scan_trend_three"]
    ):
        db.create_scan(_scan(scan_id, base_time + timedelta(days=offset)))
    db.add_findings(
        "scan_trend_one",
        [_finding("rule-a", "/a"), _finding("rule-b", "/b")],
    )
    db.add_findings(
        "scan_trend_two",
        [_finding("rule-b", "/b"), _finding("rule-c", "/c")],
    )
    db.add_findings(
        "scan_trend_three",
        [_finding("rule-b", "/b"), _finding("rule-d", "/d")],
    )
    reviewed = next(
        item
        for item in db.get_findings("scan_trend_two")
        if item.rule_id == "rule-c"
    )
    db.set_finding_review(reviewed.id, "confirmed", "已確認", "tester")

    trends = db.target_trends()
    assert len(trends) == 1
    group = trends[0]
    assert group["scan_count"] == 3
    assert [row["scan"].id for row in group["series"]] == [
        "scan_trend_one",
        "scan_trend_two",
        "scan_trend_three",
    ]
    first, second, third = group["series"]
    assert first["new"] is None
    assert second["new"] == 1
    assert second["new_confirmed"] == 1
    assert second["fixed"] == 1
    assert second["review_counts"]["confirmed"] == 1
    assert third["new"] == 1
    assert third["fixed"] == 1
    assert third["findings"] == 2
    assert group["latest_findings"] == 2
    assert group["open_high"] == 0
