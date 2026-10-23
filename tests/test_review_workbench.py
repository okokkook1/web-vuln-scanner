from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from pathlib import Path

from vulnscan.db import Database
from vulnscan.models import Confidence, Finding, Scan, Severity, utcnow


def _finding(
    rule_id: str,
    path: str,
    *,
    severity: Severity = Severity.MEDIUM,
) -> Finding:
    return Finding(
        rule_id=rule_id,
        title=rule_id,
        severity=severity,
        confidence=Confidence.HIGH,
        url=f"https://example.com{path}",
        category="測試",
        description="測試",
        remediation="修正",
    )


def _scan(scan_id: str, created_at: datetime, target: str = "https://example.com") -> Scan:
    return Scan(
        id=scan_id,
        status="completed",
        profile="safe",
        targets_json=json.dumps([target]),
        scope_json=json.dumps({"authorized_by": "test", "contact": "test@example.com"}),
        stats_json="{}",
        created_at=created_at,
    )


def test_review_workbench_deduplicates_and_handles_expiry(tmp_path: Path):
    db = Database(tmp_path / "vulnscan.db")
    db.init()
    base = datetime(2026, 1, 1, tzinfo=UTC)
    db.create_scan(_scan("scan_review_wb_one", base))
    db.create_scan(_scan("scan_review_wb_two", base + timedelta(days=1)))
    db.create_scan(
        _scan("scan_review_wb_other", base, target="https://other.example")
    )
    db.add_findings(
        "scan_review_wb_one",
        [
            _finding("rule-repeat", "/repeat"),
            _finding("rule-confirmed", "/confirmed", severity=Severity.HIGH),
            _finding("rule-expired", "/expired"),
        ],
    )
    db.add_findings(
        "scan_review_wb_two",
        [
            _finding("rule-repeat", "/repeat"),
            _finding("rule-new", "/new"),
            _finding("rule-expiring", "/expiring"),
        ],
    )
    db.add_findings(
        "scan_review_wb_other",
        [_finding("rule-other", "/other")],
    )

    confirmed = next(
        item
        for item in db.get_findings("scan_review_wb_one")
        if item.rule_id == "rule-confirmed"
    )
    db.set_finding_review(confirmed.id, "confirmed", "已確認", "tester")
    expired = next(
        item
        for item in db.get_findings("scan_review_wb_one")
        if item.rule_id == "rule-expired"
    )
    db.set_finding_review(
        expired.id,
        "accepted_risk",
        "已到期",
        "owner",
        expires_at=base,
    )
    expiring = next(
        item
        for item in db.get_findings("scan_review_wb_two")
        if item.rule_id == "rule-expiring"
    )
    db.set_finding_review(
        expiring.id,
        "accepted_risk",
        "即將到期",
        "owner",
        expires_at=utcnow() + timedelta(days=10),
    )

    result = db.review_workbench()
    assert result["counts"]["needs_review"] == 3
    assert result["counts"]["confirmed"] == 1
    assert result["counts"]["accepted_risk"] == 2
    assert result["high_priority"] == 0
    assert [item["fingerprint"].split("|")[0] for item in result["rows"]] == [
        "rule-new",
        "rule-repeat",
        "rule-other",
    ]
    repeat = next(
        item for item in result["rows"] if item["finding"].rule_id == "rule-repeat"
    )
    assert repeat["occurrence_count"] == 2
    assert repeat["scan_count"] == 2
    assert result["expired_risks"][0]["finding"].rule_id == "rule-expired"
    assert result["expired_risks"][0]["expiry_state"] == "expired"
    assert result["expiring_risks"][0]["finding"].rule_id == "rule-expiring"
    assert result["expiring_risks"][0]["expiry_state"] == "expiring"

    high = db.review_workbench(
        status="all",
        severity="high",
    )
    assert [item["finding"].rule_id for item in high["rows"]] == [
        "rule-confirmed"
    ]

    filtered = db.review_workbench(target="https://other.example")
    assert [item["finding"].rule_id for item in filtered["rows"]] == ["rule-other"]
