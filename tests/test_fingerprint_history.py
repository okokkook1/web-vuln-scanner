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


def _scan(scan_id: str, created_at: datetime) -> Scan:
    return Scan(
        id=scan_id,
        status="completed",
        profile="safe",
        targets_json=json.dumps(["https://example.com"]),
        scope_json=json.dumps({"authorized_by": "test", "contact": "test@example.com"}),
        stats_json="{}",
        created_at=created_at,
        finished_at=created_at + timedelta(minutes=1),
    )


def test_fingerprint_history_collects_occurrences_and_reviews(tmp_path: Path):
    db = Database(tmp_path / "vulnscan.db")
    db.init()
    base_time = datetime(2026, 1, 1, tzinfo=UTC)
    scan_ids = ["scan_fp_one", "scan_fp_two", "scan_fp_three"]
    for offset, scan_id in enumerate(scan_ids):
        db.create_scan(_scan(scan_id, base_time + timedelta(days=offset)))
        db.add_findings(scan_id, [_finding("rule-history", "/history")])

    first = db.get_findings(scan_ids[0])[0]
    db.set_finding_review(first.id, "confirmed", "第一次確認", "tester")
    db.set_finding_review(
        first.id,
        "accepted_risk",
        "暫存環境可接受",
        "risk-owner",
        expires_at=datetime(2027, 1, 1, tzinfo=UTC),
    )

    history = db.fingerprint_history(first.fingerprint)
    assert history is not None
    assert history["occurrence_count"] == 3
    assert history["scan_count"] == 3
    assert history["first_seen"] <= history["last_seen"]
    assert [item["finding"].scan_id for item in history["occurrences"]] == scan_ids
    assert [item["scan"].created_at for item in history["occurrences"]] == [
        base_time + timedelta(days=offset) for offset in range(3)
    ]
    assert history["review"]["status"] == "accepted_risk"
    assert history["review"]["note"] == "暫存環境可接受"
    assert history["review"]["expires_at"] is not None
    assert [event["status"] for event in history["events"]] == [
        "accepted_risk",
        "confirmed",
    ]
    assert history["severity_counts"] == {"medium": 3}
    assert history["latest_finding_id"] == db.get_findings(scan_ids[-1])[0].id
    assert db.fingerprint_history("missing|GET|example.com|/none|") is None
