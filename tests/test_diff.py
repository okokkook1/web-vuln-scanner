from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from pathlib import Path

from vulnscan.db import Database
from vulnscan.diff import compare_scans
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


def test_diff_classifies_new_fixed_unchanged_and_ignores_suppressed(tmp_path: Path):
    db = Database(tmp_path / "vulnscan.db")
    db.init()
    base_time = datetime(2026, 1, 1, tzinfo=UTC)
    previous_id = "scan_previous"
    current_id = "scan_current"
    db.create_scan(_scan(previous_id, base_time))
    db.create_scan(_scan(current_id, base_time + timedelta(days=1)))

    db.add_findings(
        previous_id,
        [
            _finding("rule-a", "/a"),
            _finding("rule-b", "/b"),
            _finding("rule-c", "/c"),
        ],
    )
    db.add_findings(
        current_id,
        [
            _finding("rule-b", "/b"),
            _finding("rule-c", "/c"),
            _finding("rule-d", "/d"),
        ],
    )
    current_c = next(
        item
        for item in db.get_findings(current_id, include_suppressed=True)
        if item.rule_id == "rule-c"
    )
    db.add_suppression(current_c, reason="accepted", created_by="tester")

    result = compare_scans(db, current_id, previous_id)
    assert {item.rule_id for item in result.new} == {"rule-d"}
    assert {item.rule_id for item in result.fixed} == {"rule-a"}
    assert {item.rule_id for item in result.unchanged} == {"rule-b"}
    assert result.current_suppressed == 1
    assert "rule-c" not in {item.rule_id for item in result.fixed}
    assert [scan.id for scan in db.list_previous_scans(current_id)] == [previous_id]


def test_diff_separates_untested_api_from_fixed(tmp_path: Path):
    db = Database(tmp_path / "vulnscan.db")
    db.init()
    base_time = datetime(2026, 1, 1, tzinfo=UTC)
    previous_id = "scan_api_previous"
    current_id = "scan_api_current"
    db.create_scan(_scan(previous_id, base_time))
    db.create_scan(_scan(current_id, base_time + timedelta(days=1)))
    db.add_findings(
        previous_id,
        [
            _finding("api-xss-reflected", "/api/echo"),
            _finding("api-bola-readonly", "/api/object/1"),
            _finding("rule-fixed", "/fixed"),
        ],
    )
    db.update_scan(
        previous_id,
        scope_json=json.dumps(
            {
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
                        "enabled": True,
                        "results": [
                            {
                                "url": "https://example.com/api/object/1",
                                "path": "/api/object/1",
                                "result": "vulnerable",
                            }
                        ],
                    },
                }
            }
        ),
    )
    db.update_scan(
        current_id,
        scope_json=json.dumps(
            {
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
                        "enabled": True,
                        "results": [
                            {
                                "url": "https://example.com/api/object/1",
                                "path": "/api/object/1",
                                "result": "budget",
                            }
                        ],
                    },
                }
            }
        ),
    )

    result = compare_scans(db, current_id, previous_id)
    assert {item.rule_id for item in result.untested} == {
        "api-xss-reflected",
        "api-bola-readonly",
    }
    assert {item.rule_id for item in result.fixed} == {"rule-fixed"}
    assert result.summary["untested"] == 2
    assert result.untested_reasons
    assert result.api_changes
    assert result.api_changes[0]["change"] == "became_untested"


def test_diff_excludes_reviewed_out_findings(tmp_path: Path):
    db = Database(tmp_path / "vulnscan.db")
    db.init()
    base_time = datetime(2026, 1, 1, tzinfo=UTC)
    previous_id = "scan_review_previous"
    current_id = "scan_review_current"
    db.create_scan(_scan(previous_id, base_time))
    db.create_scan(_scan(current_id, base_time + timedelta(days=1)))
    db.add_findings(current_id, [_finding("rule-new", "/new")])
    finding = db.get_findings(current_id, include_suppressed=True)[0]
    db.set_finding_review(finding.id, "false_positive", "lab only", "tester")

    result = compare_scans(db, current_id, previous_id)
    assert result.new == []
    assert [item.rule_id for item in result.reviewed_out] == ["rule-new"]
    assert result.summary["reviewed_out"] == 1


def test_diff_uses_review_state_from_older_scan(tmp_path: Path):
    db = Database(tmp_path / "vulnscan.db")
    db.init()
    base_time = datetime(2026, 1, 1, tzinfo=UTC)
    oldest_id = "scan_review_oldest"
    previous_id = "scan_review_previous_empty"
    current_id = "scan_review_current_again"
    db.create_scan(_scan(oldest_id, base_time))
    db.create_scan(_scan(previous_id, base_time + timedelta(days=1)))
    db.create_scan(_scan(current_id, base_time + timedelta(days=2)))
    db.add_findings(oldest_id, [_finding("rule-recurring", "/recurring")])
    db.add_findings(current_id, [_finding("rule-recurring", "/recurring")])

    oldest = db.get_findings(oldest_id, include_suppressed=True)[0]
    db.set_finding_review(
        oldest.id,
        "accepted_risk",
        "已接受風險",
        "risk-owner",
    )

    result = compare_scans(db, current_id, previous_id)
    assert result.new == []
    assert [item.rule_id for item in result.reviewed_out] == ["rule-recurring"]
    assert result.summary["reviewed_out"] == 1


def test_diff_includes_bola_results(tmp_path: Path):
    db = Database(tmp_path / "vulnscan.db")
    db.init()
    base_time = datetime(2026, 1, 1, tzinfo=UTC)
    previous_id = "scan_bola_previous"
    current_id = "scan_bola_current"
    db.create_scan(_scan(previous_id, base_time))
    db.create_scan(_scan(current_id, base_time + timedelta(days=1)))
    db.update_scan(
        previous_id,
        scope_json=json.dumps(
            {
                "api": {
                    "bola": {
                        "results": [
                            {
                                "url": "https://example.com/api/object/1",
                                "path": "/api/object/1",
                                "result": "vulnerable",
                            },
                            {
                                "url": "https://example.com/api/object/2",
                                "path": "/api/object/2",
                                "result": "protected",
                            },
                            {
                                "url": "https://example.com/api/object/3",
                                "path": "/api/object/3",
                                "result": "budget",
                            },
                        ]
                    }
                }
            }
        ),
    )
    db.update_scan(
        current_id,
        scope_json=json.dumps(
            {
                "api": {
                    "bola": {
                        "results": [
                            {
                                "url": "https://example.com/api/object/1",
                                "path": "/api/object/1",
                                "result": "protected",
                            },
                            {
                                "url": "https://example.com/api/object/2",
                                "path": "/api/object/2",
                                "result": "vulnerable",
                            },
                            {
                                "url": "https://example.com/api/object/3",
                                "path": "/api/object/3",
                                "result": "protected",
                            },
                            {
                                "url": "https://example.com/api/object/4",
                                "path": "/api/object/4",
                                "result": "vulnerable",
                            },
                        ]
                    }
                }
            }
        ),
    )

    result = compare_scans(db, current_id, previous_id)
    changes = {item["url"]: item["change"] for item in result.bola_changes}
    assert changes["https://example.com/api/object/1"] == "no_longer_vulnerable"
    assert changes["https://example.com/api/object/2"] == "newly_vulnerable"
    assert changes["https://example.com/api/object/3"] == "coverage_gained"
    assert changes["https://example.com/api/object/4"] == "newly_vulnerable"
    assert result.summary["bola_changes"] == 4
