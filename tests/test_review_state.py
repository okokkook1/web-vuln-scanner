from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from vulnscan.db import Database, finding_fingerprint
from vulnscan.models import (
    Confidence,
    Finding,
    FindingReview,
    FindingReviewEvent,
    Scan,
    Severity,
)


def _finding(
    rule_id: str,
    path: str,
    *,
    severity: Severity = Severity.MEDIUM,
    evidence: dict | None = None,
) -> Finding:
    return Finding(
        rule_id=rule_id,
        title=rule_id,
        severity=severity,
        confidence=Confidence.HIGH,
        url=f"https://example.com{path}",
        category="測試",
        description="測試",
        evidence=evidence or {},
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


def test_review_state_is_shared_across_scans_by_fingerprint(tmp_path: Path):
    db = Database(tmp_path / "vulnscan.db")
    db.init()
    base_time = datetime(2026, 1, 1, tzinfo=UTC)
    previous_id = "scan_shared_previous"
    current_id = "scan_shared_current"
    db.create_scan(_scan(previous_id, base_time))
    db.create_scan(_scan(current_id, base_time + timedelta(days=1)))
    db.add_findings(previous_id, [_finding("rule-shared", "/shared")])
    db.add_findings(current_id, [_finding("rule-shared", "/shared")])

    previous = db.get_findings(previous_id)[0]
    current = db.get_findings(current_id)[0]
    assert finding_fingerprint(previous) == finding_fingerprint(current)

    db.set_finding_review(
        previous.id,
        "confirmed",
        "跨掃描確認",
        "tester",
    )

    inherited = db.get_findings(current_id)[0]
    assert inherited.review_status == "confirmed"
    assert inherited.review_note == "跨掃描確認"
    assert inherited.review_updated_by == "tester"
    assert db.get_review_history(current.id)[0].note == "跨掃描確認"
    confirmed = db.get_findings(current_id, review_status="confirmed")
    assert [item.id for item in confirmed] == [current.id]

    db.set_finding_review(
        current.id,
        "false_positive",
        "只在測試環境出現",
        "reviewer",
    )

    updated = db.get_findings(previous_id)[0]
    assert updated.review_status == "false_positive"
    assert updated.review_note == "只在測試環境出現"
    assert updated.review_updated_by == "reviewer"
    assert [item.status for item in db.get_review_history(previous.id)] == [
        "false_positive",
        "confirmed",
    ]


def test_legacy_reviews_are_backfilled_once(tmp_path: Path):
    db = Database(tmp_path / "vulnscan.db")
    db.init()
    scan_id = "scan_legacy_review"
    db.create_scan(_scan(scan_id, datetime(2026, 1, 1, tzinfo=UTC)))
    db.add_findings(scan_id, [_finding("rule-legacy", "/legacy")])
    finding = db.get_findings(scan_id)[0]

    with db.session() as session:
        session.add(
            FindingReview(
                finding_id=finding.id,
                status="false_positive",
                note="舊資料誤報",
                updated_by="legacy-user",
            )
        )
        session.add(
            FindingReviewEvent(
                finding_id=finding.id,
                status="false_positive",
                note="舊資料誤報",
                updated_by="legacy-user",
            )
        )
        session.commit()

    db.init()

    migrated = db.get_finding_view(finding.id)
    assert migrated.review_status == "false_positive"
    assert migrated.review_note == "舊資料誤報"
    assert migrated.review_updated_by == "legacy-user"
    assert len(db.get_review_history(finding.id)) == 1
    assert db.review_status_counts(scan_id)["false_positive"] == 1

    db.init()
    assert len(db.get_review_history(finding.id)) == 1


def test_review_policy_requires_notes_for_risk_decisions(tmp_path: Path):
    db = Database(tmp_path / "vulnscan.db")
    db.init()
    scan_id = "scan_review_policy"
    db.create_scan(_scan(scan_id, datetime(2026, 1, 1, tzinfo=UTC)))
    db.add_findings(scan_id, [_finding("rule-policy", "/policy")])
    finding = db.get_findings(scan_id)[0]

    with pytest.raises(ValueError):
        db.set_finding_review(finding.id, "false_positive", "   ")
    with pytest.raises(ValueError):
        db.set_finding_review(finding.id, "accepted_risk", "")
    with pytest.raises(ValueError):
        db.set_review_many([finding.id], "accepted_risk", "")

    assert db.get_finding_view(finding.id).review_status == "needs_review"
    db.set_finding_review(finding.id, "confirmed", "")
    assert db.get_finding_view(finding.id).review_status == "confirmed"


def test_review_reopens_when_severity_escalates(tmp_path: Path):
    db = Database(tmp_path / "vulnscan.db")
    db.init()
    base_time = datetime(2026, 1, 1, tzinfo=UTC)
    old_id = "scan_reopen_severity_old"
    new_id = "scan_reopen_severity_new"
    db.create_scan(_scan(old_id, base_time))
    db.create_scan(_scan(new_id, base_time + timedelta(days=1)))
    db.add_findings(old_id, [_finding("rule-escalate", "/escalate")])
    old = db.get_findings(old_id)[0]
    db.set_finding_review(old.id, "confirmed", "原本已確認", "tester")

    db.add_findings(
        new_id,
        [_finding("rule-escalate", "/escalate", severity=Severity.HIGH)],
    )

    current = db.get_findings(new_id)[0]
    assert current.review_status == "needs_review"
    assert "嚴重度" in current.review_note
    assert "自動重開" in current.review_note
    newest = db.get_review_history(current.id)[0]
    assert newest.updated_by == "system"
    assert newest.status == "needs_review"


def test_accepted_risk_reopens_after_expiry(tmp_path: Path):
    db = Database(tmp_path / "vulnscan.db")
    db.init()
    base_time = datetime(2026, 1, 1, tzinfo=UTC)
    old_id = "scan_expiry_old"
    new_id = "scan_expiry_new"
    db.create_scan(_scan(old_id, base_time))
    db.create_scan(_scan(new_id, base_time + timedelta(days=1)))
    db.add_findings(old_id, [_finding("rule-expiry", "/expiry")])
    old = db.get_findings(old_id)[0]
    db.set_finding_review(
        old.id,
        "accepted_risk",
        "暫時接受",
        "owner",
        expires_at=datetime(2025, 12, 31, tzinfo=UTC),
    )

    db.add_findings(new_id, [_finding("rule-expiry", "/expiry")])

    current = db.get_findings(new_id)[0]
    assert current.review_status == "needs_review"
    assert "到期" in current.review_note
    history = db.get_review_history(current.id)
    assert history[0].updated_by == "system"
    assert history[-1].expires_at is not None


def test_false_positive_reopens_when_evidence_changes(tmp_path: Path):
    db = Database(tmp_path / "vulnscan.db")
    db.init()
    base_time = datetime(2026, 1, 1, tzinfo=UTC)
    old_id = "scan_evidence_old"
    new_id = "scan_evidence_new"
    db.create_scan(_scan(old_id, base_time))
    db.create_scan(_scan(new_id, base_time + timedelta(days=1)))
    db.add_findings(
        old_id,
        [_finding("rule-evidence", "/evidence", evidence={"detail": "a"})],
    )
    old = db.get_findings(old_id)[0]
    db.set_finding_review(old.id, "false_positive", "實驗室誤報", "tester")

    db.add_findings(
        new_id,
        [_finding("rule-evidence", "/evidence", evidence={"detail": "b"})],
    )

    current = db.get_findings(new_id)[0]
    assert current.review_status == "needs_review"
    assert "證據" in current.review_note
