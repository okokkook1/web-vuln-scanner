"""Seed a deterministic local database for the CI diff-gate smoke test."""

from __future__ import annotations

import argparse
import json
from datetime import UTC, datetime, timedelta
from pathlib import Path

from vulnscan.db import Database
from vulnscan.models import Confidence, Finding, Scan, Severity


def _scan(scan_id: str, target: str, created_at: datetime) -> Scan:
    return Scan(
        id=scan_id,
        status="completed",
        profile="safe",
        targets_json=json.dumps([target]),
        scope_json=json.dumps(
            {
                "authorized_by": "CI fixture",
                "contact": "ci@example.com",
                "expires": "2099-12-31",
            }
        ),
        stats_json="{}",
        created_at=created_at,
        started_at=created_at,
        finished_at=created_at + timedelta(minutes=1),
    )


def _finding(
    rule_id: str,
    url: str,
    severity: Severity = Severity.MEDIUM,
) -> Finding:
    return Finding(
        rule_id=rule_id,
        title=rule_id,
        severity=severity,
        confidence=Confidence.HIGH,
        url=url,
        category="CI fixture",
        description="Deterministic CI fixture finding",
        remediation="Fixture only",
    )


def seed(data_dir: Path) -> None:
    db = Database(data_dir / "vulnscan.db")
    db.init()
    base = datetime(2026, 1, 1, tzinfo=UTC)
    later = base + timedelta(days=1)

    fail_target = "https://ci-fail.example"
    db.create_scan(_scan("ci_gate_fail_base", fail_target, base))
    db.create_scan(_scan("ci_gate_fail_current", fail_target, later))
    db.add_findings(
        "ci_gate_fail_base",
        [_finding("ci-rule-existing", f"{fail_target}/existing")],
    )
    db.add_findings(
        "ci_gate_fail_current",
        [
            _finding("ci-rule-existing", f"{fail_target}/existing"),
            _finding("ci-rule-new", f"{fail_target}/new"),
        ],
    )
    new_finding = next(
        item
        for item in db.get_findings("ci_gate_fail_current")
        if item.rule_id == "ci-rule-new"
    )
    db.set_finding_review(
        new_finding.id,
        "confirmed",
        "CI gate fixture",
        "ci",
    )
    db.set_baseline("ci_gate_fail_base", "ci")

    pass_target = "https://ci-pass.example"
    db.create_scan(_scan("ci_gate_pass_base", pass_target, base))
    db.create_scan(_scan("ci_gate_pass_current", pass_target, later))
    db.add_findings(
        "ci_gate_pass_base",
        [_finding("ci-rule-existing", f"{pass_target}/existing")],
    )
    db.add_findings(
        "ci_gate_pass_current",
        [
            _finding("ci-rule-existing", f"{pass_target}/existing"),
            _finding("ci-rule-pending", f"{pass_target}/pending"),
        ],
    )
    db.set_baseline("ci_gate_pass_base", "ci")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--data-dir", required=True, type=Path)
    args = parser.parse_args()
    seed(args.data_dir)
    print(f"Seeded CI diff-gate fixture in {args.data_dir.resolve()}")


if __name__ == "__main__":
    main()
