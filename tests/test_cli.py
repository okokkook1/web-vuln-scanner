from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from pathlib import Path

from typer.testing import CliRunner

from vulnscan.cli import app
from vulnscan.db import Database
from vulnscan.models import Confidence, Finding, Scan, Severity


def _scan(scan_id: str, created_at: datetime) -> Scan:
    return Scan(
        id=scan_id,
        status="completed",
        profile="safe",
        targets_json=json.dumps(["https://example.com"]),
        scope_json=json.dumps({"authorized_by": "test", "contact": "test@example.com"}),
        stats_json="{}",
        created_at=created_at,
    )


def _finding(rule_id: str, path: str) -> Finding:
    return Finding(
        rule_id=rule_id,
        title=rule_id,
        severity=Severity.MEDIUM,
        confidence=Confidence.HIGH,
        url=f"https://example.com{path}",
        category="測試",
        remediation="修正",
    )


def test_cli_diff_suppress_and_unsuppress(tmp_path: Path):
    data_dir = tmp_path / "data"
    db = Database(data_dir / "vulnscan.db")
    db.init()
    now = datetime.now(UTC)
    db.create_scan(_scan("scan_old", now - timedelta(days=1)))
    db.create_scan(_scan("scan_new", now))
    db.add_findings("scan_old", [_finding("rule-old", "/old")])
    db.add_findings("scan_new", [_finding("rule-new", "/new")])
    finding_id = db.get_findings("scan_new")[0].id
    runner = CliRunner()

    result = runner.invoke(
        app,
        ["diff", "--current", "scan_new", "--data-dir", str(data_dir)],
    )
    assert result.exit_code == 0, result.output
    assert "新增 1" in result.output
    assert "已修復 1" in result.output
    assert "rule-new" in result.output
    assert "rule-old" in result.output

    suppressed = runner.invoke(
        app,
        [
            "suppress",
            "--finding",
            str(finding_id),
            "--reason",
            "CLI test",
            "--created-by",
            "pytest",
            "--data-dir",
            str(data_dir),
        ],
    )
    assert suppressed.exit_code == 0, suppressed.output
    assert "已抑制" in suppressed.output

    listed = runner.invoke(
        app,
        ["suppressions", "--json", "--data-dir", str(data_dir)],
    )
    assert listed.exit_code == 0, listed.output
    rows = json.loads(listed.output)
    assert rows[0]["rule_id"] == "rule-new"
    assert rows[0]["reason"] == "CLI test"

    diff_json = runner.invoke(
        app,
        ["diff", "--current", "scan_new", "--json", "--data-dir", str(data_dir)],
    )
    assert diff_json.exit_code == 0, diff_json.output
    payload = json.loads(diff_json.output)
    assert payload["summary"]["suppressed"] == 1
    assert payload["summary"]["new"] == 0

    removed = runner.invoke(
        app,
        ["unsuppress", "--finding", str(finding_id), "--data-dir", str(data_dir)],
    )
    assert removed.exit_code == 0, removed.output
    assert "已移除抑制" in removed.output
    assert db.count_suppressed("scan_new") == 0


def test_cli_openapi_url_requires_one_source_and_excludes_file(tmp_path: Path):
    runner = CliRunner()
    base_args = [
        "scan",
        "--url",
        "http://127.0.0.1:9/",
        "--allow-private",
        "--acknowledge-authorized",
    ]

    missing_source = runner.invoke(app, [*base_args, "--api-post"])
    assert missing_source.exit_code == 2
    assert "--openapi" in missing_source.output

    both_sources = runner.invoke(
        app,
        [
            *base_args,
            "--openapi",
            str(tmp_path / "missing.json"),
            "--openapi-url",
            "http://127.0.0.1:9/openapi.json",
        ],
    )
    assert both_sources.exit_code == 2
    assert "只能擇一" in both_sources.output

    spec_path = tmp_path / "openapi.json"
    spec_path.write_text(
        json.dumps({"openapi": "3.0.0", "paths": {}}),
        encoding="utf-8",
    )
    no_allow_ack = runner.invoke(
        app,
        [*base_args, "--openapi", str(spec_path), "--api-post"],
    )
    assert no_allow_ack.exit_code == 2
    assert "--api-post-all" in no_allow_ack.output


def test_cli_diff_gate_and_stored_baseline(tmp_path: Path):
    data_dir = tmp_path / "data"
    db = Database(data_dir / "vulnscan.db")
    db.init()
    now = datetime.now(UTC)
    db.create_scan(_scan("scan_gate_base", now - timedelta(days=3)))
    db.create_scan(_scan("scan_gate_middle", now - timedelta(days=2)))
    db.create_scan(_scan("scan_gate_latest", now))
    db.add_findings("scan_gate_base", [_finding("rule-gate-base", "/base")])
    db.add_findings("scan_gate_middle", [_finding("rule-gate-mid", "/mid")])
    db.add_findings("scan_gate_latest", [_finding("rule-gate-new", "/new")])
    assert db.set_baseline("scan_gate_base", "pytest") is not None

    runner = CliRunner()
    failed = runner.invoke(
        app,
        [
            "diff",
            "--current",
            "scan_gate_latest",
            "--fail-on",
            "new",
            "--json",
            "--data-dir",
            str(data_dir),
        ],
    )
    assert failed.exit_code == 1, failed.output
    payload = json.loads(failed.output)
    assert payload["previous"] == "scan_gate_base"
    assert payload["gate"] == {"fail_on": "new", "failed": True}
    assert payload["summary"]["new"] == 1

    passed = runner.invoke(
        app,
        [
            "diff",
            "--current",
            "scan_gate_latest",
            "--fail-on",
            "new_confirmed",
            "--data-dir",
            str(data_dir),
        ],
    )
    assert passed.exit_code == 0, passed.output
    assert "Gate: new_confirmed" in passed.output
    assert "PASS" in passed.output

    db.remove_baseline_for_scan("scan_gate_latest")
    missing = runner.invoke(
        app,
        [
            "diff",
            "--current",
            "scan_gate_latest",
            "--baseline",
            "--data-dir",
            str(data_dir),
        ],
    )
    assert missing.exit_code == 2
    assert "尚未設定" in missing.output

    invalid = runner.invoke(
        app,
        [
            "diff",
            "--current",
            "scan_gate_latest",
            "--fail-on",
            "unknown",
            "--data-dir",
            str(data_dir),
        ],
    )
    assert invalid.exit_code == 2
    assert "未知的 --fail-on" in invalid.output
