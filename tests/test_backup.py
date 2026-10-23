from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path
from zipfile import ZipFile

import pytest
from typer.testing import CliRunner

from vulnscan.backup import BackupError, create_backup, restore_backup
from vulnscan.cli import app
from vulnscan.db import Database
from vulnscan.models import Confidence, Finding, Scan, Severity


def _scan(scan_id: str = "scan_backup_test") -> Scan:
    return Scan(
        id=scan_id,
        status="completed",
        profile="safe",
        targets_json=json.dumps(["https://example.com"]),
        scope_json=json.dumps(
            {"authorized_by": "test", "contact": "test@example.com"}
        ),
        stats_json="{}",
        created_at=datetime(2026, 1, 1, tzinfo=UTC),
    )


def _finding() -> Finding:
    return Finding(
        rule_id="rule-backup",
        title="備份測試",
        severity=Severity.MEDIUM,
        confidence=Confidence.HIGH,
        url="https://example.com/backup",
        category="測試",
        description="測試",
        remediation="修正",
    )


def _make_source(tmp_path: Path) -> Path:
    data_dir = tmp_path / "data"
    db = Database(data_dir / "vulnscan.db")
    db.init()
    db.create_scan(_scan())
    db.add_findings("scan_backup_test", [_finding()])
    (data_dir / "settings.json").write_text(
        json.dumps({"rps_per_host": 2}),
        encoding="utf-8",
    )
    scan_dir = data_dir / "scans" / "scan_backup_test"
    scan_dir.mkdir(parents=True)
    (scan_dir / "audit.jsonl").write_text('{"status": 200}\n', encoding="utf-8")
    return data_dir


def test_backup_and_restore_roundtrip(tmp_path: Path):
    data_dir = _make_source(tmp_path)
    archive = tmp_path / "backup.zip"
    result = create_backup(data_dir, archive)
    assert archive.is_file()
    assert result["file_count"] == 2

    with ZipFile(archive) as backup:
        names = set(backup.namelist())
    assert "vulnscan.db" in names
    assert "backup.json" in names
    assert "settings.json" in names
    assert "scans/scan_backup_test/audit.jsonl" in names

    restored_dir = tmp_path / "restored"
    restore = restore_backup(archive, restored_dir)
    assert restore["previous"] is None
    restored = Database(restored_dir / "vulnscan.db")
    restored.init()
    scans = restored.list_scans()
    assert [scan.id for scan in scans] == ["scan_backup_test"]
    assert restored.get_findings("scan_backup_test")[0].rule_id == "rule-backup"
    assert (restored_dir / "settings.json").is_file()
    assert (
        restored_dir / "scans" / "scan_backup_test" / "audit.jsonl"
    ).is_file()
    assert not (restored_dir / "backup.json").exists()


def test_restore_requires_force_and_preserves_old_data(tmp_path: Path):
    data_dir = _make_source(tmp_path)
    archive = tmp_path / "backup.zip"
    create_backup(data_dir, archive)

    target = tmp_path / "target"
    target.mkdir()
    (target / "keep.txt").write_text("old data", encoding="utf-8")
    with pytest.raises(BackupError, match="不是空的"):
        restore_backup(archive, target)

    result = restore_backup(archive, target, force=True)
    assert result["previous"]
    previous = Path(result["previous"])
    assert (previous / "keep.txt").read_text(encoding="utf-8") == "old data"
    assert (target / "vulnscan.db").is_file()


def test_restore_rejects_unsafe_archive_paths(tmp_path: Path):
    archive = tmp_path / "bad.zip"
    with ZipFile(archive, "w") as backup:
        backup.writestr("../evil.txt", "bad")
        backup.writestr("vulnscan.db", "")
    with pytest.raises(BackupError, match="不安全路徑"):
        restore_backup(archive, tmp_path / "restored")


def test_cli_backup_and_restore(tmp_path: Path):
    data_dir = _make_source(tmp_path)
    archive = tmp_path / "cli-backup.zip"
    runner = CliRunner()
    created = runner.invoke(
        app,
        ["backup", "--data-dir", str(data_dir), "--out", str(archive)],
    )
    assert created.exit_code == 0, created.output
    assert "備份完成" in created.output
    assert archive.is_file()

    target = tmp_path / "cli-restored"
    restored = runner.invoke(
        app,
        ["restore", "--from", str(archive), "--data-dir", str(target)],
    )
    assert restored.exit_code == 0, restored.output
    assert "還原完成" in restored.output
    assert (target / "vulnscan.db").is_file()
