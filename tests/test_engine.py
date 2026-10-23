from __future__ import annotations

import asyncio
import json
from pathlib import Path

from vulnscan.db import Database
from vulnscan.engine import ScanEngine
from vulnscan.models import AdvancedCheck, Profile, Scan, new_scan_id
from vulnscan.scope import build_scope

from .fixture_server import fixture_server
from .helpers import make_config


async def _run_scan(tmp_path: Path, config):
    scope = build_scope(config)
    db = Database(tmp_path / "vulnscan.db")
    db.init()
    scan_id = new_scan_id()
    db.create_scan(
        Scan(
            id=scan_id,
            status="running",
            profile=config.profile.value,
            targets_json=json.dumps(config.targets),
            scope_json=json.dumps(scope.snapshot(), ensure_ascii=False),
        )
    )
    updates: list[tuple[str, str, int]] = []

    def on_update(phase: str, message: str, stats: dict, progress: int) -> None:
        updates.append((phase, message, progress))

    engine = ScanEngine(
        scan_id=scan_id,
        config=config,
        db=db,
        data_dir=tmp_path,
        cancel_event=asyncio.Event(),
        on_update=on_update,
    )
    result = await engine.run()
    return result, db, scan_id, updates


async def test_safe_scan_against_demo_site(tmp_path: Path):
    with fixture_server() as base:
        result, db, scan_id, updates = await _run_scan(tmp_path, make_config(base))

    rule_ids = {finding.rule_id for finding in result.findings}
    expected = {
        "hdr-csp-missing",
        "hdr-xfo-missing",
        "cookie-httponly-missing",
        "disc-server-version",
        "cors-reflect-credentials",
        "method-dangerous",
        "csrf-token-missing",
        "file-env-exposed",
        "api-openapi-exposed",
        "js-secret-aws-access-key",
        "redirect-open",
        "xss-reflected",
        "sqli-error",
        "disc-stacktrace",
    }
    missing = expected - rule_ids
    assert not missing, f"缺少檢查結果：{sorted(missing)}；實際：{sorted(rule_ids)}"
    assert "sqli-boolean" not in rule_ids
    assert "traversal-error" not in rule_ids
    assert result.stats.findings == len(result.findings)
    assert result.stats.requests > 10
    assert (tmp_path / "scans" / scan_id / "audit.jsonl").exists()
    assert any(progress == 100 for _, _, progress in updates)
    assert db.count_findings(scan_id) == len(result.findings)
    assert updates[0][0] == "validate"


async def test_full_mode_runs_boolean_sqli_and_traversal(tmp_path: Path):
    config = make_config(
        "http://127.0.0.1:1",
        profile=Profile.FULL,
        advanced_checks=[
            AdvancedCheck.SQLI_BOOLEAN,
            AdvancedCheck.TRAVERSAL,
            AdvancedCheck.SSRF,
        ],
        advanced_ack=True,
    )
    with fixture_server() as base:
        config.targets = [base]
        result, _, _, _ = await _run_scan(tmp_path, config)

    rule_ids = {finding.rule_id for finding in result.findings}
    assert "sqli-boolean" in rule_ids
    assert "traversal-error" in rule_ids
    assert "ssrf-callback" in rule_ids
    assert "xss-reflected" in rule_ids
    assert result.stats.requests > 20
