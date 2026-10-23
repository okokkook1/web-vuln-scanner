from __future__ import annotations

from collections import Counter
from typing import Any

from .. import __version__
from ..db import Database, finding_to_dict
from ..models import Scan
from ..presentation import load_json, scan_stats, severity_order


def build_report(db: Database, scan: Scan) -> dict[str, Any]:
    rows = db.get_findings(scan.id, limit=5000)
    findings = [finding_to_dict(row) for row in rows]
    all_rows = db.get_findings(scan.id, limit=5000, include_suppressed=True)
    suppressed = [finding_to_dict(row) for row in all_rows if row.suppressed]
    counts = {key: 0 for key in severity_order()}
    for item in findings:
        counts[item["severity"]] = counts.get(item["severity"], 0) + 1
    review_counts = Counter(
        item.get("review_status") or "needs_review" for item in findings
    )
    history = db.review_histories(scan.id)
    for item in findings + suppressed:
        item["review_history"] = history.get(item.get("id"), [])
    scope = load_json(scan.scope_json, {})
    api = scope.get("api", {}) if isinstance(scope, dict) else {}
    return {
        "report_version": "1.0",
        "tool": {"name": "VulnScan", "version": __version__},
        "scan": {
            "id": scan.id,
            "created_at": scan.created_at.isoformat() if scan.created_at else None,
            "started_at": scan.started_at.isoformat() if scan.started_at else None,
            "finished_at": scan.finished_at.isoformat() if scan.finished_at else None,
            "status": scan.status,
            "profile": scan.profile,
            "targets": load_json(scan.targets_json, []),
        },
        "scope": scope,
        "api": api,
        "stats": scan_stats(scan),
        "summary": {
            "total": len(findings),
            "suppressed": len(suppressed),
            "by_severity": counts,
            "by_review_status": dict(review_counts),
        },
        "findings": findings,
        "suppressed_findings": suppressed,
    }
