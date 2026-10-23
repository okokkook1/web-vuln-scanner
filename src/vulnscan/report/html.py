from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path

from jinja2 import Environment, FileSystemLoader, select_autoescape

from ..db import Database, finding_to_dict
from ..models import Scan
from ..presentation import (
    ADVANCED_LABELS,
    AUTH_LABELS,
    CONFIDENCE_LABELS,
    PROFILE_LABELS,
    REVIEW_LABELS,
    SEVERITY_LABELS,
    STATUS_LABELS,
    TZ,
    format_dt,
    format_duration,
    load_json,
    scan_stats,
    severity_order,
)

TEMPLATE_DIR = Path(__file__).parent / "templates"


def render_html_report(db: Database, scan: Scan) -> str:
    env = Environment(
        loader=FileSystemLoader(str(TEMPLATE_DIR)),
        autoescape=select_autoescape(["html", "xml"]),
    )
    env.filters["dt"] = format_dt
    env.filters["duration"] = format_duration
    env.filters["status_label"] = lambda value: STATUS_LABELS.get(value, value)
    env.filters["severity_label"] = lambda value: SEVERITY_LABELS.get(value, value)
    env.filters["confidence_label"] = lambda value: CONFIDENCE_LABELS.get(value, value)
    env.filters["profile_label"] = lambda value: PROFILE_LABELS.get(value, value)
    env.filters["advanced_label"] = lambda value: ADVANCED_LABELS.get(value, value)
    env.filters["auth_label"] = lambda value: AUTH_LABELS.get(value, value)
    env.filters["review_label"] = lambda value: REVIEW_LABELS.get(value, value)
    env.filters["pretty"] = lambda value: json.dumps(value, ensure_ascii=False, indent=2)
    template = env.get_template("report.html")

    rows = db.get_findings(scan.id, limit=5000)
    findings = [finding_to_dict(row) for row in rows]
    all_rows = db.get_findings(scan.id, limit=5000, include_suppressed=True)
    suppressed_findings = [finding_to_dict(row) for row in all_rows if row.suppressed]
    history = db.review_histories(scan.id)
    for finding in findings + suppressed_findings:
        finding["review_history"] = history.get(finding.get("id"), [])
    counts = {key: 0 for key in severity_order()}
    for finding in findings:
        counts[finding["severity"]] = counts.get(finding["severity"], 0) + 1
    scope = load_json(scan.scope_json, {})
    stats = scan_stats(scan)
    return template.render(
        scan=scan,
        findings=findings,
        suppressed_findings=suppressed_findings,
        suppressed_count=len(suppressed_findings),
        counts=counts,
        total=len(findings),
        scope=scope,
        stats=stats,
        targets=load_json(scan.targets_json, []),
        fingerprint=stats.get("fingerprint", {}),
        generated_at=datetime.now(TZ),
    )
