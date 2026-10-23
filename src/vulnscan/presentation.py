from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta, timezone
from typing import Any

TZ = timezone(timedelta(hours=8))

STATUS_LABELS = {
    "queued": "排隊中",
    "running": "掃描中",
    "completed": "已完成",
    "failed": "失敗",
    "cancelled": "已取消",
}

REVIEW_LABELS = {
    "needs_review": "待確認",
    "confirmed": "已確認",
    "false_positive": "誤報",
    "accepted_risk": "接受風險",
}


SEVERITY_LABELS = {
    "critical": "嚴重",
    "high": "高",
    "medium": "中",
    "low": "低",
    "info": "資訊",
}

CONFIDENCE_LABELS = {"high": "高", "medium": "中", "low": "低"}

PROFILE_LABELS = {
    "passive": "被動盤點",
    "safe": "安全主動",
    "full": "完整",
}

ADVANCED_LABELS = {
    "sqli_boolean": "布林型 SQLi",
    "traversal": "路徑遍歷",
    "ssrf": "SSRF",
}

AUTH_LABELS = {
    "none": "不使用登入",
    "cookie": "Cookie",
    "header": "自訂 Header",
    "form": "表單登入",
    "state": "瀏覽器狀態檔（SSO／MFA）",
    "browser": "瀏覽器互動登入（SSO／MFA）",
}


def format_dt(value: datetime | str | None) -> str:
    if not value:
        return "—"
    if isinstance(value, str):
        try:
            value = datetime.fromisoformat(value)
        except ValueError:
            return value
    if value.tzinfo is None:
        value = value.replace(tzinfo=UTC)
    return value.astimezone(TZ).strftime("%Y-%m-%d %H:%M")


def format_duration(scan) -> str:
    if not scan.started_at or not scan.finished_at:
        return "—"
    start = scan.started_at
    end = scan.finished_at
    if start.tzinfo is None:
        start = start.replace(tzinfo=UTC)
    if end.tzinfo is None:
        end = end.replace(tzinfo=UTC)
    seconds = max(0, int((end - start).total_seconds()))
    if seconds < 60:
        return f"{seconds} 秒"
    return f"{seconds // 60} 分 {seconds % 60} 秒"


def load_json(raw: str | None, fallback: Any = None) -> Any:
    if not raw:
        return fallback if fallback is not None else {}
    try:
        return json.loads(raw)
    except (TypeError, json.JSONDecodeError):
        return fallback if fallback is not None else {}


def scan_stats(scan) -> dict[str, Any]:
    return load_json(scan.stats_json, {})


def severity_order() -> list[str]:
    return ["critical", "high", "medium", "low", "info"]
