from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any

from .db import Database, finding_fingerprint
from .models import FindingView, Scan

RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


@dataclass
class DiffResult:
    current: Scan
    previous: Scan
    new: list[FindingView]
    fixed: list[FindingView]
    unchanged: list[FindingView]
    current_suppressed: int
    previous_suppressed: int
    untested: list[FindingView] = field(default_factory=list)
    untested_reasons: dict[str, str] = field(default_factory=dict)
    reviewed_out: list[FindingView] = field(default_factory=list)
    bola_changes: list[dict[str, Any]] = field(default_factory=list)
    api_changes: list[dict[str, Any]] = field(default_factory=list)

    @property
    def summary(self) -> dict[str, int]:
        return {
            "new": len(self.new),
            "new_confirmed": sum(
                1 for item in self.new if item.review_status == "confirmed"
            ),
            "new_needs_review": sum(
                1 for item in self.new if item.review_status == "needs_review"
            ),
            "fixed": len(self.fixed),
            "untested": len(self.untested),
            "reviewed_out": len(self.reviewed_out),
            "unchanged": len(self.unchanged),
            "suppressed": self.current_suppressed,
            "bola_changes": len(self.bola_changes),
            "api_changes": len(self.api_changes),
        }


def _sort(findings: list[FindingView]) -> list[FindingView]:
    return sorted(
        findings,
        key=lambda item: (RANK.get(item.severity, 9), item.rule_id, item.url, item.parameter or ""),
    )


def _api_scope(scan: Scan) -> dict[str, Any]:
    try:
        scope = json.loads(scan.scope_json or "{}")
    except (TypeError, json.JSONDecodeError):
        return {}
    if not isinstance(scope, dict):
        return {}
    api = scope.get("api") or {}
    return api if isinstance(api, dict) else {}


def _api_bola_results(scan: Scan) -> dict[str, dict[str, Any]]:
    api = _api_scope(scan)
    bola = api.get("bola") or {}
    if not isinstance(bola, dict):
        return {}
    results = bola.get("results") or []
    if not isinstance(results, list):
        return {}
    return {
        str(item.get("url")): item
        for item in results
        if isinstance(item, dict) and item.get("url")
    }


def _api_test_results(scan: Scan) -> dict[str, dict[str, Any]]:
    api = _api_scope(scan)
    tests = api.get("test_results") or {}
    if not isinstance(tests, dict):
        return {}
    endpoints = tests.get("endpoints") or []
    if not isinstance(endpoints, list):
        return {}
    return {
        str(item.get("url")): item
        for item in endpoints
        if isinstance(item, dict) and item.get("url")
    }


def _untested_reason(finding: FindingView, current: Scan) -> str | None:
    if not finding.rule_id.startswith("api-"):
        return None
    api = _api_scope(current)
    url = finding.url
    if finding.rule_id in ("api-bola-readonly", "api-bfla-readonly"):
        bola = api.get("bola") or {}
        if not isinstance(bola, dict) or not bola.get("enabled"):
            return "本次未啟用 BOLA／IDOR 檢查"
        result = _api_bola_results(current).get(url)
        if not result:
            return "本次 BOLA 未測試此端點"
        value = str(result.get("result") or "")
        if value in (
            "budget",
            "inconclusive",
            "primary_auth_failed",
            "secondary_auth_failed",
            "secondary_session_invalid",
        ):
            return f"本次 BOLA 結果：{value}"
        return None
    if not api.get("allow_post"):
        return "本次未啟用 API POST 測試"
    selection = api.get("selection") or {}
    if isinstance(selection, dict) and selection.get("skipped_reason"):
        return f"本次 API POST 略過：{selection.get('skipped_reason')}"
    result = _api_test_results(current).get(url)
    if not result:
        return "本次 API POST 未選取此端點"
    if not result.get("tested"):
        reason = result.get("skipped_reason") or "未測試"
        return f"本次 API POST 未測試：{reason}"
    return None


def _compare_api_tests(current: Scan, previous: Scan) -> list[dict[str, Any]]:
    current_results = _api_test_results(current)
    previous_results = _api_test_results(previous)
    changes: list[dict[str, Any]] = []
    for url in sorted(set(current_results) | set(previous_results)):
        current_item = current_results.get(url)
        previous_item = previous_results.get(url)
        current_tested = bool(current_item and current_item.get("tested"))
        previous_tested = bool(previous_item and previous_item.get("tested"))
        current_skip = (
            current_item.get("skipped_reason") if current_item else "not_present"
        )
        previous_skip = (
            previous_item.get("skipped_reason") if previous_item else "not_present"
        )
        current_checks = tuple(
            sorted((current_item or {}).get("checks") or [])
        )
        previous_checks = tuple(
            sorted((previous_item or {}).get("checks") or [])
        )
        current_findings = int((current_item or {}).get("findings") or 0)
        previous_findings = int((previous_item or {}).get("findings") or 0)
        if previous_tested and not current_tested:
            change = "became_untested"
        elif not previous_tested and current_tested:
            change = "became_tested"
        elif not current_tested and current_skip != previous_skip:
            change = "skip_reason_changed"
        elif current_checks != previous_checks:
            change = "checks_changed"
        elif current_findings != previous_findings:
            change = "findings_changed"
        else:
            continue
        sample = current_item or previous_item or {}
        changes.append(
            {
                "url": url,
                "path": sample.get("path") or "",
                "change": change,
                "previous_tested": previous_tested,
                "current_tested": current_tested,
                "previous_skip_reason": previous_skip,
                "current_skip_reason": current_skip,
                "previous_checks": list(previous_checks),
                "current_checks": list(current_checks),
                "previous_findings": previous_findings,
                "current_findings": current_findings,
            }
        )
    return changes


def _compare_bola(current: Scan, previous: Scan) -> list[dict[str, Any]]:
    current_results = _api_bola_results(current)
    previous_results = _api_bola_results(previous)
    changes: list[dict[str, Any]] = []
    for url in sorted(set(current_results) | set(previous_results)):
        current_item = current_results.get(url)
        previous_item = previous_results.get(url)
        current_result = (
            str(current_item.get("result")) if current_item else "not_tested"
        )
        previous_result = (
            str(previous_item.get("result")) if previous_item else "not_tested"
        )
        if current_result == previous_result:
            continue
        if current_result == "vulnerable" and previous_result != "vulnerable":
            change = "newly_vulnerable"
        elif previous_result == "vulnerable" and current_result != "vulnerable":
            change = "no_longer_vulnerable"
        elif current_result in ("budget", "not_tested") and previous_result not in (
            "budget",
            "not_tested",
        ):
            change = "coverage_lost"
        elif previous_result in ("budget", "not_tested") and current_result not in (
            "budget",
            "not_tested",
        ):
            change = "coverage_gained"
        else:
            change = "status_changed"
        sample = current_item or previous_item or {}
        changes.append(
            {
                "url": url,
                "kind": sample.get("kind") or "bola",
                "path": sample.get("path") or "",
                "parameter": sample.get("parameter"),
                "change": change,
                "previous": previous_result,
                "current": current_result,
                "primary_status": (
                    current_item or previous_item or {}
                ).get("primary_status"),
                "secondary_status": (
                    current_item or previous_item or {}
                ).get("secondary_status"),
                "unauth_status": (
                    current_item or previous_item or {}
                ).get("unauth_status"),
                "similarity": (current_item or {}).get("similarity"),
            }
        )
    return changes


DIFF_GATE_CHOICES = (
    "none",
    "new",
    "new_confirmed",
    "new_needs_review",
    "reviewed_out",
    "any",
)


def gate_failed(result: DiffResult, fail_on: str) -> bool:
    if fail_on == "none":
        return False
    if fail_on == "new":
        return result.summary["new"] > 0
    if fail_on == "new_confirmed":
        return result.summary["new_confirmed"] > 0
    if fail_on == "new_needs_review":
        return result.summary["new_needs_review"] > 0
    if fail_on == "reviewed_out":
        return result.summary["reviewed_out"] > 0
    if fail_on == "any":
        return (
            result.summary["new"] > 0
            or result.summary["reviewed_out"] > 0
        )
    raise ValueError("未知的 diff gate 條件")


def compare_scans(db: Database, current_id: str, previous_id: str) -> DiffResult:
    current = db.get_scan(current_id)
    previous = db.get_scan(previous_id)
    if not current or not previous:
        raise ValueError("找不到要比較的掃描")
    if current.id == previous.id:
        raise ValueError("不能與自己比較")

    current_findings = db.get_findings(current_id, limit=5000, include_suppressed=True)
    previous_findings = db.get_findings(previous_id, limit=5000, include_suppressed=True)
    current_map = {finding_fingerprint(item): item for item in current_findings}
    previous_map = {finding_fingerprint(item): item for item in previous_findings}

    new_candidates = [
        current_map[key]
        for key in current_map
        if not current_map[key].suppressed
        and (key not in previous_map or previous_map[key].suppressed)
    ]
    reviewed_out: list[FindingView] = []
    new: list[FindingView] = []
    for item in new_candidates:
        if item.review_status in ("false_positive", "accepted_risk"):
            reviewed_out.append(item)
        else:
            new.append(item)
    missing_current = [
        previous_map[key]
        for key in previous_map
        if not previous_map[key].suppressed and key not in current_map
    ]
    untested: list[FindingView] = []
    untested_reasons: dict[str, str] = {}
    fixed: list[FindingView] = []
    for item in missing_current:
        if item.review_status in ("false_positive", "accepted_risk"):
            continue
        reason = _untested_reason(item, current)
        if reason:
            untested.append(item)
            untested_reasons[str(item.id)] = reason
        else:
            fixed.append(item)
    unchanged = [
        current_map[key]
        for key in current_map
        if not current_map[key].suppressed
        and key in previous_map
        and not previous_map[key].suppressed
    ]
    return DiffResult(
        current=current,
        previous=previous,
        new=_sort(new),
        fixed=_sort(fixed),
        unchanged=_sort(unchanged),
        current_suppressed=db.count_suppressed(current_id),
        previous_suppressed=db.count_suppressed(previous_id),
        untested=_sort(untested),
        untested_reasons=untested_reasons,
        reviewed_out=_sort(reviewed_out),
        bola_changes=_compare_bola(current, previous),
        api_changes=_compare_api_tests(current, previous),
    )
