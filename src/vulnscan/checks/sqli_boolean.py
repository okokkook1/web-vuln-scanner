from __future__ import annotations

import re
from difflib import SequenceMatcher
from urllib.parse import urlsplit

from ..models import AdvancedCheck, Confidence, Endpoint, Severity
from .active_utils import replace_param, testable_params, with_param_values
from .base import ScanContext, make_finding

SQL_ERROR = re.compile(
    r"You have an error in your SQL syntax|SQLSTATE\[|Unclosed quotation mark|"
    r"ORA-\d{4,5}|near \".*\": syntax error",
    re.IGNORECASE,
)


async def check(endpoints: list[Endpoint], ctx: ScanContext) -> list:
    if AdvancedCheck.SQLI_BOOLEAN not in ctx.config.advanced_checks:
        return []
    findings = []
    tested = 0
    seen: set[tuple[str, str]] = set()
    for endpoint, param in testable_params(endpoints, limit=30):
        key = (urlsplit(endpoint.url).path, param.name)
        if key in seen:
            continue
        seen.add(key)
        if tested >= 6 or not ctx.take_advanced_test():
            break
        original = param.value or "1"
        if "'" in original:
            continue
        tested += 1

        baseline_url = with_param_values(endpoint.url, endpoint.params)
        true_payload = f"{original}' AND '1'='1' -- "
        false_payload = f"{original}' AND '1'='2' -- "
        baseline = await ctx.engine.get(baseline_url, rule_id="sqli-boolean-baseline")
        true_page = await ctx.engine.get(
            replace_param(baseline_url, param.name, true_payload),
            rule_id="sqli-boolean-true",
        )
        false_page = await ctx.engine.get(
            replace_param(baseline_url, param.name, false_payload),
            rule_id="sqli-boolean-false",
        )
        pages = (baseline, true_page, false_page)
        if any(page.status == 0 or page.status in (403, 429) for page in pages):
            continue
        if any(SQL_ERROR.search(page.text) for page in pages):
            # Let the error-based check handle visible SQL errors.
            continue

        base_norm = _normalize(baseline.text)
        true_norm = _normalize(true_page.text)
        false_norm = _normalize(false_page.text)
        sim_base_true = _similarity(base_norm, true_norm)
        sim_true_false = _similarity(true_norm, false_norm)
        status_signal = true_page.status == baseline.status and false_page.status != baseline.status
        content_signal = sim_true_false < 0.93 and sim_base_true > 0.97
        if not (status_signal or content_signal):
            continue

        findings.append(
            make_finding(
                rule_id="sqli-boolean",
                title="布林型 SQL Injection（疑似）",
                severity=Severity.HIGH,
                confidence=Confidence.HIGH if status_signal else Confidence.MEDIUM,
                url=endpoint.url,
                parameter=param.name,
                category="SQLi",
                description=(
                    "成對的真／假 SQL 條件造成不同的回應；可能是布林型 SQL Injection。"
                    "此檢查只讀取頁面，沒有 UNION、寫入或資料匯出。"
                ),
                evidence={
                    "baseline_status": baseline.status,
                    "true_status": true_page.status,
                    "false_status": false_page.status,
                    "baseline_length": len(baseline.text),
                    "true_length": len(true_page.text),
                    "false_length": len(false_page.text),
                    "similarity_baseline_true": round(sim_base_true, 3),
                    "similarity_true_false": round(sim_true_false, 3),
                    "payload_variants": ["true-condition", "false-condition"],
                },
                remediation="使用參數化查詢或預存程序，不要將使用者輸入拼接進 SQL；並關閉詳細錯誤訊息。",
                refs={"owasp": "A03:2021", "cwe": "89"},
            )
        )
        break
    return findings


def _normalize(text: str) -> str:
    text = re.sub(r"<script\b.*?</script>", " ", text, flags=re.IGNORECASE | re.DOTALL)
    text = re.sub(r"<style\b.*?</style>", " ", text, flags=re.IGNORECASE | re.DOTALL)
    text = re.sub(r"\b[0-9a-f]{16,}\b", "token", text, flags=re.IGNORECASE)
    text = re.sub(r"\d+", "0", text)
    text = re.sub(r"\s+", " ", text)
    return text.strip()[:20_000]


def _similarity(left: str, right: str) -> float:
    if not left and not right:
        return 1.0
    return SequenceMatcher(None, left, right).ratio()
