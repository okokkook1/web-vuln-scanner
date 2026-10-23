from __future__ import annotations

import re

from ..models import Confidence, Endpoint, Severity
from .active_utils import replace_param, testable_params, with_param_values
from .base import ScanContext, make_finding

ERROR_PATTERNS = [
    ("MySQL", re.compile(r"You have an error in your SQL syntax|Warning:\s*mysql_|MySqlException", re.I)),
    ("PostgreSQL", re.compile(r"PostgreSQL.*ERROR|pg_query\(\)|unterminated quoted string", re.I)),
    (
        "Microsoft SQL Server",
        re.compile(
            r"Unclosed quotation mark after the character string|Microsoft OLE DB Provider for SQL Server|SqlException",
            re.I,
        ),
    ),
    ("Oracle", re.compile(r"ORA-\d{4,5}|quoted string not properly terminated", re.I)),
    ("SQLite", re.compile(r"SQLite/JDBCDriver|SQLite\.Exception|near \".*\": syntax error", re.I)),
]


async def check(endpoints: list[Endpoint], ctx: ScanContext) -> list:
    findings = []
    candidates = testable_params(endpoints, limit=16)
    tested = 0
    for endpoint, param in candidates:
        if tested >= 8 or not ctx.take_test():
            break
        tested += 1
        baseline_url = with_param_values(endpoint.url, endpoint.params)
        baseline = await ctx.engine.get(baseline_url, rule_id="sqli-baseline")
        if baseline.status == 0 or baseline.error:
            continue
        original = param.value or "1"
        if original.endswith("'"):
            continue
        payload = f"{original}'"
        url = replace_param(baseline_url, param.name, payload)
        page = await ctx.engine.get(url, rule_id="sqli-error")
        if page.status == 0 or page.error:
            continue
        for label, pattern in ERROR_PATTERNS:
            if not pattern.search(page.text):
                continue
            if pattern.search(baseline.text):
                continue
            match = pattern.search(page.text)
            start = max(0, match.start() - 120) if match else 0
            findings.append(
                make_finding(
                    rule_id="sqli-error",
                    title="SQL 錯誤訊息洩漏（疑似 SQL Injection）",
                    severity=Severity.HIGH,
                    confidence=Confidence.HIGH,
                    url=endpoint.url,
                    parameter=param.name,
                    category="SQLi",
                    description="加入單引號後出現資料庫錯誤特徵，且基準請求沒有相同訊息；需人工確認是否可注入。",
                    evidence={
                        "database": label,
                        "baseline_status": baseline.status,
                        "quote_status": page.status,
                        "snippet": page.text[start : start + 500],
                    },
                    remediation="使用參數化查詢／預存程序，關閉詳細資料庫錯誤，並對輸入做型別驗證。",
                    refs={"owasp": "A03:2021", "cwe": "89"},
                )
            )
            break
    return findings
