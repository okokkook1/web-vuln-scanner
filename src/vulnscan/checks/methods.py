from __future__ import annotations

from ..http import BudgetExceeded, ScanCancelled
from ..models import Confidence, Severity
from .base import ScanContext, make_finding

DANGEROUS = {"PUT", "DELETE", "PATCH", "CONNECT"}


async def check(ctx: ScanContext) -> list:
    findings = []
    for base in ctx.scope.base_urls():
        try:
            page = await ctx.engine.options(base, rule_id="method-check")
        except BudgetExceeded:
            return findings
        except ScanCancelled:
            raise
        if page.status == 0 or page.status >= 400:
            continue
        allow_header = page.headers.get("allow", "")
        if not allow_header:
            continue
        methods = {item.strip().upper() for item in allow_header.split(",") if item.strip()}
        risky = sorted(methods & DANGEROUS)
        if risky:
            findings.append(
                make_finding(
                    rule_id="method-dangerous",
                    title="伺服器允許高風險 HTTP 方法",
                    severity=Severity.LOW,
                    confidence=Confidence.HIGH,
                    url=base,
                    category="HTTP 方法",
                    description="OPTIONS 回應顯示允許可用於修改或刪除資源的方法；是否真的可用仍需人工確認。",
                    evidence={"allow": allow_header, "methods": risky},
                    remediation="只開放應用實際需要的方法，並在伺服器或 WAF 層限制 PUT/DELETE/PATCH。",
                    refs={"owasp": "A05:2021", "cwe": "650"},
                )
            )
        if "TRACE" in methods:
            findings.append(
                make_finding(
                    rule_id="method-trace",
                    title="TRACE 方法開啟",
                    severity=Severity.MEDIUM,
                    confidence=Confidence.HIGH,
                    url=base,
                    category="HTTP 方法",
                    description="TRACE 可能被用於 Cross-Site Tracing（XST）。",
                    evidence={"allow": allow_header},
                    remediation="關閉 TRACE 方法（Apache: TraceEnable off；Nginx 預設不支援）。",
                    refs={"owasp": "A05:2021", "cwe": "650"},
                )
            )
    return findings
