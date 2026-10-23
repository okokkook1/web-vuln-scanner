from __future__ import annotations

from ..models import Confidence, Endpoint, Severity
from .active_utils import replace_param, testable_params
from .base import ScanContext, make_finding

CANARY = "https://vulnscan-canary.invalid/redirect"
HINTS = (
    "redirect",
    "redir",
    "next",
    "return",
    "returnto",
    "continue",
    "dest",
    "destination",
    "target",
    "url",
    "uri",
    "callback",
    "back",
)


async def check(endpoints: list[Endpoint], ctx: ScanContext) -> list:
    findings = []
    candidates = []
    for endpoint, param in testable_params(endpoints, limit=50):
        value = (param.value or "").lower()
        if any(hint in param.name.lower() for hint in HINTS) or value.startswith(
            ("http://", "https://", "/")
        ):
            candidates.append((endpoint, param))
        if len(candidates) >= 20:
            break

    for endpoint, param in candidates:
        if not ctx.take_test():
            break
        url = replace_param(endpoint.url, param.name, CANARY)
        page = await ctx.engine.get(url, rule_id="redirect-open")
        if page.status not in (301, 302, 303, 307, 308):
            continue
        location = page.headers.get("location", "")
        if "vulnscan-canary.invalid" not in location:
            continue
        findings.append(
            make_finding(
                rule_id="redirect-open",
                title="開放式重新導向",
                severity=Severity.MEDIUM,
                confidence=Confidence.HIGH,
                url=endpoint.url,
                parameter=param.name,
                category="開放重導",
                description="應用將使用者可控參數當成導向目標，可能被用於釣魚或繞過檢查。",
                evidence={
                    "payload": CANARY,
                    "status": page.status,
                    "location": location,
                },
                remediation="只允許導向固定白名單或站內相對路徑，並驗證最終目標。",
                refs={"owasp": "A01:2021", "cwe": "601"},
            )
        )
    return findings
