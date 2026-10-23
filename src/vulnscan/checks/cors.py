from __future__ import annotations

from ..http import BudgetExceeded, ScanCancelled
from ..models import Confidence, Severity
from .base import ScanContext, make_finding

CANARY_ORIGIN = "https://vulnscan-canary.invalid"


async def check(ctx: ScanContext) -> list:
    findings = []
    for base in ctx.scope.base_urls():
        try:
            page = await ctx.engine.get(
                base,
                headers={"Origin": CANARY_ORIGIN},
                rule_id="cors-check",
            )
        except BudgetExceeded:
            return findings
        except ScanCancelled:
            raise
        if page.status == 0:
            continue
        acao = page.headers.get("access-control-allow-origin", "")
        acac = page.headers.get("access-control-allow-credentials", "").lower() == "true"
        if not acao:
            continue
        normalized = acao.strip()
        reflected = normalized == CANARY_ORIGIN or normalized == "null"
        if reflected and acac:
            findings.append(
                make_finding(
                    rule_id="cors-reflect-credentials",
                    title="CORS 反射 Origin 且允許 credentials",
                    severity=Severity.HIGH,
                    confidence=Confidence.HIGH,
                    url=base,
                    category="CORS",
                    description="任意來源都可能帶著使用者 Cookie 讀取回應，屬於高風險 CORS 設定。",
                    evidence={"origin": CANARY_ORIGIN, "acao": acao, "acac": acac},
                    remediation="改用明確的允許來源清單，不要反射 Origin；確有必要才開啟 credentials。",
                    refs={"owasp": "A01:2021", "cwe": "942"},
                )
            )
        elif reflected:
            findings.append(
                make_finding(
                    rule_id="cors-reflect-origin",
                    title="CORS 反射任意 Origin",
                    severity=Severity.MEDIUM,
                    confidence=Confidence.HIGH,
                    url=base,
                    category="CORS",
                    description="伺服器將任意 Origin 回寫到 Access-Control-Allow-Origin，可能讓惡意網站讀取回應。",
                    evidence={"origin": CANARY_ORIGIN, "acao": acao, "acac": acac},
                    remediation="使用允許來源白名單，不要直接反射請求的 Origin。",
                    refs={"owasp": "A01:2021", "cwe": "942"},
                )
            )
        elif normalized == "*" and acac:
            findings.append(
                make_finding(
                    rule_id="cors-wildcard-credentials",
                    title="CORS 萬用 Origin 搭配 credentials",
                    severity=Severity.MEDIUM,
                    confidence=Confidence.MEDIUM,
                    url=base,
                    category="CORS",
                    description=(
                        "Access-Control-Allow-Origin: * 與 credentials 同時出現，設定不一致；"
                        "部分實作可能誤放行。"
                    ),
                    evidence={"acao": acao, "acac": acac},
                    remediation="改為明確來源，並確認 credentials 只在必要端點開啟。",
                    refs={"owasp": "A01:2021", "cwe": "942"},
                )
            )
    return findings
