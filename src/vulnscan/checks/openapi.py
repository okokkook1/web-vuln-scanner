from __future__ import annotations

from urllib.parse import urljoin

from ..http import BudgetExceeded, ScanCancelled
from ..models import Confidence, Severity
from .base import ScanContext, make_finding

PATHS = ("/openapi.json", "/swagger.json", "/v3/api-docs", "/api-docs")


async def check(ctx: ScanContext) -> list:
    findings = []
    for base in ctx.scope.base_urls():
        for path in PATHS:
            url = urljoin(base, path.lstrip("/"))
            try:
                page = await ctx.engine.get(url, rule_id="api-openapi-exposed")
            except BudgetExceeded:
                return findings
            except ScanCancelled:
                raise
            if page.status != 200:
                continue
            body = page.text.strip()
            lowered = body[:2000].lower()
            if not body.startswith("{") or not (
                '"openapi"' in lowered or '"swagger"' in lowered
            ):
                continue
            findings.append(
                make_finding(
                    rule_id="api-openapi-exposed",
                    title="OpenAPI / Swagger 文件公開",
                    severity=Severity.LOW,
                    confidence=Confidence.HIGH,
                    url=url,
                    category="API",
                    description="API 規格文件可協助攻擊者列舉端點、參數與資料模型。",
                    evidence={
                        "status": page.status,
                        "content_type": page.content_type,
                        "snippet": body[:400],
                    },
                    remediation="將 API 文件限制在內部網路或加上驗證，正式環境避免公開。",
                    refs={"owasp": "A05:2021", "cwe": "200"},
                )
            )
            break
    return findings
