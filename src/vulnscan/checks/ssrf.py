from __future__ import annotations

import secrets
from urllib.parse import urlsplit

from ..models import AdvancedCheck, Confidence, Endpoint, Severity
from .active_utils import replace_param, testable_params
from .base import ScanContext, make_finding

HINTS = (
    "url",
    "uri",
    "link",
    "src",
    "source",
    "dest",
    "destination",
    "callback",
    "webhook",
    "image",
    "img",
    "avatar",
    "fetch",
    "feed",
    "host",
    "domain",
    "redirect",
    "next",
    "return",
    "target",
    "proxy",
)


async def check(endpoints: list[Endpoint], ctx: ScanContext) -> list:
    if AdvancedCheck.SSRF not in ctx.config.advanced_checks:
        return []
    if ctx.callback is None:
        ctx.log("SSRF 略過：callback listener 未啟動")
        return []

    findings = []
    tested = 0
    seen: set[tuple[str, str]] = set()
    for endpoint, param in testable_params(endpoints, limit=50):
        value = (param.value or "").lower()
        if not (
            any(hint in param.name.lower() for hint in HINTS)
            or value.startswith(("http://", "https://"))
        ):
            continue
        key = (urlsplit(endpoint.url).path, param.name)
        if key in seen:
            continue
        seen.add(key)
        if tested >= 8 or not ctx.take_advanced_test():
            break
        tested += 1

        token = secrets.token_hex(8)
        callback_url = ctx.callback.url_for(token)
        probe = await ctx.engine.get(
            replace_param(endpoint.url, param.name, callback_url),
            rule_id="ssrf-probe",
        )
        hits = await ctx.callback.wait(token, timeout=3.0)
        if not hits:
            continue

        first = hits[0]
        findings.append(
            make_finding(
                rule_id="ssrf-callback",
                title="SSRF（callback 驗證）",
                severity=Severity.HIGH,
                confidence=Confidence.HIGH,
                url=endpoint.url,
                parameter=param.name,
                category="SSRF",
                description=(
                    "目標伺服器主動連線到掃描器提供的唯一 callback URL，"
                    "表示此參數可被用來發出伺服器端請求。"
                ),
                evidence={
                    "callback_url": callback_url,
                    "hit_count": len(hits),
                    "probe_status": probe.status,
                    "method": first.method,
                    "path": first.path,
                    "client": first.client,
                    "user_agent": first.headers.get("user-agent"),
                    "received_at": first.received_at,
                },
                remediation=(
                    "限制伺服器可連線的目的地（allowlist），封鎖私有 IP 與 metadata 位址，"
                    "並對使用者提供的 URL 做解析後 IP 檢查。"
                ),
                refs={"owasp": "A10:2021", "cwe": "918"},
            )
        )
        if len(findings) >= 3:
            break
    return findings
