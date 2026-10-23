from __future__ import annotations

import secrets

from ..models import Confidence, Endpoint, Severity
from .active_utils import replace_param, testable_params
from .base import ScanContext, make_finding


async def check(endpoints: list[Endpoint], ctx: ScanContext) -> list:
    findings = []
    candidates = testable_params(endpoints, limit=25)
    for endpoint, param in candidates:
        if not ctx.take_test():
            break
        token = secrets.token_hex(4)
        payload = f"<b>vs{token}</b>"
        url = replace_param(endpoint.url, param.name, payload)
        page = await ctx.engine.get(url, rule_id="xss-reflected")
        if page.status == 0 or page.status >= 500 or not page.is_html:
            continue
        if payload not in page.text:
            continue
        index = page.text.find(payload)
        if _is_inert_context(page.text, index):
            continue
        snippet = page.text[max(0, index - 100) : index + len(payload) + 100]
        findings.append(
            make_finding(
                rule_id="xss-reflected",
                title="反射型 HTML 注入 / XSS 風險",
                severity=Severity.MEDIUM,
                confidence=Confidence.HIGH,
                url=endpoint.url,
                parameter=param.name,
                category="XSS",
                description="無害的 HTML 標記被原樣反射，表示輸入未經 HTML 編碼；實際可利用性需人工確認。",
                evidence={
                    "payload": payload,
                    "status": page.status,
                    "snippet": snippet,
                },
                remediation="依輸出語境進行 HTML / 屬性 / JavaScript 編碼，並搭配 CSP 作為縱深防禦。",
                refs={"owasp": "A03:2021", "cwe": "79"},
            )
        )
    return findings


def _is_inert_context(text: str, index: int) -> bool:
    """Avoid flagging reflections inside script/style/textarea/title or attributes."""
    before = text[:index].lower()
    if before.rfind("<!--") > before.rfind("-->"):
        return True
    for tag in ("script", "style", "textarea", "title"):
        if before.rfind(f"<{tag}") > before.rfind(f"</{tag}>"):
            return True
    last_lt = text.rfind("<", 0, index)
    last_gt = text.rfind(">", 0, index)
    return last_lt > last_gt
