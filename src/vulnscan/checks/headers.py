from __future__ import annotations

from ..models import Confidence, Page, Severity
from .base import ScanContext, make_finding, representative_pages

HEADER_RULES = {
    "content-security-policy": (
        "hdr-csp-missing",
        "缺少 Content-Security-Policy",
        Severity.MEDIUM,
        "CSP 可以限制瀏覽器只載入與執行允許的資源，降低 XSS 與第三方腳本風險。",
        "為 HTML 回應設定 Content-Security-Policy，預設拒絕 inline script，只允許必要來源。",
        {"owasp": "A05:2021", "cwe": "693"},
    ),
    "x-content-type-options": (
        "hdr-xcto-missing",
        "缺少 X-Content-Type-Options: nosniff",
        Severity.LOW,
        "瀏覽器可能以不同於宣告的型別解讀回應，增加 MIME sniffing 風險。",
        "在所有回應加上 X-Content-Type-Options: nosniff。",
        {"owasp": "A05:2021", "cwe": "693"},
    ),
    "referrer-policy": (
        "hdr-referrer-missing",
        "缺少 Referrer-Policy",
        Severity.LOW,
        "跨站請求可能透過 Referer 洩漏路徑或查詢參數。",
        "設定 Referrer-Policy: strict-origin-when-cross-origin 或更嚴格的策略。",
        {"owasp": "A05:2021", "cwe": "200"},
    ),
    "permissions-policy": (
        "hdr-permissions-missing",
        "缺少 Permissions-Policy",
        Severity.LOW,
        "瀏覽器功能（攝影機、麥克風、地理位置）未明確限制。",
        "設定 Permissions-Policy，只開放網站實際需要的功能。",
        {"owasp": "A05:2021", "cwe": "693"},
    ),
}


def check(pages: list[Page], ctx: ScanContext) -> list:
    findings = []
    for page in representative_pages(pages):
        headers = page.headers
        csp = headers.get("content-security-policy", "")
        for header, rule in HEADER_RULES.items():
            if header == "content-security-policy":
                if csp or headers.get("content-security-policy-report-only"):
                    continue
            elif header == "x-content-type-options":
                if headers.get(header, "").lower().strip() == "nosniff":
                    continue
            elif header in headers:
                continue
            rule_id, title, severity, description, remediation, refs = rule
            findings.append(
                make_finding(
                    rule_id=rule_id,
                    title=title,
                    severity=severity,
                    confidence=Confidence.HIGH,
                    url=page.url,
                    category="安全標頭",
                    description=description,
                    evidence={"status": page.status, "headers": _header_snapshot(headers)},
                    remediation=remediation,
                    refs=refs,
                )
            )

        if page.url.startswith("https://"):
            hsts = headers.get("strict-transport-security")
            if not hsts:
                findings.append(
                    make_finding(
                        rule_id="hdr-hsts-missing",
                        title="缺少 HSTS",
                        severity=Severity.MEDIUM,
                        confidence=Confidence.HIGH,
                        url=page.url,
                        category="安全標頭",
                        description="未強制瀏覽器後續只用 HTTPS 連線，可能遭 downgrade 攻擊。",
                        evidence={"status": page.status, "headers": _header_snapshot(headers)},
                        remediation="設定 Strict-Transport-Security: max-age=31536000; includeSubDomains。",
                        refs={"owasp": "A02:2021", "cwe": "319"},
                    )
                )
            else:
                max_age = _max_age(hsts)
                if max_age is not None and max_age < 15_552_000:
                    findings.append(
                        make_finding(
                            rule_id="hdr-hsts-short",
                            title="HSTS max-age 過短",
                            severity=Severity.LOW,
                            confidence=Confidence.HIGH,
                            url=page.url,
                            category="安全標頭",
                            description="HSTS 有效期過短，瀏覽器很快又會允許 HTTP 連線。",
                            evidence={"strict-transport-security": hsts},
                            remediation="將 max-age 設為至少 15552000（180 天），建議 31536000。",
                            refs={"owasp": "A02:2021", "cwe": "319"},
                        )
                    )

        xfo = headers.get("x-frame-options", "").lower()
        if not xfo and "frame-ancestors" not in csp.lower():
            findings.append(
                make_finding(
                    rule_id="hdr-xfo-missing",
                    title="缺少點擊劫持防護",
                    severity=Severity.MEDIUM,
                    confidence=Confidence.HIGH,
                    url=page.url,
                    category="安全標頭",
                    description="頁面可能被嵌入其他網站的 iframe，造成點擊劫持。",
                    evidence={"x-frame-options": None, "csp": csp or None},
                    remediation="設定 CSP frame-ancestors 'self'，或 X-Frame-Options: DENY / SAMEORIGIN。",
                    refs={"owasp": "A05:2021", "cwe": "1021"},
                )
            )

        if csp and "unsafe-inline" in csp.lower() and "nonce-" not in csp.lower() and "sha256-" not in csp.lower():
            findings.append(
                make_finding(
                    rule_id="hdr-csp-unsafe-inline",
                    title="CSP 允許 unsafe-inline",
                    severity=Severity.LOW,
                    confidence=Confidence.MEDIUM,
                    url=page.url,
                    category="安全標頭",
                    description="CSP 允許 inline script，會大幅降低阻擋 XSS 的效果。",
                    evidence={"content-security-policy": csp[:500]},
                    remediation="改用 nonce 或 hash，移除 script-src 的 unsafe-inline。",
                    refs={"owasp": "A05:2021", "cwe": "693"},
                )
            )
    return findings


def _header_snapshot(headers: dict[str, str]) -> dict[str, str | None]:
    keys = [
        "content-security-policy",
        "strict-transport-security",
        "x-frame-options",
        "x-content-type-options",
        "referrer-policy",
        "permissions-policy",
    ]
    return {key: headers.get(key) for key in keys}


def _max_age(value: str) -> int | None:
    for part in value.split(";"):
        part = part.strip()
        if part.lower().startswith("max-age="):
            try:
                return int(part.split("=", 1)[1])
            except ValueError:
                return None
    return None
