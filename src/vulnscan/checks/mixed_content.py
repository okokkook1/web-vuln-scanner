from __future__ import annotations

from urllib.parse import urlsplit

from selectolax.lexbor import LexborHTMLParser as HTMLParser

from ..models import Confidence, Page, Severity
from .base import ScanContext, make_finding

ATTRS = (
    ("script[src]", "src"),
    ("link[href]", "href"),
    ("img[src]", "src"),
    ("iframe[src]", "src"),
    ("form[action]", "action"),
)


def check(pages: list[Page], ctx: ScanContext) -> list:
    findings = []
    seen_hosts: set[str] = set()
    for page in pages:
        if not page.url.startswith("https://") or not page.is_html or not page.text:
            continue
        host = urlsplit(page.url).hostname or page.url
        if host in seen_hosts:
            continue
        try:
            tree = HTMLParser(page.text)
        except Exception:
            continue
        insecure: list[str] = []
        for selector, attr in ATTRS:
            for node in tree.css(selector):
                value = (node.attributes.get(attr) or "").strip()
                if value.lower().startswith("http://") and value not in insecure:
                    insecure.append(value)
        if insecure:
            seen_hosts.add(host)
            findings.append(
                make_finding(
                    rule_id="mixed-content",
                    title="HTTPS 頁面載入 HTTP 資源",
                    severity=Severity.LOW,
                    confidence=Confidence.HIGH,
                    url=page.url,
                    category="混合內容",
                    description="混合內容可能被中間人竄改，瀏覽器也可能封鎖該資源。",
                    evidence={"resources": insecure[:10]},
                    remediation="將所有資源改以 HTTPS 載入，或使用相對路徑／CDN 的 HTTPS 端點。",
                    refs={"owasp": "A02:2021", "cwe": "319"},
                )
            )
    return findings
