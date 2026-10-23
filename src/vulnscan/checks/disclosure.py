from __future__ import annotations

import re
from urllib.parse import urlsplit

from ..models import Confidence, Page, Severity
from .base import ScanContext, base_url_for, make_finding, representative_pages

STACK_PATTERNS = [
    ("Python traceback", re.compile(r"Traceback \(most recent call last\)")),
    ("PHP error", re.compile(r"(?:Fatal error|Parse error|Warning):\s+.+? in .+? on line \d+")),
    ("Java stack trace", re.compile(r"(?:java\.lang\.|at org\.springframework\.|at com\.\w+\.)")),
    (
        "SQL error",
        re.compile(
            r"(?:SQLSTATE\[\w+\]|You have an error in your SQL syntax|Unclosed quotation mark)"
        ),
    ),
    (
        "ASP.NET error",
        re.compile(
            r"(?:System\.(?:Web|Data|NullReference)Exception|Microsoft OLE DB Provider)"
        ),
    ),
]


def check(pages: list[Page], ctx: ScanContext) -> list:
    findings = []
    seen_hosts: set[str] = set()

    for page in representative_pages(pages):
        base = base_url_for(page.url)
        server = page.headers.get("server", "")
        if server and re.search(r"\d+\.\d+", server):
            findings.append(
                make_finding(
                    rule_id="disc-server-version",
                    title="Server 標頭洩漏版本",
                    severity=Severity.LOW,
                    confidence=Confidence.HIGH,
                    url=base,
                    category="資訊洩漏",
                    description="版本資訊可協助攻擊者尋找對應的已知漏洞。",
                    evidence={"server": server},
                    remediation="移除或模糊化 Server 標頭中的版本資訊。",
                    refs={"owasp": "A05:2021", "cwe": "200"},
                )
            )
        powered = page.headers.get("x-powered-by")
        if powered:
            findings.append(
                make_finding(
                    rule_id="disc-powered-by",
                    title="X-Powered-By 洩漏技術棧",
                    severity=Severity.LOW,
                    confidence=Confidence.HIGH,
                    url=base,
                    category="資訊洩漏",
                    description="回應標頭揭露後端框架或版本。",
                    evidence={"x-powered-by": powered},
                    remediation="關閉 X-Powered-By 或移除框架版本資訊。",
                    refs={"owasp": "A05:2021", "cwe": "200"},
                )
            )

        title = _title(page.text).lower()
        if "index of /" in title or "directory listing for" in title:
            findings.append(
                make_finding(
                    rule_id="disc-directory-listing",
                    title="目錄列表公開",
                    severity=Severity.MEDIUM,
                    confidence=Confidence.HIGH,
                    url=page.url,
                    category="資訊洩漏",
                    description="伺服器列出目錄內容，可能暴露備份檔、設定檔或原始碼。",
                    evidence={"title": title[:120]},
                    remediation="關閉目錄列表（autoindex off），並確認目錄內沒有敏感檔案。",
                    refs={"owasp": "A05:2021", "cwe": "548"},
                )
            )

    # Stack traces can appear on any page, but we only need one per host.
    for page in pages:
        if not page.text or not page.is_html:
            continue
        host = urlsplit(page.url).hostname or page.url
        if host in seen_hosts:
            continue
        for label, pattern in STACK_PATTERNS:
            match = pattern.search(page.text)
            if not match:
                continue
            seen_hosts.add(host)
            start = max(0, match.start() - 80)
            findings.append(
                make_finding(
                    rule_id="disc-stacktrace",
                    title="錯誤頁洩漏程式細節",
                    severity=Severity.MEDIUM,
                    confidence=Confidence.HIGH,
                    url=page.url,
                    category="資訊洩漏",
                    description=f"偵測到 {label}，錯誤訊息可能暴露路徑、框架或 SQL 結構。",
                    evidence={"pattern": label, "snippet": page.text[start : match.end() + 160]},
                    remediation="關閉正式環境的詳細錯誤顯示，改為通用錯誤頁並記錄到伺服器端日誌。",
                    refs={"owasp": "A05:2021", "cwe": "209"},
                )
            )
            break
    return findings


def _title(html: str) -> str:
    match = re.search(r"<title[^>]*>(.*?)</title>", html, re.IGNORECASE | re.DOTALL)
    return re.sub(r"\s+", " ", match.group(1)).strip() if match else ""
