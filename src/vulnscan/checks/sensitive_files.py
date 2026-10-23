from __future__ import annotations

import re
from urllib.parse import urljoin

from ..http import BudgetExceeded, ScanCancelled
from ..models import Confidence, Severity
from .base import ScanContext, make_finding

CHECKS = [
    (
        "/.env",
        "file-env-exposed",
        "環境設定檔 .env 可讀取",
        Severity.HIGH,
        "檔案可能包含資料庫密碼、API key 與其他機密。",
        lambda text: len(re.findall(r"(?m)^[A-Z][A-Z0-9_]{2,}\s*=", text)) >= 2,
        {"owasp": "A05:2021", "cwe": "538"},
    ),
    (
        "/.git/HEAD",
        "file-git-exposed",
        "Git 中繼資料可讀取",
        Severity.HIGH,
        "原始碼與提交歷史可能被下載，進而找出更多漏洞或機密。",
        lambda text: text.lstrip().startswith("ref:") or "refs/heads/" in text[:200],
        {"owasp": "A05:2021", "cwe": "538"},
    ),
    (
        "/server-status",
        "file-server-status",
        "伺服器狀態頁公開",
        Severity.MEDIUM,
        "狀態頁可能洩漏目前請求、內部路徑與流量資訊。",
        lambda text: "Apache Server Status" in text or "Server Status" in text[:1000],
        {"owasp": "A05:2021", "cwe": "200"},
    ),
    (
        "/phpinfo.php",
        "file-phpinfo",
        "phpinfo() 頁面公開",
        Severity.MEDIUM,
        "phpinfo 會揭露 PHP 版本、模組、環境變數與伺服器路徑。",
        lambda text: "phpinfo()" in text.lower() or "PHP Version" in text[:2000],
        {"owasp": "A05:2021", "cwe": "200"},
    ),
]


async def check(ctx: ScanContext) -> list:
    findings = []
    for base in ctx.scope.base_urls():
        for path, rule_id, title, severity, description, signature, refs in CHECKS:
            url = urljoin(base, path)
            try:
                page = await ctx.engine.get(url, rule_id=rule_id)
            except BudgetExceeded:
                return findings
            except ScanCancelled:
                raise
            if page.status != 200 or not page.text:
                continue
            try:
                matched = signature(page.text)
            except Exception:
                matched = False
            if not matched:
                continue
            findings.append(
                make_finding(
                    rule_id=rule_id,
                    title=title,
                    severity=severity,
                    confidence=Confidence.HIGH,
                    url=url,
                    category="敏感檔案",
                    description=description,
                    evidence={
                        "status": page.status,
                        "content_type": page.content_type,
                        "snippet": page.text[:500],
                    },
                    remediation="移除或限制此檔案/端點的公開存取，並輪替已暴露的機密。",
                    refs=refs,
                )
            )
    return findings
