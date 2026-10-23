from __future__ import annotations

from ..models import Confidence, Page, Severity
from .base import ScanContext, make_finding

SENSITIVE_FIELDS = ("password", "passwd", "email", "username", "account", "card", "otp")
SENSITIVE_ACTIONS = ("admin", "account", "profile", "settings", "password", "email", "user")


def check(pages: list[Page], ctx: ScanContext) -> list:
    findings = []
    seen_actions: set[str] = set()
    count = 0
    for page in pages:
        if not page.is_html or not page.forms:
            continue
        for form in page.forms:
            if form.method != "POST" or form.has_token or not form.fields:
                continue
            if form.action in seen_actions:
                continue
            seen_actions.add(form.action)
            names = [field.name for field in form.fields]
            sensitive = any(
                token in " ".join(names).lower() or token in form.action.lower()
                for token in SENSITIVE_FIELDS + SENSITIVE_ACTIONS
            )
            findings.append(
                make_finding(
                    rule_id="csrf-token-missing",
                    title="POST 表單未見 CSRF token",
                    severity=Severity.MEDIUM if sensitive else Severity.LOW,
                    confidence=Confidence.MEDIUM if sensitive else Confidence.LOW,
                    url=form.action,
                    method="POST",
                    parameter=",".join(names)[:120],
                    category="CSRF",
                    description=(
                        "表單沒有可見的 CSRF token；實際保護可能由 SameSite Cookie 或前端標頭提供，"
                        "需人工確認。"
                    ),
                    evidence={"action": form.action, "fields": names[:20]},
                    remediation="為狀態變更請求加入 CSRF token，並在伺服器端驗證；同時設定 SameSite Cookie。",
                    refs={"owasp": "A01:2021", "cwe": "352"},
                )
            )
            count += 1
            if count >= 20:
                return findings
    return findings
