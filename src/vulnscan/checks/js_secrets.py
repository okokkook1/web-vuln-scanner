from __future__ import annotations

import re

from ..models import Confidence, Page, Severity
from .base import ScanContext, make_finding

PATTERNS = [
    (
        "AWS Access Key",
        re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
        Severity.HIGH,
        Confidence.HIGH,
        "偵測到疑似 AWS Access Key。",
    ),
    (
        "GitHub Token",
        re.compile(r"\bgh[pousr]_[0-9A-Za-z]{36,}\b"),
        Severity.HIGH,
        Confidence.HIGH,
        "偵測到疑似 GitHub token。",
    ),
    (
        "Stripe Live Key",
        re.compile(r"\bsk_live_[0-9A-Za-z]{20,}\b"),
        Severity.HIGH,
        Confidence.HIGH,
        "偵測到疑似 Stripe 正式環境金鑰。",
    ),
    (
        "Private Key",
        re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"),
        Severity.HIGH,
        Confidence.HIGH,
        "偵測到私密金鑰內容。",
    ),
    (
        "Google API Key",
        re.compile(r"\bAIza[0-9A-Za-z_\-]{35}\b"),
        Severity.MEDIUM,
        Confidence.MEDIUM,
        "偵測到疑似 Google API key；是否可用需進一步確認。",
    ),
    (
        "Generic Secret",
        re.compile(
            r"(?:api[_-]?key|apikey|client_secret|access_token)\s*[:=]\s*[\"']([A-Za-z0-9_\-]{24,})[\"']",
            re.IGNORECASE,
        ),
        Severity.MEDIUM,
        Confidence.LOW,
        "JS 中出現疑似 API key / secret 的字串，可能是設定值或誤判。",
    ),
]


def check(pages: list[Page], ctx: ScanContext) -> list:
    findings = []
    seen: set[tuple[str, str]] = set()
    count = 0
    for page in pages:
        if not page.is_javascript or not page.text:
            continue
        for name, pattern, severity, confidence, description in PATTERNS:
            for match in pattern.finditer(page.text):
                preview = _redact(match.group(0))
                key = (name, preview)
                if key in seen:
                    continue
                seen.add(key)
                findings.append(
                    make_finding(
                        rule_id=f"js-secret-{_slug(name)}",
                        title=f"JS 檔案可能包含 {name}",
                        severity=severity,
                        confidence=confidence,
                        url=page.url,
                        parameter=name,
                        category="JS 洩漏",
                        description=description + " 請確認是否為測試值或已撤銷的金鑰。",
                        evidence={
                            "preview": preview,
                            "position": match.start(),
                            "file": page.url,
                        },
                        remediation="移除前端硬編碼金鑰，改用後端代理或短期權杖，並輪替已暴露的金鑰。",
                        refs={"owasp": "A02:2021", "cwe": "798"},
                    )
                )
                count += 1
                if count >= 20:
                    return findings
                break
        if count >= 20:
            break
    return findings


def _redact(value: str) -> str:
    if len(value) <= 12:
        return value
    return f"{value[:6]}…{value[-4:]}"


def _slug(value: str) -> str:
    return value.lower().replace(" ", "-")
