from __future__ import annotations

from urllib.parse import urlsplit

from ..models import Confidence, Page, Severity
from .base import ScanContext, make_finding

IGNORED_COOKIE_PREFIXES = ("_ga", "_gid", "_fbp", "_hj", "__utm", "amplitude_", "mp_")
SESSION_HINTS = ("sess", "sid", "auth", "token", "jwt", "login", "user")


def check(pages: list[Page], ctx: ScanContext) -> list:
    findings = []
    seen: set[tuple[str, str]] = set()
    for page in pages:
        if page.status >= 400:
            continue
        host = urlsplit(page.url).hostname or page.url
        is_https = page.url.startswith("https://")
        for raw in page.set_cookie:
            name, attrs = _parse_cookie(raw)
            if not name or name.lower().startswith(IGNORED_COOKIE_PREFIXES):
                continue
            key = (host, name)
            if key in seen:
                continue
            seen.add(key)
            lower_name = name.lower()
            session_cookie = any(hint in lower_name for hint in SESSION_HINTS)

            if is_https and "secure" not in attrs:
                findings.append(
                    make_finding(
                        rule_id="cookie-secure-missing",
                        title=f"Cookie「{name}」缺少 Secure",
                        severity=Severity.MEDIUM,
                        confidence=Confidence.HIGH,
                        url=page.url,
                        parameter=name,
                        category="Cookie",
                        description="Cookie 可能透過明文 HTTP 傳送。",
                        evidence={"cookie": name, "attributes": sorted(attrs)},
                        remediation="為 Cookie 加上 Secure 屬性。",
                        refs={"owasp": "A05:2021", "cwe": "614"},
                    )
                )
            if "httponly" not in attrs:
                findings.append(
                    make_finding(
                        rule_id="cookie-httponly-missing",
                        title=f"Cookie「{name}」缺少 HttpOnly",
                        severity=Severity.MEDIUM if session_cookie else Severity.LOW,
                        confidence=Confidence.HIGH,
                        url=page.url,
                        parameter=name,
                        category="Cookie",
                        description="JavaScript 可以讀取此 Cookie，XSS 時可能被竊取。",
                        evidence={"cookie": name, "session_like": session_cookie},
                        remediation="為工作階段 Cookie 加上 HttpOnly 屬性。",
                        refs={"owasp": "A07:2021", "cwe": "1004"},
                    )
                )
            samesite = attrs.get("samesite", "")
            if not samesite:
                findings.append(
                    make_finding(
                        rule_id="cookie-samesite-missing",
                        title=f"Cookie「{name}」缺少 SameSite",
                        severity=Severity.LOW,
                        confidence=Confidence.HIGH,
                        url=page.url,
                        parameter=name,
                        category="Cookie",
                        description="跨站請求可能一併帶上此 Cookie。",
                        evidence={"cookie": name, "attributes": sorted(attrs)},
                        remediation="設定 SameSite=Lax 或 Strict；需要跨站時再使用 None + Secure。",
                        refs={"owasp": "A01:2021", "cwe": "1275"},
                    )
                )
            elif samesite.lower() == "none" and "secure" not in attrs:
                findings.append(
                    make_finding(
                        rule_id="cookie-samesite-none-insecure",
                        title=f"Cookie「{name}」SameSite=None 但缺少 Secure",
                        severity=Severity.MEDIUM,
                        confidence=Confidence.HIGH,
                        url=page.url,
                        parameter=name,
                        category="Cookie",
                        description="SameSite=None 的 Cookie 必須加上 Secure，否則瀏覽器會拒絕或明文傳送。",
                        evidence={"cookie": name, "samesite": samesite, "secure": False},
                        remediation="加上 Secure，或改用 SameSite=Lax/Strict。",
                        refs={"owasp": "A05:2021", "cwe": "614"},
                    )
                )
    return findings


def _parse_cookie(raw: str) -> tuple[str, dict[str, str]]:
    parts = [part.strip() for part in raw.split(";") if part.strip()]
    if not parts:
        return "", {}
    name = parts[0].split("=", 1)[0].strip()
    attrs: dict[str, str] = {}
    for part in parts[1:]:
        if "=" in part:
            key, value = part.split("=", 1)
            attrs[key.strip().lower()] = value.strip()
        else:
            attrs[part.strip().lower()] = ""
    return name, attrs
