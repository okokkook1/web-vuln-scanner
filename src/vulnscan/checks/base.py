from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field
from urllib.parse import urlsplit

from ..audit import AuditLogger
from ..callback import CallbackServer
from ..http import HttpEngine
from ..models import Confidence, Finding, Page, ScanConfig, Severity
from ..scope import Scope


@dataclass
class ScanContext:
    scan_id: str
    config: ScanConfig
    scope: Scope
    engine: HttpEngine
    audit: AuditLogger
    log: Callable[[str], None]
    active_tests: int = 0
    max_active_tests: int = 100
    advanced_tests: int = 0
    max_advanced_tests: int = 12
    api_tests: int = 0
    max_api_tests: int = 20
    api_results: dict[str, dict] = field(default_factory=dict)
    bola_tests: int = 0
    max_bola_tests: int = 8
    bola_results: list[dict] = field(default_factory=list)
    callback: CallbackServer | None = None
    findings: list[Finding] = field(default_factory=list)

    def take_test(self) -> bool:
        if self.active_tests >= self.max_active_tests:
            return False
        self.active_tests += 1
        return True

    def take_advanced_test(self) -> bool:
        if self.advanced_tests >= self.max_advanced_tests:
            return False
        self.advanced_tests += 1
        return True

    def take_api_test(self) -> bool:
        if self.api_tests >= self.max_api_tests:
            return False
        self.api_tests += 1
        return True

    def take_bola_test(self) -> bool:
        if self.bola_tests >= self.max_bola_tests:
            return False
        self.bola_tests += 1
        return True

    def record_api_test(self, endpoint, check: str, outcome: str = "tested") -> None:
        entry = self.api_results.setdefault(
            endpoint.url,
            {
                "method": endpoint.method.upper(),
                "url": endpoint.url,
                "path": urlsplit(endpoint.url).path or "/",
                "host": urlsplit(endpoint.url).netloc,
                "checks": [],
                "outcomes": {},
            },
        )
        if check not in entry["checks"]:
            entry["checks"].append(check)
        entry["outcomes"][check] = outcome


def make_finding(
    *,
    rule_id: str,
    title: str,
    severity: Severity,
    confidence: Confidence,
    url: str,
    method: str = "GET",
    parameter: str | None = None,
    category: str = "",
    description: str = "",
    evidence: dict | None = None,
    remediation: str = "",
    refs: dict[str, str] | None = None,
) -> Finding:
    return Finding(
        rule_id=rule_id,
        title=title,
        severity=severity,
        confidence=confidence,
        url=url,
        method=method,
        parameter=parameter,
        category=category,
        description=description,
        evidence=evidence or {},
        remediation=remediation,
        refs=refs or {},
    )


def representative_pages(pages: list[Page]) -> list[Page]:
    """One HTML page per host, used for host-level checks."""
    seen: set[str] = set()
    result: list[Page] = []
    for page in pages:
        if not page.is_html or page.status >= 400:
            continue
        host = urlsplit(page.url).hostname or page.url
        if host in seen:
            continue
        seen.add(host)
        result.append(page)
    return result


def base_url_for(url: str) -> str:
    parsed = urlsplit(url)
    return f"{parsed.scheme}://{parsed.netloc}/"
