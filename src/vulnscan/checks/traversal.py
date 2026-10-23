from __future__ import annotations

import secrets
from urllib.parse import urlsplit

from ..models import AdvancedCheck, Confidence, Endpoint, Severity
from .active_utils import replace_param, testable_params, with_param_values
from .base import ScanContext, make_finding

HINTS = (
    "file",
    "filename",
    "filepath",
    "path",
    "download",
    "doc",
    "document",
    "page",
    "template",
    "include",
    "view",
    "load",
    "src",
    "image",
    "attachment",
    "folder",
    "dir",
)

ERROR_SIGNATURES = (
    "No such file or directory",
    "The system cannot find the path specified",
    "open_basedir restriction",
    "failed to open stream",
    "FileNotFoundException",
    "java.io.File",
    "Permission denied",
)


async def check(endpoints: list[Endpoint], ctx: ScanContext) -> list:
    if AdvancedCheck.TRAVERSAL not in ctx.config.advanced_checks:
        return []
    findings = []
    tested = 0
    seen: set[tuple[str, str]] = set()
    for endpoint, param in testable_params(endpoints, limit=50):
        if not any(hint in param.name.lower() for hint in HINTS):
            continue
        key = (urlsplit(endpoint.url).path, param.name)
        if key in seen:
            continue
        seen.add(key)
        if tested >= 6 or not ctx.take_advanced_test():
            break
        tested += 1

        token = secrets.token_hex(4)
        canary = f"vs-{token}.txt"
        baseline_url = with_param_values(endpoint.url, endpoint.params)
        baseline = await ctx.engine.get(baseline_url, rule_id="traversal-baseline")
        if baseline.status == 0 or baseline.status in (403, 429):
            continue
        baseline_hits = {
            signature
            for signature in ERROR_SIGNATURES
            if signature.lower() in baseline.text.lower()
        }
        payloads = (
            f"../../../../{canary}",
            f"..\\..\\..\\..\\{canary}",
        )
        for payload in payloads:
            page = await ctx.engine.get(
                replace_param(baseline_url, param.name, payload),
                rule_id="traversal-probe",
            )
            if page.status == 0 or page.status in (403, 429):
                continue
            matched = [
                signature
                for signature in ERROR_SIGNATURES
                if signature.lower() in page.text.lower()
                and signature not in baseline_hits
            ]
            if not matched:
                continue
            first = matched[0]
            index = page.text.lower().find(first.lower())
            snippet = page.text[max(0, index - 80) : index + 220]
            findings.append(
                make_finding(
                    rule_id="traversal-error",
                    title="路徑遍歷（錯誤訊息）",
                    severity=Severity.MEDIUM,
                    confidence=Confidence.MEDIUM,
                    url=endpoint.url,
                    parameter=param.name,
                    category="路徑遍歷",
                    description=(
                        "帶有 ../ 的檔名觸發了檔案系統錯誤訊息，表示參數可能被當成檔案路徑。"
                        "此檢查只使用不存在的 canary 檔名，沒有讀取或下載檔案內容。"
                    ),
                    evidence={
                        "canary": canary,
                        "payload": payload,
                        "status": page.status,
                        "baseline_status": baseline.status,
                        "matched": matched,
                        "snippet": snippet,
                    },
                    remediation="將檔案存取限制在允許的目錄內，使用 canonical path 檢查，並避免直接使用使用者輸入。",
                    refs={"owasp": "A01:2021", "cwe": "22"},
                )
            )
            break
        if findings:
            break
    return findings
