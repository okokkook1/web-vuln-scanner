from __future__ import annotations

import copy
import re
import secrets

from ..models import AdvancedCheck, Confidence, Endpoint, Severity
from ..openapi_import import filter_post_endpoints
from .base import ScanContext, make_finding
from .sqli_boolean import _normalize, _similarity

SQL_ERRORS = [
    ("MySQL", re.compile(r"You have an error in your SQL syntax|Warning:\s*mysql_|MySqlException", re.I)),
    ("PostgreSQL", re.compile(r"PostgreSQL.*ERROR|pg_query\(\)|unterminated quoted string", re.I)),
    (
        "Microsoft SQL Server",
        re.compile(
            r"Unclosed quotation mark after the character string|Microsoft OLE DB Provider for SQL Server|SqlException",
            re.I,
        ),
    ),
    ("Oracle", re.compile(r"ORA-\d{4,5}|quoted string not properly terminated", re.I)),
    ("SQLite", re.compile(r"SQLite/JDBCDriver|SQLite\.Exception|near \".*\": syntax error", re.I)),
]

SSRF_HINTS = (
    "url",
    "uri",
    "link",
    "src",
    "source",
    "dest",
    "destination",
    "callback",
    "webhook",
    "image",
    "avatar",
    "fetch",
    "feed",
    "host",
)

_PATH_TOKEN = re.compile(r"([^.[\]]+)|\[(\d+)\]")
_MISSING = object()
BOOLEAN_CONFIRMATION_ROUNDS = 2


def _tokens(path: str) -> list[str | int]:
    tokens: list[str | int] = []
    for match in _PATH_TOKEN.finditer(path):
        tokens.append(int(match.group(2)) if match.group(2) is not None else match.group(1))
    return tokens


def _get_path(data, path: str):
    current = data
    for token in _tokens(path):
        if isinstance(token, int):
            if not isinstance(current, list) or token >= len(current):
                return _MISSING
            current = current[token]
        else:
            if not isinstance(current, dict) or token not in current:
                return _MISSING
            current = current[token]
    return current


def _set_path(data, path: str, value):
    updated = copy.deepcopy(data)
    tokens = _tokens(path)
    current = updated
    for index, token in enumerate(tokens):
        last = index == len(tokens) - 1
        if isinstance(token, int):
            if not isinstance(current, list) or token >= len(current):
                return updated
            if last:
                current[token] = value
            else:
                current = current[token]
        else:
            if not isinstance(current, dict) or token not in current:
                return updated
            if last:
                current[token] = value
            else:
                current = current[token]
    return updated


async def run(endpoints: list[Endpoint], ctx: ScanContext) -> list:
    endpoints = filter_post_endpoints(endpoints, ctx.config.api_post_allowlist)
    findings = []
    findings.extend(await _xss(endpoints, ctx))
    findings.extend(await _sqli(endpoints, ctx))
    findings.extend(await _boolean_sqli(endpoints, ctx))
    findings.extend(await _ssrf(endpoints, ctx))
    return findings


def _json_candidates(endpoints: list[Endpoint], limit: int = 12):
    result = []
    for endpoint in endpoints:
        if endpoint.method.upper() != "POST" or not isinstance(endpoint.body, dict):
            continue
        for param in endpoint.params:
            if (
                param.location == "body"
                and _get_path(endpoint.body, param.name) is not _MISSING
            ):
                result.append((endpoint, param))
                if len(result) >= limit:
                    return result
    return result


def _with_value(body: dict, name: str, value) -> dict:
    return _set_path(body, name, value)


async def _xss(endpoints: list[Endpoint], ctx: ScanContext) -> list:
    findings = []
    for endpoint, param in _json_candidates(endpoints, limit=6):
        if not ctx.take_api_test():
            ctx.record_api_test(endpoint, "xss", "budget")
            break
        ctx.record_api_test(endpoint, "xss")
        token = secrets.token_hex(4)
        payload = f"<b>vs{token}</b>"
        page = await ctx.engine.post_json(
            endpoint.url,
            _with_value(endpoint.body or {}, param.name, payload),
            rule_id="api-xss-reflected",
        )
        if page.status == 0 or page.status >= 500 or payload not in page.text:
            continue
        index = page.text.find(payload)
        findings.append(
            make_finding(
                rule_id="api-xss-reflected",
                title="API JSON 反射 HTML / XSS 風險",
                severity=Severity.MEDIUM,
                confidence=Confidence.HIGH,
                url=endpoint.url,
                method="POST",
                parameter=param.name,
                category="API / XSS",
                description="JSON 請求中的無害 HTML 標記被原樣反射；實際可利用性需依前端渲染方式確認。",
                evidence={
                    "payload": payload,
                    "status": page.status,
                    "snippet": page.text[max(0, index - 100) : index + 200],
                },
                remediation="依輸出語境進行編碼，並避免把使用者輸入直接渲染為 HTML。",
                refs={"owasp": "A03:2021", "cwe": "79"},
            )
        )
    return findings


async def _sqli(endpoints: list[Endpoint], ctx: ScanContext) -> list:
    findings = []
    for endpoint, param in _json_candidates(endpoints, limit=6):
        if not ctx.take_api_test():
            ctx.record_api_test(endpoint, "sqli_error", "budget")
            break
        ctx.record_api_test(endpoint, "sqli_error")
        baseline = await ctx.engine.post_json(
            endpoint.url,
            copy.deepcopy(endpoint.body or {}),
            rule_id="api-sqli-baseline",
        )
        if baseline.status == 0 or baseline.error:
            continue
        original = _get_path(endpoint.body or {}, param.name)
        if original is _MISSING:
            continue
        if not isinstance(original, str):
            original = str(original)
        if original.endswith("'"):
            continue
        page = await ctx.engine.post_json(
            endpoint.url,
            _with_value(endpoint.body or {}, param.name, f"{original}'"),
            rule_id="api-sqli-error",
        )
        if page.status == 0 or page.error:
            continue
        for label, pattern in SQL_ERRORS:
            if not pattern.search(page.text):
                continue
            if pattern.search(baseline.text):
                continue
            match = pattern.search(page.text)
            start = max(0, match.start() - 100) if match else 0
            findings.append(
                make_finding(
                    rule_id="api-sqli-error",
                    title="API JSON SQL 錯誤訊息洩漏（疑似 SQL Injection）",
                    severity=Severity.HIGH,
                    confidence=Confidence.HIGH,
                    url=endpoint.url,
                    method="POST",
                    parameter=param.name,
                    category="API / SQLi",
                    description="JSON 參數加入單引號後出現資料庫錯誤特徵，基準請求沒有相同訊息。",
                    evidence={
                        "database": label,
                        "baseline_status": baseline.status,
                        "quote_status": page.status,
                        "snippet": page.text[start : start + 500],
                    },
                    remediation="使用參數化查詢／預存程序，關閉詳細資料庫錯誤。",
                    refs={"owasp": "A03:2021", "cwe": "89"},
                )
            )
            break
    return findings


async def _boolean_sqli(endpoints: list[Endpoint], ctx: ScanContext) -> list:
    findings = []
    for endpoint, param in _json_candidates(endpoints, limit=4):
        if not ctx.take_api_test():
            ctx.record_api_test(endpoint, "sqli_boolean", "budget")
            break
        ctx.record_api_test(endpoint, "sqli_boolean")
        original = _get_path(endpoint.body or {}, param.name)
        if original is _MISSING:
            continue
        if not isinstance(original, str):
            original = str(original)
        if "'" in original:
            continue
        rounds: list[dict] = []
        for _ in range(BOOLEAN_CONFIRMATION_ROUNDS):
            result = await _boolean_round(endpoint, param, original, ctx)
            if result is None:
                rounds = []
                break
            rounds.append(result)
        if len(rounds) != BOOLEAN_CONFIRMATION_ROUNDS or not all(
            item["signal"] for item in rounds
        ):
            continue
        last = rounds[-1]
        status_consistent = all(item["status_signal"] for item in rounds)
        findings.append(
            make_finding(
                rule_id="api-sqli-boolean",
                title="API JSON 布林型 SQL Injection（疑似）",
                severity=Severity.HIGH,
                confidence=Confidence.HIGH if status_consistent else Confidence.MEDIUM,
                url=endpoint.url,
                method="POST",
                parameter=param.name,
                category="API / SQLi",
                description=(
                    "JSON 參數的成對真假 SQL 條件在重複測試中持續造成不同回應，"
                    "可能是布林型 SQL Injection；此檢查只讀取回應，沒有 UNION 或寫入。"
                ),
                evidence={
                    "confirmation_rounds": len(rounds),
                    "baseline_status": last["baseline_status"],
                    "true_status": last["true_status"],
                    "false_status": last["false_status"],
                    "similarity_baseline_true": round(
                        last["similarity_baseline_true"], 3
                    ),
                    "similarity_true_false": round(last["similarity_true_false"], 3),
                    "rounds": rounds,
                },
                remediation="使用參數化查詢或預存程序，不要將 JSON 值拼接進 SQL。",
                refs={"owasp": "A03:2021", "cwe": "89"},
            )
        )
    return findings


async def _boolean_round(
    endpoint: Endpoint,
    param,
    original: str,
    ctx: ScanContext,
) -> dict | None:
    baseline = await ctx.engine.post_json(
        endpoint.url,
        copy.deepcopy(endpoint.body or {}),
        rule_id="api-sqli-boolean-baseline",
    )
    true_page = await ctx.engine.post_json(
        endpoint.url,
        _with_value(endpoint.body or {}, param.name, f"{original}' AND '1'='1' -- "),
        rule_id="api-sqli-boolean-true",
    )
    false_page = await ctx.engine.post_json(
        endpoint.url,
        _with_value(endpoint.body or {}, param.name, f"{original}' AND '1'='2' -- "),
        rule_id="api-sqli-boolean-false",
    )
    pages = (baseline, true_page, false_page)
    if any(
        page.status == 0 or page.status in (403, 429) or page.error for page in pages
    ):
        return None
    if any(pattern.search(page.text) for _, pattern in SQL_ERRORS for page in pages):
        return None
    base_norm = _normalize(baseline.text)
    true_norm = _normalize(true_page.text)
    false_norm = _normalize(false_page.text)
    sim_base_true = _similarity(base_norm, true_norm)
    sim_true_false = _similarity(true_norm, false_norm)
    status_signal = (
        true_page.status == baseline.status
        and false_page.status != baseline.status
    )
    content_signal = sim_true_false < 0.93 and sim_base_true > 0.97
    return {
        "baseline_status": baseline.status,
        "true_status": true_page.status,
        "false_status": false_page.status,
        "similarity_baseline_true": sim_base_true,
        "similarity_true_false": sim_true_false,
        "status_signal": status_signal,
        "content_signal": content_signal,
        "signal": status_signal or content_signal,
    }


async def _ssrf(endpoints: list[Endpoint], ctx: ScanContext) -> list:
    if AdvancedCheck.SSRF not in ctx.config.advanced_checks or ctx.callback is None:
        return []
    findings = []
    for endpoint, param in _json_candidates(endpoints, limit=12):
        value = _get_path(endpoint.body or {}, param.name)
        if value is _MISSING:
            continue
        text = str(value or "").lower()
        if not (
            any(hint in param.name.lower() for hint in SSRF_HINTS)
            or text.startswith(("http://", "https://"))
        ):
            continue
        if not ctx.take_api_test():
            ctx.record_api_test(endpoint, "ssrf", "budget")
            break
        ctx.record_api_test(endpoint, "ssrf")
        token = secrets.token_hex(8)
        callback_url = ctx.callback.url_for(token)
        await ctx.engine.post_json(
            endpoint.url,
            _with_value(endpoint.body or {}, param.name, callback_url),
            rule_id="api-ssrf-probe",
        )
        hits = await ctx.callback.wait(token, timeout=3.0)
        if not hits:
            continue
        first = hits[0]
        findings.append(
            make_finding(
                rule_id="api-ssrf-callback",
                title="API JSON SSRF（callback 驗證）",
                severity=Severity.HIGH,
                confidence=Confidence.HIGH,
                url=endpoint.url,
                method="POST",
                parameter=param.name,
                category="API / SSRF",
                description="JSON 參數中的 callback URL 被目標伺服器主動請求，確認存在 SSRF。",
                evidence={
                    "callback_url": callback_url,
                    "hit_count": len(hits),
                    "client": first.client,
                    "user_agent": first.headers.get("user-agent"),
                    "received_at": first.received_at,
                },
                remediation="限制伺服器可連線的目的地，封鎖私有 IP 與 metadata 位址。",
                refs={"owasp": "A10:2021", "cwe": "918"},
            )
        )
        if len(findings) >= 3:
            break
    return findings
