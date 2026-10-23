from __future__ import annotations

import json
import re
from urllib.parse import parse_qsl, urlsplit

from ..http import HttpEngine
from ..models import Confidence, Endpoint, Severity
from .base import ScanContext, make_finding
from .sqli_boolean import _normalize, _similarity

ID_NAMES = (
    "id",
    "user",
    "account",
    "order",
    "item",
    "record",
    "profile",
    "tenant",
    "invoice",
    "document",
    "project",
)
ID_VALUE_RE = re.compile(
    r"^(?:\d{1,18}|[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-"
    r"[0-9a-f]{4}-[0-9a-f]{12}|[0-9a-f]{16,64})$",
    re.I,
)
LOGIN_PATH_RE = re.compile(r"(?:^|/)(?:login|signin|sign-in|auth|sso)(?:/|$)", re.I)
ADMIN_PATH_RE = re.compile(
    r"(?:^|/)(?:admin|administrator|manage|management|internal|backoffice|"
    r"role|roles|permission|permissions|staff)(?:/|$)",
    re.I,
)
LOGIN_TEXT_RE = re.compile(
    r"(?:type=[\"']password[\"']|name=[\"']password[\"']|"
    r"sign in|log in|登入|登录)",
    re.I,
)
REDIRECT_STATUSES = {301, 302, 303, 307, 308}


def _is_login_redirect(page) -> bool:
    if page.status not in REDIRECT_STATUSES:
        return False
    location = str(page.headers.get("location") or "")
    return bool(LOGIN_PATH_RE.search(location))


def _is_login_page(page) -> bool:
    return page.status < 400 and bool(LOGIN_TEXT_RE.search(page.text[:3000]))


def _candidate_score(endpoint: Endpoint) -> tuple[int, str | None]:
    if endpoint.method.upper() != "GET":
        return 0, None
    parsed = urlsplit(endpoint.url)
    if LOGIN_PATH_RE.search(parsed.path):
        return 0, None
    score = 0
    parameter: str | None = None
    for segment in parsed.path.split("/"):
        if segment and ID_VALUE_RE.match(segment):
            score += 3
            break
    for name, value in parse_qsl(parsed.query, keep_blank_values=False):
        lowered = name.lower()
        if any(hint in lowered for hint in ID_NAMES) and value:
            score += 2
            parameter = name
            break
    return score, parameter


def _bfla_candidate_score(endpoint: Endpoint) -> int:
    if endpoint.method.upper() != "GET":
        return 0
    parsed = urlsplit(endpoint.url)
    if LOGIN_PATH_RE.search(parsed.path):
        return 0
    return 2 if ADMIN_PATH_RE.search(parsed.path) else 0


def select_bfla_candidates(
    endpoints: list[Endpoint],
    limit: int,
) -> list[tuple[Endpoint, None, int]]:
    scored: list[tuple[int, Endpoint]] = []
    seen: set[str] = set()
    for endpoint in endpoints:
        if endpoint.url in seen:
            continue
        score = _bfla_candidate_score(endpoint)
        if score <= 0:
            continue
        seen.add(endpoint.url)
        scored.append((score, endpoint))
    scored.sort(key=lambda item: item[0], reverse=True)
    return [(endpoint, None, score) for score, endpoint in scored[:limit]]


def select_authorization_candidates(
    endpoints: list[Endpoint],
    limit: int,
) -> list[tuple[Endpoint, str | None, int, str]]:
    combined: list[tuple[Endpoint, str | None, int, str]] = []
    seen: set[str] = set()
    for endpoint, parameter, score in select_bola_candidates(endpoints, limit):
        if endpoint.url in seen:
            continue
        seen.add(endpoint.url)
        combined.append((endpoint, parameter, score, "bola"))
    for endpoint, parameter, score in select_bfla_candidates(endpoints, limit):
        if endpoint.url in seen:
            continue
        seen.add(endpoint.url)
        combined.append((endpoint, parameter, score, "bfla"))
    return combined[: max(1, limit)]


def select_bola_candidates(
    endpoints: list[Endpoint],
    limit: int,
) -> list[tuple[Endpoint, str | None, int]]:
    scored: list[tuple[int, Endpoint, str | None]] = []
    seen: set[str] = set()
    for endpoint in endpoints:
        if endpoint.url in seen:
            continue
        score, parameter = _candidate_score(endpoint)
        if score <= 0:
            continue
        seen.add(endpoint.url)
        scored.append((score, endpoint, parameter))
    scored.sort(key=lambda item: item[0], reverse=True)
    return [
        (endpoint, parameter, score)
        for score, endpoint, parameter in scored[:limit]
    ]


def _json_shape(value, depth: int = 0):
    if depth > 8:
        return "..."
    if isinstance(value, dict):
        return {
            str(key): _json_shape(item, depth + 1)
            for key, item in list(value.items())[:100]
        }
    if isinstance(value, list):
        return [_json_shape(value[0], depth + 1)] if value else []
    return type(value).__name__


def _similarity_for_pages(primary: str, secondary: str) -> tuple[float, str]:
    try:
        primary_json = json.loads(primary)
        secondary_json = json.loads(secondary)
    except (TypeError, ValueError):
        return (
            _similarity(_normalize(primary), _normalize(secondary)),
            "text",
        )
    primary_shape = json.dumps(
        _json_shape(primary_json),
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    )
    secondary_shape = json.dumps(
        _json_shape(secondary_json),
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    )
    return (
        _similarity(_normalize(primary_shape), _normalize(secondary_shape)),
        "json_shape",
    )


def _record(
    ctx: ScanContext,
    endpoint: Endpoint,
    parameter: str | None,
    result: str,
    *,
    kind: str = "bola",
    primary_status: int | None = None,
    secondary_status: int | None = None,
    unauth_status: int | None = None,
    similarity: float | None = None,
    compare_mode: str | None = None,
    detail: str = "",
) -> None:
    parsed = urlsplit(endpoint.url)
    ctx.bola_results.append(
        {
            "method": "GET",
            "kind": kind,
            "url": endpoint.url,
            "path": parsed.path or "/",
            "host": parsed.netloc,
            "parameter": parameter,
            "result": result,
            "a_to_b": bool(
                secondary_status is not None
                and 200 <= secondary_status < 300
            ),
            "b_to_a": bool(
                primary_status is not None and 200 <= primary_status < 300
            ),
            "primary_status": primary_status,
            "secondary_status": secondary_status,
            "unauth_status": unauth_status,
            "similarity": (
                round(similarity, 3) if similarity is not None else None
            ),
            "compare_mode": compare_mode,
            "detail": detail,
        }
    )


def _status_result(
    *,
    primary_status: int,
    secondary_status: int,
    unauth_status: int | None = None,
    kind: str = "bola",
) -> str:
    if primary_status in (401, 403):
        if kind == "bfla" and 200 <= secondary_status < 300:
            return "candidate"
        return "primary_auth_failed"
    if primary_status == 404:
        return "not_found"
    if primary_status < 200 or primary_status >= 300:
        return "inconclusive"
    if secondary_status in (401, 403):
        return "protected"
    if secondary_status == 404:
        return "not_found"
    if secondary_status < 200 or secondary_status >= 300:
        return "inconclusive"
    if unauth_status is not None and 200 <= unauth_status < 300:
        return "public"
    return "candidate"


async def run(
    endpoints: list[Endpoint],
    primary: HttpEngine,
    secondary: HttpEngine,
    unauthenticated: HttpEngine,
    ctx: ScanContext,
) -> list:
    candidates = select_authorization_candidates(
        endpoints,
        max(1, ctx.max_bola_tests),
    )
    findings = []
    for index, (endpoint, parameter, _score, kind) in enumerate(candidates):
        if not ctx.take_bola_test():
            for remaining, remaining_parameter, _, remaining_kind in candidates[index:]:
                _record(
                    ctx,
                    remaining,
                    remaining_parameter,
                    "budget",
                    kind=remaining_kind,
                    detail="BOLA／BFLA 測試預算用盡",
                )
            break
        primary_page = await primary.get(endpoint.url, rule_id="bola-primary")
        primary_status = primary_page.status
        secondary_page = await secondary.get(endpoint.url, rule_id="bola-secondary")
        secondary_status = secondary_page.status
        unauth_page = await unauthenticated.get(endpoint.url, rule_id="bola-unauth")
        unauth_status = unauth_page.status

        base_result = _status_result(
            primary_status=primary_status,
            secondary_status=secondary_status,
            unauth_status=unauth_status,
            kind=kind,
        )
        if base_result != "candidate":
            _record(
                ctx,
                endpoint,
                parameter,
                base_result,
                kind=kind,
                primary_status=primary_status,
                secondary_status=secondary_status,
                unauth_status=unauth_status,
            )
            continue

        unauth_protected = (
            unauth_status in (401, 403)
            or _is_login_redirect(unauth_page)
            or _is_login_page(unauth_page)
        )
        if not unauth_protected:
            _record(
                ctx,
                endpoint,
                parameter,
                "inconclusive",
                primary_status=primary_status,
                secondary_status=secondary_status,
                kind=kind,
                unauth_status=unauth_status,
                detail="無法確認未登入請求被拒絕",
            )
            continue
        if _is_login_page(secondary_page):
            _record(
                ctx,
                endpoint,
                parameter,
                "inconclusive",
                kind=kind,
                primary_status=primary_status,
                secondary_status=secondary_status,
                unauth_status=unauth_status,
                detail="第二帳號取得登入頁",
            )
            continue

        status_only = (
            kind == "bfla"
            and primary_status in (401, 403)
            and 200 <= secondary_status < 300
        )
        similarity = 0.0
        compare_mode = "status_only"
        if not status_only:
            if _is_login_page(primary_page):
                _record(
                    ctx,
                    endpoint,
                    parameter,
                    "inconclusive",
                    kind=kind,
                    primary_status=primary_status,
                    secondary_status=secondary_status,
                    unauth_status=unauth_status,
                    detail="主要帳號取得登入頁",
                )
                continue
            if not primary_page.text or not secondary_page.text:
                _record(
                    ctx,
                    endpoint,
                    parameter,
                    "inconclusive",
                    kind=kind,
                    primary_status=primary_status,
                    secondary_status=secondary_status,
                    unauth_status=unauth_status,
                    detail="回應為空，無法比較形狀",
                )
                continue
            similarity, compare_mode = _similarity_for_pages(
                primary_page.text,
                secondary_page.text,
            )
            if similarity < 0.5:
                _record(
                    ctx,
                    endpoint,
                    parameter,
                    "inconclusive",
                    kind=kind,
                    primary_status=primary_status,
                    secondary_status=secondary_status,
                    unauth_status=unauth_status,
                    similarity=similarity,
                    compare_mode=compare_mode,
                    detail="兩個帳號的回應形狀差異過大",
                )
                continue

        _record(
            ctx,
            endpoint,
            parameter,
            "vulnerable",
            kind=kind,
            primary_status=primary_status,
            secondary_status=secondary_status,
            unauth_status=unauth_status,
            similarity=similarity if not status_only else None,
            compare_mode=compare_mode,
        )
        is_bfla = kind == "bfla"
        findings.append(
            make_finding(
                rule_id=(
                    "api-bfla-readonly" if is_bfla else "api-bola-readonly"
                ),
                title=(
                    "API 功能層級授權缺失（疑似 BFLA）"
                    if is_bfla
                    else "API 物件層級授權缺失（疑似 BOLA／IDOR）"
                ),
                severity=Severity.HIGH,
                confidence=(
                    Confidence.HIGH
                    if similarity >= 0.95 or (status_only and is_bfla)
                    else Confidence.MEDIUM
                ),
                url=endpoint.url,
                method="GET",
                parameter=parameter,
                category="API / Authorization",
                description=(
                    "第二帳號可讀取疑似 admin／管理功能，且未登入請求被拒絕；"
                    "可能是 BFLA。此檢查只做 GET，不枚舉、不保存回應內容。"
                    if is_bfla
                    else (
                        "主要帳號與第二帳號都能讀取同一個疑似物件資源，"
                        "且未登入請求被拒絕；可能是 BOLA／IDOR。"
                        "此檢查只做 GET，不枚舉 ID、不保存回應內容。"
                    )
                ),
                evidence={
                    "kind": kind,
                    "primary_status": primary_status,
                    "secondary_status": secondary_status,
                    "unauthenticated_status": unauth_status,
                    "similarity": (
                        round(similarity, 3) if not status_only else None
                    ),
                    "compare_mode": compare_mode,
                    "note": "相似度只比較正規化後的回應形狀，不保存內容。",
                },
                remediation=(
                    "在伺服器端檢查功能／角色權限，不要只依賴 UI 隱藏或前端路由。"
                    if is_bfla
                    else (
                        "在伺服器端逐一檢查物件權限，不要只依賴 URL 中的 ID；"
                        "以目前登入使用者與資源 ownership 做授權判斷。"
                    )
                ),
                refs=(
                    {"owasp": "API5:2023", "cwe": "285"}
                    if is_bfla
                    else {"owasp": "API1:2023", "cwe": "639"}
                ),
            )
        )
    return findings
