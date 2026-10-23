from __future__ import annotations

import asyncio
import json
import re
from datetime import date, timedelta
from urllib.parse import quote, urljoin, urlsplit

import httpx
import yaml
from fastapi import APIRouter, HTTPException, Request
from fastapi.encoders import jsonable_encoder
from fastapi.responses import JSONResponse, RedirectResponse
from pydantic import ValidationError

from ...audit import AuditLogger
from ...auth import AuthError, AuthMaterials, prepare_auth
from ...config import RuntimeSettings
from ...models import AdvancedCheck, AuthConfig, AuthType, Profile, Scan, ScanConfig, new_scan_id
from ...openapi_import import parse_openapi_report, preview_post_endpoints
from ...openapi_refs import bundle_external_refs, fingerprint_spec
from ...presentation import load_json, scan_stats
from ...scope import build_scope
from ..security import verify_csrf
from .common import get_db, get_manager, render, scan_targets

router = APIRouter()


class FormError(ValueError):
    pass


def _split_multi(value: str) -> list[str]:
    return [item.strip() for item in re.split(r"[\r\n,]+", value) if item.strip()]


ADVANCED_FIELDS = {
    AdvancedCheck.SQLI_BOOLEAN: "advanced_sqli_boolean",
    AdvancedCheck.TRAVERSAL: "advanced_traversal",
    AdvancedCheck.SSRF: "advanced_ssrf",
}


def _advanced_values(form) -> list[AdvancedCheck]:
    return [
        check
        for check, field in ADVANCED_FIELDS.items()
        if str(form.get(field) or "") == "on"
    ]


def _default_form(settings: RuntimeSettings) -> dict:
    return {
        "targets": "",
        "exclude": "",
        "allow_private": False,
        "authorized_by": "",
        "contact": "",
        "expires": (date.today() + timedelta(days=30)).isoformat(),
        "profile": settings.default_profile,
        "rps_per_host": settings.rps_per_host,
        "max_requests_per_host": settings.max_requests_per_host,
        "max_depth": settings.max_depth,
        "timeout": settings.timeout,
        "advanced_checks": [],
        "ssrf_callback": "",
        "auth_type": "none",
        "auth_cookie": "",
        "auth_header_name": "Authorization",
        "auth_header_value": "",
        "login_url": "",
        "username": "",
        "password": "",
        "login_user_field": "username",
        "login_pass_field": "password",
        "auth_verify_url": "",
        "auth_verify_text": "",
        "storage_token_key": "",
        "storage_header_name": "",
        "storage_header_prefix": "Bearer ",
        "browser_login_url": "",
        "browser_token_key": "",
        "browser_header_name": "",
        "browser_header_prefix": "Bearer ",
        "allow_api_post": False,
        "openapi_url": "",
        "openapi_fingerprint": "",
        "api_post_allowlist": "",
        "api_post_all_ack": False,
        "max_api_tests": 20,
        "enable_bola": False,
        "bola_ack": False,
        "bola_auth_type": "none",
        "bola_auth_cookie": "",
        "bola_auth_header_name": "Authorization",
        "bola_auth_header_value": "",
        "bola_allowlist": "",
        "bola_allow_all_ack": False,
        "max_bola_tests": 8,
    }


def _form_values(form) -> dict:
    return {
        "targets": str(form.get("targets") or ""),
        "exclude": str(form.get("exclude") or ""),
        "allow_private": str(form.get("allow_private") or "") == "on",
        "authorized_by": str(form.get("authorized_by") or ""),
        "contact": str(form.get("contact") or ""),
        "expires": str(form.get("expires") or ""),
        "profile": str(form.get("profile") or "safe"),
        "rps_per_host": str(form.get("rps_per_host") or "3"),
        "max_requests_per_host": str(form.get("max_requests_per_host") or "2000"),
        "max_depth": str(form.get("max_depth") or "3"),
        "timeout": str(form.get("timeout") or "10"),
        "advanced_checks": [item.value for item in _advanced_values(form)],
        "ssrf_callback": str(form.get("ssrf_callback") or ""),
        "auth_type": str(form.get("auth_type") or "none"),
        "auth_cookie": "",
        "auth_header_name": str(form.get("auth_header_name") or ""),
        "auth_header_value": "",
        "login_url": str(form.get("login_url") or ""),
        "username": str(form.get("username") or ""),
        "password": "",
        "login_user_field": str(form.get("login_user_field") or "username"),
        "login_pass_field": str(form.get("login_pass_field") or "password"),
        "auth_verify_url": str(form.get("auth_verify_url") or ""),
        "auth_verify_text": str(form.get("auth_verify_text") or ""),
        "storage_token_key": str(form.get("storage_token_key") or ""),
        "storage_header_name": str(form.get("storage_header_name") or ""),
        "storage_header_prefix": str(form.get("storage_header_prefix") or "Bearer "),
        "browser_login_url": str(form.get("browser_login_url") or ""),
        "browser_token_key": str(form.get("browser_token_key") or ""),
        "browser_header_name": str(form.get("browser_header_name") or ""),
        "browser_header_prefix": str(form.get("browser_header_prefix") or "Bearer "),
        "allow_api_post": str(form.get("allow_api_post") or "") == "on",
        "openapi_url": str(form.get("openapi_url") or ""),
        "openapi_fingerprint": str(form.get("openapi_fingerprint") or ""),
        "api_post_allowlist": str(form.get("api_post_allowlist") or ""),
        "api_post_all_ack": str(form.get("api_post_all_ack") or "") == "on",
        "max_api_tests": str(form.get("max_api_tests") or "20"),
        "enable_bola": str(form.get("enable_bola") or "") == "on",
        "bola_ack": str(form.get("bola_ack") or "") == "on",
        "bola_auth_type": str(form.get("bola_auth_type") or "none"),
        "bola_auth_cookie": "",
        "bola_auth_header_name": str(form.get("bola_auth_header_name") or ""),
        "bola_auth_header_value": "",
        "bola_allowlist": str(form.get("bola_allowlist") or ""),
        "bola_allow_all_ack": str(form.get("bola_allow_all_ack") or "") == "on",
        "max_bola_tests": str(form.get("max_bola_tests") or "8"),
    }


def _build_auth(
    form,
    storage_state: dict | None = None,
    browser_state: dict | None = None,
) -> AuthConfig:
    raw_type = str(form.get("auth_type") or "none")
    try:
        auth_type = AuthType(raw_type)
    except ValueError as exc:
        raise FormError("未知的登入方式。") from exc
    verify_url = str(form.get("auth_verify_url") or "") or None
    verify_text = str(form.get("auth_verify_text") or "") or None
    if auth_type is AuthType.NONE:
        return AuthConfig()
    if auth_type is AuthType.COOKIE:
        return AuthConfig(
            type=auth_type,
            cookie=str(form.get("auth_cookie") or ""),
            verify_url=verify_url,
            verify_text=verify_text,
        )
    if auth_type is AuthType.HEADER:
        return AuthConfig(
            type=auth_type,
            header_name=str(form.get("auth_header_name") or ""),
            header_value=str(form.get("auth_header_value") or ""),
            verify_url=verify_url,
            verify_text=verify_text,
        )
    if auth_type is AuthType.STATE:
        if not storage_state:
            raise FormError("瀏覽器狀態登入需要上傳 storage state JSON 檔。")
        return AuthConfig(
            type=auth_type,
            storage_state=storage_state,
            storage_token_key=str(form.get("storage_token_key") or "") or None,
            storage_header_name=str(form.get("storage_header_name") or "") or None,
            storage_header_prefix=str(form.get("storage_header_prefix") or ""),
            verify_url=verify_url,
            verify_text=verify_text,
        )
    if auth_type is AuthType.BROWSER:
        if not browser_state:
            raise FormError("請先完成瀏覽器互動登入。")
        return AuthConfig(
            type=auth_type,
            storage_state=browser_state,
            storage_token_key=str(form.get("browser_token_key") or "") or None,
            storage_header_name=str(form.get("browser_header_name") or "") or None,
            storage_header_prefix=str(form.get("browser_header_prefix") or ""),
            verify_url=verify_url,
            verify_text=verify_text,
        )
    return AuthConfig(
        type=auth_type,
        login_url=str(form.get("login_url") or ""),
        username=str(form.get("username") or ""),
        password=str(form.get("password") or ""),
        username_field=str(form.get("login_user_field") or "username"),
        password_field=str(form.get("login_pass_field") or "password"),
        verify_url=verify_url,
        verify_text=verify_text,
    )


async def _read_storage_state(form) -> dict | None:
    if str(form.get("auth_type") or "none") != "state":
        return None
    upload = form.get("auth_state_file")
    if upload is None or not getattr(upload, "filename", ""):
        return None
    raw = await upload.read()
    if len(raw) > 2_000_000:
        raise FormError("storage state 檔案过大（上限 2 MB）。")
    try:
        data = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise FormError("storage state 不是有效的 UTF-8 JSON。") from exc
    if not isinstance(data, dict):
        raise FormError("storage state 必須是 JSON 物件。")
    return data


async def _read_bola_storage_state(form) -> dict | None:
    upload = form.get("bola_auth_state_file")
    if upload is None or not getattr(upload, "filename", ""):
        return None
    raw = await upload.read()
    if len(raw) > 2_000_000:
        raise FormError("BOLA storage state 檔案過大（上限 2 MB）。")
    try:
        data = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise FormError("BOLA storage state 不是有效的 UTF-8 JSON。") from exc
    if not isinstance(data, dict):
        raise FormError("BOLA storage state 必須是 JSON 物件。")
    return data


def _build_bola_auth(
    form,
    storage_state: dict | None,
) -> AuthConfig | None:
    raw_type = str(form.get("bola_auth_type") or "none")
    try:
        auth_type = AuthType(raw_type)
    except ValueError as exc:
        raise FormError("未知的 BOLA 第二帳號登入方式。") from exc
    if auth_type is AuthType.NONE:
        return None
    verify_url = str(form.get("auth_verify_url") or "") or None
    verify_text = str(form.get("auth_verify_text") or "") or None
    if auth_type is AuthType.COOKIE:
        return AuthConfig(
            type=auth_type,
            cookie=str(form.get("bola_auth_cookie") or ""),
            verify_url=verify_url,
            verify_text=verify_text,
        )
    if auth_type is AuthType.HEADER:
        return AuthConfig(
            type=auth_type,
            header_name=str(form.get("bola_auth_header_name") or ""),
            header_value=str(form.get("bola_auth_header_value") or ""),
            verify_url=verify_url,
            verify_text=verify_text,
        )
    if auth_type is AuthType.STATE:
        if not storage_state:
            raise FormError("BOLA 第二帳號需要上傳 storage state JSON 檔。")
        return AuthConfig(
            type=auth_type,
            storage_state=storage_state,
            verify_url=verify_url,
            verify_text=verify_text,
        )
    raise FormError("BOLA 第二帳號僅支援 Cookie、Header 或 Storage state。")


async def _read_openapi(form) -> tuple[dict | None, str | None]:
    upload = form.get("openapi_file")
    if upload is None or not getattr(upload, "filename", ""):
        return None, None
    raw = await upload.read()
    if len(raw) > 2_000_000:
        raise FormError("OpenAPI 檔案過大（上限 2 MB）。")
    try:
        data = yaml.safe_load(raw.decode("utf-8"))
    except (UnicodeDecodeError, yaml.YAMLError) as exc:
        raise FormError("OpenAPI 不是有效的 UTF-8 JSON/YAML。") from exc
    if not isinstance(data, dict):
        raise FormError("OpenAPI 規格必須是 JSON/YAML 物件。")
    return data, str(getattr(upload, "filename", "openapi") or "openapi")


async def _fetch_preview_openapi(
    raw_url: str,
    scope,
    settings: RuntimeSettings,
    auth: AuthMaterials,
    audit: AuditLogger | None = None,
) -> tuple[dict, str]:
    """Fetch a spec for preview using the configured authentication materials."""
    current = urljoin(scope.base_urls()[0], raw_url)
    redirects = 0
    headers = {
        "User-Agent": settings.user_agent,
        "Accept": "application/json, application/yaml, text/yaml, */*",
    }
    headers.update(auth.headers)
    async with httpx.AsyncClient(
        timeout=httpx.Timeout(settings.timeout, connect=min(10.0, settings.timeout)),
        follow_redirects=False,
        headers=headers,
        cookies=auth.cookies or None,
        proxy=settings.proxy or None,
    ) as client:
        while redirects <= 3:
            parsed_current = urlsplit(current)
            if parsed_current.username or parsed_current.password:
                raise FormError("OpenAPI URL 不可包含帳密")
            if not scope.is_allowed(current):
                raise FormError(f"OpenAPI URL 不在授權範圍：{current}")
            try:
                response = await client.get(current)
            except httpx.HTTPError as exc:
                if audit:
                    audit.log(
                        method="GET",
                        url=current,
                        status=0,
                        request_headers=headers,
                        response_headers={},
                        rule_id="openapi-preview",
                        error=str(exc),
                    )
                raise FormError(f"OpenAPI URL 取得失敗：{exc}") from exc
            if audit:
                audit.log(
                    method="GET",
                    url=current,
                    status=response.status_code,
                    request_headers=headers,
                    response_headers={
                        key.lower(): value
                        for key, value in response.headers.items()
                    },
                    body_excerpt=response.text[:300],
                    rule_id="openapi-preview",
                )
            if response.status_code in (301, 302, 303, 307, 308):
                if redirects >= 3:
                    break
                location = str(response.headers.get("location") or "").strip()
                if not location:
                    raise FormError("OpenAPI URL 回應 redirect，但沒有 Location")
                next_url = urljoin(current, location)
                if urlsplit(next_url).scheme not in ("http", "https"):
                    raise FormError("OpenAPI redirect 只允許 http:// 或 https://")
                if not scope.is_allowed(next_url):
                    raise FormError(f"OpenAPI redirect 不在授權範圍：{next_url}")
                redirects += 1
                current = next_url
                continue
            if response.status_code in (401, 403):
                raise FormError(
                    "OpenAPI URL 預覽未使用登入 session（HTTP "
                    f"{response.status_code}）；請改用檔案上傳。"
                )
            if response.status_code != 200:
                raise FormError(f"OpenAPI URL 匯入失敗：HTTP {response.status_code}")
            if len(response.content) > 2_000_000:
                raise FormError("OpenAPI 規格過大（上限 2 MB）。")
            try:
                loaded = yaml.safe_load(response.text)
            except yaml.YAMLError as exc:
                raise FormError(f"OpenAPI URL 不是有效 JSON/YAML：{exc}") from exc
            if not isinstance(loaded, dict):
                raise FormError("OpenAPI URL 回傳的不是 JSON/YAML 物件")
            return loaded, current
    raise FormError("OpenAPI URL redirect 次數過多（上限 3 次）")


def _build_config(
    form,
    settings: RuntimeSettings,
    storage_state: dict | None = None,
    browser_state: dict | None = None,
    openapi_spec: dict | None = None,
    openapi_name: str | None = None,
    openapi_url: str | None = None,
    openapi_fingerprint: str | None = None,
    bola_auth: AuthConfig | None = None,
) -> ScanConfig:
    if str(form.get("authorized_ack") or "") != "on":
        raise FormError("請確認已取得此目標的書面授權。")
    targets = _split_multi(str(form.get("targets") or ""))
    if not targets:
        raise FormError("請至少輸入一個目標網址。")
    exclude = _split_multi(str(form.get("exclude") or ""))
    expires_raw = str(form.get("expires") or "").strip()
    if not expires_raw:
        raise FormError("請選擇授權到期日。")
    try:
        expires = date.fromisoformat(expires_raw)
    except ValueError as exc:
        raise FormError("授權到期日格式不正確。") from exc
    profile_raw = str(form.get("profile") or "safe")
    try:
        profile = Profile(profile_raw)
    except ValueError as exc:
        raise FormError("未知的掃描模式。") from exc
    advanced_checks = _advanced_values(form)
    advanced_ack = str(form.get("advanced_ack") or "") == "on"
    ssrf_callback = str(form.get("ssrf_callback") or "").strip() or None
    if profile is Profile.FULL:
        if not advanced_checks:
            raise FormError("完整模式至少需要選擇一項進階檢查。")
        if not advanced_ack:
            raise FormError("完整模式需要確認進階檢查的風險。")
    else:
        advanced_checks = []
        advanced_ack = False
        ssrf_callback = None
    if AdvancedCheck.SSRF not in advanced_checks:
        ssrf_callback = None
    try:
        rps = float(form.get("rps_per_host") or settings.rps_per_host)
        max_requests = int(form.get("max_requests_per_host") or settings.max_requests_per_host)
        max_depth = int(form.get("max_depth") or settings.max_depth)
        timeout = float(form.get("timeout") or settings.timeout)
        max_api_tests = int(form.get("max_api_tests") or 20)
        max_bola_tests = int(form.get("max_bola_tests") or 8)
    except ValueError as exc:
        raise FormError(
            "速率、請求上限、深度、timeout 或 API/BOLA 測試預算必須是數字。"
        ) from exc
    try:
        auth = _build_auth(form, storage_state, browser_state)
        return ScanConfig(
            targets=targets,
            exclude=exclude,
            allow_private=str(form.get("allow_private") or "") == "on",
            authorized_by=str(form.get("authorized_by") or ""),
            contact=str(form.get("contact") or ""),
            expires=expires,
            profile=profile,
            rps_per_host=rps,
            max_requests_per_host=max_requests,
            max_depth=max_depth,
            timeout=timeout,
            user_agent=settings.user_agent,
            proxy=settings.proxy,
            advanced_checks=advanced_checks,
            advanced_ack=advanced_ack,
            ssrf_callback=ssrf_callback,
            auth=auth,
            openapi_spec=openapi_spec,
            openapi_name=openapi_name or openapi_url,
            openapi_url=openapi_url,
            openapi_fingerprint=openapi_fingerprint,
            allow_api_post=str(form.get("allow_api_post") or "") == "on",
            api_post_allowlist=_split_multi(
                str(form.get("api_post_allowlist") or "")
            ),
            api_post_all_ack=str(form.get("api_post_all_ack") or "") == "on",
            max_api_tests=max_api_tests,
            enable_bola=str(form.get("enable_bola") or "") == "on",
            bola_ack=str(form.get("bola_ack") or "") == "on",
            bola_auth=bola_auth,
            bola_allowlist=_split_multi(
                str(form.get("bola_allowlist") or "")
            ),
            bola_allow_all_ack=(
                str(form.get("bola_allow_all_ack") or "") == "on"
            ),
            max_bola_tests=max_bola_tests,
        )
    except ValidationError as exc:
        messages = []
        for error in exc.errors():
            location = ".".join(str(item) for item in error.get("loc", []))
            messages.append(f"{location}: {error.get('msg')}")
        raise FormError("；".join(messages)) from exc


@router.get("/scans/new")
async def new_scan(request: Request):
    settings = request.app.state.settings_store.load()
    return render(
        request,
        "scan_new.html",
        active="new",
        page_title="新增掃描",
        page_subtitle="三步驟建立一次授權掃描",
        form_data=_default_form(settings),
        error=None,
        initial_step=0,
    )


@router.post("/scans/api/preview")
async def preview_api(request: Request):
    form = await request.form()
    settings = request.app.state.settings_store.load()
    audit: AuditLogger | None = None
    try:
        verify_csrf(request, form)
        if str(form.get("authorized_ack") or "") != "on":
            raise FormError("預覽前請先確認已取得此目標的書面授權。")
        targets = _split_multi(str(form.get("targets") or ""))
        if not targets:
            raise FormError("請先輸入至少一個目標網址。")
        openapi_spec, openapi_name = await _read_openapi(form)
        openapi_url = str(form.get("openapi_url") or "").strip() or None
        if openapi_spec and openapi_url:
            raise FormError("OpenAPI 檔案與 URL 只能擇一。")
        if not openapi_spec and not openapi_url:
            raise FormError("請先上傳 OpenAPI 規格檔或填寫 URL。")
        expires_raw = str(form.get("expires") or "").strip()
        try:
            expires = (
                date.fromisoformat(expires_raw)
                if expires_raw
                else date.today() + timedelta(days=30)
            )
        except ValueError as exc:
            raise FormError("授權到期日格式不正確。") from exc
        preview_config = ScanConfig(
            targets=targets,
            allow_private=str(form.get("allow_private") or "") == "on",
            authorized_by=str(form.get("authorized_by") or "").strip()
            or "預覽使用者",
            contact=str(form.get("contact") or "").strip() or "preview@localhost",
            expires=expires,
            profile=Profile.SAFE,
            user_agent=settings.user_agent,
            timeout=settings.timeout,
            proxy=settings.proxy,
        )
        scope = await asyncio.to_thread(build_scope, preview_config)
        allowlist = _split_multi(str(form.get("api_post_allowlist") or ""))
        auth = AuthConfig()
        auth_used = False
        warning = None
        spec_base: str | None = None
        materials = AuthMaterials()
        if openapi_url:
            storage_state = await _read_storage_state(form)
            browser_state = None
            if str(form.get("auth_type") or "none") == "browser":
                session_id = str(form.get("browser_session_id") or "").strip()
                if not session_id:
                    raise FormError("URL 預覽需要先完成瀏覽器互動登入。")
                browser_state = request.app.state.browser_login.get_state(session_id)
                if not browser_state:
                    raise FormError(
                        "瀏覽器登入尚未完成、已過期；請重新登入後再預覽。"
                    )
            auth = _build_auth(form, storage_state, browser_state)
            preview_config = preview_config.model_copy(update={"auth": auth})
            audit = AuditLogger(
                request.app.state.data_dir / "preview-audit.jsonl",
                "preview",
            )
            try:
                materials = await prepare_auth(preview_config, scope, audit)
            except (AuthError, httpx.HTTPError) as exc:
                raise FormError(f"預覽登入失敗：{exc}") from exc
            spec, spec_base = await _fetch_preview_openapi(
                openapi_url,
                scope,
                settings,
                materials,
                audit,
            )
            source = spec_base
            auth_used = auth.type is not AuthType.NONE
            if not auth_used:
                warning = (
                    "URL 預覽未使用登入 session；若規格需要登入，"
                    "請先設定登入方式或改用檔案上傳。"
                )
        else:
            spec = openapi_spec or {}
            source = openapi_name or "OpenAPI 檔案"

        async def fetch_external(url: str) -> tuple[dict, str]:
            nonlocal audit
            if audit is None:
                audit = AuditLogger(
                    request.app.state.data_dir / "preview-audit.jsonl",
                    "preview",
                )
            return await _fetch_preview_openapi(
                url,
                scope,
                settings,
                materials,
                audit,
            )

        bundle = await bundle_external_refs(
            spec,
            base_url=spec_base,
            scope=scope,
            fetch=fetch_external,
        )
        spec = bundle.spec
        report = parse_openapi_report(spec, scope, allow_post=True)
        warnings = bundle.warnings + report.warnings
        stats = dict(report.stats)
        stats.update(bundle.stats)
        stats["warnings"] = len(warnings)
        items = preview_post_endpoints(report.endpoints, allowlist)
        return JSONResponse(
            jsonable_encoder(
                {
                    "source": source,
                    "spec_fingerprint": fingerprint_spec(spec),
                    "count": len(items),
                    "allowed_count": sum(1 for item in items if item["allowed"]),
                    "allowlist": allowlist,
                    "warning": warning,
                    "warnings": warnings,
                    "stats": stats,
                    "auth": auth.summary(),
                    "auth_used": auth_used,
                    "endpoints": items,
                }
            )
        )
    except Exception as exc:
        return JSONResponse({"error": str(exc)}, status_code=400)
    finally:
        if audit:
            audit.close()


@router.post("/scans")
async def create_scan(request: Request):
    settings = request.app.state.settings_store.load()
    form = await request.form()
    verify_csrf(request, form)
    values = _form_values(form)

    browser_manager = request.app.state.browser_login
    browser_session_id = str(form.get("browser_session_id") or "").strip()
    try:
        storage_state = await _read_storage_state(form)
        bola_auth = None
        if str(form.get("enable_bola") or "") == "on":
            bola_storage_state = await _read_bola_storage_state(form)
            bola_auth = _build_bola_auth(form, bola_storage_state)
        openapi_spec, openapi_name = await _read_openapi(form)
        browser_state = None
        if str(form.get("auth_type") or "") == "browser":
            if not browser_session_id:
                raise FormError("請先完成瀏覽器互動登入。")
            browser_state = browser_manager.get_state(browser_session_id)
            if not browser_state:
                raise FormError("瀏覽器登入尚未完成、已過期，或已被使用；請重新登入。")
        config = _build_config(
            form,
            settings,
            storage_state,
            browser_state,
            openapi_spec,
            openapi_name,
            str(form.get("openapi_url") or "").strip() or None,
            str(form.get("openapi_fingerprint") or "").strip() or None,
            bola_auth,
        )
        scope = await asyncio.to_thread(build_scope, config)
    except Exception as exc:
        return render(
            request,
            "scan_new.html",
            active="new",
            page_title="新增掃描",
            page_subtitle="三步驟建立一次授權掃描",
            form_data=values,
            error=str(exc),
            initial_step=0,
        )

    db = get_db(request)
    manager = get_manager(request)
    scan = Scan(
        id=new_scan_id(),
        status="queued",
        profile=config.profile.value,
        targets_json=json.dumps(config.targets, ensure_ascii=False),
        scope_json=json.dumps(scope.snapshot(), ensure_ascii=False),
        stats_json="{}",
        phase="排隊中",
        message="已排入掃描佇列",
    )
    db.create_scan(scan)
    manager.enqueue(scan.id, config)
    if config.auth.type is AuthType.BROWSER:
        browser_manager.consume(browser_session_id)
    return RedirectResponse(url=f"/scans/{scan.id}", status_code=303)


@router.get("/scans")
async def history(request: Request):
    db = get_db(request)
    scans = db.list_scans(50)
    rows = [
        {
            "scan": scan,
            "findings": db.count_findings(scan.id),
            "targets": load_json(scan.targets_json, []),
        }
        for scan in scans
    ]
    return render(
        request,
        "history.html",
        active="history",
        page_title="掃描歷史",
        page_subtitle=f"最近 {len(rows)} 次掃描",
        rows=rows,
    )


@router.get("/scans/{scan_id}")
async def live_scan(request: Request, scan_id: str):
    db = get_db(request)
    scan = db.get_scan(scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="找不到掃描")
    manager = get_manager(request)
    job_status = manager.status(scan_id) or {}
    scope = load_json(scan.scope_json, {})
    terminal = scan.status in ("completed", "failed", "cancelled")
    return render(
        request,
        "scan_live.html",
        active="history",
        page_title="掃描進度",
        page_subtitle=scan.id,
        scan=scan,
        targets=scan_targets(scan),
        stats=job_status.get("stats") or scan_stats(scan),
        phase_key=job_status.get("phase_key", ""),
        findings_count=db.count_findings(scan.id),
        scope=scope,
        terminal=terminal,
        msg=request.query_params.get("msg"),
        kind=request.query_params.get("kind", "info"),
    )


@router.get("/api/scans/{scan_id}/status")
async def scan_status(request: Request, scan_id: str):
    manager = get_manager(request)
    payload = manager.status(scan_id)
    if not payload:
        raise HTTPException(status_code=404, detail="找不到掃描")
    return JSONResponse(payload)


@router.post("/scans/{scan_id}/cancel")
async def cancel_scan(request: Request, scan_id: str):
    form = await request.form()
    verify_csrf(request, form)
    db = get_db(request)
    if not db.get_scan(scan_id):
        raise HTTPException(status_code=404, detail="找不到掃描")
    ok = await get_manager(request).cancel(scan_id)
    message = "已送出取消要求" if ok else "掃描已結束，不需取消"
    return RedirectResponse(
        url=f"/scans/{scan_id}?msg={quote(message)}",
        status_code=303,
    )


@router.post("/scans/{scan_id}/delete")
async def delete_scan(request: Request, scan_id: str):
    form = await request.form()
    verify_csrf(request, form)
    db = get_db(request)
    if not db.get_scan(scan_id):
        raise HTTPException(status_code=404, detail="找不到掃描")
    db.delete_scan(scan_id)
    return RedirectResponse(url="/scans?msg=掃描已刪除", status_code=303)
