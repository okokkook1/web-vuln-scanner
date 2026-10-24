from __future__ import annotations

import re
from dataclasses import dataclass, field
from http.cookies import SimpleCookie
from urllib.parse import urljoin, urlsplit

import httpx
from selectolax.lexbor import LexborHTMLParser

from .audit import AuditLogger
from .models import AuthConfig, AuthType, ScanConfig
from .scope import Scope

HEADER_NAME_RE = re.compile(r"^[A-Za-z0-9-]+$")


class AuthError(RuntimeError):
    pass


@dataclass
class AuthMaterials:
    headers: dict[str, str] = field(default_factory=dict)
    cookies: dict[str, str] = field(default_factory=dict)
    summary: dict = field(default_factory=dict)


def _resolve_url(raw: str, scope: Scope) -> str:
    raw = raw.strip()
    if not raw:
        raise AuthError("登入 URL 不可空白")
    if raw.startswith(("http://", "https://")):
        url = raw
    else:
        bases = scope.base_urls()
        if not bases:
            raise AuthError("沒有可用的起始網址，無法解析登入 URL")
        url = urljoin(bases[0], raw)
    if not scope.is_allowed(url):
        raise AuthError(f"登入 URL 不在授權範圍內：{url}")
    return url


def _parse_cookies(raw: str) -> dict[str, str]:
    value = raw.strip()
    if value.lower().startswith("cookie:"):
        value = value[7:].strip()
    jar = SimpleCookie()
    try:
        jar.load(value)
    except Exception as exc:
        raise AuthError("Cookie 字串格式不正確") from exc
    cookies = {key: morsel.value for key, morsel in jar.items()}
    if not cookies:
        raise AuthError("Cookie 字串沒有可用的 name=value")
    return cookies


def _parse_header(raw_name: str, raw_value: str) -> dict[str, str]:
    name = raw_name.strip()
    value = raw_value.strip()
    if not HEADER_NAME_RE.match(name):
        raise AuthError("Header 名稱格式不正確")
    if "\r" in value or "\n" in value:
        raise AuthError("Header 值不可包含換行")
    if not value:
        raise AuthError("Header 值不可空白")
    return {name: value}


async def prepare_auth(
    config: ScanConfig,
    scope: Scope,
    audit: AuditLogger,
) -> AuthMaterials:
    auth = config.auth
    if auth.type is AuthType.NONE:
        return AuthMaterials(summary=auth.summary())
    if auth.type is AuthType.COOKIE:
        return AuthMaterials(cookies=_parse_cookies(auth.cookie or ""), summary=auth.summary())
    if auth.type is AuthType.HEADER:
        headers = _parse_header(auth.header_name or "", auth.header_value or "")
        return AuthMaterials(headers=headers, summary=auth.summary())
    if auth.type is AuthType.STATE or auth.type is AuthType.BROWSER:
        return _state_auth(auth, scope)
    if auth.type is AuthType.FORM:
        materials = await _form_login(config, scope, audit)
        materials.summary = auth.summary()
        return materials
    raise AuthError("未知的登入方式")


def _state_auth(auth: AuthConfig, scope: Scope) -> AuthMaterials:
    state = auth.storage_state or {}
    cookies: dict[str, str] = {}
    for item in state.get("cookies") or []:
        if not isinstance(item, dict):
            continue
        domain = str(item.get("domain") or "").lstrip(".").lower()
        name = str(item.get("name") or "")
        value = str(item.get("value") or "")
        if not name or not domain:
            continue
        if _cookie_domain_matches(domain, scope.allowed_hosts):
            cookies[name] = value

    headers: dict[str, str] = {}
    token_key = (auth.storage_token_key or "").strip()
    header_name = (auth.storage_header_name or "").strip()
    if token_key and header_name:
        token = _find_storage_token(state, scope, token_key)
        if token is None:
            raise AuthError(f"storage state 找不到 localStorage key：{token_key}")
        headers[header_name] = f"{auth.storage_header_prefix}{token}"

    if not cookies and not headers:
        raise AuthError("storage state 沒有適用於此 scope 的 Cookie 或 token")
    return AuthMaterials(cookies=cookies, headers=headers, summary=auth.summary())


def _cookie_domain_matches(domain: str, hosts: set[str]) -> bool:
    domain = domain.lower().lstrip(".")
    for host in hosts:
        host = host.lower()
        if host == domain or host.endswith(f".{domain}"):
            return True
    return False


def _find_storage_token(state: dict, scope: Scope, key: str) -> str | None:
    for origin in state.get("origins") or []:
        if not isinstance(origin, dict):
            continue
        parsed = urlsplit(str(origin.get("origin") or ""))
        host = (parsed.hostname or "").lower()
        if host not in {item.lower() for item in scope.allowed_hosts}:
            continue
        for item in origin.get("localStorage") or []:
            if isinstance(item, dict) and item.get("name") == key:
                return str(item.get("value") or "")
    return None


async def refresh_auth(
    config: ScanConfig,
    scope: Scope,
    audit: AuditLogger,
    *,
    headers: dict[str, str] | None = None,
    cookies: dict[str, str] | None = None,
) -> AuthMaterials:
    """Refresh header/cookie credentials through an OAuth-style token endpoint."""
    auth = config.auth
    if not (auth.refresh_url or "").strip() or not (auth.refresh_token or "").strip():
        raise AuthError("未設定 refresh URL 或 refresh token")
    refresh_url = _resolve_url(auth.refresh_url or "", scope)
    parsed_refresh = urlsplit(refresh_url)
    if parsed_refresh.username or parsed_refresh.password:
        raise AuthError("refresh URL 不可包含帳密")
    data = {
        "grant_type": "refresh_token",
        auth.refresh_token_field: auth.refresh_token or "",
    }
    if auth.refresh_client_id:
        data["client_id"] = auth.refresh_client_id
    request_headers = {
        "User-Agent": config.user_agent,
        "Accept": "application/json, application/x-www-form-urlencoded",
        **(headers or {}),
    }
    async with httpx.AsyncClient(
        follow_redirects=False,
        timeout=httpx.Timeout(config.timeout, connect=min(10.0, config.timeout)),
        headers=request_headers,
        cookies=cookies or None,
        proxy=config.proxy or None,
    ) as client:
        try:
            response = await client.post(refresh_url, data=data)
        except httpx.HTTPError as exc:
            raise AuthError(f"refresh 請求失敗：{exc}") from exc
        audit.log(
            method="POST",
            url=refresh_url,
            status=response.status_code,
            request_headers={"content-type": "application/x-www-form-urlencoded"},
            response_headers={
                key.lower(): value for key, value in response.headers.items()
            },
            body_excerpt="",
            rule_id="auth-refresh",
        )
        if response.status_code >= 400:
            raise AuthError(f"refresh 端點回應 HTTP {response.status_code}")
        try:
            payload = response.json()
        except ValueError:
            payload = {}
        token = (
            payload.get(auth.refresh_access_token_field)
            if isinstance(payload, dict)
            else None
        )
        new_cookies = {key: value for key, value in client.cookies.items()}
        new_headers = dict(headers or {})
        if token:
            token = str(token)
            if "\r" in token or "\n" in token:
                raise AuthError("refresh 回應的 access token 含非法換行")
            header_name = (
                auth.refresh_header_name
                or auth.header_name
                or "Authorization"
            )
            if not HEADER_NAME_RE.match(header_name):
                raise AuthError("refresh Header 名稱格式不正確")
            if "\r" in auth.refresh_header_prefix or "\n" in auth.refresh_header_prefix:
                raise AuthError("refresh Header 前綴含非法換行")
            new_headers[header_name] = f"{auth.refresh_header_prefix}{token}"
        if not token and new_cookies == (cookies or {}):
            raise AuthError("refresh 回應沒有新的 access token 或 Cookie")
        return AuthMaterials(
            headers=new_headers,
            cookies=new_cookies,
            summary=auth.summary(),
        )


async def _form_login(config: ScanConfig, scope: Scope, audit: AuditLogger) -> AuthMaterials:
    auth = config.auth
    login_url = _resolve_url(auth.login_url or "", scope)
    client = httpx.AsyncClient(
        follow_redirects=False,
        timeout=httpx.Timeout(config.timeout, connect=min(10.0, config.timeout)),
        headers={
            "User-Agent": config.user_agent,
            "Accept": "text/html,application/xhtml+xml",
        },
        proxy=config.proxy or None,
    )
    try:
        page = await _fetch(client, "GET", login_url, audit, rule_id="auth-login-page")
        page = await _follow_redirects(client, page, scope, audit)
        if page.status_code >= 400:
            raise AuthError(f"登入頁面回應 HTTP {page.status_code}")
        login_page_url = str(page.url)
        form = _find_login_form(page.text, login_page_url, auth)
        if form is None:
            raise AuthError("找不到登入表單；可改用 Cookie 或 Header 登入")
        action_url, data, username_key, password_key = form
        if not scope.is_allowed(action_url):
            raise AuthError(f"登入表單 action 不在授權範圍內：{action_url}")
        data[username_key] = auth.username or ""
        data[password_key] = auth.password or ""
        response = await _fetch(
            client,
            "POST",
            action_url,
            audit,
            data=data,
            rule_id="auth-login",
        )
        response = await _follow_redirects(client, response, scope, audit, initial_data=data)

        if auth.verify_url:
            verify_url = _resolve_url(auth.verify_url, scope)
            verified = await _fetch(client, "GET", verify_url, audit, rule_id="auth-verify")
            if verified.status_code >= 400:
                raise AuthError(f"登入驗證頁面回應 HTTP {verified.status_code}")
            if auth.verify_text and auth.verify_text not in verified.text:
                raise AuthError("登入驗證頁面沒有出現指定的驗證文字")
        else:
            if response.status_code >= 400:
                raise AuthError(f"登入請求回應 HTTP {response.status_code}")
            if auth.verify_text and auth.verify_text not in response.text:
                raise AuthError("登入後頁面沒有出現指定的驗證文字")
            if urlsplit(str(response.url)).path.rstrip("/") == urlsplit(login_page_url).path.rstrip("/"):
                raise AuthError("登入後仍停留在登入頁，請確認帳號、密碼或欄位名稱")

        cookies = {key: value for key, value in client.cookies.items()}
        if not cookies:
            raise AuthError("登入成功但沒有取得 Cookie；此版本僅支援 Cookie 型 session")
        return AuthMaterials(cookies=cookies, summary=auth.summary())
    finally:
        await client.aclose()


def _find_login_form(
    html: str,
    page_url: str,
    auth: AuthConfig,
) -> tuple[str, dict[str, str], str, str] | None:
    try:
        tree = LexborHTMLParser(html)
    except Exception:
        return None
    for form in tree.css("form"):
        inputs = list(form.css("input"))
        password_inputs = [
            item
            for item in inputs
            if (item.attributes.get("type") or "").lower() == "password"
        ]
        if not password_inputs:
            continue
        action = form.attributes.get("action") or page_url
        action_url = urljoin(page_url, action)
        data: dict[str, str] = {}
        for item in inputs:
            name = item.attributes.get("name")
            input_type = (item.attributes.get("type") or "text").lower()
            if not name:
                continue
            if input_type == "hidden":
                data[name] = item.attributes.get("value") or ""
        password_key = _pick_field(
            password_inputs, auth.password_field, ("password", "passwd", "pwd")
        )
        if not password_key:
            continue
        username_inputs = [
            item
            for item in inputs
            if (item.attributes.get("type") or "text").lower() in ("text", "email", "tel")
            and item.attributes.get("name")
        ]
        username_key = _pick_field(
            username_inputs, auth.username_field, ("user", "email", "login", "account")
        )
        if not username_key:
            continue
        return action_url, data, username_key, password_key
    return None


def _pick_field(inputs, preferred: str, hints: tuple[str, ...]) -> str | None:
    names = [item.attributes.get("name") or "" for item in inputs]
    if preferred in names:
        return preferred
    for name in names:
        if any(hint in name.lower() for hint in hints):
            return name
    return names[0] if names else None


async def _follow_redirects(
    client: httpx.AsyncClient,
    response: httpx.Response,
    scope: Scope,
    audit: AuditLogger,
    initial_data: dict[str, str] | None = None,
) -> httpx.Response:
    current = response
    method = "GET"
    data = initial_data
    for _ in range(6):
        if current.status_code not in (301, 302, 303, 307, 308):
            return current
        location = current.headers.get("location")
        if not location:
            return current
        target = urljoin(str(current.url), location)
        if not scope.is_allowed(target):
            raise AuthError(f"登入重新導向到授權範圍外：{target}")
        if current.status_code in (301, 302, 303):
            method = "GET"
            data = None
        else:
            method = "POST"
        current = await _fetch(
            client, method, target, audit, data=data, rule_id="auth-redirect"
        )
    raise AuthError("登入重新導向次數過多")


async def _fetch(
    client: httpx.AsyncClient,
    method: str,
    url: str,
    audit: AuditLogger,
    *,
    data: dict[str, str] | None = None,
    rule_id: str = "auth",
) -> httpx.Response:
    headers = {"Content-Type": "application/x-www-form-urlencoded"} if data else None
    response = await client.request(method, url, data=data, headers=headers)
    request_headers = {"content-type": "application/x-www-form-urlencoded"} if data else {}
    audit.log(
        method=method,
        url=url,
        status=response.status_code,
        request_headers=request_headers,
        response_headers={key.lower(): value for key, value in response.headers.items()},
        body_excerpt="",
        rule_id=rule_id,
    )
    return response
