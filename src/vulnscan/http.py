from __future__ import annotations

import asyncio
import random
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urlparse

import httpx

from .audit import AuditLogger
from .models import Page, ScanConfig
from .scope import Scope, ScopeError

MAX_BODY_BYTES = 512 * 1024
ALLOWED_METHODS = {"GET", "HEAD", "OPTIONS"}


class BudgetExceeded(RuntimeError):
    pass


class ScanCancelled(RuntimeError):
    pass


@dataclass
class RequestStats:
    total: int = 0
    by_host: dict[str, int] = field(default_factory=dict)
    errors: int = 0


class HostRateLimiter:
    def __init__(self, rps_per_host: float) -> None:
        self.interval = 1.0 / max(rps_per_host, 0.2)
        self._locks: dict[str, asyncio.Lock] = {}
        self._next: dict[str, float] = {}

    async def wait(self, host: str) -> None:
        lock = self._locks.setdefault(host, asyncio.Lock())
        async with lock:
            loop = asyncio.get_running_loop()
            now = loop.time()
            wait_for = max(0.0, self._next.get(host, 0.0) - now)
            if wait_for:
                await asyncio.sleep(wait_for + random.uniform(0, self.interval * 0.15))
            self._next[host] = max(now, self._next.get(host, 0.0)) + self.interval


class HttpEngine:
    def __init__(
        self,
        *,
        scope: Scope,
        config: ScanConfig,
        audit: AuditLogger,
        cancel_event: asyncio.Event,
        user_agent: str,
        proxy: str | None = None,
        on_request: Callable[[RequestStats], None] | None = None,
        auth_headers: dict[str, str] | None = None,
        auth_cookies: dict[str, str] | None = None,
        limiter: HostRateLimiter | None = None,
        stats: RequestStats | None = None,
    ) -> None:
        self.scope = scope
        self.config = config
        self.audit = audit
        self.cancel_event = cancel_event
        self.stats = stats if stats is not None else RequestStats()
        self.on_request = on_request
        self.limiter = limiter or HostRateLimiter(config.rps_per_host)
        client_headers = {"User-Agent": user_agent, "Accept": "*/*"}
        if auth_headers:
            client_headers.update(auth_headers)
        self._auth_header_names = set((auth_headers or {}).keys())
        self.client = httpx.AsyncClient(
            follow_redirects=False,
            timeout=httpx.Timeout(config.timeout, connect=min(10.0, config.timeout)),
            headers=client_headers,
            cookies=auth_cookies or None,
            proxy=proxy or None,
        )

    async def close(self) -> None:
        await self.client.aclose()

    def update_auth(
        self,
        headers: dict[str, str],
        cookies: dict[str, str],
    ) -> None:
        """Replace auth materials on the existing client after a re-login."""
        for name in self._auth_header_names:
            self.client.headers.pop(name, None)
        self.client.headers.update(headers)
        self._auth_header_names = set(headers)
        self.client.cookies.clear()
        if cookies:
            self.client.cookies.update(cookies)

    @property
    def auth_headers(self) -> dict[str, str]:
        return {
            name: self.client.headers[name]
            for name in self._auth_header_names
            if name in self.client.headers
        }

    @property
    def auth_cookies(self) -> dict[str, str]:
        return {key: value for key, value in self.client.cookies.items()}

    def _check_cancel(self) -> None:
        if self.cancel_event.is_set():
            raise ScanCancelled("掃描已取消")

    async def request(
        self,
        method: str,
        url: str,
        *,
        headers: dict[str, str] | None = None,
        json_body: dict[str, Any] | None = None,
        rule_id: str | None = None,
    ) -> Page:
        method = method.upper()
        if method == "POST":
            if not self.config.allow_api_post or json_body is None:
                raise ValueError("未啟用 API POST 主動測試")
        elif method not in ALLOWED_METHODS:
            raise ValueError(f"不允許的 HTTP 方法：{method}")
        if not self.scope.is_allowed(url):
            raise ScopeError(f"目標不在授權範圍內：{url}")
        self._check_cancel()

        host = urlparse(url).hostname or ""
        used = self.stats.by_host.get(host, 0)
        if used >= self.config.max_requests_per_host:
            raise BudgetExceeded(f"{host} 已達請求上限 {self.config.max_requests_per_host}")
        await self.limiter.wait(host)
        self._check_cancel()

        request_headers = dict(self.client.headers)
        if headers:
            request_headers.update(headers)
        if json_body is not None:
            request_headers["content-type"] = "application/json"
        started = time.perf_counter()
        try:
            if json_body is not None:
                request = self.client.build_request(method, url, json=json_body, headers=headers)
            else:
                request = self.client.build_request(method, url, headers=headers)
            response = await self.client.send(request, stream=True)
            try:
                response_headers = {key.lower(): value for key, value in response.headers.items()}
                set_cookie = response.headers.get_list("set-cookie")
                content_type = response_headers.get("content-type", "")
                body = b""
                if method != "HEAD":
                    async for chunk in response.aiter_bytes():
                        body += chunk
                        if len(body) >= MAX_BODY_BYTES:
                            break
                text = body.decode(_charset(content_type), errors="replace")
                elapsed_ms = int((time.perf_counter() - started) * 1000)
                page = Page(
                    url=str(response.url),
                    status=response.status_code,
                    headers=response_headers,
                    set_cookie=set_cookie,
                    text=text,
                    content_type=content_type,
                    elapsed_ms=elapsed_ms,
                )
            finally:
                await response.aclose()
        except (httpx.HTTPError, OSError) as exc:
            elapsed_ms = int((time.perf_counter() - started) * 1000)
            page = Page(
                url=url,
                status=0,
                headers={},
                content_type="",
                elapsed_ms=elapsed_ms,
                error=str(exc),
            )
            self.stats.errors += 1

        self.stats.total += 1
        self.stats.by_host[host] = self.stats.by_host.get(host, 0) + 1
        if self.on_request:
            self.on_request(self.stats)
        self.audit.log(
            method=method,
            url=url,
            status=page.status,
            request_headers=request_headers,
            response_headers=page.headers,
            body_excerpt=page.text[:300],
            rule_id=rule_id,
            error=page.error,
        )
        return page

    async def get(
        self,
        url: str,
        *,
        headers: dict[str, str] | None = None,
        rule_id: str | None = None,
    ) -> Page:
        return await self.request("GET", url, headers=headers, rule_id=rule_id)

    async def options(self, url: str, *, rule_id: str | None = None) -> Page:
        return await self.request("OPTIONS", url, rule_id=rule_id)

    async def post_json(
        self,
        url: str,
        body: dict[str, Any],
        *,
        rule_id: str | None = None,
    ) -> Page:
        return await self.request("POST", url, json_body=body, rule_id=rule_id)


def _charset(content_type: str) -> str:
    for part in content_type.split(";"):
        part = part.strip()
        if part.lower().startswith("charset="):
            return part.split("=", 1)[1].strip().strip('"') or "utf-8"
    return "utf-8"
