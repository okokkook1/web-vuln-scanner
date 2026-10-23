from __future__ import annotations

from collections import deque
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import parse_qsl, urlencode, urljoin, urlsplit, urlunsplit

from selectolax.lexbor import LexborHTMLParser as HTMLParser

from .http import BudgetExceeded, HttpEngine, ScanCancelled
from .models import Endpoint, FormField, FormInfo, Page, Parameter, ScanConfig
from .scope import Scope

SKIP_EXTENSIONS = {
    ".css",
    ".png",
    ".jpg",
    ".jpeg",
    ".gif",
    ".svg",
    ".ico",
    ".webp",
    ".avif",
    ".woff",
    ".woff2",
    ".ttf",
    ".eot",
    ".mp3",
    ".mp4",
    ".webm",
    ".avi",
    ".mov",
    ".pdf",
    ".zip",
    ".gz",
    ".tar",
    ".rar",
    ".7z",
    ".exe",
    ".msi",
    ".dmg",
    ".apk",
    ".iso",
}

TOKEN_HINTS = ("csrf", "xsrf", "token", "authenticity", "nonce", "__requestverificationtoken")

ProgressCallback = Callable[[str, str, dict[str, Any]], None]


@dataclass
class CrawlResult:
    pages: list[Page] = field(default_factory=list)
    endpoints: list[Endpoint] = field(default_factory=list)
    stats: dict[str, Any] = field(default_factory=dict)


def normalize_url(url: str) -> str:
    parsed = urlsplit(url)
    query = urlencode(sorted(parse_qsl(parsed.query, keep_blank_values=True)))
    path = parsed.path or "/"
    return urlunsplit((parsed.scheme.lower(), parsed.netloc.lower(), path, query, ""))


def _extension(url: str) -> str:
    path = urlsplit(url).path.lower()
    dot = path.rfind(".")
    return path[dot:] if dot >= 0 else ""


def _form_info(page: Page, node, scope: Scope) -> FormInfo | None:
    action_raw = node.attributes.get("action") or page.url
    action = urljoin(page.url, action_raw)
    if not scope.is_allowed(action) or scope.is_excluded(action):
        return None
    method = (node.attributes.get("method") or "GET").upper()
    if method not in ("GET", "POST"):
        method = "GET"
    fields: list[FormField] = []
    has_token = False
    for input_node in node.css("input, select, textarea"):
        name = input_node.attributes.get("name")
        if not name:
            continue
        input_type = input_node.attributes.get("type") or input_node.tag
        value = input_node.attributes.get("value")
        if any(hint in name.lower() for hint in TOKEN_HINTS):
            has_token = True
        fields.append(FormField(name=name, type=input_type, value=value))
    return FormInfo(action=action, method=method, fields=fields, has_token=has_token)


def parse_forms(page: Page, scope: Scope) -> list[FormInfo]:
    if not page.text:
        return []
    try:
        tree = HTMLParser(page.text)
    except Exception:
        return []
    forms: list[FormInfo] = []
    for node in tree.css("form"):
        info = _form_info(page, node, scope)
        if info:
            forms.append(info)
    return forms


class Crawler:
    def __init__(
        self,
        engine: HttpEngine,
        scope: Scope,
        config: ScanConfig,
        *,
        on_progress: ProgressCallback | None = None,
    ) -> None:
        self.engine = engine
        self.scope = scope
        self.config = config
        self.on_progress = on_progress
        self.pages: list[Page] = []
        self.endpoints: dict[str, Endpoint] = {}
        self.js_pages = 0
        self.max_pages = min(150, max(20, config.max_requests_per_host // 2))

    def _emit(self, message: str) -> None:
        if self.on_progress:
            self.on_progress(
                "crawl",
                message,
                {
                    "requests": self.engine.stats.total,
                    "pages": len(self.pages),
                    "endpoints": len(self.endpoints),
                },
            )

    def _add_endpoint(
        self, url: str, method: str, params: list[Parameter], source: str, depth: int
    ) -> None:
        key = f"{method.upper()} {normalize_url(url)}"
        if key in self.endpoints:
            existing = self.endpoints[key]
            known = {(p.name, p.location) for p in existing.params}
            for param in params:
                if (param.name, param.location) not in known:
                    existing.params.append(param)
                    known.add((param.name, param.location))
            return
        self.endpoints[key] = Endpoint(
            url=normalize_url(url),
            method=method.upper(),
            params=params,
            source=source,  # type: ignore[arg-type]
            depth=depth,
        )

    def _add_forms(self, page: Page, forms: list[FormInfo], depth: int) -> None:
        for form in forms:
            if form.method == "GET":
                params = [
                    Parameter(name=field.name, location="query", value=field.value)
                    for field in form.fields
                ]
                self._add_endpoint(form.action, "GET", params, "form", depth + 1)
            else:
                self._add_endpoint(form.action, "POST", [], "form", depth + 1)

    def _enqueue_links(
        self, page: Page, queue: deque[tuple[str, int]], seen: set[str], depth: int
    ) -> None:
        if depth >= self.config.max_depth:
            return
        try:
            tree = HTMLParser(page.text)
        except Exception:
            return
        base = page.url
        for node in tree.css("a[href], area[href], iframe[src], script[src]"):
            raw = node.attributes.get("href") or node.attributes.get("src")
            if not raw:
                continue
            if raw.startswith(("mailto:", "tel:", "javascript:", "data:", "#")):
                continue
            target = urljoin(base, raw).split("#", 1)[0]
            if urlsplit(target).scheme not in ("http", "https"):
                continue
            if _extension(target) in SKIP_EXTENSIONS:
                continue
            if not self.scope.is_allowed(target) or self.scope.is_excluded(target):
                continue
            target = normalize_url(target)
            if target not in seen:
                queue.append((target, depth + 1))

    async def crawl(self) -> CrawlResult:
        queue: deque[tuple[str, int]] = deque((seed, 0) for seed in self.scope.seeds)
        seen: set[str] = set()

        while queue:
            if self.engine.cancel_event.is_set():
                raise ScanCancelled("掃描已取消")
            if len(self.pages) >= self.max_pages:
                self._emit(f"已達頁面探索上限 {self.max_pages}")
                break
            url, depth = queue.popleft()
            url = normalize_url(url)
            if url in seen:
                continue
            seen.add(url)
            if not self.scope.is_allowed(url) or self.scope.is_excluded(url):
                continue

            try:
                page = await self.engine.get(url)
            except BudgetExceeded:
                self._emit(f"{url} 已達請求上限，停止探索並使用目前結果")
                break
            except ScanCancelled:
                raise
            except Exception as exc:
                self._emit(f"略過 {url}（{exc}）")
                continue

            if page.error:
                self._emit(f"無法連線 {url}（{page.error}）")
                continue

            if page.status in (301, 302, 303, 307, 308):
                location = page.headers.get("location", "")
                if location and depth < self.config.max_depth:
                    target = urljoin(page.url, location).split("#", 1)[0]
                    if (
                        urlsplit(target).scheme in ("http", "https")
                        and self.scope.is_allowed(target)
                        and not self.scope.is_excluded(target)
                    ):
                        target = normalize_url(target)
                        if target not in seen:
                            self._emit(f"跟隨重新導向 {url} → {target}")
                            queue.appendleft((target, depth))
                continue

            self._emit(f"探索 {url} [{page.status}]")
            if page.is_javascript:
                if self.js_pages >= 30 or len(page.text) > 2_000_000:
                    continue
                self.js_pages += 1
                self.pages.append(page)
                continue

            if not page.is_html:
                continue

            forms = parse_forms(page, self.scope)
            page.forms = forms
            self.pages.append(page)

            params = [
                Parameter(name=name, location="query", value=value)
                for name, value in parse_qsl(urlsplit(url).query, keep_blank_values=True)
            ]
            self._add_endpoint(url, "GET", params, "crawl", depth)
            self._add_forms(page, forms, depth)
            self._enqueue_links(page, queue, seen, depth)
            self._emit(f"已收集 {len(self.endpoints)} 個端點、{len(self.pages)} 個頁面")

        return CrawlResult(
            pages=self.pages,
            endpoints=list(self.endpoints.values()),
            stats={
                "requests": self.engine.stats.total,
                "pages": len(self.pages),
                "endpoints": len(self.endpoints),
            },
        )
