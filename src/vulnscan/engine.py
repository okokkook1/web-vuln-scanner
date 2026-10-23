from __future__ import annotations

import asyncio
import json
import re
from collections import Counter
from collections.abc import Callable
from pathlib import Path
from typing import Any
from urllib.parse import urljoin, urlsplit

import httpx
import yaml

from .audit import AuditLogger
from .auth import AuthError, prepare_auth
from .callback import CallbackServer
from .checks import run_active, run_advanced, run_api, run_bola, run_passive
from .checks.base import ScanContext
from .checks.bola import select_authorization_candidates
from .crawler import Crawler, normalize_url
from .db import Database
from .fingerprint import fingerprint_pages
from .http import HttpEngine, RequestStats, ScanCancelled
from .models import (
    AdvancedCheck,
    AuthConfig,
    AuthType,
    Finding,
    Profile,
    ScanConfig,
    ScanResult,
    ScanStats,
    Severity,
)
from .openapi_import import (
    filter_get_endpoints,
    filter_post_endpoints,
    parse_openapi_report,
)
from .openapi_refs import bundle_external_refs, fingerprint_spec
from .scope import Scope, ScopeError, build_scope

UpdateCallback = Callable[[str, str, dict[str, Any], int], None]


class ScanError(RuntimeError):
    pass


class ScanEngine:
    def __init__(
        self,
        *,
        scan_id: str,
        config: ScanConfig,
        db: Database,
        data_dir: Path,
        cancel_event: asyncio.Event,
        on_update: UpdateCallback,
    ) -> None:
        self.scan_id = scan_id
        self.config = config
        self.db = db
        self.data_dir = data_dir
        self.cancel_event = cancel_event
        self.on_update = on_update
        self.stats = ScanStats()
        self._http: HttpEngine | None = None
        self._bola_http: HttpEngine | None = None
        self._unauth_http: HttpEngine | None = None
        self._phase = "validate"
        self._message = ""
        self._progress = 0
        self._api_meta: dict[str, Any] = {}
        self._api_drift = False
        self._session_valid = True
        self._session_reason = ""
        self._session_recovery_attempted: set[str] = set()

    def _emit(self, phase: str, message: str, progress: int) -> None:
        self._phase = phase
        self._message = message
        self._progress = max(self._progress, progress)
        if self._http:
            self.stats.requests = self._http.stats.total
        self.on_update(phase, message, self.stats.model_dump(), self._progress)

    def _log(self, message: str) -> None:
        self._emit(self._phase, message, self._progress)

    def _on_request(self, stats: RequestStats) -> None:
        self.stats.requests = stats.total
        self.on_update(self._phase, self._message, self.stats.model_dump(), self._progress)

    async def run(self) -> ScanResult:
        audit: AuditLogger | None = None
        callback: CallbackServer | None = None
        try:
            self._emit("validate", "驗證授權與掃描範圍…", 2)
            try:
                scope = await asyncio.to_thread(build_scope, self.config)
            except Exception as exc:
                raise ScanError(str(exc)) from exc
            self._api_meta = dict(scope.snapshot().get("api") or {})
            self._emit(
                "validate",
                f"授權驗證通過：{len(scope.seeds)} 個起始目標、到期日 {self.config.expires}",
                5,
            )

            scan_dir = self.data_dir / "scans" / self.scan_id
            audit = AuditLogger(scan_dir / "audit.jsonl", self.scan_id)
            audit.write_scope(scope.snapshot())

            if self.config.auth.type is not AuthType.NONE:
                self._emit("validate", "開始登入驗證…", 5)
                try:
                    auth_materials = await prepare_auth(self.config, scope, audit)
                except httpx.HTTPError as exc:
                    raise ScanError(f"登入請求失敗：{exc}") from exc
                except AuthError as exc:
                    raise ScanError(f"登入失敗：{exc}") from exc
                self._emit(
                    "validate",
                    f"登入驗證通過：{self.config.auth.type.label}",
                    7,
                )
            else:
                auth_materials = await prepare_auth(self.config, scope, audit)

            self._http = HttpEngine(
                scope=scope,
                config=self.config,
                audit=audit,
                cancel_event=self.cancel_event,
                user_agent=self.config.user_agent,
                proxy=self.config.proxy,
                on_request=self._on_request,
                auth_headers=auth_materials.headers,
                auth_cookies=auth_materials.cookies,
            )
            if self.config.enable_bola and self.config.bola_auth is not None:
                self._emit("validate", "準備 BOLA 第二帳號 session…", 6)
                try:
                    bola_config = self.config.model_copy(
                        update={"auth": self.config.bola_auth}
                    )
                    bola_materials = await prepare_auth(bola_config, scope, audit)
                    self._bola_http = HttpEngine(
                        scope=scope,
                        config=self.config,
                        audit=audit,
                        cancel_event=self.cancel_event,
                        user_agent=self.config.user_agent,
                        proxy=self.config.proxy,
                        on_request=self._on_request,
                        auth_headers=bola_materials.headers,
                        auth_cookies=bola_materials.cookies,
                        limiter=self._http.limiter,
                        stats=self._http.stats,
                    )
                    self._unauth_http = HttpEngine(
                        scope=scope,
                        config=self.config,
                        audit=audit,
                        cancel_event=self.cancel_event,
                        user_agent=self.config.user_agent,
                        proxy=self.config.proxy,
                        on_request=self._on_request,
                        limiter=self._http.limiter,
                        stats=self._http.stats,
                    )
                except (AuthError, httpx.HTTPError) as exc:
                    self._api_meta["bola"] = {
                        "enabled": True,
                        "skipped_reason": "secondary_auth_failed",
                        "error": str(exc),
                        "allowlist": self.config.bola_allowlist,
                        "allow_all": bool(
                            self.config.bola_allow_all_ack
                            and not self.config.bola_allowlist
                        ),
                    }
                    self._emit("validate", f"BOLA 第二帳號登入失敗，將略過：{exc}", 6)
            if self.config.profile is Profile.FULL and AdvancedCheck.SSRF in self.config.advanced_checks:
                try:
                    callback = CallbackServer(self.config.ssrf_callback)
                    callback_base = await callback.start()
                except Exception as exc:  # surface a clear scan error
                    raise ScanError(f"SSRF callback listener 無法啟動：{exc}") from exc
                self._emit("validate", f"SSRF callback listener：{callback_base}", 6)
            ctx = ScanContext(
                scan_id=self.scan_id,
                config=self.config,
                scope=scope,
                engine=self._http,
                audit=audit,
                log=self._log,
                max_active_tests=max(20, min(100, self.config.max_requests_per_host // 20)),
                max_advanced_tests=max(6, 6 * len(self.config.advanced_checks)),
                max_api_tests=self.config.max_api_tests,
                max_bola_tests=self.config.max_bola_tests,
                callback=callback,
            )

            openapi_endpoints = []
            spec = self.config.openapi_spec
            spec_base: str | None = None
            if self.config.openapi_url:
                source_url = urljoin(scope.base_urls()[0], self.config.openapi_url)
                spec, spec_base = await self._fetch_url_document(
                    source_url,
                    scope,
                    rule_id="openapi-import",
                )
                self._emit("validate", f"OpenAPI URL 匯入：{spec_base}", 8)
            if spec:
                try:
                    bundle = await bundle_external_refs(
                        spec,
                        base_url=spec_base,
                        scope=scope,
                        fetch=lambda url: self._fetch_url_document(
                            url,
                            scope,
                            rule_id="openapi-ref",
                        ),
                    )
                    spec = bundle.spec
                    report = parse_openapi_report(
                        spec,
                        scope,
                        allow_post=self.config.allow_api_post,
                    )
                except Exception as exc:
                    raise ScanError(f"OpenAPI 匯入失敗：{exc}") from exc
                actual_fingerprint = fingerprint_spec(spec)
                expected_fingerprint = self.config.openapi_fingerprint
                self._api_drift = bool(
                    expected_fingerprint
                    and expected_fingerprint != actual_fingerprint
                )
                self._api_meta.update(
                    {
                        "spec_fingerprint": actual_fingerprint,
                        "expected_spec_fingerprint": expected_fingerprint,
                        "fingerprint_match": (
                            None
                            if not expected_fingerprint
                            else not self._api_drift
                        ),
                    }
                )
                warnings = bundle.warnings + report.warnings
                stats = dict(report.stats)
                stats.update(bundle.stats)
                stats["warnings"] = len(warnings)
                self._api_meta.update(
                    {
                        "import_stats": stats,
                        "import_warnings": warnings,
                    }
                )
                openapi_endpoints = report.endpoints
                self._persist_scope(scope, audit)
                if self._api_drift:
                    self._emit(
                        "validate",
                        "OpenAPI 規格與預覽時不同；已保留匯入結果，但會略過 API POST 測試",
                        9,
                    )
                self._emit(
                    "validate",
                    f"OpenAPI 匯入：{len(openapi_endpoints)} 個端點"
                    f"（GET {report.stats.get('get', 0)}、POST {report.stats.get('post', 0)}）",
                    9,
                )
                for warning in report.warnings[:3]:
                    self._emit("validate", f"OpenAPI 警告：{warning}", 9)
                if len(report.warnings) > 3:
                    self._emit(
                        "validate",
                        f"OpenAPI 另有 {len(report.warnings) - 3} 個警告，"
                        "詳情可先用 API 預覽查看",
                        9,
                    )

            def crawl_progress(_phase: str, message: str, stats: dict[str, Any]) -> None:
                self.stats.pages = int(stats.get("pages", 0))
                self.stats.endpoints = int(stats.get("endpoints", 0))
                progress = min(48, 10 + self.stats.pages // 3)
                self._emit("crawl", message, progress)

            self._emit("crawl", "開始探索頁面與端點…", 10)
            crawler = Crawler(
                self._http,
                scope,
                self.config,
                on_progress=crawl_progress,
            )
            crawl_result = await crawler.crawl()
            all_endpoints = merge_endpoints(crawl_result.endpoints, openapi_endpoints)
            self.stats.pages = len(crawl_result.pages)
            self.stats.endpoints = len(all_endpoints)
            self.stats.requests = self._http.stats.total
            self._emit(
                "crawl",
                f"探索完成：{self.stats.pages} 個頁面、{self.stats.endpoints} 個端點",
                48,
            )

            if not crawl_result.pages and not all_endpoints:
                raise ScanError(
                    "沒有取得任何可分析的頁面或 API 端點；請確認目標可連線、網址正確，且授權範圍包含重新導向後的主機。"
                )

            self.stats.fingerprint = fingerprint_pages(crawl_result.pages)
            self._emit("passive", "開始被動檢查…", 50)
            passive = dedupe(await run_passive(crawl_result.pages, ctx))
            seen = {finding_key(item) for item in passive}
            self._save_findings(passive)
            self._recount(passive)
            self._emit("passive", f"被動檢查完成：{len(passive)} 個發現", 70)

            active: list[Finding] = []
            if self.config.profile in (Profile.SAFE, Profile.FULL):
                self._emit("active", "開始安全主動檢查…", 72)
                active_raw = await run_active(all_endpoints, ctx)
                active = [item for item in dedupe(active_raw) if finding_key(item) not in seen]
                seen.update(finding_key(item) for item in active)
                self._save_findings(active)
                active_progress = 88 if self.config.profile is Profile.FULL else (
                    86 if self.config.allow_api_post else 95
                )
                self._emit("active", f"主動檢查完成：新增 {len(active)} 個發現", active_progress)
            else:
                self._emit("active", "被動模式：略過主動探測", 95)

            api_findings: list[Finding] = []
            if self.config.allow_api_post and self.config.profile in (Profile.SAFE, Profile.FULL):
                if not self._api_drift:
                    self._session_valid, self._session_reason = (
                        await self._check_auth_session(scope)
                    )
                    if (
                        not self._session_valid
                        and self.config.auth.type is AuthType.FORM
                    ):
                        self._session_valid, self._session_reason = (
                            await self._recover_auth_session(
                                scope,
                                audit,
                                engine=self._http,
                                auth=self.config.auth,
                                meta_key="auth_session",
                                label="主要帳號",
                            )
                        )
                all_post = [
                    item for item in all_endpoints if item.method.upper() == "POST"
                ]
                skip_reason = (
                    "spec_drift"
                    if self._api_drift
                    else "session_invalid"
                    if not self._session_valid
                    else None
                )
                if skip_reason:
                    self._api_meta["selection"] = self._skipped_api_selection(
                        all_post,
                        skip_reason,
                    )
                    self._persist_scope(scope, audit)
                    message = (
                        "OpenAPI 規格與預覽時不同，略過 API POST 檢查"
                        if skip_reason == "spec_drift"
                        else f"登入 session 無效（{self._session_reason}），"
                        "略過 API POST 檢查"
                    )
                    self._emit("active", message, 93)
                else:
                    api_endpoints = all_endpoints
                    if self.config.api_post_allowlist:
                        api_endpoints = filter_post_endpoints(
                            all_endpoints,
                            self.config.api_post_allowlist,
                        )
                        kept_post_count = sum(
                            1
                            for item in api_endpoints
                            if item.method.upper() == "POST"
                        )
                        excluded = len(all_post) - kept_post_count
                        self._emit(
                            "active",
                            f"API POST 白名單：保留 {kept_post_count} 個端點"
                            + (f"，排除 {excluded} 個" if excluded else ""),
                            89,
                        )
                    post_endpoints = [
                        item for item in api_endpoints if item.method.upper() == "POST"
                    ]
                    self._api_meta["selection"] = self._build_api_selection(
                        all_endpoints,
                        post_endpoints,
                    )
                    self._persist_scope(scope, audit)
                    if not post_endpoints:
                        self._emit(
                            "active",
                            "沒有符合白名單的 POST 端點，略過 API 檢查",
                            93,
                        )
                    else:
                        self._emit("active", "開始 API POST／JSON 檢查…", 89)
                        api_raw = await run_api(api_endpoints, ctx)
                        api_findings = [
                            item
                            for item in dedupe(api_raw)
                            if finding_key(item) not in seen
                        ]
                        seen.update(finding_key(item) for item in api_findings)
                        self._save_findings(api_findings)
                        self._api_meta["test_results"] = (
                            self._build_api_test_results(
                                post_endpoints,
                                api_findings,
                                ctx,
                            )
                        )
                        self._persist_scope(scope, audit)
                        self._emit(
                            "active",
                            f"API 檢查完成：新增 {len(api_findings)} 個發現",
                            93,
                        )

            bola_findings: list[Finding] = []
            if (
                self.config.enable_bola
                and self.config.profile in (Profile.SAFE, Profile.FULL)
                and self.config.bola_auth is not None
            ):
                if "auth_session" not in self._api_meta:
                    self._session_valid, self._session_reason = (
                        await self._check_auth_session(scope)
                    )
                    if (
                        not self._session_valid
                        and self.config.auth.type is AuthType.FORM
                    ):
                        self._session_valid, self._session_reason = (
                            await self._recover_auth_session(
                                scope,
                                audit,
                                engine=self._http,
                                auth=self.config.auth,
                                meta_key="auth_session",
                                label="主要帳號",
                            )
                        )
                bola_endpoints = filter_get_endpoints(
                    all_endpoints,
                    self.config.bola_allowlist,
                )
                all_bola_candidates = select_authorization_candidates(
                    all_endpoints,
                    ctx.max_bola_tests,
                )
                bola_candidates = select_authorization_candidates(
                    bola_endpoints,
                    ctx.max_bola_tests,
                )
                bola_secondary_valid = True
                bola_secondary_reason = ""
                if (
                    self._session_valid
                    and self._bola_http is not None
                    and self.config.bola_auth is not None
                    and "bola_auth_session" not in self._api_meta
                ):
                    bola_secondary_valid, bola_secondary_reason = (
                        await self._check_auth_session(
                            scope,
                            engine=self._bola_http,
                            auth=self.config.bola_auth,
                            meta_key="bola_auth_session",
                            label="BOLA 第二帳號",
                        )
                    )
                    if (
                        not bola_secondary_valid
                        and self.config.bola_auth is not None
                        and self.config.bola_auth.type is AuthType.FORM
                    ):
                        bola_secondary_valid, bola_secondary_reason = (
                            await self._recover_auth_session(
                                scope,
                                audit,
                                engine=self._bola_http,
                                auth=self.config.bola_auth,
                                meta_key="bola_auth_session",
                                label="BOLA 第二帳號",
                            )
                        )
                if not self._session_valid:
                    self._api_meta["bola"] = {
                        "enabled": True,
                        "candidates": len(bola_candidates),
                        "tested": 0,
                        "findings": 0,
                        "skipped_reason": "primary_session_invalid",
                        "error": self._session_reason,
                        "result_counts": {},
                        "results": [],
                        "allowlist": self.config.bola_allowlist,
                        "allow_all": bool(
                            self.config.bola_allow_all_ack
                            and not self.config.bola_allowlist
                        ),
                        "candidates_before_allowlist": len(all_bola_candidates),
                    }
                    self._persist_scope(scope, audit)
                    self._emit(
                        "active",
                        f"主要帳號 session 無效（{self._session_reason}），"
                        "略過 BOLA／IDOR 檢查",
                        94,
                    )
                elif self._bola_http is None or self._unauth_http is None:
                    self._api_meta.setdefault(
                        "bola",
                        {
                            "enabled": True,
                            "candidates": len(bola_candidates),
                            "tested": 0,
                            "findings": 0,
                            "skipped_reason": "secondary_auth_failed",
                            "result_counts": {},
                            "results": [],
                            "allowlist": self.config.bola_allowlist,
                        "allow_all": bool(
                            self.config.bola_allow_all_ack
                            and not self.config.bola_allowlist
                        ),
                            "candidates_before_allowlist": len(
                                all_bola_candidates
                            ),
                        },
                    )
                    self._persist_scope(scope, audit)
                    self._emit("active", "BOLA 第二帳號不可用，略過檢查", 94)
                elif not bola_secondary_valid:
                    self._api_meta["bola"] = {
                        "enabled": True,
                        "candidates": len(bola_candidates),
                        "tested": 0,
                        "findings": 0,
                        "skipped_reason": "secondary_session_invalid",
                        "error": bola_secondary_reason,
                        "result_counts": {},
                        "results": [],
                        "allowlist": self.config.bola_allowlist,
                        "allow_all": bool(
                            self.config.bola_allow_all_ack
                            and not self.config.bola_allowlist
                        ),
                        "candidates_before_allowlist": len(
                            all_bola_candidates
                        ),
                    }
                    self._persist_scope(scope, audit)
                    self._emit(
                        "active",
                        f"BOLA 第二帳號 session 無效（{bola_secondary_reason}），"
                        "略過檢查",
                        94,
                    )
                elif not bola_candidates:
                    self._api_meta["bola"] = {
                        "enabled": True,
                        "candidates": 0,
                        "tested": 0,
                        "findings": 0,
                        "skipped_reason": "no_candidates",
                        "result_counts": {},
                        "results": [],
                        "allowlist": self.config.bola_allowlist,
                        "allow_all": bool(
                            self.config.bola_allow_all_ack
                            and not self.config.bola_allowlist
                        ),
                        "candidates_before_allowlist": len(all_bola_candidates),
                    }
                    self._persist_scope(scope, audit)
                    message = (
                        "BOLA GET 白名單沒有符合的物件端點，略過 BOLA／IDOR 檢查"
                        if self.config.bola_allowlist
                        else "找不到具物件 ID 的 GET 端點，略過 BOLA／IDOR 檢查"
                    )
                    self._emit("active", message, 94)
                else:
                    self._emit("active", "開始 BOLA／IDOR 唯讀檢查…", 94)
                    bola_raw = await run_bola(
                        bola_endpoints,
                        self._http,
                        self._bola_http,
                        self._unauth_http,
                        ctx,
                    )
                    bola_findings = [
                        item
                        for item in dedupe(bola_raw)
                        if finding_key(item) not in seen
                    ]
                    seen.update(finding_key(item) for item in bola_findings)
                    self._save_findings(bola_findings)
                    result_counts = dict(
                        Counter(
                            item["result"] for item in ctx.bola_results
                        )
                    )
                    tested_count = sum(
                        1
                        for item in ctx.bola_results
                        if item["result"] != "budget"
                    )
                    self._api_meta["bola"] = {
                        "enabled": True,
                        "candidates": len(bola_candidates),
                        "tested": tested_count,
                        "findings": len(bola_findings),
                        "secondary_auth": (
                            self.config.bola_auth.type.value
                            if self.config.bola_auth
                            else None
                        ),
                        "skipped_reason": None,
                        "result_counts": result_counts,
                        "results": ctx.bola_results[:100],
                        "allowlist": self.config.bola_allowlist,
                        "allow_all": bool(
                            self.config.bola_allow_all_ack
                            and not self.config.bola_allowlist
                        ),
                        "candidates_before_allowlist": len(all_bola_candidates),
                        "truncated": len(ctx.bola_results) > 100,
                    }
                    self._persist_scope(scope, audit)
                    self._emit(
                        "active",
                        f"BOLA／IDOR 檢查完成：新增 {len(bola_findings)} 個發現",
                        94,
                    )
            advanced: list[Finding] = []
            if self.config.profile is Profile.FULL:
                labels = "、".join(item.label for item in self.config.advanced_checks)
                self._emit("active", f"開始進階檢查（{labels}）…", 94)
                advanced_raw = await run_advanced(all_endpoints, ctx)
                advanced = [
                    item for item in dedupe(advanced_raw) if finding_key(item) not in seen
                ]
                seen.update(finding_key(item) for item in advanced)
                self._save_findings(advanced)
                self._emit("active", f"進階檢查完成：新增 {len(advanced)} 個發現", 95)

            self._save_endpoints(all_endpoints)
            if self._http:
                self.stats.requests = self._http.stats.total
            all_findings = (
                passive + active + api_findings + bola_findings + advanced
            )
            self._recount(all_findings)
            self._emit(
                "report",
                f"掃描完成：共 {len(all_findings)} 個發現、{self.stats.requests} 個請求",
                100,
            )
            return ScanResult(
                stats=self.stats,
                findings=sorted(all_findings, key=lambda item: item.severity.rank),
                endpoints=all_endpoints,
                fingerprint=self.stats.fingerprint,
            )
        except ScanCancelled:
            raise
        finally:
            if callback:
                await callback.stop()
            if self._http:
                await self._http.close()
            if self._bola_http:
                await self._bola_http.close()
            if self._unauth_http:
                await self._unauth_http.close()
            if audit:
                audit.close()

    def _build_api_test_results(
        self,
        post_endpoints: list,
        api_findings: list[Finding],
        ctx: ScanContext,
    ) -> dict[str, Any]:
        finding_counts = Counter(item.url for item in api_findings)
        rule_by_check = {
            "xss": "api-xss-reflected",
            "sqli_error": "api-sqli-error",
            "sqli_boolean": "api-sqli-boolean",
            "ssrf": "api-ssrf-callback",
        }
        findings_by_url: dict[str, set[str]] = {}
        for finding in api_findings:
            findings_by_url.setdefault(finding.url, set()).add(finding.rule_id)
        results: list[dict[str, Any]] = []
        for endpoint in post_endpoints[:100]:
            parsed = urlsplit(endpoint.url)
            entry = ctx.api_results.get(endpoint.url, {})
            checks = list(entry.get("checks") or [])
            outcomes = dict(entry.get("outcomes") or {})
            endpoint_rules = findings_by_url.get(endpoint.url, set())
            for check in checks:
                if outcomes.get(check) not in (None, "tested"):
                    continue
                rule_id = rule_by_check.get(check)
                if rule_id:
                    outcomes[check] = (
                        "finding" if rule_id in endpoint_rules else "no_finding"
                    )
            fields = [
                param.name
                for param in endpoint.params
                if param.location == "body"
            ]
            if checks:
                skipped_reason = None
            elif not fields:
                skipped_reason = "no_json_body"
            elif ctx.api_tests >= ctx.max_api_tests:
                skipped_reason = "budget"
            else:
                skipped_reason = "not_reached"
            results.append(
                {
                    "method": endpoint.method.upper(),
                    "url": endpoint.url,
                    "path": parsed.path or "/",
                    "host": parsed.netloc,
                    "fields": fields,
                    "checks": checks,
                    "outcomes": outcomes,
                    "tested": bool(checks),
                    "findings": finding_counts.get(endpoint.url, 0),
                    "skipped_reason": skipped_reason,
                }
            )
        tested = sum(1 for item in results if item["tested"])
        return {
            "selected": len(post_endpoints),
            "tested": tested,
            "skipped": max(0, len(post_endpoints) - tested),
            "api_tests": ctx.api_tests,
            "max_api_tests": ctx.max_api_tests,
            "findings": len(api_findings),
            "truncated": len(post_endpoints) > 100,
            "endpoints": results,
        }

    async def _recover_auth_session(
        self,
        scope: Scope,
        audit: AuditLogger,
        *,
        engine: HttpEngine | None,
        auth: AuthConfig | None,
        meta_key: str,
        label: str,
    ) -> tuple[bool, str]:
        if auth is None or engine is None:
            return False, "缺少認證或 HTTP client"
        if meta_key in self._session_recovery_attempted:
            return False, "本次掃描已嘗試過重新登入"
        self._session_recovery_attempted.add(meta_key)
        if auth.type is not AuthType.FORM:
            return False, "此登入方式不支援自動重新登入"
        try:
            retry_config = self.config.model_copy(update={"auth": auth})
            materials = await prepare_auth(retry_config, scope, audit)
            engine.update_auth(materials.headers, materials.cookies)
        except (AuthError, httpx.HTTPError) as exc:
            self._api_meta.setdefault(meta_key, {})
            self._api_meta[meta_key]["recovered"] = False
            self._api_meta[meta_key]["recovery_error"] = str(exc)
            return False, str(exc)
        self._emit("active", f"{label} session 已重新登入，重新檢查…", 88)
        valid, reason = await self._check_auth_session(
            scope,
            engine=engine,
            auth=auth,
            meta_key=meta_key,
            label=label,
        )
        self._api_meta.setdefault(meta_key, {})["recovered"] = valid
        if not valid:
            self._api_meta[meta_key]["recovery_error"] = reason
        return valid, reason

    async def _check_auth_session(
        self,
        scope: Scope,
        *,
        engine: HttpEngine | None = None,
        auth: AuthConfig | None = None,
        meta_key: str = "auth_session",
        label: str = "登入",
    ) -> tuple[bool, str]:
        auth = auth or self.config.auth
        engine = engine or self._http
        if auth.type is AuthType.NONE:
            self._api_meta[meta_key] = {
                "checked": False,
                "valid": None,
                "reason": "not_required",
            }
            return True, ""
        if engine is None or not scope.base_urls():
            return False, "沒有可用的驗證網址"
        base = scope.base_urls()[0]
        raw_verify = (auth.verify_url or "").strip()
        check_url = urljoin(base, raw_verify) if raw_verify else base
        parsed = urlsplit(check_url)
        safe_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
        if not scope.is_allowed(check_url):
            self._api_meta[meta_key] = {
                "checked": True,
                "valid": False,
                "reason": "驗證 URL 不在授權 scope",
                "url": safe_url,
            }
            return False, "驗證 URL 不在授權 scope"
        self._emit("active", f"檢查{label} session 有效性…", 87)
        try:
            page = await engine.get(check_url, rule_id="auth-session-check")
        except ScopeError as exc:
            self._api_meta[meta_key] = {
                "checked": True,
                "valid": False,
                "reason": str(exc),
                "url": safe_url,
            }
            return False, str(exc)
        valid = True
        reason = ""
        if page.status in (0, 401, 403):
            valid = False
            reason = f"HTTP {page.status}"
        elif auth.verify_text and auth.verify_text not in page.text:
            valid = False
            reason = "驗證文字不存在"
        elif page.status in (301, 302, 303, 307, 308):
            location = str(page.headers.get("location") or "")
            if re.search(r"(login|signin|sign-in|sso|/auth)", location, re.I):
                valid = False
                reason = f"重新導向至登入頁：{location}"
        elif raw_verify and page.status >= 400:
            valid = False
            reason = f"驗證頁 HTTP {page.status}"
        self._api_meta[meta_key] = {
            "checked": True,
            "valid": valid,
            "reason": reason,
            "url": safe_url,
        }
        return valid, reason

    def _skipped_api_selection(
        self,
        all_post: list,
        reason: str,
    ) -> dict[str, Any]:
        return {
            "allowlist": self.config.api_post_allowlist,
            "allow_all": bool(
                self.config.api_post_all_ack
                and not self.config.api_post_allowlist
            ),
            "selected_count": 0,
            "skipped_count": len(all_post),
            "hosts": [],
            "selected_endpoints": [],
            "skipped_reason": reason,
            "manifest_summary": {
                "method": "POST",
                "count": 0,
                "hosts": [],
                "field_count": 0,
                "fields": [],
                "truncated": False,
            },
        }

    def _build_api_selection(
        self,
        all_endpoints: list,
        selected_post: list,
    ) -> dict[str, Any]:
        all_post = [
            item for item in all_endpoints if item.method.upper() == "POST"
        ]
        selected: list[dict[str, Any]] = []
        for endpoint in selected_post[:100]:
            parsed = urlsplit(endpoint.url)
            selected.append(
                {
                    "method": endpoint.method.upper(),
                    "url": endpoint.url,
                    "path": parsed.path or "/",
                    "host": parsed.netloc,
                    "fields": [
                        param.name
                        for param in endpoint.params
                        if param.location == "body"
                    ][:100],
                }
            )
        hosts = sorted(
            {
                urlsplit(item.url).netloc
                for item in selected_post
                if urlsplit(item.url).netloc
            }
        )
        field_names = sorted(
            {
                param.name
                for endpoint in selected_post
                for param in endpoint.params
                if param.location == "body"
            }
        )
        return {
            "allowlist": self.config.api_post_allowlist,
            "allow_all": bool(
                self.config.api_post_all_ack
                and not self.config.api_post_allowlist
            ),
            "selected_count": len(selected_post),
            "skipped_count": max(0, len(all_post) - len(selected_post)),
            "hosts": hosts,
            "selected_endpoints": selected,
            "skipped_reason": None,
            "manifest_summary": {
                "method": "POST",
                "count": len(selected_post),
                "hosts": hosts,
                "field_count": len(field_names),
                "fields": field_names[:50],
                "truncated": len(selected_post) > 100,
            },
        }

    def _persist_scope(
        self,
        scope: Scope,
        audit: AuditLogger | None = None,
    ) -> None:
        snapshot = scope.snapshot()
        api = dict(snapshot.get("api") or {})
        api.update(self._api_meta)
        snapshot["api"] = api
        try:
            self.db.update_scan(
                self.scan_id,
                scope_json=json.dumps(snapshot, ensure_ascii=False, default=str),
            )
        except Exception as exc:
            self._log(f"寫入 API 掃描範圍失敗：{exc}")
        if audit:
            try:
                audit.write_scope(snapshot)
            except OSError as exc:
                self._log(f"更新 audit scope 失敗：{exc}")

    async def _fetch_url_document(
        self,
        source_url: str,
        scope: Scope,
        *,
        rule_id: str = "openapi-import",
    ) -> tuple[dict[str, Any], str]:
        if self._http is None:
            raise ScanError("HTTP 引擎尚未初始化")
        current = source_url
        redirects = 0
        while redirects <= 3:
            parsed_current = urlsplit(current)
            if parsed_current.username or parsed_current.password:
                raise ScanError("OpenAPI URL 不可包含帳密")
            try:
                page = await self._http.get(current, rule_id=rule_id)
            except ScopeError as exc:
                raise ScanError(f"OpenAPI URL 不在授權範圍：{exc}") from exc
            if page.status in (301, 302, 303, 307, 308):
                if redirects >= 3:
                    break
                location = str(page.headers.get("location") or "").strip()
                if not location:
                    raise ScanError("OpenAPI URL 回應 redirect，但沒有 Location")
                next_url = urljoin(current, location)
                if urlsplit(next_url).scheme not in ("http", "https"):
                    raise ScanError("OpenAPI redirect 只允許 http:// 或 https://")
                if not scope.is_allowed(next_url):
                    raise ScanError(f"OpenAPI redirect 不在授權範圍：{next_url}")
                redirects += 1
                self._emit("validate", f"OpenAPI redirect：{next_url}", 8)
                current = next_url
                continue
            if page.status != 200 or not page.text:
                raise ScanError(
                    f"OpenAPI URL 匯入失敗：HTTP {page.status}"
                    + (f"（{page.error}）" if page.error else "")
                )
            try:
                loaded = yaml.safe_load(page.text)
            except yaml.YAMLError as exc:
                raise ScanError(f"OpenAPI URL 不是有效 JSON/YAML：{exc}") from exc
            if not isinstance(loaded, dict):
                raise ScanError("OpenAPI URL 回傳的不是 JSON/YAML 物件")
            return loaded, current
        raise ScanError("OpenAPI URL redirect 次數過多（上限 3 次）")

    def _save_findings(self, findings: list[Finding]) -> None:
        if not findings:
            return
        try:
            self.db.add_findings(self.scan_id, findings)
        except Exception as exc:
            self._log(f"寫入發現失敗：{exc}")

    def _save_endpoints(self, endpoints) -> None:
        try:
            self.db.save_endpoints(self.scan_id, endpoints)
        except Exception as exc:
            self._log(f"寫入端點失敗：{exc}")

    def _recount(self, findings: list[Finding]) -> None:
        self.stats.findings = len(findings)
        counts = Counter(item.severity.value for item in findings)
        self.stats.by_severity = {
            severity.value: counts.get(severity.value, 0) for severity in Severity
        }


def dedupe(findings: list[Finding]) -> list[Finding]:
    seen: set[tuple[str, str, str]] = set()
    result: list[Finding] = []
    for finding in findings:
        key = finding_key(finding)
        if key in seen:
            continue
        seen.add(key)
        result.append(finding)
    return result


def finding_key(finding: Finding) -> tuple[str, str, str]:
    # Query values are scan-specific; keep the path so the same issue on the same
    # endpoint is only reported once.
    url_without_query = normalize_url(finding.url).split("?", 1)[0]
    return (finding.rule_id, url_without_query, finding.parameter or "")


def merge_endpoints(*groups) -> list:
    merged: dict[str, object] = {}
    for group in groups:
        for endpoint in group:
            key = f"{endpoint.method.upper()} {normalize_url(endpoint.url)}"
            if key not in merged or endpoint.source == "openapi":
                merged[key] = endpoint
    return list(merged.values())
