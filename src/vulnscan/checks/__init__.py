from __future__ import annotations

import inspect
from collections.abc import Callable
from typing import Any

from ..http import BudgetExceeded, ScanCancelled
from ..models import Endpoint, Page
from . import (
    api_active,
    bola,
    cookies,
    cors,
    csrf,
    disclosure,
    headers,
    js_secrets,
    methods,
    mixed_content,
    openapi,
    redirect,
    sensitive_files,
    sqli,
    sqli_boolean,
    ssrf,
    tls,
    traversal,
    xss,
)
from .base import ScanContext

PassiveCheck = Callable[[list[Page], ScanContext], Any]
ActiveCheck = Callable[[list[Endpoint], ScanContext], Any]


PASSIVE_CHECKS: list[tuple[str, PassiveCheck]] = [
    ("安全標頭", lambda pages, ctx: headers.check(pages, ctx)),
    ("Cookie 屬性", lambda pages, ctx: cookies.check(pages, ctx)),
    ("資訊洩漏", lambda pages, ctx: disclosure.check(pages, ctx)),
    ("TLS 憑證", lambda pages, ctx: tls.check(ctx)),
    ("CORS", lambda pages, ctx: cors.check(ctx)),
    ("HTTP 方法", lambda pages, ctx: methods.check(ctx)),
    ("CSRF 表單", lambda pages, ctx: csrf.check(pages, ctx)),
    ("敏感檔案", lambda pages, ctx: sensitive_files.check(ctx)),
    ("OpenAPI 文件", lambda pages, ctx: openapi.check(ctx)),
    ("混合內容", lambda pages, ctx: mixed_content.check(pages, ctx)),
    ("JS 機密", lambda pages, ctx: js_secrets.check(pages, ctx)),
]

ACTIVE_CHECKS: list[tuple[str, ActiveCheck]] = [
    ("開放重導", lambda endpoints, ctx: redirect.check(endpoints, ctx)),
    ("反射型 XSS", lambda endpoints, ctx: xss.check(endpoints, ctx)),
    ("錯誤型 SQLi", lambda endpoints, ctx: sqli.check(endpoints, ctx)),
]

ADVANCED_CHECKS: list[tuple[str, str, ActiveCheck]] = [
    ("布林型 SQLi", "sqli_boolean", lambda endpoints, ctx: sqli_boolean.check(endpoints, ctx)),
    ("路徑遍歷", "traversal", lambda endpoints, ctx: traversal.check(endpoints, ctx)),
    ("SSRF", "ssrf", lambda endpoints, ctx: ssrf.check(endpoints, ctx)),
]


async def run_passive(pages: list[Page], ctx: ScanContext) -> list:
    findings = []
    for label, check in PASSIVE_CHECKS:
        ctx.log(f"被動檢查：{label}")
        try:
            result = check(pages, ctx)
            if inspect.isawaitable(result):
                result = await result
            findings.extend(result or [])
        except ScanCancelled:
            raise
        except BudgetExceeded as exc:
            ctx.log(f"{label} 略過：{exc}")
        except Exception as exc:
            ctx.log(f"{label} 失敗：{exc}")
    return findings


async def run_active(endpoints: list[Endpoint], ctx: ScanContext) -> list:
    findings = []
    for label, check in ACTIVE_CHECKS:
        ctx.log(f"主動檢查：{label}")
        try:
            result = check(endpoints, ctx)
            if inspect.isawaitable(result):
                result = await result
            findings.extend(result or [])
        except ScanCancelled:
            raise
        except BudgetExceeded as exc:
            ctx.log(f"{label} 略過：{exc}")
        except Exception as exc:
            ctx.log(f"{label} 失敗：{exc}")
    return findings


async def run_advanced(endpoints: list[Endpoint], ctx: ScanContext) -> list:
    enabled = {item.value for item in ctx.config.advanced_checks}
    findings = []
    for label, key, check in ADVANCED_CHECKS:
        if key not in enabled:
            continue
        ctx.log(f"進階檢查：{label}")
        try:
            result = check(endpoints, ctx)
            if inspect.isawaitable(result):
                result = await result
            findings.extend(result or [])
        except ScanCancelled:
            raise
        except BudgetExceeded as exc:
            ctx.log(f"{label} 略過：{exc}")
        except Exception as exc:
            ctx.log(f"{label} 失敗：{exc}")
    return findings


async def run_api(endpoints: list[Endpoint], ctx: ScanContext) -> list:
    ctx.log("API 檢查：JSON POST 參數")
    try:
        return await api_active.run(endpoints, ctx)
    except ScanCancelled:
        raise
    except BudgetExceeded as exc:
        ctx.log(f"API 檢查略過：{exc}")
    except Exception as exc:
        ctx.log(f"API 檢查失敗：{exc}")
    return []


async def run_bola(
    endpoints: list[Endpoint],
    primary,
    secondary,
    unauthenticated,
    ctx: ScanContext,
) -> list:
    ctx.log("API 檢查：BOLA／IDOR 唯讀")
    try:
        return await bola.run(
            endpoints,
            primary,
            secondary,
            unauthenticated,
            ctx,
        )
    except ScanCancelled:
        raise
    except BudgetExceeded as exc:
        ctx.log(f"BOLA 檢查略過：{exc}")
    except Exception as exc:
        ctx.log(f"BOLA 檢查失敗：{exc}")
    return []


CHECK_CATALOG = [
    {
        "category": "安全標頭",
        "items": ["CSP、HSTS、X-Frame-Options", "X-Content-Type-Options、Referrer-Policy", "Permissions-Policy"],
        "profiles": "被動 / 安全 / 完整",
    },
    {
        "category": "Cookie",
        "items": ["Secure、HttpOnly、SameSite", "SameSite=None 必須搭配 Secure"],
        "profiles": "被動 / 安全 / 完整",
    },
    {
        "category": "TLS",
        "items": ["憑證到期、憑證驗證失敗", "TLS 1.0 / 1.1"],
        "profiles": "被動 / 安全 / 完整",
    },
    {
        "category": "CORS",
        "items": ["Origin 反射", "反射 + credentials", "萬用 Origin + credentials"],
        "profiles": "被動 / 安全 / 完整",
    },
    {
        "category": "資訊洩漏",
        "items": ["Server 版本、X-Powered-By", "錯誤堆疊、目錄列表"],
        "profiles": "被動 / 安全 / 完整",
    },
    {
        "category": "敏感檔案",
        "items": [".env、.git/HEAD、phpinfo、server-status"],
        "profiles": "被動 / 安全 / 完整",
    },
    {
        "category": "CSRF / API / 混合內容",
        "items": ["POST 表單 token", "OpenAPI 公開", "HTTPS 頁面載入 HTTP 資源"],
        "profiles": "被動 / 安全 / 完整",
    },
    {
        "category": "JS 洩漏",
        "items": ["AWS / GitHub / Stripe / Google 金鑰", "私密金鑰、通用 secret"],
        "profiles": "被動 / 安全 / 完整",
    },
    {
        "category": "主動檢查",
        "items": ["開放重導", "反射型 HTML 注入 / XSS", "錯誤型 SQL Injection"],
        "profiles": "安全 / 完整",
    },
    {
        "category": "進階檢查（完整模式）",
        "items": [
            "布林型 SQL Injection（成對條件比對）",
            "路徑遍歷（錯誤訊息、canary 檔名）",
            "SSRF（自架 callback listener）",
        ],
        "profiles": "完整",
    },
    {
        "category": "API 授權",
        "items": [
            "BOLA／IDOR 雙帳號唯讀檢查",
            "BFLA 管理／角色 GET 唯讀檢查",
            "只比較狀態與回應形狀，不保存內容",
        ],
        "profiles": "安全 / 完整（需明確確認與第二帳號）",
    },
]
