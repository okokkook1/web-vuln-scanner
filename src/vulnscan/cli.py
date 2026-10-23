from __future__ import annotations

import asyncio
import json
import os
import threading
import webbrowser
from datetime import date, datetime, timedelta
from pathlib import Path

import typer
import yaml

from . import __version__
from .backup import BackupError, create_backup, restore_backup
from .checks import CHECK_CATALOG
from .config import DEFAULT_USER_AGENT, default_data_dir
from .db import Database, finding_fingerprint, finding_to_dict
from .diff import DIFF_GATE_CHOICES, compare_scans, gate_failed
from .engine import ScanEngine
from .models import AuthConfig, AuthType, Scan, ScanConfig, new_scan_id, utcnow
from .presentation import SEVERITY_LABELS
from .report import build_report, render_html_report
from .scope import ScopeError, build_scope

app = typer.Typer(
    name="vulnscan",
    help="Authorized, non-destructive web vulnerability scanner.",
    no_args_is_help=True,
    add_completion=False,
)
baseline_app = typer.Typer(
    name="baseline",
    help="Manage the stored baseline for a target.",
)
app.add_typer(baseline_app, name="baseline")


@app.command()
def ui(
    host: str = typer.Option("127.0.0.1", help="Bind address. Keep 127.0.0.1 unless you add a token."),
    port: int = typer.Option(8765, help="HTTP port."),
    no_browser: bool = typer.Option(False, "--no-browser", help="Do not open a browser."),
    data_dir: Path | None = typer.Option(None, "--data-dir", help="Data directory (default: ./data)."),
) -> None:
    """Start the local web UI."""
    import uvicorn

    if data_dir:
        os.environ["VULNSCAN_DATA_DIR"] = str(data_dir.expanduser().resolve())
    if host not in ("127.0.0.1", "localhost", "::1"):
        typer.echo(
            "v1 僅支援本機 UI（127.0.0.1）。請勿將未加驗證的掃描服務暴露到網路。",
            err=True,
        )
        raise typer.Exit(code=2)
    url_host = "127.0.0.1" if host in ("0.0.0.0", "::") else host
    if ":" in url_host and not url_host.startswith("["):
        url_host = f"[{url_host}]"
    url = f"http://{url_host}:{port}"
    typer.echo(f"VulnScan {__version__} → {url}")
    if not no_browser:
        threading.Timer(1.2, lambda: webbrowser.open(url)).start()
    uvicorn.run(
        "vulnscan.web.app:create_app",
        factory=True,
        host=host,
        port=port,
        log_level="info",
    )


@app.command("login")
def browser_login(
    url: str = typer.Option(..., "--url", help="Login URL to open in a headed browser."),
    out: Path = typer.Option(
        Path("auth-state.json"), "--out", help="Where to save Playwright storage_state JSON."
    ),
    browser: str = typer.Option("chromium", "--browser", help="chromium | firefox | webkit"),
    acknowledge: bool = typer.Option(
        False, "--acknowledge-authorized", help="Confirm you have written authorization."
    ),
) -> None:
    """Open a browser for interactive SSO/MFA/JavaScript login and save storage state."""
    if not acknowledge:
        typer.echo("拒絕執行：請加上 --acknowledge-authorized 確認已取得書面授權。", err=True)
        raise typer.Exit(code=2)
    if not url.startswith(("http://", "https://")):
        typer.echo("--url 必須是 http:// 或 https:// 網址。", err=True)
        raise typer.Exit(code=2)
    if browser not in ("chromium", "firefox", "webkit"):
        typer.echo("--browser 僅支援 chromium、firefox、webkit。", err=True)
        raise typer.Exit(code=2)
    try:
        from playwright.sync_api import sync_playwright
    except ImportError:
        typer.echo(
            '需要 Playwright：pip install -e ".[browser]" 然後 playwright install chromium',
            err=True,
        )
        raise typer.Exit(code=2) from None

    out = out.expanduser().resolve()
    out.parent.mkdir(parents=True, exist_ok=True)
    typer.echo(f"開啟瀏覽器：{url}")
    typer.echo("請完成登入（含 SSO／MFA／JavaScript），完成後回到終端機按 Enter。")
    try:
        with sync_playwright() as playwright:
            browser_type = getattr(playwright, browser)
            browser_instance = browser_type.launch(headless=False)
            context = browser_instance.new_context()
            page = context.new_page()
            page.goto(url, wait_until="domcontentloaded")
            input()
            context.storage_state(path=str(out))
            browser_instance.close()
    except Exception as exc:
        typer.echo(f"瀏覽器登入失敗：{exc}", err=True)
        raise typer.Exit(code=1) from exc
    typer.echo(f"已儲存 storage state：{out}")
    typer.echo("此檔案含 session 憑證，請妥善保管，不要提交到版本控制。")


@app.command("scan")
def scan_command(
    scope_file: Path | None = typer.Option(None, "--scope", help="YAML scope file."),
    url: list[str] = typer.Option([], "--url", help="Target URL (repeatable)."),
    profile: str = typer.Option("safe", "--profile", help="passive | safe | full"),
    advanced: str = typer.Option(
        "",
        "--enable-advanced",
        help="Comma-separated advanced checks for full mode: sqli_boolean,traversal,ssrf.",
    ),
    ssrf_callback: str = typer.Option(
        "",
        "--ssrf-callback",
        help="Reachable HTTP base URL for SSRF callbacks (default: 127.0.0.1 ephemeral port).",
    ),
    auth_cookie: str = typer.Option(
        "", "--auth-cookie", help="Cookie header (prefer VULNSCAN_AUTH_COOKIE env)."
    ),
    auth_header_name: str = typer.Option(
        "", "--auth-header-name", help="Custom auth header name (e.g. Authorization)."
    ),
    auth_header_value: str = typer.Option(
        "", "--auth-header-value", help="Custom auth header value (prefer VULNSCAN_AUTH_HEADER_VALUE)."
    ),
    login_url: str = typer.Option("", "--login-url", help="Form login URL."),
    username: str = typer.Option("", "--username", help="Form login username."),
    password: str = typer.Option("", "--password", help="Form login password (prefer prompt or VULNSCAN_PASSWORD)."),
    login_user_field: str = typer.Option("username", "--login-user-field"),
    login_pass_field: str = typer.Option("password", "--login-pass-field"),
    auth_verify_url: str = typer.Option("", "--auth-verify-url", help="URL used to verify login."),
    auth_verify_text: str = typer.Option("", "--auth-verify-text", help="Text expected after login."),
    auth_state: Path | None = typer.Option(
        None, "--auth-state", help="Playwright storage_state JSON from `vulnscan login`."
    ),
    openapi: Path | None = typer.Option(
        None, "--openapi", help="OpenAPI 3.0/3.1 or Swagger 2 JSON/YAML file to import."
    ),
    openapi_url: str = typer.Option(
        "",
        "--openapi-url",
        help="OpenAPI 3.0/3.1 or Swagger 2 URL to import (fetched with auth).",
    ),
    api_post: bool = typer.Option(
        False,
        "--api-post",
        help="Enable active POST/JSON API tests (may create data; explicit opt-in).",
    ),
    api_post_allow: list[str] = typer.Option(
        [],
        "--api-post-allow",
        help=(
            "Allowlist pattern for POST tests, e.g. 'POST /api/items/*' "
            "or 'POST https://host/api/items/*' (repeatable)."
        ),
    ),
    api_post_all: bool = typer.Option(
        False,
        "--api-post-all",
        help="Explicitly confirm testing all POST endpoints when the allowlist is empty.",
    ),
    max_api_tests: int = typer.Option(
        20,
        "--max-api-tests",
        min=1,
        max=200,
        help="Maximum JSON POST parameter tests.",
    ),
    bola: bool = typer.Option(
        False,
        "--bola",
        help="Enable read-only BOLA/IDOR testing with a second account.",
    ),
    max_bola_tests: int = typer.Option(
        8,
        "--max-bola-tests",
        min=1,
        max=50,
        help="Maximum object endpoints tested for BOLA/IDOR.",
    ),
    bola_auth_cookie: str = typer.Option(
        "",
        "--bola-auth-cookie",
        help="Second-account Cookie header for BOLA.",
    ),
    bola_auth_header_name: str = typer.Option(
        "",
        "--bola-auth-header-name",
        help="Second-account custom Header name for BOLA.",
    ),
    bola_auth_header_value: str = typer.Option(
        "",
        "--bola-auth-header-value",
        help="Second-account custom Header value for BOLA.",
    ),
    bola_auth_state: Path | None = typer.Option(
        None,
        "--bola-auth-state",
        help="Second-account Playwright storage_state JSON for BOLA.",
    ),
    bola_login_url: str = typer.Option(
        "",
        "--bola-login-url",
        help="Second-account form login URL for BOLA.",
    ),
    bola_username: str = typer.Option(
        "",
        "--bola-username",
        help="Second-account form login username for BOLA.",
    ),
    bola_password: str = typer.Option(
        "",
        "--bola-password",
        help="Second-account form login password (prefer VULNSCAN_BOLA_PASSWORD).",
    ),
    bola_login_user_field: str = typer.Option(
        "username",
        "--bola-login-user-field",
        help="Second-account username field name.",
    ),
    bola_login_pass_field: str = typer.Option(
        "password",
        "--bola-login-pass-field",
        help="Second-account password field name.",
    ),
    bola_verify_url: str = typer.Option(
        "",
        "--bola-verify-url",
        help="Second-account post-login verification URL.",
    ),
    bola_verify_text: str = typer.Option(
        "",
        "--bola-verify-text",
        help="Second-account post-login verification text.",
    ),
    bola_allow: list[str] = typer.Option(
        [],
        "--bola-allow",
        help="GET allowlist pattern for BOLA, e.g. 'GET https://host/orders/*'.",
    ),
    bola_allow_all: bool = typer.Option(
        False,
        "--bola-allow-all",
        help="Explicitly confirm BOLA testing all matching GET endpoints when allowlist is empty.",
    ),
    storage_token_key: str = typer.Option(
        "", "--storage-token-key", help="localStorage key to map into an HTTP header."
    ),
    storage_header_name: str = typer.Option(
        "", "--storage-header-name", help="Header name for the localStorage token."
    ),
    storage_header_prefix: str = typer.Option(
        "Bearer ", "--storage-header-prefix", help="Prefix for the mapped header value."
    ),
    out: Path = typer.Option(Path("reports"), "--out", help="Report output directory."),
    acknowledge: bool = typer.Option(
        False, "--acknowledge-authorized", help="Confirm you have written authorization."
    ),
    allow_private: bool = typer.Option(
        False, "--allow-private", help="Allow private/internal IP targets (authorized labs only)."
    ),
    rps: float | None = typer.Option(None, "--rps", help="Requests per second per host."),
    max_requests: int | None = typer.Option(None, "--max-requests", help="Request cap per host."),
    depth: int | None = typer.Option(None, "--depth", help="Maximum crawl depth."),
    timeout: float | None = typer.Option(None, "--timeout", help="Request timeout in seconds."),
    data_dir: Path | None = typer.Option(None, "--data-dir", help="Data directory (default: ./data)."),
) -> None:
    """Run a scan without the UI and write HTML + JSON reports."""
    if not acknowledge:
        typer.echo("拒絕執行：請加上 --acknowledge-authorized 確認已取得書面授權。", err=True)
        raise typer.Exit(code=2)
    if profile not in ("passive", "safe", "full"):
        typer.echo("--profile 僅支援 passive、safe 或 full。", err=True)
        raise typer.Exit(code=2)
    advanced_checks = [item.strip() for item in advanced.split(",") if item.strip()]
    allowed_advanced = {"sqli_boolean", "traversal", "ssrf"}
    unknown = set(advanced_checks) - allowed_advanced
    if unknown:
        typer.echo(f"未知的進階檢查：{', '.join(sorted(unknown))}", err=True)
        raise typer.Exit(code=2)
    if profile == "full" and not advanced_checks:
        typer.echo(
            "完整模式需要 --enable-advanced sqli_boolean,traversal,ssrf（可只選一項）。",
            err=True,
        )
        raise typer.Exit(code=2)
    if profile != "full" and advanced_checks:
        typer.echo("--enable-advanced 只能搭配 --profile full。", err=True)
        raise typer.Exit(code=2)
    if ssrf_callback and "ssrf" not in advanced_checks:
        typer.echo("--ssrf-callback 需要同時啟用 ssrf 進階檢查。", err=True)
        raise typer.Exit(code=2)

    if not auth_cookie and not auth_header_name and not login_url and not auth_state:
        auth_cookie = os.environ.get("VULNSCAN_AUTH_COOKIE", "")
    if auth_header_name and not auth_header_value:
        auth_header_value = os.environ.get("VULNSCAN_AUTH_HEADER_VALUE", "")
    if login_url and not password:
        password = os.environ.get("VULNSCAN_PASSWORD", "")
    auth_modes = [bool(auth_cookie), bool(auth_header_name), bool(login_url), bool(auth_state)]
    if sum(auth_modes) > 1:
        typer.echo("Cookie、Header、表單登入、storage state 只能擇一。", err=True)
        raise typer.Exit(code=2)
    try:
        if auth_cookie:
            auth_config = AuthConfig(type=AuthType.COOKIE, cookie=auth_cookie)
        elif auth_header_name:
            if not auth_header_value:
                auth_header_value = typer.prompt("Header value", hide_input=True)
            auth_config = AuthConfig(
                type=AuthType.HEADER,
                header_name=auth_header_name,
                header_value=auth_header_value,
            )
        elif login_url:
            if not username:
                typer.echo("表單登入需要 --username。", err=True)
                raise typer.Exit(code=2)
            if not password:
                password = typer.prompt("Password", hide_input=True)
            auth_config = AuthConfig(
                type=AuthType.FORM,
                login_url=login_url,
                username=username,
                password=password,
                username_field=login_user_field,
                password_field=login_pass_field,
                verify_url=auth_verify_url or None,
                verify_text=auth_verify_text or None,
            )
        elif auth_state:
            if not auth_state.exists():
                typer.echo(f"找不到 storage state 檔：{auth_state}", err=True)
                raise typer.Exit(code=2)
            try:
                state_data = json.loads(auth_state.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError) as exc:
                typer.echo(f"storage state 讀取失敗：{exc}", err=True)
                raise typer.Exit(code=2) from exc
            if not isinstance(state_data, dict):
                typer.echo("storage state 必須是 JSON 物件。", err=True)
                raise typer.Exit(code=2)
            if bool(storage_token_key) != bool(storage_header_name):
                typer.echo(
                    "--storage-token-key 與 --storage-header-name 必須同時提供或同時省略。",
                    err=True,
                )
                raise typer.Exit(code=2)
            auth_config = AuthConfig(
                type=AuthType.STATE,
                storage_state=state_data,
                storage_token_key=storage_token_key or None,
                storage_header_name=storage_header_name or None,
                storage_header_prefix=storage_header_prefix,
            )
        else:
            if (
                auth_header_value
                or username
                or password
                or auth_verify_url
                or auth_verify_text
                or storage_token_key
                or storage_header_name
            ):
                typer.echo(
                    "登入參數需要搭配 --auth-cookie、--auth-header-name、--login-url 或 --auth-state。",
                    err=True,
                )
                raise typer.Exit(code=2)
            auth_config = AuthConfig()
    except ValueError as exc:
        typer.echo(f"登入設定錯誤：{exc}", err=True)
        raise typer.Exit(code=2) from exc

    bola_auth = None
    if bola:
        if not bola_allow and not bola_allow_all:
            typer.echo(
                "--bola 需要提供 --bola-allow，或加上 --bola-allow-all "
                "明確確認測試所有 BOLA 候選 GET 端點。",
                err=True,
            )
            raise typer.Exit(code=2)
        bola_modes = [
            bool(bola_auth_cookie),
            bool(bola_auth_header_name),
            bool(bola_auth_state),
            bool(bola_login_url),
        ]
        if sum(bola_modes) != 1:
            typer.echo(
                "--bola 需要且只能提供一種第二帳號認證："
                "--bola-auth-cookie、--bola-auth-header-name、"
                "--bola-auth-state 或 --bola-login-url。",
                err=True,
            )
            raise typer.Exit(code=2)
        bola_verify_url_value = bola_verify_url or auth_verify_url
        bola_verify_text_value = bola_verify_text or auth_verify_text
        try:
            if bola_auth_cookie:
                bola_auth = AuthConfig(
                    type=AuthType.COOKIE,
                    cookie=bola_auth_cookie,
                    verify_url=bola_verify_url_value or None,
                    verify_text=bola_verify_text_value or None,
                )
            elif bola_auth_header_name:
                if not bola_auth_header_value:
                    bola_auth_header_value = typer.prompt(
                        "BOLA header value",
                        hide_input=True,
                    )
                bola_auth = AuthConfig(
                    type=AuthType.HEADER,
                    header_name=bola_auth_header_name,
                    header_value=bola_auth_header_value,
                    verify_url=bola_verify_url_value or None,
                    verify_text=bola_verify_text_value or None,
                )
            elif bola_login_url:
                if not bola_username:
                    typer.echo(
                        "--bola-login-url 需要 --bola-username。",
                        err=True,
                    )
                    raise typer.Exit(code=2)
                if not bola_password:
                    bola_password = os.environ.get(
                        "VULNSCAN_BOLA_PASSWORD",
                        "",
                    )
                if not bola_password:
                    bola_password = typer.prompt(
                        "BOLA password",
                        hide_input=True,
                    )
                bola_auth = AuthConfig(
                    type=AuthType.FORM,
                    login_url=bola_login_url,
                    username=bola_username,
                    password=bola_password,
                    username_field=bola_login_user_field,
                    password_field=bola_login_pass_field,
                    verify_url=bola_verify_url_value or None,
                    verify_text=bola_verify_text_value or None,
                )
            else:
                assert bola_auth_state is not None
                if not bola_auth_state.exists():
                    typer.echo(f"找不到 BOLA storage state：{bola_auth_state}", err=True)
                    raise typer.Exit(code=2)
                try:
                    state_data = json.loads(
                        bola_auth_state.read_text(encoding="utf-8")
                    )
                except (OSError, json.JSONDecodeError) as exc:
                    typer.echo(f"BOLA storage state 讀取失敗：{exc}", err=True)
                    raise typer.Exit(code=2) from exc
                if not isinstance(state_data, dict):
                    typer.echo("BOLA storage state 必須是 JSON 物件。", err=True)
                    raise typer.Exit(code=2)
                bola_auth = AuthConfig(
                    type=AuthType.STATE,
                    storage_state=state_data,
                    verify_url=bola_verify_url_value or None,
                    verify_text=bola_verify_text_value or None,
                )
        except ValueError as exc:
            typer.echo(f"BOLA 第二帳號設定錯誤：{exc}", err=True)
            raise typer.Exit(code=2) from exc

    openapi_spec = None
    openapi_name = None
    openapi_url = openapi_url.strip()
    if openapi and openapi_url:
        typer.echo("--openapi 與 --openapi-url 只能擇一。", err=True)
        raise typer.Exit(code=2)
    if openapi:
        if not openapi.exists():
            typer.echo(f"找不到 OpenAPI 檔：{openapi}", err=True)
            raise typer.Exit(code=2)
        try:
            loaded = yaml.safe_load(openapi.read_text(encoding="utf-8"))
        except (OSError, yaml.YAMLError) as exc:
            typer.echo(f"OpenAPI 讀取失敗：{exc}", err=True)
            raise typer.Exit(code=2) from exc
        if not isinstance(loaded, dict):
            typer.echo("OpenAPI 規格必須是 JSON/YAML 物件。", err=True)
            raise typer.Exit(code=2)
        openapi_spec = loaded
        openapi_name = openapi.name
    if api_post and not (openapi_spec or openapi_url):
        typer.echo("--api-post 需要同時提供 --openapi 或 --openapi-url。", err=True)
        raise typer.Exit(code=2)
    if api_post and not api_post_allow and not api_post_all:
        typer.echo(
            "--api-post 需要提供 --api-post-allow，"
            "或加上 --api-post-all 明確確認測試全部 POST 端點。",
            err=True,
        )
        raise typer.Exit(code=2)

    if scope_file is None and not url:
        typer.echo("請提供 --scope 或至少一個 --url。", err=True)
        raise typer.Exit(code=2)
    raw: dict = {}
    if scope_file:
        if not scope_file.exists():
            typer.echo(f"找不到 scope 檔：{scope_file}", err=True)
            raise typer.Exit(code=2)
        raw = yaml.safe_load(scope_file.read_text(encoding="utf-8")) or {}
    limits = raw.get("limits") or {}
    targets = url or list(raw.get("targets") or [])
    if not targets:
        typer.echo("scope 檔沒有 targets。", err=True)
        raise typer.Exit(code=2)
    try:
        config = ScanConfig(
            targets=targets,
            exclude=list(raw.get("exclude") or []),
            allow_private=allow_private or bool(raw.get("allow_private", False)),
            authorized_by=str(raw.get("authorized_by") or "CLI operator"),
            contact=str(raw.get("contact") or "unknown"),
            expires=_parse_date(raw.get("expires")),
            profile=profile,  # type: ignore[arg-type]
            rps_per_host=rps or float(raw.get("rps_per_host") or limits.get("rps_per_host") or 3),
            max_requests_per_host=max_requests
            or int(raw.get("max_requests_per_host") or limits.get("max_requests_per_host") or 2000),
            max_depth=depth
            if depth is not None
            else int(raw.get("max_depth") or limits.get("max_depth") or 3),
            timeout=timeout
            or float(raw.get("timeout") or limits.get("timeout") or 10),
            user_agent=DEFAULT_USER_AGENT,
            advanced_checks=advanced_checks,
            advanced_ack=bool(advanced_checks),
            ssrf_callback=ssrf_callback if "ssrf" in advanced_checks else None,
            auth=auth_config,
            openapi_spec=openapi_spec,
            openapi_url=openapi_url or None,
            openapi_name=openapi_name or openapi_url or None,
            allow_api_post=api_post,
            api_post_allowlist=api_post_allow,
            api_post_all_ack=api_post_all,
            max_api_tests=max_api_tests,
            enable_bola=bola,
            bola_ack=bola,
            bola_auth=bola_auth,
            bola_allowlist=bola_allow,
            bola_allow_all_ack=bola_allow_all,
            max_bola_tests=max_bola_tests,
        )
        build_scope(config)
    except (ScopeError, ValueError, TypeError) as exc:
        typer.echo(f"設定錯誤：{exc}", err=True)
        raise typer.Exit(code=2) from exc

    resolved_data = (data_dir or default_data_dir()).resolve()
    result = asyncio.run(_run_headless(config, resolved_data, out))
    typer.echo("")
    typer.echo(f"完成：{result['findings']} 個發現，{result['requests']} 個請求")
    typer.echo(f"HTML：{result['html']}")
    typer.echo(f"JSON：{result['json']}")
    typer.echo(f"Audit：{result['audit']}")


def _cli_db(data_dir: Path | None) -> Database:
    db = Database((data_dir or default_data_dir()) / "vulnscan.db")
    db.init()
    return db


def _print_diff_findings(label: str, findings) -> None:
    typer.echo(f"\n{label}（{len(findings)}）")
    if not findings:
        typer.echo("  —")
        return
    for finding in findings:
        severity = SEVERITY_LABELS.get(finding.severity, finding.severity)
        parameter = f" · {finding.parameter}" if finding.parameter else ""
        typer.echo(
            f"  [{severity}] {finding.title} — {finding.method} {finding.url}{parameter}"
        )


@app.command("diff")
def diff_command(
    current: str = typer.Option(..., "--current", help="Current scan ID."),
    previous: str | None = typer.Option(
        None,
        "--previous",
        help="Previous scan ID (default: stored baseline or latest comparable scan).",
    ),
    baseline: bool = typer.Option(
        False,
        "--baseline",
        help="Use the target's stored baseline; fail if none is set.",
    ),
    fail_on: str = typer.Option(
        "none",
        "--fail-on",
        help=(
            "Return exit code 1 when the diff gate fails: "
            + ", ".join(DIFF_GATE_CHOICES)
            + "."
        ),
    ),
    json_output: bool = typer.Option(False, "--json", help="Output JSON."),
    data_dir: Path | None = typer.Option(None, "--data-dir"),
) -> None:
    """Compare two scans: new, fixed, unchanged (suppressed findings excluded)."""
    db = _cli_db(data_dir)
    scan = db.get_scan(current)
    if not scan:
        typer.echo(f"找不到掃描：{current}", err=True)
        raise typer.Exit(code=2)
    fail_on = fail_on.strip().lower()
    if fail_on not in DIFF_GATE_CHOICES:
        typer.echo(
            "未知的 --fail-on 條件；可用：" + ", ".join(DIFF_GATE_CHOICES),
            err=True,
        )
        raise typer.Exit(code=2)

    choices = db.list_previous_scans(current, limit=100)
    stored_baseline = db.get_baseline_for_scan(scan)
    if stored_baseline and stored_baseline.id == current:
        stored_baseline = None
    if previous:
        if not db.can_compare_scans(current, previous):
            typer.echo("只能比較相同目標、且較早完成的掃描。", err=True)
            raise typer.Exit(code=2)
    elif stored_baseline and db.can_compare_scans(current, stored_baseline.id):
        previous = stored_baseline.id
    elif baseline:
        typer.echo("此目標尚未設定可用的 baseline。", err=True)
        raise typer.Exit(code=2)
    elif choices:
        previous = choices[0].id
    else:
        typer.echo("沒有可比較的前次掃描。", err=True)
        raise typer.Exit(code=2)
    try:
        result = compare_scans(db, current, previous)
    except ValueError as exc:
        typer.echo(str(exc), err=True)
        raise typer.Exit(code=2) from exc
    failed = gate_failed(result, fail_on)

    if json_output:
        payload = {
            "current": current,
            "previous": previous,
            "summary": result.summary,
            "gate": {"fail_on": fail_on, "failed": failed},
            "new": [finding_to_dict(item) for item in result.new],
            "fixed": [finding_to_dict(item) for item in result.fixed],
            "untested": [finding_to_dict(item) for item in result.untested],
            "untested_reasons": result.untested_reasons,
            "reviewed_out": [
                finding_to_dict(item) for item in result.reviewed_out
            ],
            "unchanged": [finding_to_dict(item) for item in result.unchanged],
            "bola_changes": result.bola_changes,
            "api_changes": result.api_changes,
        }
        typer.echo(json.dumps(payload, ensure_ascii=False, indent=2))
        if failed:
            raise typer.Exit(code=1)
        return

    typer.echo(f"目前：{current}")
    typer.echo(f"前次：{previous}")
    typer.echo(
        f"新增 {result.summary['new']} · 已修復 {result.summary['fixed']} · "
        f"本次未測 {result.summary['untested']} · 已排除 {result.summary['reviewed_out']} · "
        f"未變 {result.summary['unchanged']} · 目前已抑制 {result.summary['suppressed']}"
    )
    if fail_on != "none":
        typer.echo(f"Gate: {fail_on} → {'FAIL' if failed else 'PASS'}")
    _print_diff_findings("新增", result.new)
    _print_diff_findings("已修復", result.fixed)
    _print_diff_findings("本次未測", result.untested)
    _print_diff_findings("未變", result.unchanged)
    if result.api_changes:
        typer.echo(f"API 覆蓋變化 {len(result.api_changes)} 個")
        for item in result.api_changes:
            typer.echo(
                f"  {item['change']}: {item['url']} "
                f"（{item['previous_tested']} → {item['current_tested']}）"
            )
    if result.bola_changes:
        typer.echo(f"BOLA 變化 {len(result.bola_changes)} 個")
        for item in result.bola_changes:
            typer.echo(
                f"  {item['change']}: {item['url']} "
                f"({item['previous']} → {item['current']})"
            )
    if failed:
        raise typer.Exit(code=1)


@baseline_app.command("set")
def baseline_set_command(
    scan: str = typer.Option(..., "--scan", help="Scan ID to store as the target baseline."),
    created_by: str = typer.Option("local", "--created-by"),
    data_dir: Path | None = typer.Option(None, "--data-dir"),
) -> None:
    """Store a completed scan as the baseline for its target."""
    db = _cli_db(data_dir)
    target = db.get_scan(scan)
    if not target:
        typer.echo(f"找不到掃描：{scan}", err=True)
        raise typer.Exit(code=2)
    baseline = db.set_baseline(scan, created_by)
    if not baseline:
        typer.echo("只有已完成或取消的掃描可以設為 baseline。", err=True)
        raise typer.Exit(code=2)
    typer.echo(f"已設定 baseline：{scan}")
    typer.echo(f"目標數：{len(json.loads(baseline.targets_json or '[]'))}")
    typer.echo(f"建立者：{baseline.created_by}")


@baseline_app.command("show")
def baseline_show_command(
    scan: str = typer.Option(..., "--scan", help="Scan ID whose target baseline should be shown."),
    json_output: bool = typer.Option(False, "--json", help="Output JSON."),
    data_dir: Path | None = typer.Option(None, "--data-dir"),
) -> None:
    """Show the stored baseline for a scan's target."""
    db = _cli_db(data_dir)
    target = db.get_scan(scan)
    if not target:
        typer.echo(f"找不到掃描：{scan}", err=True)
        raise typer.Exit(code=2)
    baseline = db.get_baseline_for_scan(target)
    payload = {
        "scan": scan,
        "targets": json.loads(target.targets_json or "[]"),
        "baseline": baseline.id if baseline else None,
        "is_self": bool(baseline and baseline.id == scan),
    }
    if json_output:
        typer.echo(json.dumps(payload, ensure_ascii=False, indent=2))
        return
    if not baseline:
        typer.echo("此目標尚未設定 baseline。")
        return
    typer.echo(f"目前 baseline：{baseline.id}")
    if baseline.id == scan:
        typer.echo("（此掃描本身就是 baseline）")
    typer.echo("目標：")
    for item in payload["targets"]:
        typer.echo(f"  - {item}")


@baseline_app.command("clear")
def baseline_clear_command(
    scan: str = typer.Option(..., "--scan", help="Scan ID whose target baseline should be cleared."),
    data_dir: Path | None = typer.Option(None, "--data-dir"),
) -> None:
    """Clear the stored baseline for a scan's target."""
    db = _cli_db(data_dir)
    target = db.get_scan(scan)
    if not target:
        typer.echo(f"找不到掃描：{scan}", err=True)
        raise typer.Exit(code=2)
    if db.remove_baseline_for_scan(scan):
        typer.echo(f"已清除 baseline：{scan}")
    else:
        typer.echo("此目標沒有 baseline。")


@app.command("backup")
def backup_command(
    out: Path | None = typer.Option(
        None,
        "--out",
        help="Backup ZIP path (default: backups/vulnscan-<timestamp>.zip).",
    ),
    data_dir: Path | None = typer.Option(None, "--data-dir"),
    overwrite: bool = typer.Option(
        False,
        "--overwrite",
        help="Overwrite an existing backup file.",
    ),
) -> None:
    """Create a consistent backup of the SQLite DB and scan artifacts."""
    source_dir = (data_dir or default_data_dir()).expanduser().resolve()
    target = out
    if target is None:
        target = Path("backups") / f"vulnscan-{datetime.now():%Y%m%d-%H%M%S}.zip"
    try:
        result = create_backup(source_dir, target, overwrite=overwrite)
    except BackupError as exc:
        typer.echo(f"備份失敗：{exc}", err=True)
        raise typer.Exit(code=2) from exc
    typer.echo(f"備份完成：{result['path']}")
    typer.echo(f"資料庫：{result['database_size']} bytes")
    typer.echo(f"附加檔案：{result['file_count']} 個")
    typer.echo(f"備份大小：{result['size']} bytes")


@app.command("restore")
def restore_command(
    source: Path = typer.Option(..., "--from", help="Backup ZIP path."),
    data_dir: Path | None = typer.Option(None, "--data-dir"),
    force: bool = typer.Option(
        False,
        "--force",
        help="Restore into a non-empty data directory; old data is renamed.",
    ),
) -> None:
    """Restore a backup created by `vulnscan backup`."""
    target_dir = (data_dir or default_data_dir()).expanduser().resolve()
    try:
        result = restore_backup(source, target_dir, force=force)
    except BackupError as exc:
        typer.echo(f"還原失敗：{exc}", err=True)
        raise typer.Exit(code=2) from exc
    typer.echo(f"還原完成：{result['path']}")
    if result["previous"]:
        typer.echo(f"舊資料已保留：{result['previous']}")


@app.command("suppress")
def suppress_command(
    finding: int = typer.Option(..., "--finding", help="Finding ID (from /findings/<id>)."),
    reason: str = typer.Option(..., "--reason", help="Why this finding is suppressed."),
    created_by: str = typer.Option("local", "--created-by"),
    data_dir: Path | None = typer.Option(None, "--data-dir"),
) -> None:
    """Add a cross-scan suppression rule for a finding."""
    db = _cli_db(data_dir)
    view = db.get_finding_view(finding)
    if not view:
        typer.echo(f"找不到弱點：{finding}", err=True)
        raise typer.Exit(code=2)
    reason = reason.strip()
    if not reason:
        typer.echo("抑制原因不可空白。", err=True)
        raise typer.Exit(code=2)
    suppression = db.add_suppression(
        view,
        reason=reason,
        created_by=created_by.strip() or "local",
    )
    typer.echo(f"已抑制 {view.rule_id} @ {view.url}")
    typer.echo(f"fingerprint：{finding_fingerprint(view)}")
    typer.echo(f"原因：{suppression.reason}")


@app.command("unsuppress")
def unsuppress_command(
    finding: int = typer.Option(..., "--finding", help="Finding ID."),
    data_dir: Path | None = typer.Option(None, "--data-dir"),
) -> None:
    """Remove the suppression rule that matches a finding."""
    db = _cli_db(data_dir)
    view = db.get_finding_view(finding)
    if not view:
        typer.echo(f"找不到弱點：{finding}", err=True)
        raise typer.Exit(code=2)
    if not view.suppression_id:
        typer.echo("此弱點沒有抑制規則。")
        return
    db.remove_suppression(view.suppression_id)
    typer.echo(f"已移除抑制：{view.rule_id} @ {view.url}")


@app.command("suppressions")
def suppressions_command(
    json_output: bool = typer.Option(False, "--json", help="Output JSON."),
    data_dir: Path | None = typer.Option(None, "--data-dir"),
) -> None:
    """List active suppression rules."""
    db = _cli_db(data_dir)
    rows = db.list_suppressions()
    if json_output:
        payload = [
            {
                "id": item.id,
                "fingerprint": item.fingerprint,
                "rule_id": item.rule_id,
                "method": item.method,
                "host": item.host,
                "path": item.path,
                "parameter": item.parameter,
                "reason": item.reason,
                "created_by": item.created_by,
                "created_at": item.created_at.isoformat(),
            }
            for item in rows
        ]
        typer.echo(json.dumps(payload, ensure_ascii=False, indent=2))
        return
    if not rows:
        typer.echo("目前沒有抑制規則。")
        return
    for item in rows:
        parameter = f" · {item.parameter}" if item.parameter else ""
        typer.echo(
            f"[{item.id}] {item.rule_id} — {item.method} {item.host}{item.path}{parameter}\n"
            f"    原因：{item.reason}（{item.created_by}）"
        )


@app.command("rules")
def rules_list() -> None:
    """List built-in checks."""
    for group in CHECK_CATALOG:
        typer.echo(f"[{group['category']}] ({group['profiles']})")
        for item in group["items"]:
            typer.echo(f"  - {item}")


async def _run_headless(config: ScanConfig, data_dir: Path, out_dir: Path) -> dict:
    db = Database(data_dir / "vulnscan.db")
    db.init()
    scan_id = new_scan_id()
    scan = Scan(
        id=scan_id,
        status="running",
        profile=config.profile.value,
        targets_json=json.dumps(config.targets, ensure_ascii=False),
        scope_json=json.dumps(
            {
                "targets": config.targets,
                "authorized_by": config.authorized_by,
                "contact": config.contact,
                "expires": config.expires.isoformat(),
                "allow_private": config.allow_private,
                "profile": config.profile.value,
                "advanced_checks": [item.value for item in config.advanced_checks],
                "advanced_ack": config.advanced_ack,
                "auth": config.auth.summary(),
                "api": {
                    "openapi": bool(config.openapi_spec or config.openapi_url),
                    "name": config.openapi_name,
                    "url": config.openapi_url,
                    "expected_spec_fingerprint": config.openapi_fingerprint,
                    "allow_post": config.allow_api_post,
                    "post_allowlist": config.api_post_allowlist,
                    "post_allow_all": config.api_post_all_ack,
                    "max_api_tests": config.max_api_tests,
                    "bola": {
                        "enabled": config.enable_bola,
                        "ack": config.bola_ack,
                        "secondary_auth": (
                            config.bola_auth.summary()
                            if config.bola_auth
                            else None
                        ),
                        "allowlist": config.bola_allowlist,
                        "allow_all": config.bola_allow_all_ack,
                        "max_tests": config.max_bola_tests,
                    },
                },
            },
            ensure_ascii=False,
        ),
        started_at=utcnow(),
    )
    db.create_scan(scan)
    cancel_event = asyncio.Event()
    last_message = {"text": ""}

    def on_update(phase: str, message: str, stats: dict, progress: int) -> None:
        if message != last_message["text"] or progress == 100:
            typer.echo(f"[{progress:3d}%] {message}")
            last_message["text"] = message

    engine = ScanEngine(
        scan_id=scan_id,
        config=config,
        db=db,
        data_dir=data_dir,
        cancel_event=cancel_event,
        on_update=on_update,
    )
    try:
        result = await engine.run()
        db.update_scan(
            scan_id,
            status="completed",
            finished_at=utcnow(),
            phase="已完成",
            progress=100,
            message=f"掃描完成：{result.stats.findings} 個發現",
            stats_json=json.dumps(result.stats.model_dump(), ensure_ascii=False),
        )
    except Exception as exc:
        db.update_scan(
            scan_id,
            status="failed",
            finished_at=utcnow(),
            phase="失敗",
            message=f"掃描失敗：{exc}",
            error=str(exc),
        )
        typer.echo(f"掃描失敗：{exc}", err=True)
        raise typer.Exit(code=1) from exc

    out_dir.mkdir(parents=True, exist_ok=True)
    updated = db.get_scan(scan_id)
    assert updated is not None
    json_path = out_dir / f"vulnscan-{scan_id}.json"
    html_path = out_dir / f"vulnscan-{scan_id}.html"
    json_path.write_text(
        json.dumps(build_report(db, updated), ensure_ascii=False, indent=2),
        encoding="utf-8",
    )
    html_path.write_text(render_html_report(db, updated), encoding="utf-8")
    return {
        "findings": result.stats.findings,
        "requests": result.stats.requests,
        "html": html_path,
        "json": json_path,
        "audit": data_dir / "scans" / scan_id / "audit.jsonl",
    }


def _parse_date(value) -> date:
    if not value:
        return date.today() + timedelta(days=30)
    if isinstance(value, date):
        return value
    return date.fromisoformat(str(value))


if __name__ == "__main__":
    app()
