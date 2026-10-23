from __future__ import annotations

import os
import socket
import threading
import time
from pathlib import Path

import pytest

from vulnscan.web.app import create_app

playwright_api = pytest.importorskip("playwright.sync_api")
uvicorn = pytest.importorskip("uvicorn")

pytestmark = pytest.mark.skipif(
    os.environ.get("VULNSCAN_E2E") != "1",
    reason="set VULNSCAN_E2E=1 and install Playwright Chromium to run GUI E2E",
)


def _free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def _wait_for_port(port: int, timeout: float = 15.0) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.5):
                return
        except OSError:
            time.sleep(0.1)
    raise RuntimeError("UI server did not start")


def test_new_scan_api_and_bola_controls(tmp_path: Path):
    port = _free_port()
    app = create_app(tmp_path)
    server = uvicorn.Server(
        uvicorn.Config(
            app,
            host="127.0.0.1",
            port=port,
            log_level="warning",
        )
    )
    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()
    try:
        _wait_for_port(port)
        with playwright_api.sync_playwright() as playwright:
            browser = playwright.chromium.launch(headless=True)
            try:
                page = browser.new_page()
                page.goto(f"http://127.0.0.1:{port}/scans/new")
                assert "新增掃描" in page.content()
                page.fill('[name="targets"]', "http://127.0.0.1:9/")
                page.fill('[name="authorized_by"]', "E2E")
                page.fill('[name="contact"]', "e2e@example.com")
                page.fill('[name="expires"]', "2099-01-01")
                page.check('[name="authorized_ack"]')
                page.click("[data-next]")
                page.locator("#api-preview-button").wait_for(state="visible")
                page.fill('[name="openapi_url"]', "https://api.example.com/openapi.json")
                page.select_option("#bola-auth-type", "cookie")
                assert page.locator('[name="bola_auth_cookie"]').is_visible()
                page.check('[name="enable_bola"]')
                page.check('[name="bola_ack"]')
                page.check('[name="bola_allow_all_ack"]')
                assert page.locator('[name="bola_auth_cookie"]').is_visible()
                page.goto(f"http://127.0.0.1:{port}/review")
                assert "驗證工作台" in page.content()
            finally:
                browser.close()
    finally:
        server.should_exit = True
        thread.join(timeout=5)
