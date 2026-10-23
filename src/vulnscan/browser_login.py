from __future__ import annotations

import contextlib
import importlib.util
import secrets
import threading
import time
from dataclasses import dataclass, field
from typing import Any

SESSION_TTL_SECONDS = 900
LOGIN_TIMEOUT_SECONDS = 600


class BrowserLoginError(RuntimeError):
    pass


@dataclass
class BrowserSession:
    id: str
    login_url: str
    status: str = "starting"
    message: str = "正在啟動瀏覽器…"
    error: str | None = None
    state: dict[str, Any] | None = None
    complete_event: threading.Event = field(default_factory=threading.Event)
    cancel_event: threading.Event = field(default_factory=threading.Event)
    created_at: float = field(default_factory=time.monotonic)
    lock: threading.Lock = field(default_factory=threading.RLock, repr=False)
    thread: threading.Thread | None = field(default=None, repr=False)

    def set_status(self, status: str, message: str) -> None:
        with self.lock:
            self.status = status
            self.message = message

    def fail(self, message: str) -> None:
        with self.lock:
            self.status = "failed"
            self.error = message
            self.message = message

    def snapshot(self) -> dict[str, Any]:
        with self.lock:
            return {
                "id": self.id,
                "status": self.status,
                "message": self.message,
                "error": self.error,
            }


class BrowserLoginManager:
    """Runs Playwright in worker threads so FastAPI's event loop stays responsive."""

    def __init__(self) -> None:
        self._sessions: dict[str, BrowserSession] = {}
        self._lock = threading.Lock()
        self._shutdown = False

    def start(self, login_url: str) -> dict[str, Any]:
        if importlib.util.find_spec("playwright") is None:
            raise BrowserLoginError(
                '需要 Playwright：pip install -e ".[browser]" 然後 playwright install chromium'
            )
        session = BrowserSession(id=secrets.token_urlsafe(18), login_url=login_url)
        with self._lock:
            self._expire_locked()
            self._sessions[session.id] = session
        thread = threading.Thread(
            target=self._run_session,
            args=(session,),
            name=f"vulnscan-browser-{session.id[:8]}",
            daemon=True,
        )
        session.thread = thread
        thread.start()
        return session.snapshot()

    def complete(self, session_id: str) -> dict[str, Any] | None:
        session = self._get(session_id)
        if not session:
            return None
        with session.lock:
            if session.status in ("starting", "failed", "cancelled", "ready"):
                return session.snapshot()
            session.complete_event.set()
            session.status = "capturing"
            session.message = "正在擷取登入狀態…"
        return session.snapshot()

    def cancel(self, session_id: str) -> dict[str, Any] | None:
        session = self._get(session_id)
        if not session:
            return None
        session.cancel_event.set()
        session.set_status("cancelled", "已取消瀏覽器登入")
        return session.snapshot()

    def status(self, session_id: str) -> dict[str, Any] | None:
        with self._lock:
            self._expire_locked()
        session = self._get(session_id)
        return session.snapshot() if session else None

    def get_state(self, session_id: str) -> dict[str, Any] | None:
        session = self._get(session_id)
        if not session:
            return None
        with session.lock:
            if session.status == "ready" and isinstance(session.state, dict):
                return session.state
        return None

    def consume(self, session_id: str) -> None:
        with self._lock:
            self._sessions.pop(session_id, None)

    def shutdown(self) -> None:
        self._shutdown = True
        with self._lock:
            sessions = list(self._sessions.values())
            self._sessions.clear()
        for session in sessions:
            session.cancel_event.set()
        for session in sessions:
            if session.thread and session.thread.is_alive():
                session.thread.join(timeout=2)

    def _get(self, session_id: str) -> BrowserSession | None:
        with self._lock:
            return self._sessions.get(session_id)

    def _expire_locked(self) -> None:
        now = time.monotonic()
        expired = [
            key
            for key, session in self._sessions.items()
            if now - session.created_at > SESSION_TTL_SECONDS
        ]
        for key in expired:
            session = self._sessions.pop(key)
            session.cancel_event.set()

    def _run_session(self, session: BrowserSession) -> None:
        try:
            from playwright.sync_api import sync_playwright
        except ImportError:
            session.fail(
                '需要 Playwright：pip install -e ".[browser]" 然後 playwright install chromium'
            )
            return
        browser = None
        try:
            with sync_playwright() as playwright:
                browser = playwright.chromium.launch(headless=False)
                context = browser.new_context()
                page = context.new_page()
                page.goto(session.login_url, wait_until="domcontentloaded", timeout=60_000)
                session.set_status(
                    "waiting",
                    "瀏覽器已開啟；完成登入後回到這裡按「我已完成登入」。",
                )
                deadline = time.monotonic() + LOGIN_TIMEOUT_SECONDS
                while True:
                    if self._shutdown or session.cancel_event.is_set():
                        session.set_status("cancelled", "已取消瀏覽器登入")
                        return
                    if session.complete_event.wait(0.5):
                        break
                    if time.monotonic() > deadline:
                        session.fail("瀏覽器登入逾時，請重新開始")
                        return
                    if not browser.is_connected():
                        session.fail("瀏覽器已關閉，請重新開始登入")
                        return

                session.set_status("capturing", "正在擷取 Cookie 與 localStorage…")
                try:
                    state = context.storage_state()
                except Exception as exc:
                    session.fail(f"無法擷取登入狀態：{exc}")
                    return
                with session.lock:
                    session.state = state
                    session.status = "ready"
                    session.message = "登入完成，可以開始掃描"
                    session.error = None
        except Exception as exc:  # surface browser failures to the UI
            message = str(exc)
            if "Executable doesn't exist" in message or "playwright install" in message.lower():
                message += "（請執行 playwright install chromium）"
            session.fail(f"瀏覽器登入失敗：{message}")
        finally:
            if browser is not None:
                with contextlib.suppress(Exception):
                    browser.close()
